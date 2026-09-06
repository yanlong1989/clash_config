"""用固定规则快照、真实转换器和隔离 Mihomo 验证分流流水线。"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager, ExitStack
import copy
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, Request
import uuid

import yaml

try:
    from .validate_rules import ValidationResult, read_yaml_unique, validate_routes, validate_template
except ImportError:
    from validate_rules import ValidationResult, read_yaml_unique, validate_routes, validate_template


BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
REGIONS = ("香港", "日本", "美国", "台湾", "狮城", "新加坡", "韩国")
FIXTURE_NAMES = (
    "香港 HK fixture", "日本 JP fixture", "美国 US fixture",
    "台湾 TW fixture", "新加坡 SG fixture", "韩国 KR fixture",
)
# 测试解析结果仅作为规则匹配元数据，所有连接都由本地 SOCKS 夹具接收。
TEST_IPV4 = "8.8.4.4"
TEST_IPV6 = "2001:4860:4860::8844"


def _write_json(path: Path, value: Any) -> None:
    """保存机器可读验收证据，不生成说明文档。"""
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> Any:
    """按 UTF-8 读取规则快照或固定用例。"""
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _merge(result: ValidationResult, other: ValidationResult, stage: str) -> None:
    """合并分阶段结果，并保留阶段名便于定位失败。"""
    result.errors.extend(f"{stage}: {item}" for item in other.errors)
    result.warnings.extend(f"{stage}: {item}" for item in other.warnings)
    result.details[stage] = other.details


def _free_port() -> int:
    """申请系统分配的临时本地端口，避免占用用户客户端的端口。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _request(url: str, *, secret: str = "", timeout: float = 15) -> bytes:
    """直连本地辅助服务，明确绕过系统代理设置。"""
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(url, headers=headers), timeout=timeout) as response:
        return response.read()


def _helper_environment(directory: Path | None = None) -> dict[str, str]:
    """去除可能影响辅助核心的外部控制、执行钩子和代理环境变量。"""
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("CLASH_") or key.upper() in {
            "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "API_MODE", "API_TOKEN",
            "MANAGED_PREFIX", "PORT",
        }:
            env.pop(key, None)
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"
    if directory is not None:
        # 每个辅助进程使用自己的可写临时目录，兼容受限 Windows 的系统 Temp 权限。
        temporary = directory / "tmp"
        temporary.mkdir(parents=True, exist_ok=True)
        for name in ("TMP", "TEMP", "TMPDIR"):
            env[name] = str(temporary)
    return env


@contextmanager
def _process(command: list[str], cwd: Path, log_path: Path,
             env: dict[str, str] | None = None) -> Iterator[subprocess.Popen]:
    """隐藏启动独立辅助进程；退出时只终止本函数创建的进程并回收。"""
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, env=env or _helper_environment(cwd),
            creationflags=flags,
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def _wait_http(url: str, process: subprocess.Popen, *, secret: str = "") -> bytes:
    """等待辅助服务就绪，异常退出立即失败，最多等待十五秒。"""
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"辅助进程提前退出，退出码 {process.returncode}")
        try:
            return _request(url, secret=secret, timeout=0.5)
        except (OSError, URLError):
            time.sleep(0.1)
    raise TimeoutError(f"本地辅助服务启动超时：{urlsplit(url).path}")


class _SnapshotHandler(BaseHTTPRequestHandler):
    """仅提供显式登记的快照内容，不开放目录浏览或文件写入。"""

    def do_GET(self) -> None:
        """响应白名单中的只读测试资源并记录访问路径。"""
        path = urlsplit(self.path).path
        content = self.server.payloads.get(path)
        self.server.requests.append(path)
        if content is None:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        """静默常规 HTTP 日志，验收结果另以 JSON 保存。"""


class _SnapshotServer(ThreadingHTTPServer):
    """监听回环地址的快照服务器。"""
    daemon_threads = True

    def __init__(self) -> None:
        """初始化资源白名单与请求记录。"""
        self.payloads: dict[str, bytes] = {}
        self.requests: list[str] = []
        super().__init__(("127.0.0.1", 0), _SnapshotHandler)


@contextmanager
def _serve(server: socketserver.BaseServer) -> Iterator[socketserver.BaseServer]:
    """启动本地测试服务器，结束时停止监听并等待主线程退出。"""
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        if hasattr(server, "stopping"):
            server.stopping.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    """读取完整协议字段，短读或对端关闭都直接报错。"""
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("本地测试连接提前关闭")
        chunks.extend(chunk)
    return bytes(chunks)


class _SocksHandler(socketserver.BaseRequestHandler):
    """本地 SOCKS 终点只记录连接目标，不向目标主机发起连接。"""

    def handle(self) -> None:
        """完成 SOCKS5 握手并维持连接，供 Mihomo API 读取命中证据。"""
        connection = self.request
        connection.settimeout(5)
        try:
            version, count = _recv_exact(connection, 2)
            methods = _recv_exact(connection, count)
            if version != 5 or 0 not in methods:
                return
            connection.sendall(b"\x05\x00")
            version, command, _, address_type = _recv_exact(connection, 4)
            if version != 5 or command != 1:
                return
            if address_type == 1:
                target = socket.inet_ntop(socket.AF_INET, _recv_exact(connection, 4))
            elif address_type == 4:
                target = socket.inet_ntop(socket.AF_INET6, _recv_exact(connection, 16))
            elif address_type == 3:
                target = _recv_exact(connection, _recv_exact(connection, 1)[0]).decode("ascii")
            else:
                return
            port = struct.unpack("!H", _recv_exact(connection, 2))[0]
            with self.server.lock:
                self.server.seen.append({"host": target, "port": port})
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            connection.settimeout(0.5)
            while not self.server.stopping.is_set():
                try:
                    if not connection.recv(1024):
                        break
                except socket.timeout:
                    continue
        except (OSError, UnicodeError, ValueError):
            return


class _SocksServer(socketserver.ThreadingTCPServer):
    """允许并发的回环 SOCKS 夹具。"""
    daemon_threads = True
    block_on_close = False

    def __init__(self) -> None:
        """初始化连接目标记录与停止信号。"""
        self.seen: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        super().__init__(("127.0.0.1", 0), _SocksHandler)


class _DNSHandler(socketserver.BaseRequestHandler):
    """为隔离核心返回固定 DNS 数据，不使用任何公网 DNS。"""

    def handle(self) -> None:
        """保留查询问题区，返回测试 IPv4/IPv6；其他记录返回空答案。"""
        query, transport = self.request
        try:
            if len(query) < 12 or struct.unpack("!H", query[4:6])[0] != 1:
                return
            cursor = 12
            labels = []
            while query[cursor]:
                length = query[cursor]
                if length > 63:
                    return
                labels.append(query[cursor + 1:cursor + 1 + length].decode("ascii"))
                cursor += length + 1
            end = cursor + 5
            qtype, qclass = struct.unpack("!HH", query[cursor + 1:end])
            hostname = ".".join(labels).lower()
            answer = b""
            if qclass == 1 and qtype in (1, 28):
                value = self.server.overrides.get(hostname, TEST_IPV4 if qtype == 1 else TEST_IPV6)
                address = ipaddress.ip_address(value)
                if address.version == (4 if qtype == 1 else 6):
                    packed = address.packed
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 30, len(packed)) + packed
            header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
            transport.sendto(header + query[12:end] + answer, self.client_address)
        except (IndexError, UnicodeError, ValueError, struct.error, OSError):
            return


class _DNSServer(socketserver.UDPServer):
    """仅监听回环地址的确定性 DNS 夹具。"""

    def __init__(self, cases: list[dict[str, Any]]) -> None:
        """用例同时提供域名和 IP 时，使用指定 IP 作为本地解析结果。"""
        self.overrides = {case["domain"].lower(): case["ip"] for case in cases
                          if case.get("domain") and case.get("ip")}
        super().__init__(("127.0.0.1", 0), _DNSHandler)


def _normalise_rule(rule: str) -> str:
    """统一域名大小写、FINAL 和 IPv6 别名，保留策略、顺序及 no-resolve。"""
    parts = [part.strip() for part in rule.split(",")]
    if parts[0] == "FINAL":
        parts[0] = "MATCH"
    if parts[0] in {"IP-CIDR", "IP-CIDR6"} and len(parts) > 1:
        parts[0] = "IP-CIDR"
        parts[1] = ipaddress.ip_network(parts[1], strict=False).with_prefixlen
    if parts[0].startswith("DOMAIN") and len(parts) > 1:
        parts[1] = parts[1].lower().rstrip(".")
    return ",".join(parts)


def _check_output(config: dict[str, Any], expected: list[str],
                  *, netflix_fallback: bool = False) -> ValidationResult:
    """检查完整规则序列、末尾兜底、策略组引用、空组和循环。"""
    result = ValidationResult(errors=[], warnings=[], details={})
    rules = config.get("rules")
    if not isinstance(rules, list) or not all(isinstance(item, str) for item in rules):
        result.errors.append("转换产物缺少有效 rules 数组")
        return result
    actual = [_normalise_rule(rule) for rule in rules]
    wanted = [_normalise_rule(rule) for rule in expected]
    result.details["rule_count"] = len(actual)
    result.details["expected_rule_count"] = len(wanted)
    if actual != wanted:
        missing = list((Counter(wanted) - Counter(actual)).elements())
        extra = list((Counter(actual) - Counter(wanted)).elements())
        result.errors.append(f"转换规则与快照不一致：预期 {len(wanted)} 条，实际 {len(actual)} 条")
        result.details["missing_rules"] = missing[:20]
        result.details["extra_rules"] = extra[:20]
        for index, (left, right) in enumerate(zip(wanted, actual), 1):
            if left != right:
                result.details["first_difference"] = {"index": index, "expected": left, "actual": right}
                break
    matches = [index for index, rule in enumerate(actual) if rule.startswith("MATCH,")]
    if matches != [len(actual) - 1]:
        result.errors.append("必须只有一条 MATCH，并且位于全部规则末尾")
    proxies = config.get("proxies", [])
    groups = config.get("proxy-groups", [])
    if not isinstance(proxies, list) or not proxies:
        result.errors.append("合成订阅没有产生任何可用节点")
        proxies = []
    if not isinstance(groups, list):
        result.errors.append("proxy-groups 不是数组")
        groups = []
    node_names = [item.get("name") for item in proxies if isinstance(item, dict)]
    group_names = [item.get("name") for item in groups if isinstance(item, dict)]
    all_names = node_names + group_names
    if any(not isinstance(name, str) or not name for name in all_names):
        result.errors.append("节点或策略组名称为空")
    if len(set(all_names)) != len(all_names):
        result.errors.append("节点或策略组名称重复")
    known = set(all_names) | BUILTINS
    graph: dict[str, list[str]] = {}
    for group in groups:
        if not isinstance(group, dict):
            result.errors.append("策略组对象格式错误")
            continue
        name = group.get("name", "")
        members = group.get("proxies", [])
        if not isinstance(members, list) or not members:
            result.errors.append(f"策略组为空：{name}")
            members = []
        for member in members:
            if member not in known:
                result.errors.append(f"策略组引用不存在：{name} -> {member}")
        # 转换器有时为空匹配自动补 DIRECT，仍须识别地区节点实际缺失。
        if any(region in name for region in REGIONS) and "节点" in name:
            if not any(member in node_names for member in members):
                result.errors.append(f"地区节点匹配为空：{name}")
        graph[name] = [member for member in members if member in group_names]
        if netflix_fallback and "奈飞节点" in name and (not members or members[0] != "🚀 节点选择"):
            result.errors.append("无奈飞标签时，奈飞节点组未默认使用节点选择候补")
    active: set[str] = set()
    visited: set[str] = set()

    def visit(name: str, route: list[str]) -> None:
        """深度优先检查策略组依赖图，显示具体循环路径。"""
        if name in active:
            result.errors.append("策略组存在循环：" + " -> ".join(route + [name]))
            return
        if name in visited:
            return
        active.add(name)
        for child in graph.get(name, []):
            visit(child, route + [name])
        active.remove(name)
        visited.add(name)

    for name in graph:
        visit(name, [])
    for rule in actual:
        parts = rule.split(",")
        policy = parts[1] if parts[0] == "MATCH" else parts[2] if len(parts) > 2 else ""
        if policy not in known:
            result.errors.append(f"规则引用不存在的策略：{rule}")
    result.details["node_count"] = len(node_names)
    result.details["group_count"] = len(group_names)
    return result


def _snapshot_template(template: Path, snapshot_dir: Path,
                       server: _SnapshotServer) -> bytes:
    """逐行替换规则 URL 为本地快照，保持格式前缀、策略和顺序。"""
    manifest = _read_json(snapshot_dir / "sources.json")
    if manifest.get("complete") is not True:
        raise ValueError("快照未完整生成，不能交给转换器")
    if manifest.get("template_sha256") != hashlib.sha256(template.read_bytes()).hexdigest():
        raise ValueError("模板在快照生成后发生变化，请重新固定来源")
    sources = manifest["sources"]
    lines = template.read_text(encoding="utf-8-sig").splitlines()
    host = f"http://127.0.0.1:{server.server_address[1]}"
    replaced: set[int] = set()
    for index, source in enumerate(sources):
        line_number = int(source["line"])
        path = (snapshot_dir / source["path"]).resolve()
        if not path.is_relative_to(snapshot_dir.resolve()):
            raise ValueError("快照路径越出快照目录")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != source["sha256"]:
            raise ValueError(f"快照校验和不一致：第 {line_number} 行")
        original = lines[line_number - 1].strip()
        if not original.startswith("ruleset="):
            raise ValueError(f"清单行号不对应 ruleset：第 {line_number} 行")
        group, address = original.split("=", 1)[1].split(",", 1)
        if group != source["group"]:
            raise ValueError(f"清单策略组不一致：第 {line_number} 行")
        prefix = ""
        for supported in ("surge:", "quanx:", "clash-domain:", "clash-ipcidr:", "clash-classic:"):
            if address.startswith(supported):
                prefix = supported
                break
        tail = address.rsplit(",", 1)
        interval = "," + tail[-1] if len(tail) == 2 and tail[-1].isdigit() else ""
        resource = f"/source/{index}"
        server.payloads[resource] = content
        lines[line_number - 1] = f"ruleset={group},{prefix}{host}{resource}{interval}"
        replaced.add(line_number)
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("ruleset=") and number not in replaced:
            address = stripped.split("=", 1)[1].split(",", 1)[1]
            if not address.startswith("[]"):
                raise ValueError(f"存在未固定的规则来源：第 {number} 行")
    # 验收只改变临时基底的监听设置，业务 rules 和策略组保持原模板内容。
    lines = [line for line in lines if not line.strip().startswith("clash_rule_base=")]
    lines.append(f"clash_rule_base={host}/base.yaml")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _subscription(names: tuple[str, ...], port: int) -> bytes:
    """生成只有回环 SOCKS 节点的合成 Clash 订阅，不接触真实凭据。"""
    config = {"proxies": [{"name": name, "type": "socks5", "server": "127.0.0.1", "port": port}
                          for name in names]}
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode("utf-8")


def _converter_binary(source: Path, destination: Path) -> Path:
    """复制辅助程序和同目录 DLL，防止转换器在原安装目录生成配置。"""
    destination.mkdir(parents=True, exist_ok=True)
    binary = destination / source.name
    shutil.copy2(source, binary)
    for library in source.parent.glob("*.dll"):
        shutil.copy2(library, destination / library.name)
    return binary


def _converter_preferences(port: int, base_url: str) -> str:
    """创建固定容量预算的转换设置，禁用缓存以验证每一轮快照内容。"""
    return f"""[common]
api_mode=true
enable_insert=false
clash_rule_base={base_url}/base.yaml
proxy_config=NONE
proxy_ruleset=NONE
proxy_subscription=NONE
[node_pref]
clash_use_new_field_name=true
filter_deprecated_nodes=false
[managed_config]
write_managed_config=false
managed_config_prefix=
[emojis]
add_emoji=false
remove_old_emoji=false
[rulesets]
enabled=true
overwrite_original_rules=true
update_ruleset_on_request=true
[server]
listen=127.0.0.1
port={port}
[advanced]
log_level=info
max_allowed_rulesets=0
max_allowed_rules=32768
max_allowed_download_size=1048576
enable_cache=false
async_fetch_ruleset=false
skip_failed_links=false
"""


def _convert(converter_url: str, snapshot_url: str, name: str, output: Path) -> dict[str, Any]:
    """请求真实 subconverter 生成 Clash 配置，并保存原始返回内容。"""
    query = urlencode({"target": "clash", "url": f"{snapshot_url}/{name}.yaml",
                       "config": f"{snapshot_url}/template.ini", "new_name": "true",
                       "insert": "false", "emoji": "false", "list": "false"})
    data = _request(f"{converter_url}/sub?{query}", timeout=90)
    output.write_bytes(data)
    config = read_yaml_unique(data.decode("utf-8-sig"))
    if not isinstance(config, dict):
        raise ValueError("转换器没有返回有效配置对象")
    return config


def _core_check(binary: Path, config: Path, directory: Path) -> dict[str, Any]:
    """调用真实 Mihomo 的配置检查，不启动代理监听或修改现有客户端。"""
    directory.mkdir(parents=True, exist_ok=True)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    completed = subprocess.run(
        [str(binary), "-t", "-d", str(directory), "-f", str(config)],
        capture_output=True, timeout=45, env=_helper_environment(directory), creationflags=flags,
    )
    output = (completed.stdout + completed.stderr).decode("utf-8", errors="replace")
    (directory / "config-check.log").write_text(output, encoding="utf-8")
    return {"returncode": completed.returncode, "output": output,
            "log": str(directory / "config-check.log")}


def _select_core_cases(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """选择各策略、IPv4/IPv6 和关键服务的代表性用例；进程匹配留给静态检查。"""
    eligible = [case for case in cases if not case.get("process")
                and case.get("core_test") is not False and (case.get("domain") or case.get("ip"))]
    explicit = [case for case in eligible if case.get("core_test") is True]
    if explicit:
        return explicit
    selected = []
    categories = set()
    for case in eligible:
        family = ipaddress.ip_address(case["ip"]).version if case.get("ip") else "domain"
        category = (case["expected_policy"], family)
        text = (case.get("name", "") + case.get("domain", "")).lower()
        important = any(word in text for word in (
            "copilot", "gemini", "openai", "chatgpt", "claude", "netflix", "azure ai",
            "grok", "cursor", "hugging", "github", "docker", "youtube", "中国",
        ))
        if category not in categories or important:
            selected.append(case)
            categories.add(category)
    return selected


def _expected_first_rule(rules: list[str], case: dict[str, Any]) -> str:
    """计算本地夹具元数据的首条规则，用于与核心 API 的类型和载荷逐项对照。"""
    domain = case.get("domain", "").lower().rstrip(".")
    resolved = case.get("ip") if not domain else None
    for rule in rules:
        parts = _normalise_rule(rule).split(",")
        kind, payload = parts[:2]
        matched = kind == "MATCH"
        if kind == "DOMAIN":
            matched = domain == payload.lower()
        elif kind == "DOMAIN-SUFFIX":
            matched = domain == payload.lower() or domain.endswith("." + payload.lower())
        elif kind == "DOMAIN-KEYWORD":
            matched = payload.lower() in domain
        elif kind == "IP-CIDR":
            if resolved is None and "no-resolve" not in parts[3:]:
                resolved = case.get("ip", TEST_IPV4)
            matched = resolved is not None and ipaddress.ip_address(resolved) in ipaddress.ip_network(payload)
        elif kind == "DST-PORT":
            matched = payload == str(case.get("port", 443))
        if matched:
            return rule
    raise ValueError(f"用例没有任何兜底规则：{case.get('name', domain)}")


def _core_rule_type(value: str) -> str:
    """统一核心 API 与配置中的规则类型名称，包括 IPv6 别名。"""
    name = re.sub(r"[^a-z0-9]", "", value.lower())
    return "ipcidr" if name == "ipcidr6" else "match" if name == "final" else name


def _connect_core(port: int, case: dict[str, Any]) -> socket.socket:
    """向测试核心发起 SOCKS 请求，域名由本地 DNS 或 mock 出口处理。"""
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        connection.sendall(b"\x05\x01\x00")
        if _recv_exact(connection, 2) != b"\x05\x00":
            raise ConnectionError("Mihomo 测试入口未接受 SOCKS5")
        target = case.get("domain") or case["ip"]
        try:
            address = ipaddress.ip_address(target)
            encoded = (b"\x01" if address.version == 4 else b"\x04") + address.packed
        except ValueError:
            raw = target.encode("idna")
            encoded = b"\x03" + bytes([len(raw)]) + raw
        connection.sendall(b"\x05\x01\x00" + encoded + struct.pack("!H", int(case.get("port", 443))))
        response = _recv_exact(connection, 4)
        if response[1] != 0:
            raise ConnectionError(f"核心测试连接被拒绝，SOCKS 状态 {response[1]}")
        length = {1: 4, 4: 16}.get(response[3])
        if length is None:
            length = _recv_exact(connection, 1)[0]
        _recv_exact(connection, length + 2)
        connection.sendall(b"routing-fixture\n")
        return connection
    except BaseException:
        connection.close()
        raise


def _runtime_checks(binary: Path, original: dict[str, Any], cases: list[dict[str, Any]],
                    directory: Path, mock: _SocksServer) -> ValidationResult:
    """用相同规则和策略名称做隔离核心命中验证，所有组出口固定到本地夹具。"""
    result = ValidationResult(errors=[], warnings=[], details={"routes": []})
    selected = _select_core_cases(cases)
    if not selected:
        result.errors.append("缺少可用于真实核心验证的域名/IP 用例")
        return result
    groups = {group["name"] for group in original["proxy-groups"]}
    for rule in original["rules"]:
        parts = _normalise_rule(rule).split(",")
        policy = parts[1] if parts[0] == "MATCH" else parts[2]
        # 所有规则必须经已隔离的组转发，避免未来新增内置 DIRECT 规则绕过本地夹具。
        if policy not in groups:
            result.errors.append(f"规则出口无法在保持原文时隔离为本地夹具：{rule}")
    if result.errors:
        return result
    directory.mkdir(parents=True, exist_ok=True)
    config = copy.deepcopy(original)
    fixture = "PIPELINE-LOCAL-SOCKS"
    config["proxies"] = [{"name": fixture, "type": "socks5", "server": "127.0.0.1",
                          "port": mock.server_address[1]}]
    # 只在隔离副本中统一出口；原始策略组图已经单独验证，不能把此层当真实出口验收。
    config["proxy-groups"] = [{"name": group["name"], "type": "select", "proxies": [fixture]}
                              for group in original["proxy-groups"]]
    socks_port, controller_port = _free_port(), _free_port()
    secret = uuid.uuid4().hex
    config.update({"mixed-port": socks_port, "port": 0, "socks-port": 0,
                   "redir-port": 0, "tproxy-port": 0, "allow-lan": False,
                   "bind-address": "127.0.0.1", "mode": "rule", "log-level": "info",
                   "external-controller": f"127.0.0.1:{controller_port}", "secret": secret,
                   "ipv6": True, "tun": {"enable": False}, "sniffer": {"enable": False},
                   "profile": {"store-selected": False, "store-fake-ip": False}})
    with _serve(_DNSServer(selected)) as dns:
        resolver = f"127.0.0.1:{dns.server_address[1]}"
        config["hosts"] = {}
        config["dns"] = {"enable": True, "listen": "127.0.0.1:0", "ipv6": True,
                         "enhanced-mode": "redir-host", "use-hosts": False, "use-system-hosts": False,
                         "nameserver": [resolver], "default-nameserver": [resolver],
                         "proxy-server-nameserver": [resolver]}
        config_path = directory / "runtime.yaml"
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        api = f"http://127.0.0.1:{controller_port}"
        with _process([str(binary), "-d", str(directory), "-f", str(config_path)], directory,
                      directory / "runtime.log") as core:
            result.details["version"] = json.loads(_wait_http(api + "/version", core, secret=secret))
            for case in selected:
                record = {"name": case.get("name", ""), "target": case.get("domain") or case["ip"],
                          "expected_policy": case["expected_policy"]}
                result.details["routes"].append(record)
                try:
                    expected = _expected_first_rule(original["rules"], case)
                    expected_parts = _normalise_rule(expected).split(",")
                    expected_policy = expected_parts[1] if expected_parts[0] == "MATCH" else expected_parts[2]
                    if expected_policy != case["expected_policy"]:
                        raise ValueError(f"夹具首次规则指向 {expected_policy}，用例要求 {case['expected_policy']}")
                    if expected_policy in BUILTINS:
                        raise ValueError("用例直接引用内置出口，无法在保持规则不变时接入本地 mock")
                    with mock.lock:
                        start = len(mock.seen)
                    with _connect_core(socks_port, case) as connection:
                        source_port = str(connection.getsockname()[1])
                        deadline = time.monotonic() + 5
                        found = None
                        while time.monotonic() < deadline:
                            # 核心尚未登记连接时返回 null；继续短轮询，不能把就绪间隙当异常。
                            connections = json.loads(_request(api + "/connections", secret=secret)).get("connections") or []
                            found = next((item for item in connections
                                          if str(item.get("metadata", {}).get("sourcePort")) == source_port), None)
                            if found:
                                break
                            time.sleep(0.05)
                        if not found:
                            raise RuntimeError("未从核心 API 取得该连接的命中记录")
                        with mock.lock:
                            destinations = list(mock.seen[start:])
                        record.update({"expected_first_rule": expected, "rule": found.get("rule"),
                                       "rule_payload": found.get("rulePayload"),
                                       "chains": found.get("chains", []), "mock_destinations": destinations})
                        if _core_rule_type(found.get("rule", "")) != _core_rule_type(expected_parts[0]):
                            raise ValueError("核心首次规则类型与固定规则计算结果不同")
                        wanted_payload = "" if expected_parts[0] == "MATCH" else expected_parts[1]
                        actual_payload = found.get("rulePayload", "")
                        if expected_parts[0] == "IP-CIDR":
                            actual_payload = ipaddress.ip_network(actual_payload, strict=False).with_prefixlen
                        if actual_payload != wanted_payload:
                            raise ValueError(f"核心规则载荷不同：{actual_payload} != {wanted_payload}")
                        if expected_policy not in found.get("chains", []) or fixture not in found.get("chains", []):
                            raise ValueError("核心出站链未包含预期策略组和本地 mock 节点")
                        if not destinations:
                            raise ValueError("本地 mock 未收到该连接，无法证明隔离出站")
                        record["ok"] = True
                except (OSError, ValueError, RuntimeError, URLError) as error:
                    record.update({"ok": False, "error": str(error)})
                    result.errors.append(f"{record['name']}: {error}")
    result.details["scope"] = "相同规则与策略组名称的隔离核心命中；组出口改为本地 mock，不代表真实服务解锁或默认出口性能"
    return result


def _verify_pipeline(template: Path, subconverter: Path, mihomo: Path, work_dir: Path,
                     cases_path: Path) -> ValidationResult:
    """执行完整验收，并将异常转为可由 CI 判断的失败结果。"""
    result = ValidationResult(errors=[], warnings=[], details={})
    template, subconverter, mihomo = template.resolve(), subconverter.resolve(), mihomo.resolve()
    work_dir, cases_path = work_dir.resolve(), cases_path.resolve()
    run_dir = work_dir / (datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    run_dir.mkdir(parents=True, exist_ok=False)
    result.details["run_dir"] = str(run_dir)
    result.details["real_services_tested"] = False
    result.details["limits"] = "固定验证预算：最多 32768 条规则、单次下载最多 1048576 字节、规则集数不限、缓存关闭；不代表用户转换后端的实际配置"
    try:
        for path in (template, subconverter, mihomo, cases_path):
            if not path.is_file():
                raise FileNotFoundError(f"验收输入不存在：{path}")
        cases = _read_json(cases_path)
        if not isinstance(cases, list) or not all(isinstance(case, dict) for case in cases):
            raise ValueError("用例文件必须是 JSON 对象数组")
        snapshot_dir = run_dir / "snapshots"
        snapshot_dir.mkdir()
        frozen = validate_template(template, snapshot_dir)
        _merge(result, frozen, "snapshot")
        if not frozen.ok:
            return result
        expected = _read_json(snapshot_dir / "expected-rules.json")
        if not isinstance(expected, list) or not all(isinstance(item, str) for item in expected):
            raise ValueError("expected-rules.json 必须是最终规则字符串数组")
        with ExitStack() as stack:
            server = stack.enter_context(_serve(_SnapshotServer()))
            mock = stack.enter_context(_serve(_SocksServer()))
            snapshot_url = f"http://127.0.0.1:{server.server_address[1]}"
            base = {"mixed-port": 0, "allow-lan": False, "bind-address": "127.0.0.1",
                    "mode": "rule", "log-level": "warning", "ipv6": True, "dns": {"enable": False}}
            server.payloads["/base.yaml"] = yaml.safe_dump(base, allow_unicode=True).encode("utf-8")
            server.payloads["/template.ini"] = _snapshot_template(template, snapshot_dir, server)
            (run_dir / "snapshot-template.ini").write_bytes(server.payloads["/template.ini"])
            fixtures = {"full": FIXTURE_NAMES + ("美国 US Netflix fixture",),
                        "no-netflix": FIXTURE_NAMES, "no-regions": ("Generic fixture",), "zero-nodes": ()}
            for name, nodes in fixtures.items():
                server.payloads[f"/{name}.yaml"] = _subscription(nodes, mock.server_address[1])
            converter_dir = run_dir / "converter"
            executable = _converter_binary(subconverter, converter_dir / "bin")
            port = _free_port()
            pref = converter_dir / "pref.ini"
            pref.write_text(_converter_preferences(port, snapshot_url), encoding="utf-8")
            converter_url = f"http://127.0.0.1:{port}"
            env = _helper_environment(converter_dir)
            env.update({"API_MODE": "true", "PORT": str(port)})
            converter = stack.enter_context(_process([str(executable), "-f", str(pref)], converter_dir,
                                                     converter_dir / "converter.log", env))
            result.details["subconverter_version"] = _wait_http(converter_url + "/version", converter).decode("utf-8").strip()
            normal_path = run_dir / "converted.yaml"
            config = _convert(converter_url, snapshot_url, "full", normal_path)
            _merge(result, _check_output(config, expected), "converted")
            if result.errors:
                return result
            _merge(result, validate_routes(normal_path, cases_path), "routes")
            core_check = _core_check(mihomo, normal_path, run_dir / "core-check")
            result.details["mihomo_check"] = core_check
            if core_check["returncode"] != 0:
                result.errors.append("真实 Mihomo 配置检查失败，详见 config-check.log")
            no_netflix_path = run_dir / "no-netflix.yaml"
            no_netflix = _convert(converter_url, snapshot_url, "no-netflix", no_netflix_path)
            _merge(result, _check_output(no_netflix, expected, netflix_fallback=True), "no_netflix")
            # 两个负例必须被实际转换错误或结构检查拒绝，拒绝信息作为成功的负例证据保存。
            negatives = {}
            for name in ("no-regions", "zero-nodes"):
                try:
                    negative = _convert(converter_url, snapshot_url, name, run_dir / f"{name}.yaml")
                    failures = _check_output(negative, expected).errors
                    # 负例须因节点问题失败，规则截断等无关错误不能冒充通过。
                    expected_failure = any("地区节点匹配为空" in failure for failure in failures)
                    if name == "zero-nodes":
                        expected_failure = any("没有产生任何可用节点" in failure for failure in failures)
                    negatives[name] = {"rejected": expected_failure, "errors": failures}
                    if not expected_failure:
                        result.errors.append(f"负例未被识别：{name}")
                except (HTTPError, ValueError) as error:
                    # 仅零节点订阅允许被转换器直接拒绝；地区缺失应由结构检查给出证据。
                    rejected = name == "zero-nodes" and isinstance(error, HTTPError) and error.code == 400
                    response = error.read().decode("utf-8", errors="replace") if isinstance(error, HTTPError) else ""
                    negatives[name] = {"rejected": rejected, "errors": [str(error)], "response": response}
                    if not rejected:
                        result.errors.append(f"负例因无关转换错误中断：{name}: {error}")
            result.details["negative_cases"] = negatives
            result.details["snapshot_requests"] = server.requests
            if not result.errors:
                _merge(result, _runtime_checks(mihomo, config, cases, run_dir / "core-runtime", mock), "core_runtime")
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError,
            subprocess.SubprocessError, yaml.YAMLError) as error:
        result.errors.append(f"流水线执行失败：{type(error).__name__}: {error}")
    finally:
        _write_json(run_dir / "pipeline-result.json", {"ok": result.ok, "errors": result.errors,
                                                     "warnings": result.warnings, "details": result.details})
    return result


def verify_pipeline(template: Path, subconverter: Path, mihomo: Path,
                    work_dir: Path) -> ValidationResult:
    """公开接口：使用项目固定用例验证当次快照、转换与隔离核心命中。"""
    return _verify_pipeline(template, subconverter, mihomo, work_dir,
                            template.parent / "tests" / "routing_cases.json")


def main() -> int:
    """提供适用于 Windows 和 Linux CI 的命令行入口。"""
    parser = argparse.ArgumentParser(description="验证固定快照、真实订阅转换和隔离 Mihomo 命中")
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--subconverter", type=Path, required=True)
    parser.add_argument("--mihomo", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--cases", type=Path)
    args = parser.parse_args()
    cases = args.cases or args.template.parent / "tests" / "routing_cases.json"
    result = _verify_pipeline(args.template, args.subconverter, args.mihomo, args.work_dir, cases)
    print(json.dumps({"ok": result.ok, "errors": result.errors, "warnings": result.warnings,
                      "details": result.details}, ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    # 让 Windows 控制台正确显示策略组中文及图标。
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
