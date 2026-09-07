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
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, Request
import uuid

import yaml

try:
    from .validate_rules import ValidationResult, read_yaml_unique, validate_routes, validate_template
except ImportError:
    from validate_rules import ValidationResult, read_yaml_unique, validate_routes, validate_template


BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
REGIONS = ("香港", "日本", "美国", "台湾", "狮城", "新加坡", "韩国")
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


def _request(url: str, *, secret: str = "", timeout: float = 15, method: str = "GET",
             payload: dict[str, Any] | None = None) -> bytes:
    """直连本地辅助服务，明确绕过系统代理设置。"""
    if urlsplit(url).hostname != "127.0.0.1":
        raise ValueError("辅助 HTTP 请求必须使用显式 IPv4 回环地址")
    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    opener = build_opener(ProxyHandler({}))
    with opener.open(Request(url, headers=headers, data=data, method=method), timeout=timeout) as response:
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
                available, delay = self.server.available, self.server.delay_ms
                self.server.seen.append({"host": target, "port": port, "available": available})
            if not available:
                # 仅拒绝当前夹具连接，不触碰真实节点或用户进程。
                connection.sendall(b"\x05\x05\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            connection.settimeout(0.5)
            incoming = bytearray()
            while not self.server.stopping.is_set():
                try:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    incoming.extend(chunk)
                    if incoming.startswith((b"HEAD ", b"GET ")) and b"\r\n\r\n" in incoming:
                        # 测速和业务探针都在 SOCKS 终点响应，永不转发目标地址。
                        if delay:
                            self.server.stopping.wait(delay / 1000)
                        header, _, remaining = incoming.partition(b"\r\n\r\n")
                        first = header.split(b"\r\n", 1)[0]
                        body = json.dumps({"fixture": self.server.name}, ensure_ascii=False).encode("utf-8")
                        if first.startswith(b"HEAD "):
                            response = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        else:
                            response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                        + str(len(body)).encode() + b"\r\nConnection: keep-alive\r\n\r\n" + body)
                        connection.sendall(response)
                        if first.startswith(b"HEAD "):
                            return
                        incoming = bytearray(remaining)
                    elif incoming.startswith(b"routing-fixture"):
                        # 兼容原规则命中层；保持连接以便读取核心连接 API。
                        incoming.clear()
                except socket.timeout:
                    continue
        except (OSError, UnicodeError, ValueError):
            return


class _SocksServer(socketserver.ThreadingTCPServer):
    """允许并发的回环 SOCKS 夹具。"""
    daemon_threads = True
    block_on_close = False

    def __init__(self, name: str = "PIPELINE-LOCAL-SOCKS") -> None:
        """初始化连接目标记录与停止信号。"""
        self.seen: list[dict[str, Any]] = []
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.name = name
        self.available = True
        self.delay_ms = 0
        super().__init__(("127.0.0.1", 0), _SocksHandler)

    def set_state(self, *, available: bool = True, delay_ms: int = 0) -> None:
        """原子切换合成节点状态，只影响此后新建的测试连接。"""
        with self.lock:
            self.available = available
            self.delay_ms = max(0, delay_ms)


class _ProbeHandler(BaseHTTPRequestHandler):
    """本地直连接收器，同时提供不访问外网的健康检查地址。"""
    protocol_version = "HTTP/1.1"

    def handle(self) -> None:
        """核心关闭探针长连接时容忍正常复位，避免 Windows 输出无关服务器堆栈。"""
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            return

    def do_HEAD(self) -> None:
        """为直接健康检查返回空的成功响应。"""
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        """记录真实 DIRECT 到达的探针，并返回可核验的夹具标识。"""
        with self.server.lock:
            self.server.seen.append(self.path)
        body = b'{"fixture":"DIRECT"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """测试 HTTP 服务的证据以 JSON 保存，关闭常规控制台日志。"""


class _ProbeServer(ThreadingHTTPServer):
    """只监听 IPv4 回环地址的直连接收器。"""
    daemon_threads = True
    block_on_close = False

    def __init__(self) -> None:
        """建立接收记录，端口由系统分配。"""
        self.seen: list[str] = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _ProbeHandler)


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
                value = self.server.overrides.get(hostname, self.server.default_ipv4 if qtype == 1 else self.server.default_ipv6)
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

    def __init__(self, cases: list[dict[str, Any]], *, default_ipv4: str = TEST_IPV4,
                 default_ipv6: str = TEST_IPV6) -> None:
        """用例同时提供域名和 IP 时，使用指定 IP 作为本地解析结果。"""
        self.overrides = {case["domain"].lower(): case["ip"] for case in cases
                          if case.get("domain") and case.get("ip")}
        self.default_ipv4, self.default_ipv6 = default_ipv4, default_ipv6
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
        if len(set(members)) != len(members):
            result.errors.append(f"策略组成员重复：{name}")
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


def _check_group_contract(config: dict[str, Any], expectations: dict[str, Any]) -> ValidationResult:
    """按独立节点元数据展开预期成员，检查真实转换后的完整分组合同。"""
    result = ValidationResult(details={"groups": []})
    try:
        metadata = {node["name"]: node for node in expectations["nodes"]}
        subscription = expectations.get("subscription_name", "full")
        names = (expectations["subscription_names"] if "subscription_names" in expectations
                 else expectations["subscriptions"][subscription])
        if len(set(names)) != len(names) or any(name not in metadata for name in names):
            raise ValueError("合同订阅含重复节点或缺少节点元数据")
        actual_nodes = [proxy.get("name") for proxy in config.get("proxies", [])]
        if actual_nodes != names:
            result.errors.append("转换后节点名称或顺序不符合合同，可能发生标签删除或重命名")
            result.details["nodes"] = {"expected": names, "actual": actual_nodes}
        groups = config.get("proxy-groups", [])
        expected_groups = expectations["expected_groups"]
        if [group["name"] for group in groups] != [group["name"] for group in expected_groups]:
            result.errors.append("策略组名称、数量或排列顺序不符合合同")
        actual_map = {group["name"]: group for group in groups}
        for expected in expected_groups:
            name = expected["name"]
            wanted: list[str] = []
            for member in expected["members"]:
                if member == "@all":
                    expanded = names
                elif member.startswith("@region:"):
                    expanded = [node for node in names if member[8:] in metadata[node].get("regions", [])]
                elif member.startswith("@brand:"):
                    expanded = [node for node in names if member[7:] in metadata[node].get("brands", [])]
                elif member.startswith("@"):
                    raise ValueError(f"未知合同占位符：{member}")
                else:
                    expanded = [member]
                # 正则命中的真实节点按首次出现去重，与官方转换器一致。
                for value in expanded:
                    if value not in wanted:
                        wanted.append(value)
            actual = actual_map.get(name, {})
            mismatches = {}
            for field in ("type", "url", "interval", "tolerance"):
                if field in expected and actual.get(field) != expected[field]:
                    mismatches[field] = {"expected": expected[field], "actual": actual.get(field)}
            if actual.get("proxies") != wanted:
                mismatches["members"] = {"expected": wanted, "actual": actual.get("proxies")}
            record = {"name": name, "passed": not mismatches, "differences": mismatches}
            result.details["groups"].append(record)
            if mismatches:
                result.errors.append(f"策略组合同不一致：{name}")
        result.details["group_count"] = len(groups)
        result.details["subscription"] = subscription
    except (KeyError, TypeError, ValueError) as error:
        result.errors.append(f"分组合同格式错误：{error}")
    return result


def _instrument_direct_rules(rules: list[str], target: str) -> list[str]:
    """只在隔离副本替换 DIRECT 策略，原规则条件、顺序和选项原样保留。"""
    if not target or "," in target or target in BUILTINS:
        raise ValueError("DIRECT 测试别名必须是非内置的有效策略名")
    instrumented = []
    for rule in rules:
        parts = rule.split(",")
        position = 1 if parts[0].strip() in {"MATCH", "FINAL"} else 2
        if len(parts) <= position:
            raise ValueError(f"规则缺少目标策略：{rule}")
        if parts[position].strip() == "DIRECT":
            parts[position] = target
        instrumented.append(",".join(parts))
    return instrumented


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


def _subscription(names: list[str] | tuple[str, ...], port: int) -> bytes:
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
                       "insert": "false", "add_emoji": "false", "remove_emoji": "false", "list": "false"})
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


def _connect_core(port: int, case: dict[str, Any], *, send_probe: bool = True) -> socket.socket:
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
        if send_probe:
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
        if policy not in groups and policy != "DIRECT":
            result.errors.append(f"规则出口无法在保持原文时隔离为本地夹具：{rule}")
    if result.errors:
        return result
    directory.mkdir(parents=True, exist_ok=True)
    config = copy.deepcopy(original)
    fixture = "PIPELINE-LOCAL-SOCKS"
    direct_alias = "PIPELINE-DIRECT-RULE"
    if direct_alias in groups:
        result.errors.append("DIRECT 测试别名与原始分组名称冲突")
        return result
    config["rules"] = _instrument_direct_rules(original["rules"], direct_alias)
    result.details["instrumented_rules"] = sum(left != right for left, right in zip(original["rules"], config["rules"]))
    result.details["policy_mapping"] = {"DIRECT": direct_alias}
    config["proxies"] = [{"name": fixture, "type": "socks5", "server": "127.0.0.1",
                          "port": mock.server_address[1]}]
    # 只在隔离副本中统一出口；原始策略组图已经单独验证，不能把此层当真实出口验收。
    config["proxy-groups"] = [{"name": group["name"], "type": "select", "proxies": [fixture]}
                              for group in original["proxy-groups"]]
    config["proxy-groups"].append({"name": direct_alias, "type": "select", "proxies": [fixture]})
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
                    if expected_policy in BUILTINS and expected_policy != "DIRECT":
                        raise ValueError("用例直接引用内置出口，无法在保持规则不变时接入本地 mock")
                    runtime_policy = direct_alias if expected_policy == "DIRECT" else expected_policy
                    record["runtime_policy"] = runtime_policy
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
                        if runtime_policy not in found.get("chains", []) or fixture not in found.get("chains", []):
                            raise ValueError("核心出站链未包含预期策略组和本地 mock 节点")
                        if not destinations:
                            raise ValueError("本地 mock 未收到该连接，无法证明隔离出站")
                        record["ok"] = True
                except (OSError, ValueError, RuntimeError, URLError) as error:
                    record.update({"ok": False, "error": str(error)})
                    result.errors.append(f"{record['name']}: {error}")
    result.details["scope"] = "保留条件、顺序及 no-resolve 的隔离命中；DIRECT 映射为测试别名，各组出口为本地 mock；此层不证明真实直连或原组选择行为"
    return result


def _proxy_state(api: str, secret: str, name: str) -> dict[str, Any]:
    """读取指定测试策略的当前选择和成员，不操作用户客户端。"""
    return json.loads(_request(api + "/proxies/" + quote(name, safe=""), secret=secret))


def _set_selection(api: str, secret: str, group: str, member: str) -> None:
    """通过真实核心切换 select，随后读取确认选择已经生效。"""
    _request(api + "/proxies/" + quote(group, safe=""), secret=secret,
             method="PUT", payload={"name": member})
    if _proxy_state(api, secret, group).get("now") != member:
        raise RuntimeError(f"核心未保存预期选择：{group} -> {member}")


def _health_check(api: str, secret: str, group: str, url: str) -> dict[str, Any]:
    """主动等待本地健康检查结束；全部失败也是需要记录的有效健康状态。"""
    endpoint = api + "/group/" + quote(group, safe="") + "/delay?" + urlencode({"url": url, "timeout": 1200})
    try:
        return {"status": 200, "delays": json.loads(_request(endpoint, secret=secret, timeout=20))}
    except HTTPError as error:
        response = error.read().decode("utf-8", errors="replace")
        # 只接受核心明确报告的全部探测失败，认证或接口错误不能冒充故障证据。
        if error.code not in (500, 504) or "all proxies timeout" not in response.lower():
            raise RuntimeError(f"本地健康检查接口失败：{error.code} {response}") from error
        return {"status": error.code, "response": response}


def _connection_state(api: str, secret: str, port: int) -> dict[str, Any]:
    """按入口源端口取得单个存活连接的真实命中信息。"""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        connections = json.loads(_request(api + "/connections", secret=secret)).get("connections") or []
        found = next((item for item in connections
                      if str(item.get("metadata", {}).get("sourcePort")) == str(port)), None)
        if found is not None:
            return found
        time.sleep(0.05)
    raise RuntimeError("未从核心 API 取得分组探针连接")


def _http_probe_response(connection: socket.socket) -> dict[str, Any]:
    """读取有限长度 HTTP 响应体，不能把 SOCKS 握手成功当作业务探针成功。"""
    connection.settimeout(4)
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk:
            raise ConnectionError("本地 HTTP 探针在响应头前关闭")
        data.extend(chunk)
        if len(data) > 16384:
            raise ValueError("本地 HTTP 探针响应头过长")
    header, _, body = data.partition(b"\r\n\r\n")
    if not header.startswith(b"HTTP/1.1 200 "):
        raise ValueError(f"本地 HTTP 探针返回非预期状态：{header.splitlines()[0]!r}")
    fields = dict(bytes(line).split(b":", 1) for line in header.split(b"\r\n")[1:] if b":" in line)
    length = int(next((value for key, value in fields.items() if key.lower() == b"content-length"), b"-1"))
    if not 0 <= length <= 8192:
        raise ValueError("本地 HTTP 探针缺少合理的 Content-Length")
    if len(body) < length:
        body.extend(_recv_exact(connection, length - len(body)))
    return json.loads(body[:length].decode("utf-8"))


def _group_probe(api: str, secret: str, socks_port: int, receiver: _ProbeServer,
                 mocks: dict[str, _SocksServer], rules: list[str], *, name: str,
                 target: str, policy: str, chain: list[str] | None) -> dict[str, Any]:
    """通过原始规则发新连接，核对实际终点与组链；失败探针必须排除直连成功。"""
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        address = None
    if address is not None and not address.is_loopback:
        raise ValueError("原分组探针只允许回环 IP，真实私网地址只能在规则隔离层测试")
    case = {"ip": "127.0.0.1", "port": receiver.server_address[1]}
    case["ip" if address is not None else "domain"] = target
    first = _expected_first_rule(rules, case)
    parts = _normalise_rule(first).split(",")
    actual_policy = parts[1] if parts[0] == "MATCH" else parts[2]
    if actual_policy != policy:
        raise ValueError(f"分组探针 {name} 的首条规则指向 {actual_policy}，预期 {policy}")
    token = "/probe/" + uuid.uuid4().hex
    starts = {}
    for node, mock in mocks.items():
        with mock.lock:
            starts[node] = len(mock.seen)
    record: dict[str, Any] = {"name": name, "target": target, "expected_policy": policy,
                              "expected_first_rule": first, "expected_chain": chain}
    failed: OSError | None = None
    try:
        with _connect_core(socks_port, case, send_probe=False) as connection:
            connection.sendall((f"GET {token} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n\r\n").encode("ascii"))
            response = _http_probe_response(connection)
            found = _connection_state(api, secret, connection.getsockname()[1])
            record.update({"fixture": response.get("fixture"), "chains": found.get("chains", []),
                           "rule": found.get("rule"), "rule_payload": found.get("rulePayload")})
    except OSError as error:
        failed = error
        record["connection_error"] = str(error)
    attempts = []
    for node, mock in mocks.items():
        with mock.lock:
            attempts.extend({"node": node, **item} for item in mock.seen[starts[node]:]
                            if item["host"] == target and item["port"] == receiver.server_address[1])
    record["mock_attempts"] = attempts
    with receiver.lock:
        received_direct = token in receiver.seen
    record["direct_receiver_reached"] = received_direct
    if chain is None:
        if failed is None or received_direct:
            raise RuntimeError(f"{name}：不可达候选仍使探针成功，或意外到达 DIRECT")
        # 此层只验证有真实候选但全部不可达；仅有 REJECT 的结构由负例合同另验。
        if not any(not item["available"] for item in attempts):
            raise RuntimeError(f"{name}：失败时没有本地不可用节点的拨号证据")
        record["expected_failure"] = True
    else:
        if failed is not None:
            raise RuntimeError(f"{name}：预期成功的本地探针失败：{failed}") from failed
        if record["chains"] != chain or record["fixture"] != chain[0]:
            raise RuntimeError(f"{name}：出口链或终点不同，实际 {record.get('chains')} / {record.get('fixture')}，预期 {chain}")
        if (chain[0] == "DIRECT") != received_direct:
            raise RuntimeError(f"{name}：DIRECT 终点记录与实际出口不一致")
        if _core_rule_type(record["rule"]) != _core_rule_type(parts[0]):
            raise RuntimeError(f"{name}：核心首次规则类型不符")
        payload = "" if parts[0] == "MATCH" else parts[1]
        actual_payload = record["rule_payload"]
        if parts[0] == "IP-CIDR":
            actual_payload = ipaddress.ip_network(actual_payload, strict=False).with_prefixlen
        if actual_payload != payload:
            raise RuntimeError(f"{name}：核心首次规则载荷不符")
    record["ok"] = True
    return record


def _group_runtime_checks(binary: Path, original: dict[str, Any], cases: list[dict[str, Any]],
                          directory: Path) -> ValidationResult:
    """保留原始组图与规则，替换本地叶节点和测速终点后验证选择、故障及缓存。"""
    result = ValidationResult(details={"scenarios": [], "health_checks": []})
    ai, fallback = "💬 Ai平台", "🛟 AI故障切换"
    main_group, manual, domestic = "🚀 节点选择", "🚀 手动切换", "🎯 全球直连"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        roles = cases[0]
        priority = [roles[key] for key in ("ai_primary", "ai_secondary", "ai_japan", "ai_singapore")]
        alternative = roles["manual_alternative"]
        node_names = [proxy["name"] for proxy in original["proxies"]]
        if len(set(priority + [alternative])) != 5 or any(node not in node_names for node in priority + [alternative]):
            raise ValueError("原分组运行夹具缺少独立的美国、日本、新加坡和人工候补节点")
        with ExitStack() as stack:
            mocks = {name: stack.enter_context(_serve(_SocksServer(name))) for name in node_names}
            receiver = stack.enter_context(_serve(_ProbeServer()))
            dns = stack.enter_context(_serve(_DNSServer([], default_ipv4="127.0.0.1", default_ipv6="::1")))
            health_url = f"http://127.0.0.1:{receiver.server_address[1]}/health"
            config = copy.deepcopy(original)
            config["proxies"] = [{"name": name, "type": "socks5", "server": "127.0.0.1",
                                  "port": mocks[name].server_address[1]} for name in node_names]
            for group in config["proxy-groups"]:
                if "url" in group:
                    group["url"] = health_url
            # 在生产分组中仅替换测速终点，其他字段逐项还原后必须与原图完全一致。
            restored = copy.deepcopy(config["proxy-groups"])
            for old, changed in zip(original["proxy-groups"], restored):
                if "url" in old:
                    changed["url"] = old["url"]
            if restored != original["proxy-groups"] or config["rules"] != original["rules"]:
                raise ValueError("原分组运行副本改变了生产选择结构或规则")
            socks_port, controller_port = _free_port(), _free_port()
            secret = uuid.uuid4().hex
            api = f"http://127.0.0.1:{controller_port}"
            resolver = f"127.0.0.1:{dns.server_address[1]}"
            config.update({"mixed-port": socks_port, "port": 0, "socks-port": 0, "redir-port": 0,
                           "tproxy-port": 0, "allow-lan": False, "bind-address": "127.0.0.1",
                           "mode": "rule", "log-level": "info", "external-controller": f"127.0.0.1:{controller_port}",
                           "secret": secret, "ipv6": True, "tun": {"enable": False}, "sniffer": {"enable": False},
                           "hosts": {}, "profile": {"store-selected": False, "store-fake-ip": False},
                           "dns": {"enable": True, "listen": "127.0.0.1:0", "ipv6": False,
                                   "enhanced-mode": "redir-host", "use-hosts": False, "use-system-hosts": False,
                                   "nameserver": [resolver], "default-nameserver": [resolver],
                                   "proxy-server-nameserver": [resolver]}})
            result.details["scope"] = ("保留生产规则和原组类型、成员及顺序；仅替换叶节点和健康终点，所有 DNS/控制器/数据终点使用回环。"
                                       "健康检查完成后发送新连接，不验证真实服务解锁、生产恢复耗时或已有会话连续性。")
            result.details["group_graph_preserved"] = True
            result.details["leaf_nodes"] = node_names
            result.details["health_url"] = health_url

            @contextmanager
            def start_core(value: dict[str, Any], folder: Path, stem: str) -> Iterator[None]:
                """每次启动只使用验收私有目录，缓存阶段可以显式复用该目录。"""
                folder.mkdir(parents=True, exist_ok=True)
                path = folder / f"{stem}.yaml"
                path.write_text(yaml.safe_dump(value, allow_unicode=True, sort_keys=False), encoding="utf-8")
                with _process([str(binary), "-d", str(folder), "-f", str(path)], folder, folder / f"{stem}.log") as process:
                    _wait_http(api + "/version", process, secret=secret)
                    yield

            def health(stage: str) -> None:
                """记录完成的故障切换组健康检查及当前首选节点。"""
                evidence = _health_check(api, secret, fallback, health_url)
                evidence.update({"stage": stage, "now": _proxy_state(api, secret, fallback).get("now")})
                result.details["health_checks"].append(evidence)

            def probe(name: str, target: str, policy: str, chain: list[str] | None) -> None:
                """保存一个原始规则下的新连接与本地真实出口证据。"""
                result.details["scenarios"].append(_group_probe(api, secret, socks_port, receiver, mocks,
                    original["rules"], name=name, target=target, policy=policy, chain=chain))

            with start_core(config, directory / "fresh", "runtime"):
                defaults = {group["name"]: _proxy_state(api, secret, group["name"]).get("now")
                            for group in config["proxy-groups"] if group["type"] == "select"}
                for group in config["proxy-groups"]:
                    if group["type"] == "select" and defaults[group["name"]] != group["proxies"][0]:
                        raise RuntimeError(f"无缓存的 select 未默认第一候选：{group['name']}")
                result.details["fresh_defaults"] = defaults
                probe("默认选择下 LAN 回环真实直连", "127.0.0.1", "DIRECT", ["DIRECT"])
                probe("默认选择下 private 域名真实直连", "routing-verification.example", "DIRECT", ["DIRECT"])
                # 故意使美国首项比其他候选慢，证明 fallback 按订阅优先顺序而非最低延迟选择。
                for node, delay in zip(priority, (80, 15, 5, 1)):
                    mocks[node].set_state(delay_ms=delay)
                health("全部健康且首项较慢")
                probe("AI 默认美国订阅首项", "chatgpt.com", ai, [priority[0], fallback, ai])
                for index, label in enumerate(("美国首项故障", "全部美国故障", "日本也故障")):
                    mocks[priority[index]].set_state(available=False)
                    health(label)
                    probe(label, "chatgpt.com", ai, [priority[index + 1], fallback, ai])
                mocks[priority[3]].set_state(available=False)
                health("全部 AI 候选故障")
                result.details["all_failed_current"] = _proxy_state(api, secret, fallback).get("now")
                probe("AI 全部失效必须失败且不直连", "chatgpt.com", ai, None)
                mocks[priority[0]].set_state(delay_ms=80)
                health("美国优先节点恢复")
                probe("AI 恢复后新连接回到美国首项", "chatgpt.com", ai, [priority[0], fallback, ai])
                for node in priority:
                    mocks[node].set_state()
                health("恢复所有候选")
                _set_selection(api, secret, ai, priority[2])
                _set_selection(api, secret, main_group, manual)
                _set_selection(api, secret, manual, alternative)
                probe("AI 固定日本不随主组切换", "chatgpt.com", ai, [priority[2], ai])
                _set_selection(api, secret, manual, priority[0])
                probe("AI 固定日本不随共享手动选择改变", "chatgpt.com", ai, [priority[2], ai])
                mocks[priority[2]].set_state(available=False)
                health("手动固定的日本节点故障")
                probe("AI 固定节点故障不自动换选", "chatgpt.com", ai, None)
                if _proxy_state(api, secret, ai).get("now") != priority[2]:
                    raise RuntimeError("手动固定 AI 节点故障后选择发生变化")
                mocks[priority[2]].set_state()
                _set_selection(api, secret, ai, main_group)
                _set_selection(api, secret, manual, alternative)
                probe("人工将 AI 覆盖到主组", "chatgpt.com", ai, [alternative, manual, main_group, ai])
                probe("改选主组及手动节点后 LAN 保持直连", "127.0.0.1", "DIRECT", ["DIRECT"])
                probe("改选主组及手动节点后 private 保持直连", "routing-verification.example", "DIRECT", ["DIRECT"])
                probe("普通国内默认真实直连", "www.baidu.com", domestic, ["DIRECT", domestic])
                _set_selection(api, secret, domestic, main_group)
                probe("普通国内跟随全球直连改走代理", "www.baidu.com", domestic,
                      [alternative, manual, main_group, domestic])
                probe("LAN 回环 IP 不随全局选项改变", "127.0.0.1", "DIRECT", ["DIRECT"])
                probe("private 域名不随全局选项改变", "routing-verification.example", "DIRECT", ["DIRECT"])

            # 用单独的旧菜单夹具生成缓存，再以未改组图的新配置读取；从不接触用户缓存。
            cached = copy.deepcopy(config)
            cached["profile"]["store-selected"] = True
            legacy = copy.deepcopy(cached)
            video, removed = "📹 油管视频", "♻️ 自动选择"
            legacy_video = next(group for group in legacy["proxy-groups"] if group["name"] == video)
            if removed in legacy_video["proxies"]:
                raise ValueError("缓存迁移夹具的旧候选仍存在于新菜单，无法验证移除后的回退")
            legacy_video["proxies"].append(removed)
            cache_dir = directory / "cache-migration"
            with start_core(legacy, cache_dir, "legacy-seed"):
                _set_selection(api, secret, main_group, manual)
                _set_selection(api, secret, manual, alternative)
                _set_selection(api, secret, ai, main_group)
                _set_selection(api, secret, video, removed)
                # v1.19.30 的 PUT 在同步写入 Cache.SetSelected 后返回，响应完成就是写入屏障。
                result.details["cache_seed"] = {ai: main_group, video: removed,
                    "legacy_only_change": f"为 {video} 添加旧候选 {removed} 以建立迁移前缓存"}
            with start_core(cached, cache_dir, "restored"):
                restored_choices = {group: _proxy_state(api, secret, group).get("now") for group in (ai, video)}
                if restored_choices != {ai: main_group, video: main_group}:
                    raise RuntimeError(f"缓存恢复与已确认行为不符：{restored_choices}")
                result.details["restored_choices"] = restored_choices
                probe("有效旧 AI 缓存继续选择主组", "chatgpt.com", ai, [alternative, manual, main_group, ai])
                probe("移除的普通业务旧候选回退首项", "www.youtube.com", video,
                      [alternative, manual, main_group, video])
            result.details["passed"] = len(result.details["scenarios"])
    except (OSError, ValueError, KeyError, IndexError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        result.errors.append(f"原分组运行验收失败：{type(error).__name__}: {error}")
    _write_json(directory / "group-runtime-result.json", {"ok": result.ok, "errors": result.errors, "details": result.details})
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
        group_cases_path = template.parent / "tests" / "group_cases.json"
        for path in (template, subconverter, mihomo, cases_path, group_cases_path):
            if not path.is_file():
                raise FileNotFoundError(f"验收输入不存在：{path}")
        cases = _read_json(cases_path)
        if not isinstance(cases, list) or not all(isinstance(case, dict) for case in cases):
            raise ValueError("用例文件必须是 JSON 对象数组")
        expectations = _read_json(group_cases_path)
        if not isinstance(expectations, dict) or expectations.get("schema_version") != 1:
            raise ValueError("分组夹具必须采用 schema_version=1")
        metadata = {node["name"]: node for node in expectations["nodes"]}
        full_names = expectations["subscriptions"]["full"]
        runtime_name = expectations["runtime"]["subscription"]
        runtime_names = expectations["subscriptions"][runtime_name]
        # 缺地区负例由手工标签决定，不能用待测正则或实际转换成员反推预期。
        region_groups = {}
        for group in expectations["expected_groups"]:
            region_tokens = [member[8:] for member in group["members"] if member.startswith("@region:")]
            if group["type"] == "url-test" and len(region_tokens) == 1:
                region_groups[region_tokens[0]] = group["name"]
        if set(region_groups) != {"HK", "JP", "US", "TW", "SG", "KR"}:
            raise ValueError("分组夹具必须包含六个明确的地区组合同")
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
            fixtures = {"full": full_names, "runtime": runtime_names,
                        "no-netflix": [name for name in full_names if "netflix" not in metadata[name].get("brands", [])],
                        "no-regions": [name for name in full_names if not metadata[name].get("regions")],
                        "zero-nodes": []}
            for region in region_groups:
                fixtures[f"no-{region}"] = [name for name in full_names if region not in metadata[name].get("regions", [])]
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
            _merge(result, _check_group_contract(config, expectations), "group_contract")
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
            _merge(result, _check_group_contract(no_netflix, {**expectations,
                   "subscription_names": fixtures["no-netflix"]}), "no_netflix_contract")
            # 八个负例逐项核对唯一允许的失败原因，无关转换失败或规则损失一律不能通过。
            negatives = {}
            for name in [*(f"no-{region}" for region in region_groups), "no-regions", "zero-nodes"]:
                try:
                    negative = _convert(converter_url, snapshot_url, name, run_dir / f"{name}.yaml")
                    failures = _check_output(negative, expected).errors
                    missing = list(region_groups) if name in ("no-regions", "zero-nodes") else [name[3:]]
                    wanted_errors = [f"地区节点匹配为空：{region_groups[region]}" for region in missing]
                    if name == "zero-nodes":
                        wanted_errors.append("合成订阅没有产生任何可用节点")
                    contract = _check_group_contract(negative, {**expectations, "subscription_names": fixtures[name]})
                    groups_by_name = {group["name"]: group for group in negative["proxy-groups"]}
                    placeholders = {region_groups[region]: groups_by_name[region_groups[region]]["proxies"] for region in missing}
                    placeholder_ok = all(members == ["REJECT"] for members in placeholders.values())
                    if name in ("no-regions", "zero-nodes"):
                        placeholders["🛟 AI故障切换"] = groups_by_name["🛟 AI故障切换"]["proxies"]
                        placeholder_ok = placeholder_ok and placeholders["🛟 AI故障切换"] == ["REJECT"]
                    rejected = Counter(failures) == Counter(wanted_errors) and contract.ok and placeholder_ok
                    negatives[name] = {"rejected": rejected, "errors": failures, "expected_errors": wanted_errors,
                                       "contract_errors": contract.errors, "placeholders": placeholders}
                    if not rejected:
                        result.errors.append(f"负例未严格符合预期失败原因或 REJECT 占位：{name}")
                except (HTTPError, ValueError) as error:
                    # 仅零节点订阅允许被转换器直接拒绝；地区缺失应由结构检查给出证据。
                    response = error.read().decode("utf-8", errors="replace") if isinstance(error, HTTPError) else ""
                    rejected = (name == "zero-nodes" and isinstance(error, HTTPError) and error.code == 400
                                and "doesn't contain any valid node info" in response)
                    negatives[name] = {"rejected": rejected, "errors": [str(error)], "response": response}
                    if not rejected:
                        result.errors.append(f"负例因无关转换错误中断：{name}: {error}")
            result.details["negative_cases"] = negatives
            result.details["snapshot_requests"] = server.requests
            if not result.errors:
                _merge(result, _runtime_checks(mihomo, config, cases, run_dir / "core-runtime", mock), "core_runtime")
            if not result.errors:
                runtime_path = run_dir / "group-runtime.yaml"
                runtime_config = _convert(converter_url, snapshot_url, "runtime", runtime_path)
                _merge(result, _check_output(runtime_config, expected), "group_runtime_converted")
                _merge(result, _check_group_contract(runtime_config, {**expectations,
                       "subscription_name": runtime_name}), "runtime_group_contract")
                if not result.errors:
                    _merge(result, _group_runtime_checks(mihomo, runtime_config, [expectations["runtime"]],
                           run_dir / "group-runtime"), "group_runtime")
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
