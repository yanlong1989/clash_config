"""检查 INI 模板、固定上游内容，并验证转换后的规则命中。"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
from pathlib import Path
import re
import time
from typing import Any
import urllib.request

import yaml


# 仅接受官方 subconverter 能输出、且本项目实际使用的规则类型。
SUPPORTED = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "PROCESS-NAME", "MATCH", "FINAL"}
SOURCE_FORMATS = {"surge", "clash-domain", "clash-ipcidr", "clash-classic"}
BUILTINS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
CUSTOM_PREFIX = "https://raw.githubusercontent.com/yanlong1989/clash_config/main/"
CUSTOM_FILES = {"rules.list", "rules-ai.list", "rules-jp.list"}


class _UniqueLoader(yaml.SafeLoader):
    """拒绝重复映射键，防止后一个 payload/rules 静默覆盖前一个。"""


def _unique_mapping(loader: _UniqueLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    """逐个建立映射；重复或不可作为键的值都视为格式错误。"""
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            if key in mapping:
                raise ValueError(f"YAML 含重复键：{key}")
            mapping[key] = loader.construct_object(value_node, deep=deep)
        except TypeError as exc:
            raise ValueError("YAML 映射键格式错误") from exc
    return mapping


_UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


def read_yaml_unique(content: str) -> Any:
    """安全读取 YAML，并将语法错误统一转换为可报告的验证错误。"""
    try:
        return yaml.load(content, Loader=_UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"YAML 解析失败：{exc}") from exc


@dataclass
class ValidationResult:
    """统一承载验证错误、已知限制和可复查的证据。"""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """只有不存在错误时才视为通过。"""
        return not self.errors


@dataclass
class Rule:
    """保留规则条件、目标策略及来源，方便核对首条命中。"""

    kind: str
    value: str
    policy: str
    options: tuple[str, ...] = ()
    source: str = ""
    line: int = 0

    def render(self) -> str:
        """输出与 Clash 配置一致的规则文本。"""
        parts = ["MATCH", self.policy] if self.kind in {"MATCH", "FINAL"} else [self.kind, self.value, self.policy]
        return ",".join(parts + list(self.options))


def parse_rule(text: str, policy: str | None = None) -> Rule:
    """解析源规则或含策略的输出规则，拒绝未知类型及不完整参数。"""
    parts = [part.strip() for part in text.strip().split(",")]
    kind = parts[0].upper()
    if kind not in SUPPORTED:
        raise ValueError(f"不支持的规则类型：{parts[0]}")
    if kind in {"MATCH", "FINAL"}:
        required = 1 if policy is not None else 2
        if len(parts) != required:
            raise ValueError(f"兜底规则参数错误：{text}")
        target = policy if policy is not None else parts[1]
        if not target:
            raise ValueError("规则策略不能为空")
        return Rule("MATCH", "", target)
    required = 2 if policy is not None else 3
    if len(parts) < required or any(not part for part in parts):
        raise ValueError(f"规则参数不完整：{text}")
    value = parts[1]
    target = policy if policy is not None else parts[2]
    options = tuple(parts[required:])
    if not target:
        raise ValueError("规则策略不能为空")
    if any(option != "no-resolve" for option in options) or len(options) > 1:
        raise ValueError(f"不支持的规则参数：{text}")
    if options and kind not in {"IP-CIDR", "IP-CIDR6"}:
        raise ValueError(f"no-resolve 只能用于 IP 规则：{text}")
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(value, strict=False)
        # IPv6 别名统一化，避免把文本拼写差异误判为转换丢失。
        kind = "IP-CIDR6" if network.version == 6 else "IP-CIDR"
        value = str(network)
    elif kind.startswith("DOMAIN"):
        value = value.lower().rstrip(".")
        if not value or re.search(r"[\s/*:,<>|^]", value):
            raise ValueError(f"域名条件格式错误：{text}")
        if kind in {"DOMAIN", "DOMAIN-SUFFIX"}:
            # 与规则引擎一致地接受字面标签（含广告源的尾部连字符），拒绝其他格式语法。
            try:
                labels = [label.encode("idna").decode("ascii") for label in value.split(".")]
            except UnicodeError as exc:
                raise ValueError(f"国际化域名格式错误：{text}") from exc
            if len(value) > 253 or any(not re.fullmatch(r"[a-zA-Z0-9_-]{1,63}", label) for label in labels):
                raise ValueError(f"域名标签格式错误：{text}")
    return Rule(kind, value, target, options)


def parse_source(content: str, source_format: str, policy: str, source: str = "") -> tuple[list[Rule], list[str]]:
    """按显式格式解析上游；已知 URL-REGEX 限制单独报告，其他未知类型失败。"""
    if source_format not in SOURCE_FORMATS:
        raise ValueError(f"未知规则格式：{source_format}")
    if not content.strip():
        raise ValueError("规则来源为空")
    if source_format == "surge":
        lines = content.lstrip("\ufeff").splitlines()
    else:
        payload = read_yaml_unique(content)
        if not isinstance(payload, dict) or not isinstance(payload.get("payload"), list):
            raise ValueError("规则 YAML 必须包含 payload 数组")
        lines = payload["payload"]
        if any(not isinstance(item, str) for item in lines):
            raise ValueError("payload 的每个元素必须为字符串")
    rules, warnings = [], []
    for number, raw in enumerate(lines, 1):
        text = raw.strip()
        if not text or text.startswith(("#", ";", "//")):
            continue
        if source_format == "clash-domain":
            # 官方转换器把 +. 展开为后缀匹配，裸域名保持精确匹配。
            text = "DOMAIN-SUFFIX," + text[2:] if text.startswith("+.") else "DOMAIN," + text
        elif source_format == "clash-ipcidr":
            network = ipaddress.ip_network(text, strict=False)
            text = ("IP-CIDR6," if network.version == 6 else "IP-CIDR,") + str(network)
        if text.startswith("URL-REGEX,"):
            warnings.append(f"{source}:{number}：URL-REGEX 不参与 Clash 分流，转换器原本也会过滤")
            continue
        rule = parse_rule(text, policy)
        if rule.kind == "MATCH":
            raise ValueError("远程规则源不允许包含提前兜底的 MATCH/FINAL")
        rule.source, rule.line = source, number
        rules.append(rule)
    if not rules:
        raise ValueError("规则来源没有可用条目")
    return rules, warnings


def first_match(rules: list[Rule], domain: str | None = None, ip: str | None = None, process: str | None = None) -> Rule | None:
    """在明确提供的元数据上寻找首条命中；此函数永不执行 DNS 查询。"""
    hostname = domain.lower().rstrip(".") if domain else ""
    address = ipaddress.ip_address(ip) if ip else None
    for rule in rules:
        matched = rule.kind == "MATCH"
        if rule.kind == "DOMAIN":
            matched = bool(hostname) and hostname == rule.value
        elif rule.kind == "DOMAIN-SUFFIX":
            matched = bool(hostname) and (hostname == rule.value or hostname.endswith("." + rule.value))
        elif rule.kind == "DOMAIN-KEYWORD":
            matched = bool(hostname) and rule.value in hostname
        elif rule.kind in {"IP-CIDR", "IP-CIDR6"}:
            network = ipaddress.ip_network(rule.value, strict=False)
            matched = address is not None and address.version == network.version and address in network
        elif rule.kind == "PROCESS-NAME":
            matched = process is not None and process == rule.value
        if matched:
            return rule
    return None


def validate_groups(groups: list[dict[str, Any]], proxies: list[dict[str, Any]] | None = None) -> list[str]:
    """检查策略组重名、空组、悬空引用和循环；模板阶段允许尚未展开的正则。"""
    errors: list[str] = []
    names = [group.get("name", "") for group in groups]
    if any(not isinstance(name, str) or not name for name in names):
        return ["策略组名称缺失或格式错误"]
    errors.extend(f"策略组重名：{name}" for name, count in Counter(names).items() if count > 1)
    node_names = {node.get("name") for node in (proxies or [])}
    known = set(names) | BUILTINS | node_names
    graph: dict[str, list[str]] = {}
    for group in groups:
        members = group.get("proxies", [])
        if not isinstance(members, list) or any(not isinstance(member, str) for member in members):
            errors.append(f"策略组成员格式错误：{group['name']}")
            continue
        if proxies is not None and not members:
            errors.append(f"空策略组：{group['name']}")
        errors.extend(f"策略组 {group['name']} 引用了不存在的成员 {member}" for member in members if member not in known)
        graph[group["name"]] = [member for member in members if member in names]
    visited, active = set(), set()

    def visit(name: str) -> None:
        """深度优先检测回边，禁止候补路径形成循环。"""
        if name in active:
            errors.append(f"策略组循环引用：{name}")
            return
        if name in visited:
            return
        active.add(name)
        for member in graph.get(name, []):
            visit(member)
        active.remove(name)
        visited.add(name)

    for name in names:
        visit(name)
    return errors


def read_template(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """读取保留重复键的 INI 模板，返回有序规则来源和策略组。"""
    sources, groups = [], []
    section = ""
    settings: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        text = raw.strip()
        if not text or text.startswith((";", "#")):
            continue
        if text.startswith("[") and text.endswith("]"):
            section = text[1:-1]
            continue
        if section != "custom" or "=" not in text:
            raise ValueError(f"{path}:{number}：不是有效的 custom 配置项")
        key, value = text.split("=", 1)
        settings[key] = value
        if key == "ruleset":
            group, separator, location = value.partition(",")
            if not separator or not group or not location:
                raise ValueError(f"ruleset 参数不完整：第 {number} 行")
            item: dict[str, Any] = {"line": number, "group": group, "format": "surge"}
            if location.startswith("[]"):
                item["inline"] = location[2:]
            else:
                for source_format in SOURCE_FORMATS:
                    if location.startswith(source_format + ":"):
                        item["format"] = source_format
                        location = location[len(source_format) + 1:]
                        break
                url, comma, interval = location.partition(",")
                if not url.startswith(("https://", "http://")) or (comma and not interval.isdigit()):
                    raise ValueError(f"规则 URL 或更新间隔无效：第 {number} 行")
                item["url"] = url
            sources.append(item)
        elif key == "custom_proxy_group":
            parts = value.split("`")
            if len(parts) < 3 or parts[1] not in {"select", "url-test", "fallback", "load-balance"}:
                raise ValueError(f"策略组定义错误：第 {number} 行")
            groups.append({"name": parts[0], "type": parts[1], "proxies": [item[2:] for item in parts[2:] if item.startswith("[]")], "spec": parts[2:]})
    if not sources or not groups:
        raise ValueError("模板缺少规则或策略组")
    if settings.get("enable_rule_generator") != "true" or settings.get("overwrite_original_rules") != "true":
        raise ValueError("模板必须启用规则生成并覆盖原规则")
    return sources, groups


def _download_source(item: dict[str, Any], template: Path) -> tuple[bytes, str]:
    """读取公开源或本项目个人规则；有限重试后失败，不借旧缓存伪装成功。"""
    url = item["url"]
    if url.startswith(CUSTOM_PREFIX) and url[len(CUSTOM_PREFIX):] in CUSTOM_FILES:
        # 发布前使用工作区的个人规则；清单明确记录该覆盖，防止误称远端已更新。
        return (template.parent / url[len(CUSTOM_PREFIX):]).read_bytes(), "workspace"
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "clash-config-validator/1.0", "Accept-Encoding": "identity"})
            with urllib.request.urlopen(request, timeout=25) as response:
                if response.status != 200:
                    raise ValueError(f"预期 HTTP 200，实际 {response.status}")
                content = response.read(4 * 1024 * 1024 + 1)
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) != len(content):
                    raise ValueError(f"来源长度不符：声明 {declared}，实际 {len(content)}")
            if len(content) > 4 * 1024 * 1024:
                raise ValueError("单个规则来源超过本项目的 4 MiB 检查限制")
            return content, "http"
        except (OSError, ValueError, http.client.HTTPException) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.5 * (attempt + 1))
    raise ValueError(f"读取失败：{url}：{last_error}")


def _write_json(path: Path, data: Any) -> None:
    """用原子替换写入本地证据，避免留下半截 JSON。"""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def validate_template(path: Path, snapshot_dir: Path) -> ValidationResult:
    """校验模板并固定本次使用的全部来源、展开规则和内容摘要。"""
    result = ValidationResult()
    path, snapshot_dir = Path(path).resolve(), Path(snapshot_dir).resolve()
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, Any] = {"schema_version": 1, "complete": False, "fetched_at": datetime.now(timezone.utc).isoformat(), "sources": []}
    # 先令旧清单失效，任何中途异常都不能让流水线误用上次结果。
    _write_json(snapshot_dir / "sources.json", manifest)
    try:
        sources, groups = read_template(path)
        result.errors.extend(validate_groups(groups))
        known = {group["name"] for group in groups} | BUILTINS
        result.errors.extend(f"规则引用了未定义策略组：{item['group']}" for item in sources if item["group"] not in known)
        manifest["template_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        remote = [item for item in sources if "url" in item]
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {item["line"]: pool.submit(_download_source, item, path) for item in remote}
            all_rules: list[Rule] = []
            for index, item in enumerate(sources):
                if "inline" in item:
                    rule = parse_rule(item["inline"], item["group"])
                    rule.source, rule.line = str(path), item["line"]
                    all_rules.append(rule)
                    continue
                try:
                    data, origin = futures[item["line"]].result()
                    content = data.decode("utf-8-sig")
                    rules, warnings = parse_source(content, item["format"], item["group"], item["url"])
                    filename = f"source-{index:03d}.txt"
                    (snapshot_dir / filename).write_bytes(data)
                    entry = {**item, "path": filename, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "rule_count": len(rules), "origin": origin, "ignored_count": len(warnings)}
                    manifest["sources"].append(entry)
                    all_rules.extend(rules)
                    result.warnings.extend(warnings)
                except (OSError, ValueError) as exc:
                    result.errors.append(f"第 {item['line']} 行来源失败：{exc}")
        endings = [index for index, rule in enumerate(all_rules) if rule.kind == "MATCH"]
        if endings != [len(all_rules) - 1]:
            result.errors.append("最终 MATCH 必须唯一且位于末尾")
        rendered = [rule.render() for rule in all_rules]
        # 重叠可以是有意的服务例外，仅统计；错误优先级交由固定命中样例检出。
        duplicates = len(rendered) - len(set(rendered))
        if duplicates:
            result.warnings.append(f"同策略重复规则 {duplicates} 条；保持原有顺序，未擅自更改例外语义")
        manifest["rule_count"] = len(all_rules)
        manifest["errors"] = result.errors
        _write_json(snapshot_dir / "expected-rules.json", rendered)
        (snapshot_dir / "expanded.yaml").write_text(yaml.safe_dump({"rules": rendered}, allow_unicode=True, sort_keys=False), encoding="utf-8")
        # 所有证据成功写完后，最后提交完整标记；中途失败维持初始 false。
        manifest["complete"] = result.ok
        _write_json(snapshot_dir / "sources.json", manifest)
        result.details.update({"template": str(path), "snapshot_dir": str(snapshot_dir), "sources": len(manifest["sources"]), "expected_sources": len(remote), "groups": len(groups), "rules": len(all_rules), "duplicate_rules": duplicates, "template_sha256": manifest["template_sha256"]})
    except (OSError, ValueError) as exc:
        result.errors.append(str(exc))
    return result


def validate_routes(config: Path, cases: Path) -> ValidationResult:
    """核对输出中的固定域名/IP 样例，并报告实际首条命中。"""
    result = ValidationResult()
    try:
        payload = read_yaml_unique(Path(config).read_text(encoding="utf-8-sig"))
        if not isinstance(payload, dict) or not isinstance(payload.get("rules"), list) or not payload["rules"]:
            raise ValueError("配置缺少非空 rules 数组")
        if any(not isinstance(text, str) for text in payload["rules"]):
            raise ValueError("rules 条目必须是字符串")
        rules = [parse_rule(text) for text in payload["rules"]]
        if [index for index, rule in enumerate(rules) if rule.kind == "MATCH"] != [len(rules) - 1]:
            result.errors.append("最终 MATCH 必须唯一且位于末尾")
        samples = json.loads(Path(cases).read_text(encoding="utf-8-sig"))
        if not isinstance(samples, list) or not samples:
            raise ValueError("测试样例必须为非空数组")
        checks = []
        for sample in samples:
            if not isinstance(sample, dict) or not sample.get("expected_policy") or not any(sample.get(key) for key in ("domain", "ip", "process")):
                raise ValueError("样例缺少目标或 expected_policy")
            hit = first_match(rules, sample.get("domain"), sample.get("ip"), sample.get("process"))
            actual = hit.policy if hit else None
            passed = actual == sample["expected_policy"]
            checks.append({"name": sample.get("name", sample.get("domain", sample.get("ip"))), "expected_policy": sample["expected_policy"], "actual_policy": actual, "rule": hit.render() if hit else None, "passed": passed})
            if not passed:
                result.errors.append(f"{checks[-1]['name']}：预期 {sample['expected_policy']}，实际 {actual}，首条规则 {checks[-1]['rule']}")
        result.details.update({"cases": len(checks), "passed": sum(check["passed"] for check in checks), "checks": checks, "scope": "固定元数据的规则检查，不执行 DNS 或真实业务访问"})
    except (OSError, ValueError, yaml.YAMLError) as exc:
        result.errors.append(str(exc))
    return result


def main() -> int:
    """提供一键规则校验入口，失败时返回非零退出码供自动检查使用。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", type=Path, default=Path("config.ini"))
    parser.add_argument("--snapshot-dir", type=Path, default=Path(".validation/snapshot"))
    parser.add_argument("--cases", type=Path, default=Path("tests/routing_cases.json"))
    parser.add_argument("--config", type=Path, help="仅检查已有转换配置的固定样例")
    args = parser.parse_args()
    if args.config:
        result = validate_routes(args.config, args.cases)
    else:
        result = validate_template(args.template, args.snapshot_dir)
        if result.ok:
            routes = validate_routes(args.snapshot_dir / "expanded.yaml", args.cases)
            result.errors.extend(routes.errors)
            result.warnings.extend(routes.warnings)
            result.details["routes"] = routes.details
    report = {"ok": result.ok, **asdict(result)}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
