"""用固定预期验证解析、匹配边界和失败处理，全程不访问网络。"""

from __future__ import annotations

import json
from http.client import HTTPResponse
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import validate_rules as validator
from scripts.validate_rules import (
    Rule,
    ValidationResult,
    first_match,
    parse_rule,
    parse_source,
    validate_groups,
    validate_routes,
)


class RuleParsingTests(unittest.TestCase):
    """区分无策略的上游规则和带策略的最终规则，避免选项错位。"""

    def test_source_and_final_rules_keep_no_resolve(self) -> None:
        """IPv4、IPv6 的 no-resolve 在补入策略和再次解析后都必须保留。"""
        for kind, network in (
            ("IP-CIDR", "192.168.0.0/16"),
            ("IP-CIDR6", "fd00::/8"),
        ):
            with self.subTest(kind=kind):
                rule = parse_rule(f"{kind},{network},no-resolve", "🎯 全球直连")
                expected = f"{kind},{network},🎯 全球直连,no-resolve"
                self.assertEqual(rule.options, ("no-resolve",))
                self.assertEqual(rule.render(), expected)
                final_rule = parse_rule(expected)
                self.assertEqual(final_rule.kind, kind)
                self.assertEqual(final_rule.value, network)
                self.assertEqual(final_rule.policy, "🎯 全球直连")
                self.assertEqual(final_rule.options, ("no-resolve",))

    def test_unknown_rule_type_is_rejected(self) -> None:
        """未来新增或拼错的类型不能被静默丢弃并误报验证通过。"""
        with self.assertRaises(ValueError):
            parse_rule("UNKNOWN-RULE,example.com", "DIRECT")

    def test_surge_source_reports_explicitly_ignored_url_regex(self) -> None:
        """允许的格式降级必须留下警告，其余有效行保持来源信息。"""
        content = (
            "# 上游注释\n"
            "DOMAIN-SUFFIX,example.com\n"
            "URL-REGEX,^https?://example\\.org/\n"
            "IP-CIDR,10.0.0.0/8,no-resolve\n"
        )
        rules, warnings = parse_source(content, "surge", "DIRECT", "fixed-source")
        self.assertEqual(
            [rule.render() for rule in rules],
            [
                "DOMAIN-SUFFIX,example.com,DIRECT",
                "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
            ],
        )
        self.assertTrue(any("URL-REGEX" in warning for warning in warnings))
        self.assertTrue(all(rule.source == "fixed-source" for rule in rules))

    def test_domain_payload_preserves_exact_and_suffix_semantics(self) -> None:
        """裸域名与加号后缀规则语义不同，不能全部转换为后缀规则。"""
        content = "payload:\n  - example.com\n  - '+.example.org'\n"
        rules, warnings = parse_source(content, "clash-domain", "DIRECT")
        self.assertEqual(
            [rule.render() for rule in rules],
            ["DOMAIN,example.com,DIRECT", "DOMAIN-SUFFIX,example.org,DIRECT"],
        )
        self.assertEqual(warnings, [])

    def test_ipcidr_payload_supports_both_address_families(self) -> None:
        """CIDR 提供器中的两种地址族均须能参与匹配。"""
        content = "payload:\n  - 10.0.0.0/8\n  - 'fd00::/8'\n"
        rules, warnings = parse_source(content, "clash-ipcidr", "DIRECT")
        self.assertEqual(len(rules), 2)
        self.assertEqual(first_match(rules, ip="10.2.3.4").policy, "DIRECT")
        self.assertEqual(first_match(rules, ip="fd00::123").policy, "DIRECT")
        self.assertIsNone(first_match(rules, ip="203.0.113.10"))
        self.assertEqual(warnings, [])

    def test_classic_payload_preserves_rule_type_and_options(self) -> None:
        """经典 YAML 列表须按完整规则解析，不能误当成纯域名。"""
        content = (
            "payload:\n"
            "  - DOMAIN-SUFFIX,example.com\n"
            "  - IP-CIDR6,fd00::/8,no-resolve\n"
        )
        rules, warnings = parse_source(content, "clash-classic", "DIRECT")
        self.assertEqual(
            [rule.render() for rule in rules],
            [
                "DOMAIN-SUFFIX,example.com,DIRECT",
                "IP-CIDR6,fd00::/8,DIRECT,no-resolve",
            ],
        )
        self.assertEqual(warnings, [])

    def test_invalid_payloads_fail_instead_of_becoming_empty_rules(self) -> None:
        """缺失、空白及形状错误的 payload 都必须阻止验证通过。"""
        malformed = (
            "",
            "rules: []\n",
            "payload:\n",
            "payload: []\n",
            "payload: example.com\n",
            "payload: {domain: example.com}\n",
            "payload: [123]\n",
            "payload: [{domain: example.com}]\n",
        )
        for source_format in ("clash-domain", "clash-ipcidr", "clash-classic"):
            for content in malformed:
                with self.subTest(source_format=source_format, content=content):
                    with self.assertRaises(ValueError):
                        parse_source(content, source_format, "DIRECT")

    def test_unknown_source_format_is_rejected(self) -> None:
        """没有实现的来源格式不能自动按另一种格式猜测解析。"""
        with self.assertRaises(ValueError):
            parse_source("DOMAIN,example.com\n", "unknown-format", "DIRECT")

    def test_duplicate_payload_keys_are_rejected(self) -> None:
        """两段合法 payload 也不能覆盖合并，重复键必须明确失败。"""
        content = (
            "payload:\n"
            "  - DOMAIN,first.example\n"
            "payload:\n"
            "  - DOMAIN,second.example\n"
        )
        with self.assertRaises(ValueError):
            parse_source(content, "clash-classic", "DIRECT")

    def test_html_and_filter_syntax_are_not_valid_domains(self) -> None:
        """HTML 和广告过滤器语法不能成为看似非空的有效域名来源。"""
        for value in ("<html>", "||example.com^"):
            for prefix in ("", "+."):
                with self.subTest(value=value, prefix=prefix):
                    content = f"payload:\n  - '{prefix}{value}'\n"
                    with self.assertRaises(ValueError):
                        parse_source(content, "clash-domain", "DIRECT")


class SourceIntegrityTests(unittest.TestCase):
    """检查来源完整性与完成标记，全程使用合成内容。"""

    def test_truncated_and_partial_http_responses_are_rejected(self) -> None:
        """标准库能读到的短包和 206 响应仍不代表完整规则来源。"""
        body = b"DOMAIN-SUFFIX,example.com\n"
        for status, declared_size in (("200 OK", 500), ("206 Partial Content", len(body))):
            with self.subTest(status=status, declared_size=declared_size):
                wire = (
                    f"HTTP/1.1 {status}\r\nContent-Length: {declared_size}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("ascii") + body

                def make_response(*args: object, **kwargs: object) -> HTTPResponse:
                    """每次重试返回新的真实响应解析器，底层字节来自内存。"""
                    connection = mock.Mock()
                    connection.makefile.return_value = BytesIO(wire)
                    response = HTTPResponse(connection)
                    response.begin()
                    return response

                # 只替换网络入口和等待，保留标准库对 HTTP 状态及长度的解析。
                with (
                    mock.patch.object(validator.urllib.request, "urlopen", side_effect=make_response),
                    mock.patch.object(validator.time, "sleep"),
                    self.assertRaises(ValueError),
                ):
                    validator._download_source(
                        {"url": "https://public-source.example/rules.list"}, Path("config.ini")
                    )

    def test_failed_final_artifact_keeps_manifest_incomplete(self) -> None:
        """最后产物写入失败时，磁盘上的来源清单不得宣称快照完成。"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            template = root / "config.ini"
            snapshot = root / "snapshot"
            template.write_text(
                "[custom]\n"
                "ruleset=测试组,[]FINAL\n"
                "custom_proxy_group=测试组`select`[]DIRECT\n"
                "enable_rule_generator=true\n"
                "overwrite_original_rules=true\n",
                encoding="utf-8",
            )
            original_write_text = Path.write_text

            def fail_expanded_write(path: Path, *args: object, **kwargs: object) -> int:
                """仅令展开文件失败，保留清单真实写入以核对最终磁盘状态。"""
                if path.name.startswith("expanded.yaml"):
                    raise OSError("模拟最终规则产物写入失败")
                return original_write_text(path, *args, **kwargs)

            with mock.patch.object(Path, "write_text", new=fail_expanded_write):
                result = validator.validate_template(template, snapshot)
            self.assertFalse(result.ok)
            manifest = json.loads((snapshot / "sources.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["complete"])


class RuleMatchingTests(unittest.TestCase):
    """验证首条命中及边界，避免看似正确的字符串包含匹配。"""

    def test_domain_suffix_respects_label_boundaries(self) -> None:
        """后缀匹配包含根域和子域，但不得命中相似尾串或攻击者后缀。"""
        rules = [Rule("DOMAIN-SUFFIX", "example.com", "DIRECT")]
        for domain in ("example.com", "www.example.com", "a.b.example.com"):
            with self.subTest(domain=domain):
                self.assertIsNotNone(first_match(rules, domain=domain))
        for domain in ("notexample.com", "example.com.evil", "example.net"):
            with self.subTest(domain=domain):
                self.assertIsNone(first_match(rules, domain=domain))

    def test_exact_domain_does_not_include_subdomains(self) -> None:
        """个人 Google 覆盖为精确域名，不应扩大到其他主机。"""
        rules = [Rule("DOMAIN", "www.google.com", "💬 Ai平台")]
        self.assertIsNotNone(first_match(rules, domain="www.google.com"))
        self.assertIsNone(first_match(rules, domain="mail.www.google.com"))
        self.assertIsNone(first_match(rules, domain="google.com"))

    def test_personal_and_ai_rules_win_before_broad_categories(self) -> None:
        """重叠样例必须采用首条规则，而非按来源顺序以外的方式重排。"""
        rules = [
            Rule("DOMAIN", "www.google.com", "💬 Ai平台"),
            Rule("DOMAIN", "copilot.microsoft.com", "💬 Ai平台"),
            Rule("DOMAIN-SUFFIX", "google.com", "🚀 节点选择"),
            Rule("DOMAIN-SUFFIX", "microsoft.com", "Ⓜ️ 微软服务"),
        ]
        for domain, expected in (
            ("www.google.com", "💬 Ai平台"),
            ("copilot.microsoft.com", "💬 Ai平台"),
            ("www.microsoft.com", "Ⓜ️ 微软服务"),
        ):
            with self.subTest(domain=domain):
                self.assertEqual(first_match(rules, domain=domain).policy, expected)

    def test_ipv4_and_ipv6_rules_do_not_cross_match(self) -> None:
        """同时保留两种地址族，并检查 CIDR 的内外边界。"""
        rules = [
            Rule("IP-CIDR", "10.0.0.0/8", "IPv4", ("no-resolve",)),
            Rule("IP-CIDR6", "fd00::/8", "IPv6", ("no-resolve",)),
        ]
        for address, expected in (
            ("10.0.0.0", "IPv4"),
            ("10.255.255.255", "IPv4"),
            ("fd00::1", "IPv6"),
        ):
            with self.subTest(address=address):
                self.assertEqual(first_match(rules, ip=address).policy, expected)
        for address in ("9.255.255.255", "11.0.0.0", "2001:db8::1"):
            with self.subTest(address=address):
                self.assertIsNone(first_match(rules, ip=address))

    def test_unresolved_domain_skips_no_resolve_ip_rule(self) -> None:
        """没有目标 IP 时不得为模拟命中额外查询 DNS，必须继续兜底。"""
        rules = [
            Rule("IP-CIDR", "0.0.0.0/0", "DIRECT", ("no-resolve",)),
            Rule("MATCH", "", "🐟 漏网之鱼"),
        ]
        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("禁止查询 DNS")):
            matched = first_match(rules, domain="routing-verification.example")
        self.assertEqual(matched.policy, "🐟 漏网之鱼")


class GroupValidationTests(unittest.TestCase):
    """候补路径既须能找到成员，也不能反向指回父组。"""

    def test_fallback_to_parent_group_detects_cycle(self) -> None:
        """先验证正常分组，再模拟地区候补指回主组所形成的实际循环。"""
        proxies = [{"name": "合成日本节点"}, {"name": "合成备用节点"}]
        groups = [
            {"name": "节点选择", "type": "select", "proxies": ["日本组", "备用组"]},
            {"name": "日本组", "type": "select", "proxies": ["合成日本节点"]},
            {"name": "备用组", "type": "select", "proxies": ["合成备用节点"]},
        ]
        self.assertEqual(validate_groups(groups, proxies), [])
        # 地区组不能用包含自身的父组作为候补，否则请求无法选出最终出口。
        groups[1]["proxies"] = ["节点选择"]
        self.assertTrue(any("循环" in error for error in validate_groups(groups, proxies)))

    def test_missing_member_is_reported_with_its_name(self) -> None:
        """合法节点及内置策略不应报错，新增不存在的组名必须明确报错。"""
        proxies = [{"name": "合成备用节点"}]
        groups = [
            {"name": "节点选择", "type": "select", "proxies": ["合成备用节点", "DIRECT"]}
        ]
        self.assertEqual(validate_groups(groups, proxies), [])
        groups[0]["proxies"].append("不存在的地区组")
        self.assertTrue(
            any("不存在的地区组" in error for error in validate_groups(groups, proxies))
        )


class RouteValidationTests(unittest.TestCase):
    """通过最小最终配置检查样例失败能否准确反馈到验证结果。"""

    def test_result_ok_depends_on_errors_not_warnings(self) -> None:
        """警告可以保留在通过结果中，任何错误都必须使结果失败。"""
        self.assertTrue(ValidationResult([], ["已明确忽略 URL-REGEX"], {}).ok)
        self.assertFalse(ValidationResult(["规则缺失"], [], {}).ok)

    def test_fixed_cases_check_domain_ip_and_fallback(self) -> None:
        """正确样例全部通过，改错一个预期后必须报告具体样例名称。"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "generated.yaml"
            cases = root / "cases.json"
            # JSON 是 YAML 的子集，用固定对象生成输入即可避免格式偶然差异。
            config.write_text(
                json.dumps(
                    {
                        "rules": [
                            "DOMAIN-SUFFIX,example.com,DIRECT",
                            "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
                            "MATCH,REJECT",
                        ]
                    }
                ),
                encoding="utf-8",
            )
            fixed_cases = [
                {"name": "域名命中", "domain": "www.example.com", "expected_policy": "DIRECT"},
                {"name": "地址命中", "ip": "10.1.2.3", "expected_policy": "DIRECT"},
                {"name": "兜底命中", "ip": "203.0.113.10", "expected_policy": "REJECT"},
            ]
            cases.write_text(json.dumps(fixed_cases, ensure_ascii=False), encoding="utf-8")
            self.assertTrue(validate_routes(config, cases).ok)

            # 故意给出错误预期，确保检查器没有只统计样例而忽略实际策略。
            fixed_cases[-1]["expected_policy"] = "DIRECT"
            cases.write_text(json.dumps(fixed_cases, ensure_ascii=False), encoding="utf-8")
            result = validate_routes(config, cases)
            self.assertFalse(result.ok)
            self.assertTrue(any("兜底命中" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
