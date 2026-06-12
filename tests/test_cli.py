import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from webconf_audit.cli import app
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation

runner = CliRunner()


# ---------------------------------------------------------------------------
# list-rules command
# ---------------------------------------------------------------------------


class TestListRules:
    def test_list_rules_no_filters(self) -> None:
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "Total:" in result.stdout
        assert "nginx.server_tokens_on" in result.stdout
        assert "external.https_not_available" in result.stdout

    def test_list_rules_category_universal(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "universal"])
        assert result.exit_code == 0
        assert "universal.tls_intent_without_config" in result.stdout
        assert "nginx." not in result.stdout

    def test_list_rules_category_external(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "external"])
        assert result.exit_code == 0
        assert "external.https_not_available" in result.stdout
        assert "universal." not in result.stdout

    def test_list_rules_server_type_nginx(self) -> None:
        result = runner.invoke(app, ["list-rules", "--server-type", "nginx"])
        assert result.exit_code == 0
        assert "nginx.server_tokens_on" in result.stdout
        assert "apache." not in result.stdout

    def test_list_rules_severity_high(self) -> None:
        result = runner.invoke(app, ["list-rules", "--severity", "high"])
        assert result.exit_code == 0
        assert "HIGH" in result.stdout.upper()
        assert "external.git_metadata_exposed" in result.stdout

    def test_list_rules_tag_tls(self) -> None:
        result = runner.invoke(app, ["list-rules", "--tag", "tls"])
        assert result.exit_code == 0
        assert "universal.tls_intent_without_config" in result.stdout
        assert "universal.weak_tls_protocol" in result.stdout

    def test_list_rules_combined_filters(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "local", "--server-type", "apache"])
        assert result.exit_code == 0
        assert "apache.server_tokens_not_prod" in result.stdout
        assert "nginx." not in result.stdout

    def test_list_rules_no_match(self) -> None:
        result = runner.invoke(
            app,
            ["list-rules", "--category", "universal", "--server-type", "nginx"],
        )
        assert result.exit_code == 0
        assert "No rules match" in result.stdout

    def test_list_rules_invalid_category_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "invalid"])
        assert result.exit_code != 0
        assert "invalid category" in result.output

    def test_list_rules_invalid_severity_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--severity", "urgent"])
        assert result.exit_code != 0
        assert "invalid severity" in result.output

    def test_list_rules_invalid_server_type_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--server-type", "nonexistent"])
        assert result.exit_code != 0
        assert "invalid server type" in result.output

    def test_list_rules_invalid_tag_fails(self) -> None:
        result = runner.invoke(app, ["list-rules", "--tag", "not-a-real-tag"])
        assert result.exit_code != 0
        assert "invalid tag" in result.output

    def test_list_rules_table_header(self) -> None:
        result = runner.invoke(app, ["list-rules", "--category", "universal"])
        assert result.exit_code == 0
        assert "RULE ID" in result.stdout
        assert "SEV" in result.stdout
        assert "CAT" in result.stdout
        assert "ORDER" in result.stdout

    def test_list_rules_json_format_returns_array(self) -> None:
        result = runner.invoke(app, ["list-rules", "--format", "json"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert isinstance(payload, list)
        assert len(payload) > 0

    def test_list_rules_json_entries_expose_full_rule_meta(self) -> None:
        result = runner.invoke(app, ["list-rules", "--format", "json", "--category", "universal"])
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        expected_keys = {
            "rule_id",
            "title",
            "severity",
            "description",
            "recommendation",
            "category",
            "server_type",
            "input_kind",
            "tags",
            "severity_profile",
            "standards",
            "standards_secondary",
            "condition",
            "order",
        }
        for entry in payload:
            assert set(entry.keys()) == expected_keys
            assert isinstance(entry["tags"], list)
            assert isinstance(entry["severity_profile"], dict)
            assert isinstance(entry["standards"], list)
            assert isinstance(entry["standards_secondary"], list)

    def test_list_rules_json_includes_standards_metadata(self) -> None:
        result = runner.invoke(
            app,
            [
                "list-rules",
                "--format",
                "json",
                "--category",
                "universal",
                "--tag",
                "tls",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        weak_tls = next(
            entry
            for entry in payload
            if entry["rule_id"] == "universal.weak_tls_protocol"
        )
        assert {
            "standard": "CWE",
            "reference": "CWE-327",
            "url": "https://cwe.mitre.org/data/definitions/327.html",
            "coverage": "direct",
            "origin": "declared",
            "derived_from": None,
        } in weak_tls["standards"]

    def test_list_rules_json_exposes_derived_mapping_provenance(self) -> None:
        result = runner.invoke(
            app,
            [
                "list-rules",
                "--format",
                "json",
                "--category",
                "universal",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        missing_hsts = next(
            entry
            for entry in payload
            if entry["rule_id"] == "universal.missing_hsts"
        )
        derived = next(
            ref
            for ref in missing_hsts["standards_secondary"]
            if ref["standard"] == "OWASP Top 10"
            and ref["reference"] == "A02:2025"
        )
        assert derived["origin"] == "derived"
        assert derived["derived_from"] == {
            "standard": "OWASP Top 10",
            "reference": "A05:2021",
        }

    def test_list_rules_json_respects_filters(self) -> None:
        result = runner.invoke(
            app, ["list-rules", "--format", "json", "--category", "external"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload
        assert all(entry["category"] == "external" for entry in payload)

    def test_list_rules_json_reports_profile_calibrated_severity(self) -> None:
        result = runner.invoke(
            app,
            ["list-rules", "--format", "json", "--server-type", "nginx"],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        severity_by_rule = {entry["rule_id"]: entry["severity"] for entry in payload}
        assert severity_by_rule["nginx.alias_without_trailing_slash"] == "high"
        assert severity_by_rule["nginx.allow_all_with_deny_all"] == "high"
        assert severity_by_rule["nginx.missing_auth_basic_user_file"] == "medium"

    def test_list_rules_json_empty_match_emits_empty_array(self) -> None:
        result = runner.invoke(
            app,
            ["list-rules", "--format", "json", "--category", "universal", "--server-type", "nginx"],
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout) == []
        assert "No rules match" not in result.stdout


# ---------------------------------------------------------------------------
# analyze-* commands — text output (new report format)
# ---------------------------------------------------------------------------


def test_analyze_apache_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.server_tokens_not_prod",
                    title="ServerTokens not set to Prod",
                    severity="low",
                    description="Apache config sets ServerTokens unsafely.",
                    recommendation="Set ServerTokens Prod.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/extra.conf",
                        line=3,
                    ),
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== LOW (1) ===" in result.stdout
    assert "[apache.server_tokens_not_prod] ServerTokens not set to Prod" in result.stdout
    assert "location: /tmp/extra.conf:3" in result.stdout
    assert "description: Apache config sets ServerTokens unsafely." in result.stdout
    assert "recommendation: Set ServerTokens Prod." in result.stdout


def test_analyze_cli_can_group_text_by_standard(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="universal.weak_tls_protocol",
                    title="Weak TLS/SSL protocols enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(
        app,
        ["analyze-nginx", "nginx.conf", "--group-by", "standard"],
    )

    assert result.exit_code == 0
    assert "=== STANDARD CWE (1) ===" in result.stdout
    assert "refs: CWE-327" in result.stdout
    assert "=== STANDARD OWASP TOP 10 (1) ===" in result.stdout


def test_analyze_cli_can_group_repeated_text_findings(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.missing_hsts_header",
                    title="Missing HSTS header",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/sites/app.conf",
                        line=3,
                    ),
                ),
                Finding(
                    rule_id="nginx.missing_hsts_header",
                    title="Missing HSTS header",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/sites/app.conf",
                        line=27,
                    ),
                ),
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(
        app,
        ["analyze-nginx", "nginx.conf", "--group-repeated"],
    )

    assert result.exit_code == 0
    assert result.stdout.count("[nginx.missing_hsts_header] Missing HSTS header") == 1
    assert "findings: 2 repeated" in result.stdout
    assert "locations (2):" in result.stdout
    assert "      - /sites/app.conf:3" in result.stdout
    assert "      - /sites/app.conf:27" in result.stdout


def test_analyze_nginx_cli_prints_issues_section(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="nginx_parse_error",
                    level="error",
                    message="Expected ';' or '{'",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/nginx.conf",
                        line=2,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", str(Path("nginx.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: nginx" in result.stdout
    assert "Target: nginx.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] nginx_parse_error: Expected ';' or '{'" in result.stdout
    assert "location: /tmp/nginx.conf:2" in result.stdout


def test_cli_omits_issues_section_when_empty(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "Issues:" not in result.stdout


def test_cli_does_not_print_location_when_result_entry_has_no_location(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.server_tokens_not_prod",
                    title="ServerTokens not set to Prod",
                    severity="low",
                    description="Apache config sets ServerTokens unsafely.",
                    recommendation="Set ServerTokens Prod.",
                    location=None,
                )
            ],
            issues=[
                AnalysisIssue(
                    code="apache_parse_error",
                    level="error",
                    message="Unexpected end of input",
                    location=None,
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", str(Path("httpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Target: httpd.conf" in result.stdout
    assert "[apache.server_tokens_not_prod]" in result.stdout
    assert "Issues:" in result.stdout
    assert "location:" not in result.stdout


def test_analyze_external_cli_prints_diagnostics_section(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            diagnostics=[
                "tcp_port_open: example.com:443",
                "probable_server_type: nginx",
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "Mode: external" in result.stdout
    assert "Server: nginx" in result.stdout
    assert "Target: example.com" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Diagnostics:" in result.stdout
    assert "- tcp_port_open: example.com:443" in result.stdout
    assert "- probable_server_type: nginx" in result.stdout


def test_analyze_external_cli_prints_external_summary(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            diagnostics=["probable_server_type: nginx"],
            metadata={
                "port_scan": [
                    {"host": "example.com", "port": 80, "tcp_open": False, "error_message": "refused"},
                    {"host": "example.com", "port": 443, "tcp_open": True, "error_message": None},
                    {"host": "example.com", "port": 8443, "tcp_open": True, "error_message": None},
                ],
                "server_identification": {
                    "server_type": "nginx",
                    "confidence": "high",
                    "ambiguous": False,
                    "candidate_server_types": ["nginx"],
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "error_page_body"},
                        {"signal": "malformed_response_body"},
                    ],
                },
                "probe_attempts": [
                    {
                        "scheme": "https",
                        "url": "https://example.com/",
                        "cache_control_header": "no-store",
                        "x_dns_prefetch_control_header": "off",
                        "cross_origin_embedder_policy_header": "require-corp",
                        "cross_origin_opener_policy_header": "same-origin",
                        "cross_origin_resource_policy_header": "same-origin",
                        "tls_info": {
                            "protocol_version": "TLSv1.3",
                            "cipher_name": "TLS_AES_256_GCM_SHA384",
                            "cipher_bits": 256,
                            "supported_protocols": ["TLSv1.2", "TLSv1.3"],
                            "cert_chain_complete": True,
                            "cert_chain_error": None,
                        },
                    }
                ],
                "redirect_chains": [
                    {
                        "hops": [
                            {"url": "http://example.com/"},
                            {"url": "https://example.com/login"},
                        ],
                        "final_url": "https://example.com/login",
                        "loop_detected": False,
                        "mixed_scheme_redirect": False,
                        "cross_domain_redirect": True,
                        "truncated": False,
                        "error_message": None,
                    }
                ],
            },
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "External Summary:" in result.stdout
    assert "- port discovery: 3 scanned; open ports: 443, 8443" in result.stdout
    assert "- port discovery errors: 80" in result.stdout
    assert (
        "- server identification: nginx (high confidence; signals: "
        "error_page_body, malformed_response_body, server_header)"
    ) in result.stdout
    assert (
        "- tls: https://example.com/: TLSv1.3; supports TLSv1.2, TLSv1.3; "
        "cipher TLS_AES_256_GCM_SHA384 (256 bits); chain complete"
    ) in result.stdout
    assert (
        "- extra headers: https://example.com/: Cache-Control=no-store; "
        "X-DNS-Prefetch-Control=off; COEP=require-corp; COOP=same-origin; "
        "CORP=same-origin"
    ) in result.stdout
    assert (
        "- redirect chain: http://example.com/ -> https://example.com/login "
        "(cross-domain)"
    ) in result.stdout


def test_analyze_external_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="external.hsts_header_missing",
                    title="HSTS header missing",
                    severity="low",
                    description="HTTPS endpoint responded without a Strict-Transport-Security header.",
                    recommendation="Add a Strict-Transport-Security header to the HTTPS response.",
                    location=SourceLocation(
                        mode="external",
                        kind="header",
                        target="https://example.com/",
                        details="Strict-Transport-Security",
                    ),
                )
            ],
            diagnostics=["http_status: 200 OK"],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com"])

    assert result.exit_code == 0
    assert "Mode: external" in result.stdout
    assert "Server: apache" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== MEDIUM (1) ===" in result.stdout
    assert "[external.hsts_header_missing] HSTS header missing" in result.stdout
    assert "location: https://example.com/" in result.stdout
    assert "Diagnostics:" in result.stdout


def test_analyze_iis_cli_prints_result(monkeypatch) -> None:
    def fake_analyze_iis_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="iis_parse_error",
                    level="error",
                    message="XML parse error: not well-formed",
                    location=SourceLocation(
                        mode="local",
                        kind="xml",
                        file_path="/tmp/web.config",
                        line=5,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(app, ["analyze-iis", str(Path("web.config"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: iis" in result.stdout
    assert "Target: web.config" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] iis_parse_error: XML parse error: not well-formed" in result.stdout


def test_analyze_iis_cli_passes_machine_config_option(monkeypatch) -> None:
    captured: dict[str, str | None] = {}

    def fake_analyze_iis_config(
        config_path: str,
        machine_config_path: str | None = None,
    ) -> AnalysisResult:
        captured["config_path"] = config_path
        captured["machine_config_path"] = machine_config_path
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(
        app,
        [
            "analyze-iis",
            "web.config",
            "--machine-config",
            "machine.config",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "config_path": "web.config",
        "machine_config_path": "machine.config",
    }


def test_analyze_iis_cli_passes_tls_registry_options(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_analyze_iis_config(
        config_path: str,
        **kwargs,
    ) -> AnalysisResult:
        captured["config_path"] = config_path
        captured.update(kwargs)
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(
        app,
        [
            "analyze-iis",
            "web.config",
            "--tls-registry",
            "schannel.json",
            "--no-tls-registry",
        ],
    )

    assert result.exit_code == 0
    assert captured == {
        "config_path": "web.config",
        "tls_registry_path": "schannel.json",
        "use_tls_registry": False,
    }


def test_analyze_lighttpd_cli_prints_issue_section(monkeypatch) -> None:
    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[],
            issues=[
                AnalysisIssue(
                    code="lighttpd_include_not_found",
                    level="error",
                    message="Included config path not found: conf.d/missing.conf",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/lighttpd.conf",
                        line=1,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", str(Path("lighttpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: lighttpd" in result.stdout
    assert "Target: lighttpd.conf" in result.stdout
    assert "Findings: 0" in result.stdout
    assert "Analysis issues: 1" in result.stdout
    assert "Issues:" in result.stdout
    assert "[error] lighttpd_include_not_found: Included config path not found: conf.d/missing.conf" in result.stdout
    assert "location: /tmp/lighttpd.conf:1" in result.stdout


def test_analyze_lighttpd_cli_prints_findings_section(monkeypatch) -> None:
    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[
                Finding(
                    rule_id="lighttpd.dir_listing_enabled",
                    title="Directory listing enabled",
                    severity="medium",
                    description="Lighttpd configuration explicitly enables directory listing.",
                    recommendation="Disable directory listing unless it is intentionally required.",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="/tmp/extra.conf",
                        line=4,
                    ),
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", str(Path("lighttpd.conf"))])

    assert result.exit_code == 0
    assert "Mode: local" in result.stdout
    assert "Server: lighttpd" in result.stdout
    assert "Target: lighttpd.conf" in result.stdout
    assert "Findings: 1" in result.stdout
    assert "Analysis issues: 0" in result.stdout
    assert "=== MEDIUM (1) ===" in result.stdout
    assert "[lighttpd.dir_listing_enabled] Directory listing enabled" in result.stdout
    assert "location: /tmp/extra.conf:4" in result.stdout
    assert "description: Lighttpd configuration explicitly enables directory listing." in result.stdout
    assert "recommendation: Disable directory listing unless it is intentionally required." in result.stdout


def test_analyze_lighttpd_cli_passes_execute_shell_option(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_analyze_lighttpd_config(
        config_path: str,
        execute_shell: bool = False,
        **kwargs,
    ) -> AnalysisResult:
        captured["config_path"] = config_path
        captured["execute_shell"] = execute_shell
        captured.update(kwargs)
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", "lighttpd.conf", "--execute-shell"])

    assert result.exit_code == 0
    assert captured["config_path"] == "lighttpd.conf"
    assert captured["execute_shell"] is True


# ---------------------------------------------------------------------------
# --enable-policy-review CLI flag
# ---------------------------------------------------------------------------


def _make_fake_analyzer(captured: dict[str, object], server_type: str):
    """Capture invocation kwargs and return an empty AnalysisResult."""

    def fake(config_path: str, **kwargs) -> AnalysisResult:
        captured["config_path"] = config_path
        captured.update(kwargs)
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type=server_type,
            findings=[],
            issues=[],
        )

    return fake


@pytest.mark.parametrize(
    ("command", "analyzer_path", "server_type", "extra_args"),
    [
        ("analyze-nginx", "webconf_audit.cli.analyze_nginx_config", "nginx", ()),
        ("analyze-apache", "webconf_audit.cli.analyze_apache_config", "apache", ()),
        ("analyze-lighttpd", "webconf_audit.cli.analyze_lighttpd_config", "lighttpd", ()),
        ("analyze-iis", "webconf_audit.cli.analyze_iis_config", "iis", ()),
    ],
)
def test_analyze_cli_default_excludes_policy_review(
    monkeypatch, command: str, analyzer_path: str, server_type: str,
    extra_args: tuple[str, ...],
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(analyzer_path, _make_fake_analyzer(captured, server_type))

    result = runner.invoke(app, [command, "config.txt", *extra_args])

    assert result.exit_code == 0
    # Default behaviour: the CLI must not pass enable_policy_review at all
    # when the flag is off, preserving the legacy analyzer signatures.
    assert "enable_policy_review" not in captured


@pytest.mark.parametrize(
    ("command", "analyzer_path", "server_type", "extra_args"),
    [
        ("analyze-nginx", "webconf_audit.cli.analyze_nginx_config", "nginx", ()),
        ("analyze-apache", "webconf_audit.cli.analyze_apache_config", "apache", ()),
        ("analyze-lighttpd", "webconf_audit.cli.analyze_lighttpd_config", "lighttpd", ()),
        ("analyze-iis", "webconf_audit.cli.analyze_iis_config", "iis", ()),
    ],
)
def test_analyze_cli_enables_policy_review_when_flag_set(
    monkeypatch, command: str, analyzer_path: str, server_type: str,
    extra_args: tuple[str, ...],
) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(analyzer_path, _make_fake_analyzer(captured, server_type))

    result = runner.invoke(
        app, [command, "config.txt", *extra_args, "--enable-policy-review"],
    )

    assert result.exit_code == 0
    assert captured["enable_policy_review"] is True


# ---------------------------------------------------------------------------
# --fail-on CI exit behavior
# ---------------------------------------------------------------------------


def test_fail_on_exits_2_for_findings_at_or_above_threshold(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--fail-on", "medium"])

    assert result.exit_code == 2
    assert "nginx.weak_ssl_protocols" in result.stdout


def test_fail_on_exits_0_when_findings_are_below_threshold(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.missing_access_log",
                    title="Missing access log",
                    severity="low",
                    description="desc",
                    recommendation="rec",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--fail-on", "medium"])

    assert result.exit_code == 0


def test_fail_on_exits_1_when_analysis_has_error_issue(monkeypatch) -> None:
    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.options_indexes",
                    title="Indexes enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[
                AnalysisIssue(
                    code="apache_parse_error",
                    level="error",
                    message="Unable to parse config.",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", "httpd.conf", "--fail-on", "low"])

    assert result.exit_code == 1
    assert "apache_parse_error" in result.stdout


def test_fail_on_uses_default_suppression_file(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="nginx.conf",
                        line=7,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        Path(".webconf-audit-ignore.yml").write_text(
            "\n".join(
                [
                    "suppressions:",
                    "  - rule_id: nginx.weak_ssl_protocols",
                    "    source: nginx.conf",
                    "    line: 7",
                    "    reason: accepted during migration",
                    "    expires: 2099-01-01",
                ]
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--fail-on", "medium"])

    assert result.exit_code == 0
    assert "Findings: 0" in result.stdout
    assert "Suppressed findings: 1" in result.stdout


def test_default_suppression_file_is_not_loaded_without_ci_gate(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="nginx.conf",
                        line=7,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        Path(".webconf-audit-ignore.yml").write_text(
            "\n".join(
                [
                    "suppressions:",
                    "  - rule_id: nginx.weak_ssl_protocols",
                    "    source: nginx.conf",
                    "    line: 7",
                    "    reason: accepted during migration",
                    "    expires: 2099-01-01",
                ]
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["analyze-nginx", "nginx.conf"])

    assert result.exit_code == 0
    assert "Findings: 1" in result.stdout
    assert "Suppressed findings" not in result.stdout


def test_explicit_missing_suppression_file_fails_ci_gate(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(
        app,
        [
            "analyze-nginx",
            "nginx.conf",
            "--fail-on",
            "medium",
            "--suppressions",
            "missing.yml",
        ],
    )

    assert result.exit_code == 1
    assert "suppression_file_not_found" in result.stdout


def test_explicit_missing_suppression_file_fails_without_ci_gate(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(
        app,
        [
            "analyze-nginx",
            "nginx.conf",
            "--suppressions",
            "missing.yml",
        ],
    )

    assert result.exit_code == 1
    assert "suppression_file_not_found" in result.stdout


def test_without_fail_on_keeps_interactive_exit_zero(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="critical",
                    description="desc",
                    recommendation="rec",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf"])

    assert result.exit_code == 0


def test_write_baseline_creates_baseline_file(monkeypatch) -> None:
    import json

    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.server_tokens_on",
                    title="Server tokens enabled",
                    severity="low",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=config_path,
                        line=2,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        result = runner.invoke(
            app,
            ["analyze-nginx", "nginx.conf", "--write-baseline", "baseline.json"],
        )
        baseline = json.loads(Path("baseline.json").read_text(encoding="utf-8"))

    assert result.exit_code == 0
    assert baseline["version"] == 1
    assert baseline["findings"][0]["rule_id"] == "nginx.server_tokens_on"
    assert len(baseline["findings"][0]["fingerprint"]) == 64


def test_fail_on_new_requires_baseline(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(mode="local", target=config_path, server_type="nginx")

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--fail-on-new", "medium"])

    assert result.exit_code == 1
    assert "baseline_required" in result.stdout


def test_fail_on_new_exits_2_for_new_findings_at_or_above_threshold(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        Path("baseline.json").write_text('{"findings": []}', encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "analyze-nginx",
                "nginx.conf",
                "--baseline",
                "baseline.json",
                "--fail-on-new",
                "medium",
            ],
        )

    assert result.exit_code == 2
    assert "Baseline diff:" in result.stdout
    assert "new 1, unchanged 0, resolved 0, suppressed 0" in result.stdout


def test_fail_on_new_allows_unchanged_findings(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        write_result = runner.invoke(
            app,
            ["analyze-nginx", "nginx.conf", "--write-baseline", "baseline.json"],
        )
        result = runner.invoke(
            app,
            [
                "analyze-nginx",
                "nginx.conf",
                "--baseline",
                "baseline.json",
                "--fail-on-new",
                "medium",
            ],
        )

    assert write_result.exit_code == 0
    assert result.exit_code == 0
    assert "new 0, unchanged 1, resolved 0, suppressed 0" in result.stdout


def test_fail_on_new_uses_default_suppression_file(monkeypatch) -> None:
    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[
                Finding(
                    rule_id="nginx.weak_ssl_protocols",
                    title="Weak SSL protocols",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path="nginx.conf",
                        line=7,
                    ),
                )
            ],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    with runner.isolated_filesystem():
        Path("baseline.json").write_text('{"findings": []}', encoding="utf-8")
        Path(".webconf-audit-ignore.yml").write_text(
            "\n".join(
                [
                    "suppressions:",
                    "  - rule_id: nginx.weak_ssl_protocols",
                    "    source: nginx.conf",
                    "    line: 7",
                    "    reason: accepted during migration",
                    "    expires: 2099-01-01",
                ]
            ),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "analyze-nginx",
                "nginx.conf",
                "--baseline",
                "baseline.json",
                "--fail-on-new",
                "medium",
            ],
        )

    assert result.exit_code == 0
    assert "new 0, unchanged 0, resolved 0, suppressed 1" in result.stdout


# ---------------------------------------------------------------------------
# --format json
# ---------------------------------------------------------------------------


def test_analyze_apache_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_apache_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="apache",
            findings=[
                Finding(
                    rule_id="apache.test_rule",
                    title="Test",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_apache_config", fake_analyze_apache_config)

    result = runner.invoke(app, ["analyze-apache", "httpd.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["results"][0]["server_type"] == "apache"
    assert parsed["results"][0]["findings"][0]["rule_id"] == "apache.test_rule"
    # top-level aggregated arrays
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["rule_id"] == "apache.test_rule"
    assert parsed["issues"] == []


def test_analyze_external_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_external_target(target: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="external",
            target=target,
            server_type="nginx",
            findings=[],
            metadata={"port_scan": [{"port": 443, "tcp_open": True}]},
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_external_target", fake_analyze_external_target)

    result = runner.invoke(app, ["analyze-external", "example.com", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 0
    assert parsed["results"][0]["metadata"]["port_scan"][0]["port"] == 443
    assert "generated_at" in parsed
    assert parsed["findings"] == []
    assert parsed["issues"] == []


def test_analyze_nginx_json_has_summary_and_results(monkeypatch) -> None:
    import json

    def fake_analyze_nginx_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_analyze_nginx_config)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "summary" in parsed
    assert "results" in parsed
    assert set(parsed["summary"]["by_severity"].keys()) == {
        "critical", "high", "medium", "low", "info",
    }


def test_analyze_iis_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_iis_config(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="iis",
            findings=[
                Finding(
                    rule_id="iis.directory_browse_enabled",
                    title="Directory browsing enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_iis_config", fake_analyze_iis_config)

    result = runner.invoke(app, ["analyze-iis", "web.config", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "iis.directory_browse_enabled"


def test_analyze_lighttpd_json_format(monkeypatch) -> None:
    import json

    def fake_analyze_lighttpd_config(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="lighttpd",
            findings=[
                Finding(
                    rule_id="lighttpd.dir_listing_enabled",
                    title="Directory listing enabled",
                    severity="medium",
                    description="desc",
                    recommendation="rec",
                )
            ],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_lighttpd_config", fake_analyze_lighttpd_config)

    result = runner.invoke(app, ["analyze-lighttpd", "lighttpd.conf", "--format", "json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["summary"]["total_findings"] == 1
    assert parsed["findings"][0]["rule_id"] == "lighttpd.dir_listing_enabled"


def test_all_analyze_commands_default_to_text(monkeypatch) -> None:
    def fake_result(config_path: str, **kwargs) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf"])
    assert result.exit_code == 0
    assert "webconf-audit report" in result.stdout


def test_format_flag_short_form(monkeypatch) -> None:
    import json

    def fake_result(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "-f", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "summary" in parsed


def test_json_generated_at_is_utc(monkeypatch) -> None:
    import json

    def fake_result(config_path: str) -> AnalysisResult:
        return AnalysisResult(
            mode="local",
            target=config_path,
            server_type="nginx",
            findings=[],
            issues=[],
        )

    monkeypatch.setattr("webconf_audit.cli.analyze_nginx_config", fake_result)

    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert "+00:00" in parsed["generated_at"] or "Z" in parsed["generated_at"]


def test_invalid_format_rejected() -> None:
    result = runner.invoke(app, ["analyze-nginx", "nginx.conf", "--format", "xml"])
    assert result.exit_code != 0


def test_cli_does_not_expose_placeholder_hello_command() -> None:
    result = runner.invoke(app, ["hello"])
    assert result.exit_code != 0
