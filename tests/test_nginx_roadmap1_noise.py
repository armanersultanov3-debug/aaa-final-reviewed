from tests.nginx_helpers import AnalysisResult, Path, analyze_nginx_config
from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, SourceSpan
from webconf_audit.local.nginx.rules._scope_utils import (
    fragment_only_context_metadata,
)
from webconf_audit.report import ReportData, TextFormatter

_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "nginx" / "roadmap1"


_REDIRECT_NOISE_RULE_IDS = frozenset(
    {
        "nginx.missing_backup_file_deny",
        "nginx.missing_client_max_body_size",
        "nginx.missing_content_security_policy",
        "nginx.missing_hidden_files_deny",
        "nginx.missing_limit_conn",
        "nginx.missing_limit_req",
        "nginx.missing_permissions_policy",
        "nginx.missing_referrer_policy",
        "nginx.missing_x_content_type_options",
        "nginx.missing_x_frame_options",
        "nginx.missing_x_xss_protection",
    }
)


def _rule_ids_at_line(result: AnalysisResult, line: int) -> set[str]:
    return {
        finding.rule_id
        for finding in result.findings
        if finding.location is not None and finding.location.line == line
    }


def _finding_by_rule_id(result: AnalysisResult, rule_id: str):
    for finding in result.findings:
        if finding.rule_id == rule_id:
            return finding
    raise AssertionError(f"Missing expected finding {rule_id!r}")


def _server_block_from_path(file_path: str) -> BlockNode:
    return BlockNode(
        name="server",
        source=SourceSpan(file_path=file_path, line=1, column=1),
    )


def test_nginx_redirect_dominant_http_server_does_not_emit_content_noise() -> None:
    config_path = _FIXTURE_DIR / "redirect_dominant_app.conf"

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert http_server_rule_ids.isdisjoint(_REDIRECT_NOISE_RULE_IDS)
    assert "nginx.missing_http_to_https_redirect" not in http_server_rule_ids
    assert any(finding.rule_id == "nginx.autoindex_on" for finding in result.findings)
    assert any(
        finding.rule_id == "nginx.missing_content_security_policy"
        and finding.location is not None
        and finding.location.line == 16
        for finding in result.findings
    )


def test_nginx_mixed_redirect_and_content_server_still_gets_content_checks(
) -> None:
    config_path = _FIXTURE_DIR / "mixed_redirect_content.conf"

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert "nginx.missing_content_security_policy" in http_server_rule_ids
    assert "nginx.missing_hidden_files_deny" in http_server_rule_ids


def test_nginx_fragment_only_context_requires_all_top_level_servers_to_look_like_fragments(
) -> None:
    ast = ConfigAst(
        nodes=[
            _server_block_from_path(r"C:\nginx\conf\nginx.conf"),
            _server_block_from_path(r"C:\nginx\conf\conf.d\app.conf"),
        ]
    )

    assert fragment_only_context_metadata(ast) == {}


def test_nginx_named_locations_do_not_break_redirect_only_classification(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "named-location.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name named.example.test;\n"
        "    location / {\n"
        "        return 301 https://$host$request_uri;\n"
        "    }\n"
        "    location @fallback {\n"
        "        proxy_pass http://fallback-backend;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert "nginx.missing_http_to_https_redirect" not in http_server_rule_ids
    assert http_server_rule_ids.isdisjoint(_REDIRECT_NOISE_RULE_IDS)


def test_nginx_rewrite_https_redirect_counts_as_http_to_https_redirect(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "rewrite-redirect.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name rewrite.example.test;\n"
        "    rewrite ^(.*)$ https://rewrite.example.test$1 permanent;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert "nginx.missing_http_to_https_redirect" not in http_server_rule_ids
    assert http_server_rule_ids.isdisjoint(_REDIRECT_NOISE_RULE_IDS)


def test_nginx_partial_rewrite_https_redirect_does_not_cover_whole_server(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "partial-rewrite.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name partial-rewrite.example.test;\n"
        "    rewrite ^/health$ https://$host$request_uri permanent;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert "nginx.missing_http_to_https_redirect" in http_server_rule_ids
    assert "nginx.missing_content_security_policy" in http_server_rule_ids


def test_nginx_proxying_acme_location_is_not_a_safe_redirect_exception(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "unsafe-acme.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    server_name acme.example.test;\n"
        "    location / {\n"
        "        return 301 https://$host$request_uri;\n"
        "    }\n"
        "    location /.well-known/acme-challenge/ {\n"
        "        proxy_pass http://challenge-backend;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    http_server_rule_ids = _rule_ids_at_line(result, 1)
    assert "nginx.missing_http_to_https_redirect" in http_server_rule_ids
    assert "nginx.missing_content_security_policy" in http_server_rule_ids


def test_nginx_fragment_only_missing_policy_findings_are_contextual(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "app.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name files.example.test;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key key.pem;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    for rule_id in {
        "nginx.missing_access_log",
        "nginx.missing_error_log",
        "nginx.missing_keepalive_timeout",
        "nginx.missing_client_body_timeout",
        "nginx.missing_client_header_timeout",
        "nginx.missing_send_timeout",
    }:
        finding = _finding_by_rule_id(result, rule_id)
        assert finding.metadata["analysis_context"] == "fragment_only"
        assert finding.metadata["confidence"] == "contextual"
        assert "may be inherited" in finding.metadata["note"]

    text_report = TextFormatter().format(ReportData(results=[result]))
    assert "note: This directive may be inherited from the parent nginx.conf" in text_report


def test_nginx_root_config_uses_parent_context_without_fragment_notes(
    tmp_path: Path,
) -> None:
    conf_d = tmp_path / "conf.d"
    conf_d.mkdir()
    app_conf = conf_d / "app.conf"
    app_conf.write_text(
        "server {\n"
        "    listen 443 ssl;\n"
        "    server_name files.example.test;\n"
        "    ssl_certificate cert.pem;\n"
        "    ssl_certificate_key key.pem;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx_conf = tmp_path / "nginx.conf"
    nginx_conf.write_text(
        "error_log /var/log/nginx/error.log notice;\n"
        "events {}\n"
        "http {\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    keepalive_timeout 65;\n"
        "    include conf.d/app.conf;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(nginx_conf))

    assert result.issues == []
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "nginx.missing_access_log" not in rule_ids
    assert "nginx.missing_error_log" not in rule_ids
    assert "nginx.missing_keepalive_timeout" not in rule_ids
    assert all(
        finding.metadata.get("analysis_context") != "fragment_only"
        for finding in result.findings
    )
