"""Tests for the opt-in ``policy-review`` rule family.

Covers:

1. The runtime contract: ``policy-review`` tagged rules are EXCLUDED
   from default analyzer runs and INCLUDED only when
   ``enable_policy_review=True`` is passed through the runner /
   ``analyze_*_config`` API.
2. The rule registry honours the same ``OPT_IN_TAGS`` filter for
   ``rules_for(...)``.
3. Each of the ten shipped policy-review rules surfaces a finding on a
   matching configuration and stays silent on a non-matching one when
   policy review IS enabled.

The CLI flag itself is wired in
``src/webconf_audit/cli/__init__.py`` and re-uses the same code path
that these tests exercise; see ``tests/test_cli.py`` for the CLI
surface coverage of related opt-in flags.
"""

from __future__ import annotations

from pathlib import Path

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.rule_registry import OPT_IN_TAGS, registry


POLICY_REVIEW_RULE_IDS = {
    "nginx.access_log_uses_default_format",
    "nginx.limit_req_zone_rate_review",
    "nginx.limit_conn_zone_review",
    "nginx.csp_value_review",
    "nginx.http3_alt_svc_review",
    "apache.custom_log_uses_default_format",
    "apache.csp_value_review",
    "apache.limit_request_body_value_review",
    "lighttpd.access_log_format_review",
    "iis.logging_fields_review",
}


# ---------------------------------------------------------------------------
# Registry-level contract
# ---------------------------------------------------------------------------


def test_opt_in_tags_constant_contains_policy_review() -> None:
    """policy-review must be a registered opt-in tag."""
    assert "policy-review" in OPT_IN_TAGS


def test_every_shipped_policy_review_rule_carries_the_tag() -> None:
    """Each rule listed above must carry tag=policy-review, and the
    registry must not contain any unexpected policy-review rules.

    The bidirectional check pins the contract: adding a new policy-review
    rule without updating ``POLICY_REVIEW_RULE_IDS`` (and the docs that
    enumerate the opt-in set) will fail this test instead of silently
    expanding what the ``--enable-policy-review`` flag activates.
    """
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")

    for rule_id in POLICY_REVIEW_RULE_IDS:
        meta = registry.get_meta(rule_id)
        assert meta is not None, f"Rule {rule_id} not registered"
        assert "policy-review" in meta.tags, (
            f"Rule {rule_id} missing the policy-review tag"
        )
        assert meta.severity == "info", (
            f"Rule {rule_id} must be severity=info (was {meta.severity})"
        )

    tagged_rule_ids = {
        meta.rule_id
        for meta in registry.list_rules()
        if "policy-review" in meta.tags
    }
    assert tagged_rule_ids == POLICY_REVIEW_RULE_IDS, (
        "Mismatch between policy-review-tagged rules and POLICY_REVIEW_RULE_IDS. "
        f"Extra in registry: {sorted(tagged_rule_ids - POLICY_REVIEW_RULE_IDS)!r}. "
        f"Missing from registry: {sorted(POLICY_REVIEW_RULE_IDS - tagged_rule_ids)!r}."
    )

    http3_meta = registry.get_meta("nginx.http3_alt_svc_review")
    assert http3_meta is not None
    assert http3_meta.category == "local"
    assert http3_meta.server_type == "nginx"
    assert any(
        reference.standard == "CIS"
        and reference.reference == "NGINX v3.0.0 §4.1.12"
        and reference.coverage == "partial"
        for reference in http3_meta.standards
    )


def test_rules_for_excludes_policy_review_by_default() -> None:
    """Default rules_for() must not return policy-review rules."""
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    entries = registry.rules_for("local", server_type="nginx")
    returned_ids = {entry.meta.rule_id for entry in entries}
    assert "nginx.access_log_uses_default_format" not in returned_ids
    assert "nginx.csp_value_review" not in returned_ids
    assert "nginx.http3_alt_svc_review" not in returned_ids


def test_rules_for_includes_policy_review_when_opted_in() -> None:
    """Passing include_opt_in_tags=('policy-review',) must include them."""
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    entries = registry.rules_for(
        "local", server_type="nginx", include_opt_in_tags=("policy-review",),
    )
    returned_ids = {entry.meta.rule_id for entry in entries}
    assert "nginx.access_log_uses_default_format" in returned_ids
    assert "nginx.csp_value_review" in returned_ids
    assert "nginx.http3_alt_svc_review" in returned_ids


# ---------------------------------------------------------------------------
# Default-off behaviour at the analyzer level
# ---------------------------------------------------------------------------


def test_nginx_analyzer_excludes_policy_review_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    access_log /var/log/nginx/access.log;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert not any(
        finding.rule_id == "nginx.access_log_uses_default_format"
        for finding in result.findings
    )


def test_nginx_analyzer_includes_policy_review_when_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    access_log /var/log/nginx/access.log;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)

    assert any(
        finding.rule_id == "nginx.access_log_uses_default_format"
        for finding in result.findings
    )


def test_apache_analyzer_excludes_policy_review_by_default(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'DocumentRoot "/var/www/html"\n'
        'CustomLog logs/access.log combined\n',
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert not any(
        finding.rule_id == "apache.custom_log_uses_default_format"
        for finding in result.findings
    )


def test_apache_analyzer_includes_policy_review_when_enabled(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'DocumentRoot "/var/www/html"\n'
        'CustomLog logs/access.log combined\n',
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path), enable_policy_review=True)

    assert any(
        finding.rule_id == "apache.custom_log_uses_default_format"
        for finding in result.findings
    )


# ---------------------------------------------------------------------------
# Per-rule positive / negative cases (with policy review enabled)
# ---------------------------------------------------------------------------


def _findings_for(result, rule_id: str) -> list:
    return [f for f in result.findings if f.rule_id == rule_id]


def test_nginx_access_log_default_format_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    access_log /var/log/nginx/access.log;\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert len(_findings_for(result, "nginx.access_log_uses_default_format")) == 1


def test_nginx_access_log_default_format_negative_named_format(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        '    log_format main "$time_iso8601 $remote_addr $request $status";\n'
        "    server {\n"
        "        listen 80;\n"
        "        access_log /var/log/nginx/access.log main;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.access_log_uses_default_format") == []


def test_nginx_access_log_default_format_silent_for_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n    listen 80;\n    access_log off;\n}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.access_log_uses_default_format") == []


def test_nginx_limit_req_zone_rate_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n"
        "    server { listen 80; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.limit_req_zone_rate_review")
    assert len(findings) == 1
    assert "rate=10r/s" in findings[0].title


def test_nginx_limit_req_zone_rate_review_negative(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 80; access_log off; }\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.limit_req_zone_rate_review") == []


def test_nginx_limit_conn_zone_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server { listen 80; access_log off; limit_conn addr 5; }\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.limit_conn_zone_review")
    assert len(findings) == 1
    # Title and description must surface the configured cap so the operator
    # can review the value without re-grepping the config.
    assert "cap=5" in findings[0].title
    assert "cap=5" in findings[0].description


def test_nginx_limit_conn_zone_review_notes_missing_cap(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
        "    server { listen 80; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.limit_conn_zone_review")
    assert len(findings) == 1
    assert "no matching limit_conn" in findings[0].title


def test_nginx_csp_value_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    access_log off;\n"
        "    add_header Content-Security-Policy \"default-src 'self'\" always;\n"
        "}\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.csp_value_review")
    assert len(findings) == 1
    assert "default-src" in findings[0].description.lower()


def test_nginx_csp_value_review_negative_when_no_csp(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 80; access_log off; }\n",
        encoding="utf-8",
    )
    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.csp_value_review") == []


def test_nginx_http3_alt_svc_review_missing_header(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic reuseport;\n"
        "    access_log off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing" in findings[0].description.lower()
    assert findings[0].location.line == 2


def test_nginx_http3_alt_svc_review_reports_configured_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic reuseport;\n"
        "    access_log off;\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert 'h3=":443"' in findings[0].description
    assert "ma=86400" in findings[0].description
    assert "line 4" in findings[0].description


def test_nginx_http3_alt_svc_review_reports_effective_http3_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    http3 off;\n"
        "    server { listen 443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "http3 off" in findings[0].description.lower()


def test_nginx_http3_alt_svc_review_uses_inherited_alt_svc(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600' always;\n"
        "    server { listen 443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "ma=3600" in findings[0].description


def test_nginx_http3_alt_svc_review_reports_location_alt_svc(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    access_log off;\n"
        "    location / {\n"
        "        add_header Alt-Svc 'h3=\":443\"; ma=86400';\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert 'h3=":443"' in findings[0].description
    assert "location /" in findings[0].description
    assert "missing from all reviewed" not in findings[0].description


def test_nginx_http3_alt_svc_review_reports_if_in_location_alt_svc(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    access_log off;\n"
        "    location / {\n"
        "        if ($request_method = GET) {\n"
        "            add_header Alt-Svc 'h3=\":443\"; ma=86400';\n"
        "        }\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "location / > if" in findings[0].description
    assert "ma=86400" in findings[0].description


def test_nginx_http3_alt_svc_review_treats_empty_value_as_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    access_log off;\n"
        '    add_header Alt-Svc "";\n'
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing from all reviewed" in findings[0].description
    assert "effective Alt-Svc observations" not in findings[0].description


def test_nginx_http3_alt_svc_review_keeps_literal_always_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "events {}\n"
        "http {\n"
        "  server {\n"
        "    listen 443 quic;\n"
        "    add_header Alt-Svc always;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(config_path, enable_policy_review=True)

    findings = _findings_for(result, "nginx.http3_alt_svc_review")
    assert len(findings) == 1
    assert "effective Alt-Svc observations: always" in findings[0].description
    assert "effective Alt-Svc header is missing" not in findings[0].description


def test_nginx_http3_alt_svc_review_respects_add_header_replacement(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600' always;\n"
        "    server {\n"
        "        listen 443 quic;\n"
        "        access_log off;\n"
        "        add_header X-Content-Type-Options nosniff;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing" in findings[0].description.lower()


def test_nginx_http3_alt_svc_review_respects_add_header_inherit_merge(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600';\n"
        "    add_header_inherit merge;\n"
        "    server {\n"
        "        listen 443 quic;\n"
        "        access_log off;\n"
        "        add_header X-Content-Type-Options nosniff;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "ma=3600" in findings[0].description


def test_nginx_http3_alt_svc_review_respects_add_header_inherit_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600';\n"
        "    server {\n"
        "        listen 443 quic;\n"
        "        access_log off;\n"
        "        add_header_inherit off;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing from all reviewed" in findings[0].description
    assert "ma=3600" not in findings[0].description


def test_nginx_http3_alt_svc_review_reports_all_alt_svc_values(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    access_log off;\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600';\n"
        "    add_header Alt-Svc 'h3-29=\":443\"; ma=60';\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert 'h3=":443"; ma=3600' in findings[0].description
    assert 'h3-29=":443"; ma=60' in findings[0].description


def test_nginx_http3_alt_svc_review_reports_included_header_source(
    tmp_path: Path,
) -> None:
    included_path = tmp_path / "headers.conf"
    included_path.write_text(
        "add_header Alt-Svc 'h3=\":443\"; ma=3600';\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    include headers.conf;\n"
        "    server { listen 443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert str(included_path) in findings[0].description
    assert "line 1" in findings[0].description


def test_nginx_http3_alt_svc_review_ignores_regular_tls_listener(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 443 ssl; access_log off; }\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.http3_alt_svc_review") == []


def test_nginx_http3_alt_svc_review_is_default_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 443 quic; access_log off; }\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))
    assert _findings_for(result, "nginx.http3_alt_svc_review") == []


def test_nginx_http3_alt_svc_review_deduplicates_server_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    listen [::]:443 quic;\n"
        "    access_log off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert len(_findings_for(result, "nginx.http3_alt_svc_review")) == 1


def test_nginx_http3_alt_svc_review_keeps_server_locations_separate(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server { listen 443 quic; access_log off; }\n"
        "    server { listen 8443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 2
    assert {finding.location.line for finding in findings} == {2, 3}


def test_apache_custom_log_default_format_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'CustomLog logs/access.log combined\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    assert len(_findings_for(result, "apache.custom_log_uses_default_format")) == 1


def test_apache_custom_log_default_format_negative_named_format(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'LogFormat "%h %t \\"%r\\" %>s %b %{User-Agent}i" auditfmt\n'
        'CustomLog logs/access.log auditfmt\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "apache.custom_log_uses_default_format") == []


def test_apache_csp_value_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'Header always set Content-Security-Policy "default-src \'self\'"\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "apache.csp_value_review")
    assert len(findings) == 1


def test_apache_csp_value_review_negative_when_no_csp(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'Header always set X-Frame-Options DENY\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "apache.csp_value_review") == []


def test_apache_limit_request_body_value_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n'
        'LimitRequestBody 102400\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "apache.limit_request_body_value_review")
    assert len(findings) == 1
    assert "102400" in findings[0].title


def test_apache_limit_request_body_value_review_negative(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        'ServerName example.com\n',
        encoding="utf-8",
    )
    result = analyze_apache_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "apache.limit_request_body_value_review") == []


def test_lighttpd_access_log_format_review_positive_with_explicit_format(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ( "mod_accesslog" )\n'
        'accesslog.filename = "/var/log/lighttpd/access.log"\n'
        'accesslog.format = "%h %V %u %t \\"%r\\" %>s %b"\n',
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "lighttpd.access_log_format_review")
    assert len(findings) == 1


def test_lighttpd_access_log_format_review_positive_implicit_default(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.modules = ( "mod_accesslog" )\n'
        'accesslog.filename = "/var/log/lighttpd/access.log"\n',
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "lighttpd.access_log_format_review")
    assert len(findings) == 1
    assert "default" in findings[0].title.lower()


def test_lighttpd_access_log_format_review_negative_when_module_missing(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        'server.document-root = "/var/www"\n',
        encoding="utf-8",
    )
    result = analyze_lighttpd_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "lighttpd.access_log_format_review") == []


def test_iis_logging_fields_review_positive(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        "<?xml version='1.0'?>\n"
        "<configuration>\n"
        "  <system.webServer>\n"
        "    <httpLogging dontLog=\"false\" />\n"
        "  </system.webServer>\n"
        "</configuration>\n",
        encoding="utf-8",
    )
    result = analyze_iis_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "iis.logging_fields_review")
    assert len(findings) == 1


def test_iis_logging_fields_review_negative_when_logging_disabled(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        "<?xml version='1.0'?>\n"
        "<configuration>\n"
        "  <system.webServer>\n"
        "    <httpLogging dontLog=\"true\" />\n"
        "  </system.webServer>\n"
        "</configuration>\n",
        encoding="utf-8",
    )
    result = analyze_iis_config(str(config_path), enable_policy_review=True)
    # Disabled logging is reported by iis.logging_not_configured (medium),
    # not by the policy-review rule. The review rule stays silent so it
    # does not double-surface the same configuration state.
    assert _findings_for(result, "iis.logging_fields_review") == []


def test_iis_logging_fields_review_default_off(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        "<?xml version='1.0'?>\n"
        "<configuration>\n"
        "  <system.webServer>\n"
        "    <httpLogging dontLog=\"false\" />\n"
        "  </system.webServer>\n"
        "</configuration>\n",
        encoding="utf-8",
    )
    result = analyze_iis_config(str(config_path))
    assert _findings_for(result, "iis.logging_fields_review") == []
