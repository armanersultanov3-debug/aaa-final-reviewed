from tests.lighttpd_helpers import (
    AnalysisResult,
    LighttpdAssignmentNode,
    Path,
    _collect_mod_cgi,
    _parse_header_tuple,
    analyze_lighttpd_config,
    find_mod_cgi_enabled,
    parse_lighttpd_config,
)


# ---------------------------------------------------------------------------
# Helper for new rule tests
# ---------------------------------------------------------------------------

# Base config that silences pre-existing rules (server.tag blank, no dir-listing).
_BASE = 'server.tag = ""\nserver.errorlog = "/var/log/error.log"\n'


def _analyze(tmp_path: Path, config_text: str) -> AnalysisResult:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path))


def _analyze_host(
    tmp_path: Path,
    config_text: str,
    *,
    host: str | None,
) -> AnalysisResult:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path), host=host)


def _has_finding(result: AnalysisResult, rule_id: str) -> bool:
    return any(f.rule_id == rule_id for f in result.findings)


# ---------------------------------------------------------------------------
# SSL/TLS rules
# ---------------------------------------------------------------------------


def test_ssl_engine_not_enabled_fires_when_port_443_without_ssl(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.port = 443\n")
    assert _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_ssl_enabled(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.port = 443\nssl.engine = "enable"\nssl.pemfile = "/cert.pem"\n')
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_no_443(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.port = 80\n")
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_fires_when_ssl_is_only_enabled_in_unrelated_scope(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.port = 443\n'
        + '$HTTP["host"] == "example.test" {\n'
        + '    ssl.engine = "enable"\n'
        + "}\n",
    )
    assert _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_engine_not_enabled_silent_when_socket_443_scope_enables_ssl(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.port = 443\n'
        + '$SERVER["socket"] == ":443" {\n'
        + '    ssl.engine = "enable"\n'
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.ssl_engine_not_enabled")


def test_ssl_pemfile_missing_fires_when_ssl_without_pemfile(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\n')
    assert _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_silent_when_pemfile_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/cert.pem"\n')
    assert not _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_fires_when_pemfile_empty(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = ""\n')
    assert _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_ssl_pemfile_missing_silent_when_no_ssl(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert not _has_finding(result, "lighttpd.ssl_pemfile_missing")


def test_weak_ssl_cipher_list_fires_for_rc4(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "RC4-SHA:AES128"\n')
    assert _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_weak_ssl_cipher_list_silent_for_strong(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "ECDHE-ECDSA-AES256-GCM-SHA384"\n')
    assert not _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_weak_ssl_cipher_list_ignores_disabled_weak_tokens(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.cipher-list = "HIGH:!aNULL:!MD5:-DES"\n')
    assert not _has_finding(result, "lighttpd.weak_ssl_cipher_list")


def test_lighttpd_header_tuple_keeps_comma_inside_quoted_value() -> None:
    headers = _parse_header_tuple(
        '( "Content-Security-Policy" => "default-src self, report-uri /csp" )',
        LighttpdAssignmentNode(
            name="dummy",
            operator="=",
            value='""',
        ).source,
    )

    assert len(headers) == 1
    assert headers[0].name == "content-security-policy"
    assert headers[0].value == "default-src self, report-uri /csp"


def test_ssl_honor_cipher_order_fires_when_ssl_without_honor(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/c.pem"\n')
    assert _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


def test_ssl_honor_cipher_order_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'ssl.engine = "enable"\nssl.pemfile = "/c.pem"\nssl.honor-cipher-order = "enable"\n',
    )
    assert not _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


def test_ssl_honor_cipher_order_fires_when_honor_is_only_enabled_in_unrelated_scope(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + '$HTTP["host"] == "example.test" {\n'
        + '    ssl.honor-cipher-order = "enable"\n'
        + "}\n",
    )
    assert _has_finding(result, "lighttpd.ssl_honor_cipher_order_missing")


def test_ssl_protocol_policy_fires_when_ssl_enabled_without_protocol_policy(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_silent_when_min_protocol_is_modern(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2" )\n',
    )

    assert not _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_silent_when_protocol_lists_modern_versions(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "Protocol" => "TLSv1.2 TLSv1.3" )\n',
    )

    assert not _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_weak_min_protocol(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.1" )\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_invalid_min_protocol_value(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.4" )\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_min_protocol_filters_protocol_all(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2", "Protocol" => "ALL" )\n',
    )

    assert not _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_protocol_all_without_min_protocol(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "Protocol" => "ALL" )\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_invalid_protocol_value(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "Protocol" => "BOGUS" )\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_protocol_minus_sslv3_without_min_protocol(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "Protocol" => "-SSLv3" )\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_min_protocol_filters_protocol_minus_sslv3(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2", "Protocol" => "-SSLv3" )\n',
    )

    assert not _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_reports_legacy_sslv3_enabled_without_min_protocol(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.use-sslv3 = "enable"\n',
    )

    assert _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_min_protocol_filters_legacy_sslv3_flag(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'ssl.engine = "enable"\n'
        + 'ssl.pemfile = "/c.pem"\n'
        + 'ssl.honor-cipher-order = "enable"\n'
        + 'ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2" )\n'
        + 'ssl.use-sslv3 = "enable"\n',
    )

    assert not _has_finding(result, "lighttpd.ssl_protocol_policy_missing_or_weak")


def test_ssl_protocol_policy_respects_host_filtered_conditional_scope(
    tmp_path: Path,
) -> None:
    config = (
        _BASE
        + '$HTTP["host"] == "legacy.example.test" {\n'
        + '    ssl.engine = "enable"\n'
        + '    ssl.pemfile = "/c.pem"\n'
        + '    ssl.honor-cipher-order = "enable"\n'
        + '    ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.1" )\n'
        + "}\n"
        + '$HTTP["host"] == "modern.example.test" {\n'
        + '    ssl.engine = "enable"\n'
        + '    ssl.pemfile = "/c.pem"\n'
        + '    ssl.honor-cipher-order = "enable"\n'
        + '    ssl.openssl.ssl-conf-cmd = ( "MinProtocol" => "TLSv1.2" )\n'
        + "}\n"
    )

    legacy = _analyze_host(tmp_path, config, host="legacy.example.test")
    modern = _analyze_host(tmp_path, config, host="modern.example.test")

    assert _has_finding(legacy, "lighttpd.ssl_protocol_policy_missing_or_weak")
    assert not _has_finding(modern, "lighttpd.ssl_protocol_policy_missing_or_weak")


# ---------------------------------------------------------------------------
# Security headers rules
# ---------------------------------------------------------------------------


def test_missing_strict_transport_security_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.missing_strict_transport_security")


def test_missing_strict_transport_security_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=31536000" )\n',
    )
    assert not _has_finding(result, "lighttpd.missing_strict_transport_security")


def test_missing_strict_transport_security_fires_when_only_conditional_host_sets_it(
    tmp_path: Path,
) -> None:
    config = (
        _BASE
        + '$HTTP["host"] == "secure.example.test" {\n'
        + '    setenv.add-response-header = ( "Strict-Transport-Security" => "max-age=31536000" )\n'
        + "}\n"
    )

    result = _analyze(tmp_path, config)
    result_secure = _analyze_host(tmp_path, config, host="secure.example.test")
    result_other = _analyze_host(tmp_path, config, host="other.example.test")

    assert _has_finding(result, "lighttpd.missing_strict_transport_security")
    assert not _has_finding(result_secure, "lighttpd.missing_strict_transport_security")
    assert _has_finding(result_other, "lighttpd.missing_strict_transport_security")


def test_missing_x_content_type_options_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.missing_x_content_type_options")


def test_missing_x_content_type_options_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "X-Content-Type-Options" => "nosniff" )\n',
    )
    assert not _has_finding(result, "lighttpd.missing_x_content_type_options")


def test_missing_x_content_type_options_fires_when_only_conditional_host_sets_it(
    tmp_path: Path,
) -> None:
    config = (
        _BASE
        + '$HTTP["host"] == "secure.example.test" {\n'
        + '    setenv.add-response-header = ( "X-Content-Type-Options" => "nosniff" )\n'
        + "}\n"
    )

    result = _analyze(tmp_path, config)
    result_secure = _analyze_host(tmp_path, config, host="secure.example.test")
    result_other = _analyze_host(tmp_path, config, host="other.example.test")

    assert _has_finding(result, "lighttpd.missing_x_content_type_options")
    assert not _has_finding(result_secure, "lighttpd.missing_x_content_type_options")
    assert _has_finding(result_other, "lighttpd.missing_x_content_type_options")


# ---------------------------------------------------------------------------
# Access control rules
# ---------------------------------------------------------------------------


def test_url_access_deny_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.url_access_deny_missing")


def test_url_access_deny_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'url.access-deny = ( ".bak", ".inc" )\n')
    assert not _has_finding(result, "lighttpd.url_access_deny_missing")


def test_mod_status_public_fires_when_no_remoteip(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.modules = ( "mod_status" )\nstatus.status-url = "/server-status"\n',
    )
    assert _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_inside_remoteip_block(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules = ( "mod_status" )\n'
        + '$HTTP["remoteip"] == "127.0.0.1" {\n'
        + '    status.status-url = "/server-status"\n'
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_when_nested_inside_remoteip_block(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules = ( "mod_status" )\n'
        + '$HTTP["remoteip"] == "127.0.0.1" {\n'
        + '    $HTTP["host"] == "admin.example.test" {\n'
        + '        status.status-url = "/server-status"\n'
        + "    }\n"
        + "}\n",
    )
    assert not _has_finding(result, "lighttpd.mod_status_public")


def test_mod_status_public_silent_when_no_status_url(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_status" )\n')
    assert not _has_finding(result, "lighttpd.mod_status_public")


# ---------------------------------------------------------------------------
# Logging rules
# ---------------------------------------------------------------------------


def test_error_log_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, 'server.tag = ""\n')
    assert _has_finding(result, "lighttpd.error_log_missing")


def test_error_log_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)  # _BASE includes server.errorlog
    assert not _has_finding(result, "lighttpd.error_log_missing")


def test_access_log_missing_fires_when_module_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_accesslog" )\n')
    assert _has_finding(result, "lighttpd.access_log_missing")


def test_access_log_missing_silent_when_filename_set(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.modules = ( "mod_accesslog" )\naccesslog.filename = "/var/log/access.log"\n',
    )
    assert not _has_finding(result, "lighttpd.access_log_missing")


def test_access_log_missing_silent_when_module_not_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert not _has_finding(result, "lighttpd.access_log_missing")


def test_access_log_missing_respects_host_conditional_filename(tmp_path: Path) -> None:
    config = (
        _BASE
        + 'server.modules = ( "mod_accesslog" )\n'
        + '$HTTP["host"] == "logged.example.test" {\n'
        + '    accesslog.filename = "/var/log/lighttpd/access.log"\n'
        + "}\n"
    )

    result_logged = _analyze_host(tmp_path, config, host="logged.example.test")
    result_other = _analyze_host(tmp_path, config, host="other.example.test")
    result_default = _analyze_host(tmp_path, config, host=None)

    assert not _has_finding(result_logged, "lighttpd.access_log_missing")
    assert _has_finding(result_other, "lighttpd.access_log_missing")
    assert _has_finding(result_default, "lighttpd.access_log_missing")


def test_error_log_missing_respects_host_conditional_filename(tmp_path: Path) -> None:
    config = (
        'server.tag = ""\n'
        '$HTTP["host"] == "logged.example.test" {\n'
        '    server.errorlog = "/var/log/lighttpd/error.log"\n'
        "}\n"
    )

    result_logged = _analyze_host(tmp_path, config, host="logged.example.test")
    result_other = _analyze_host(tmp_path, config, host="other.example.test")
    result_default = _analyze_host(tmp_path, config, host=None)

    assert not _has_finding(result_logged, "lighttpd.error_log_missing")
    assert _has_finding(result_other, "lighttpd.error_log_missing")
    assert _has_finding(result_default, "lighttpd.error_log_missing")


# ---------------------------------------------------------------------------
# Request limits rules
# ---------------------------------------------------------------------------


def test_max_request_size_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.max_request_size_missing")


def test_max_request_size_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.max-request-size = 1048576\n")
    assert not _has_finding(result, "lighttpd.max_request_size_missing")


def test_max_connections_missing_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)
    assert _has_finding(result, "lighttpd.max_connections_missing")


def test_max_connections_missing_silent_when_set(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + "server.max-connections = 1024\n")
    assert not _has_finding(result, "lighttpd.max_connections_missing")


# ---------------------------------------------------------------------------
# Module safety rules
# ---------------------------------------------------------------------------


def test_mod_cgi_enabled_fires(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_cgi" )\n')
    assert _has_finding(result, "lighttpd.mod_cgi_enabled")


def test_mod_cgi_enabled_silent_when_not_loaded(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'server.modules = ( "mod_access" )\n')
    assert not _has_finding(result, "lighttpd.mod_cgi_enabled")


def test_mod_cgi_enabled_falls_back_to_default_location_when_module_source_is_unknown(
    monkeypatch,
) -> None:
    ast = parse_lighttpd_config(
        'server.tag = ""\n',
        file_path="lighttpd.conf",
    )
    monkeypatch.setattr(
        "webconf_audit.local.lighttpd.rules.mod_cgi_enabled.collect_modules",
        _collect_mod_cgi,
    )

    findings = find_mod_cgi_enabled(ast)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.location is not None
    assert finding.location.file_path == "lighttpd.conf"
    assert finding.location.line == 1


# ---------------------------------------------------------------------------
# Effective config integration: last-wins and conditional scope behavior
# ---------------------------------------------------------------------------


def test_dir_listing_last_wins_disable_after_enable(tmp_path: Path) -> None:
    """Enable then disable → no finding (last-wins)."""
    config = _BASE + 'dir-listing.activate = "enable"\ndir-listing.activate = "disable"\n'
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_last_wins_enable_after_disable(tmp_path: Path) -> None:
    """Disable then enable → finding (last-wins)."""
    config = _BASE + 'dir-listing.activate = "disable"\ndir-listing.activate = "enable"\n'
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_in_conditional_still_fires(tmp_path: Path) -> None:
    """Enable inside a conditional block → finding (conditional scope)."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    dir-listing.activate = "enable"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.dir_listing_enabled")


def test_dir_listing_conditional_disable_after_enable(tmp_path: Path) -> None:
    """Enable then disable inside same conditional → no finding (last-wins in scope)."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    dir-listing.activate = "enable"\n'
        + '    dir-listing.activate = "disable"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.dir_listing_enabled")


def test_server_tag_last_wins_blank_after_non_blank(tmp_path: Path) -> None:
    """Non-blank then blank → no finding (last-wins)."""
    config = (
        'server.errorlog = "/var/log/error.log"\n'
        + 'server.tag = "lighttpd"\n'
        + 'server.tag = ""\n'
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_last_wins_non_blank_after_blank(tmp_path: Path) -> None:
    """Blank then non-blank → finding (last-wins)."""
    config = (
        'server.errorlog = "/var/log/error.log"\n'
        + 'server.tag = ""\n'
        + 'server.tag = "lighttpd"\n'
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_conditional_non_blank_fires(tmp_path: Path) -> None:
    """Non-blank in conditional scope → finding even if global is blank."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    server.tag = "custom"\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert _has_finding(result, "lighttpd.server_tag_not_blank")


def test_server_tag_conditional_blank_is_silent(tmp_path: Path) -> None:
    """Blank in conditional scope → no finding from that scope."""
    config = (
        _BASE
        + '$HTTP["host"] == "example.test" {\n'
        + '    server.tag = ""\n'
        + "}\n"
    )
    result = _analyze(tmp_path, config)
    assert not _has_finding(result, "lighttpd.server_tag_not_blank")
