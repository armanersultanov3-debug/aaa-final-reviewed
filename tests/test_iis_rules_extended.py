from tests.iis_helpers import (
    AnalysisResult,
    Path,
    analyze_iis_config,
)


def _assert_no_analysis_issues(result: AnalysisResult) -> None:
    assert not result.issues, f"Unexpected analysis issues: {result.issues}"


# ---------------------------------------------------------------------------
# New rules (4.5): attribute-based
# ---------------------------------------------------------------------------


def test_request_filtering_allow_high_bit_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowHighBitCharacters="true" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_allow_high_bit" in {f.rule_id for f in result.findings}


def test_request_filtering_allow_high_bit_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering allowHighBitCharacters="false" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_allow_high_bit" not in {f.rule_id for f in result.findings}


def test_request_filtering_allow_high_bit_absent_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_allow_high_bit" in {f.rule_id for f in result.findings}


def test_anonymous_auth_enabled_fires_with_other_scheme(tmp_path: Path) -> None:
    """anonymous + basic both enabled → fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" />
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.anonymous_auth_enabled" in {f.rule_id for f in result.findings}
    findings = [f for f in result.findings if f.rule_id == "iis.anonymous_auth_enabled"]
    assert len(findings) == 1
    finding = findings[0]
    assert "basic" in finding.description


def test_anonymous_auth_enabled_fires_with_default_anonymous_auth(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <windowsAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.anonymous_auth_enabled"]
    assert len(findings) == 1
    assert "by default" in findings[0].description
    assert "Windows" in findings[0].description


def test_anonymous_auth_alone_silent(tmp_path: Path) -> None:
    """anonymous only (no other scheme) → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.anonymous_auth_enabled" not in {f.rule_id for f in result.findings}


def test_anonymous_auth_disabled_silent(tmp_path: Path) -> None:
    """anonymous disabled + basic enabled → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="false" />
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.anonymous_auth_enabled" not in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_missing_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms requireSSL="false" loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.forms_auth_require_ssl_missing" in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_missing_fires_when_attribute_absent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.forms_auth_require_ssl_missing" in {f.rule_id for f in result.findings}


def test_forms_auth_require_ssl_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms requireSSL="true" loginUrl="/login" />
        </authentication>
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.forms_auth_require_ssl_missing" not in {f.rule_id for f in result.findings}


def test_session_state_cookieless_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="UseUri" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.session_state_cookieless" in {f.rule_id for f in result.findings}


def test_session_state_cookieless_true_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="true" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.session_state_cookieless" in {f.rule_id for f in result.findings}


def test_session_state_cookieless_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <sessionState cookieless="UseCookies" />
    </system.web>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.session_state_cookieless" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# New rules (4.5): children-based
# ---------------------------------------------------------------------------


def test_webdav_module_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="WebDAVModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.webdav_module_enabled"]
    assert len(findings) == 1
    finding = findings[0]
    assert "WebDAVModule" in finding.description


def test_webdav_module_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="StaticFileModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.webdav_module_enabled" not in {f.rule_id for f in result.findings}


def test_webdav_module_removed_silent(tmp_path: Path) -> None:
    """WebDAV added then removed via collection semantics → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <modules>
            <add name="WebDAVModule" />
            <remove name="WebDAVModule" />
        </modules>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.webdav_module_enabled" not in {f.rule_id for f in result.findings}


def test_cgi_handler_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="CGI-exe" path="*.exe" verb="*" modules="CgiModule" />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.cgi_handler_enabled" in {f.rule_id for f in result.findings}
    findings = [f for f in result.findings if f.rule_id == "iis.cgi_handler_enabled"]
    assert len(findings) == 1
    finding = findings[0]
    assert "CGI-exe" in finding.description


def test_cgi_handler_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add name="StaticFile" path="*" verb="*" modules="StaticFileModule" />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.cgi_handler_enabled" not in {f.rule_id for f in result.findings}


def test_cgi_handler_enabled_fires_for_combined_modules(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers>
            <add
                name="CGI-combined"
                path="*.cgi"
                verb="*"
                modules="StaticFileModule, CgiModule"
            />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.cgi_handler_enabled"]
    assert len(findings) == 1
    assert "CGI-combined" in findings[0].description


def test_handler_access_policy_write_script_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Write, Script">
            <add name="StaticFile" path="*" verb="*" modules="StaticFileModule" />
        </handlers>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)

    findings = [
        f
        for f in result.findings
        if f.rule_id == "iis.handler_write_script_execute_enabled"
    ]
    assert len(findings) == 1
    assert "Read, Write, Script" in findings[0].description


def test_handler_access_policy_write_execute_fires_for_location(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="uploads">
        <system.webServer>
            <handlers accessPolicy="Read;Write;Execute" />
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)

    findings = [
        f
        for f in result.findings
        if f.rule_id == "iis.handler_write_script_execute_enabled"
    ]
    assert len(findings) == 1
    assert "uploads" in findings[0].description


def test_handler_access_policy_numeric_flags_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="518" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)

    assert "iis.handler_write_script_execute_enabled" in {
        f.rule_id for f in result.findings
    }


def test_handler_access_policy_write_without_execution_silent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Write" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)

    assert "iis.handler_write_script_execute_enabled" not in {
        f.rule_id for f in result.findings
    }


def test_handler_access_policy_execution_without_write_silent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <handlers accessPolicy="Read, Script, Execute" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)

    assert "iis.handler_write_script_execute_enabled" not in {
        f.rule_id for f in result.findings
    }


def test_x_powered_by_present_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.custom_headers_expose_server" in {f.rule_id for f in result.findings}


def test_x_powered_by_removed_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <remove name="X-Powered-By" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


def test_x_powered_by_add_then_remove_silent(tmp_path: Path) -> None:
    """X-Powered-By added then removed → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <remove name="X-Powered-By" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


def test_location_scoped_anonymous_auth_includes_context(tmp_path: Path) -> None:
    """anonymousAuthentication + basic at a location mentions the path."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="public">
        <system.webServer>
            <security>
                <authentication>
                    <anonymousAuthentication enabled="true" />
                    <windowsAuthentication enabled="true" />
                </authentication>
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.anonymous_auth_enabled"]
    assert len(findings) == 1
    assert "public" in findings[0].description
    assert "Windows" in findings[0].description


# ---------------------------------------------------------------------------
# New rules (4.5): planned rules — SSL, TLS, HSTS, content length, logging
# ---------------------------------------------------------------------------


def test_ssl_not_required_fires_when_none(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="None" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


def test_ssl_not_required_fires_when_empty(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


def test_ssl_not_required_silent_when_ssl(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl,Ssl128" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


def test_weak_tls_fires_ssl_without_ssl128(tmp_path: Path) -> None:
    """sslFlags="Ssl" (without Ssl128) → weak_tls fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_weak_cipher_strength" in {f.rule_id for f in result.findings}
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


def test_weak_tls_uses_sslflag_tokens_not_substrings(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="SslNegotiateCert" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.ssl_weak_cipher_strength" not in rule_ids
    assert "iis.ssl_not_required" in rule_ids


def test_ssl_flags_semicolon_delimiter_is_tokenized(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl;Ssl128" />
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    rule_ids = {f.rule_id for f in result.findings}
    assert "iis.ssl_not_required" not in rule_ids
    assert "iis.ssl_weak_cipher_strength" not in rule_ids


def test_missing_hsts_header_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Content-Type-Options" value="nosniff" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.missing_hsts_header" in {f.rule_id for f in result.findings}


def test_missing_hsts_header_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security" value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.missing_hsts_header" not in {f.rule_id for f in result.findings}


def test_max_allowed_content_length_missing_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxUrl="4096" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.max_allowed_content_length_missing" in {f.rule_id for f in result.findings}


def test_max_allowed_content_length_set_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.max_allowed_content_length_missing" not in {f.rule_id for f in result.findings}


def test_logging_not_configured_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpLogging dontLog="true" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.logging_not_configured" in {f.rule_id for f in result.findings}


def test_logging_not_configured_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpLogging dontLog="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.logging_not_configured" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Absence-complete tests
# ---------------------------------------------------------------------------


def test_hsts_absence_fires_when_no_custom_headers_section(tmp_path: Path) -> None:
    """No customHeaders section at all → HSTS absence fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.missing_hsts_header" in {f.rule_id for f in result.findings}


def test_logging_absence_fires_when_no_httpLogging_section(tmp_path: Path) -> None:
    """No httpLogging section at all → logging absence fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <directoryBrowse enabled="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.logging_not_configured" in {f.rule_id for f in result.findings}


def test_hsts_absence_silent_when_hsts_present(tmp_path: Path) -> None:
    """customHeaders with HSTS → no absence finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.missing_hsts_header" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# Broadened expose_server tests
# ---------------------------------------------------------------------------


def test_expose_server_aspnetmvc_version_fires(tmp_path: Path) -> None:
    """X-AspNetMvc-Version header triggers expose_server."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-AspNetMvc-Version" value="5.2" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.custom_headers_expose_server" in {f.rule_id for f in result.findings}
    findings = [
        f for f in result.findings if f.rule_id == "iis.custom_headers_expose_server"
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert "X-AspNetMvc-Version" in finding.description


def test_expose_server_both_headers_single_finding(tmp_path: Path) -> None:
    """X-Powered-By + X-AspNetMvc-Version → one finding listing both."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <add name="X-AspNetMvc-Version" value="5.2" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.custom_headers_expose_server"]
    assert len(findings) == 1
    assert "X-Powered-By" in findings[0].description
    assert "X-AspNetMvc-Version" in findings[0].description


def test_expose_server_both_removed_silent(tmp_path: Path) -> None:
    """Both headers removed → no expose_server finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Powered-By" value="ASP.NET" />
                <remove name="X-Powered-By" />
                <add name="X-AspNetMvc-Version" value="5.2" />
                <remove name="X-AspNetMvc-Version" />
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.custom_headers_expose_server" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# ssl_not_required — binding-aware absence checks
# ---------------------------------------------------------------------------


def test_ssl_not_required_absence_fires_with_https_binding(tmp_path: Path) -> None:
    """HTTPS binding present but no /access section → fires ssl_not_required."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="https" bindingInformation="*:443:secure.example.test" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_not_required" in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# binding_without_host_header - host-header coverage
# ---------------------------------------------------------------------------


def test_binding_without_host_header_fires_for_http_and_https(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                    <binding protocol="https" bindingInformation="*:443:" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <access sslFlags="Ssl,Ssl128" />
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "applicationHost.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "applicationHost.config"))
    _assert_no_analysis_issues(result)

    findings = [
        f for f in result.findings if f.rule_id == "iis.binding_without_host_header"
    ]
    assert len(findings) == 2
    assert all(f.location is not None for f in findings)
    assert {f.location.xml_path for f in findings} == {
        "configuration/system.applicationHost/sites/site/bindings/binding"
    }
    descriptions = [f.description for f in findings]
    assert any("*:80:" in description for description in descriptions)
    assert any("*:443:" in description for description in descriptions)


def test_binding_without_host_header_silent_with_host_names(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:example.test" />
                    <binding protocol="https" bindingInformation="*:443:www.example.test" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <access sslFlags="Ssl,Ssl128" />
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "applicationHost.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "applicationHost.config"))
    _assert_no_analysis_issues(result)

    assert "iis.binding_without_host_header" not in {
        f.rule_id for f in result.findings
    }


def test_binding_without_host_header_ignores_non_http_bindings(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="net.tcp" bindingInformation="808:*" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "applicationHost.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "applicationHost.config"))
    _assert_no_analysis_issues(result)

    assert "iis.binding_without_host_header" not in {
        f.rule_id for f in result.findings
    }


def test_binding_without_host_header_fires_when_host_field_is_missing(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Default Web Site" id="1">
                <bindings>
                    <binding protocol="http" bindingInformation="*:80" />
                </bindings>
            </site>
        </sites>
    </system.applicationHost>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "applicationHost.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "applicationHost.config"))
    _assert_no_analysis_issues(result)

    findings = [
        f for f in result.findings if f.rule_id == "iis.binding_without_host_header"
    ]
    assert len(findings) == 1
    assert "*:80" in findings[0].description


def test_ssl_not_required_absence_silent_without_https_binding(tmp_path: Path) -> None:
    """No HTTPS binding and no /access section → no ssl_not_required finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.ssl_not_required" not in {f.rule_id for f in result.findings}


# ---------------------------------------------------------------------------
# max_allowed_content_length — absence and threshold checks
# ---------------------------------------------------------------------------


def test_max_content_length_absence_fires_when_no_request_limits(tmp_path: Path) -> None:
    """No requestLimits section at all → fires max_allowed_content_length_missing."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.max_allowed_content_length_missing" in {f.rule_id for f in result.findings}


def test_max_content_length_excessive_fires(tmp_path: Path) -> None:
    """maxAllowedContentLength=1073741824 (1 GB) exceeds threshold → fires."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="1073741824" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    findings = [f for f in result.findings if f.rule_id == "iis.max_allowed_content_length_missing"]
    assert len(findings) == 1
    assert "excessive" in findings[0].description.lower() or "1073741824" in findings[0].description


def test_max_content_length_reasonable_value_silent(tmp_path: Path) -> None:
    """maxAllowedContentLength=4194304 (4 MB) is reasonable → no finding."""
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="Strict-Transport-Security"
                     value="max-age=31536000" />
            </customHeaders>
        </httpProtocol>
        <httpLogging dontLog="false" />
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    (tmp_path / "web.config").write_text(config, encoding="utf-8")
    result = analyze_iis_config(str(tmp_path / "web.config"))
    _assert_no_analysis_issues(result)
    assert "iis.max_allowed_content_length_missing" not in {f.rule_id for f in result.findings}
