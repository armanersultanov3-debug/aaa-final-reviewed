from tests.iis_helpers import AnalysisResult, Path, analyze_iis_config


def _assert_no_analysis_issues(result: AnalysisResult) -> None:
    assert not result.issues, f"Unexpected analysis issues: {result.issues}"


def _rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_authorization_allows_all_users_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Allow" users="*" />
            </authorization>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "iis.authorization_allows_anonymous_users"
    ]
    assert len(findings) == 1
    assert "users: *" in findings[0].description


def test_authorization_denies_anonymous_users_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
                <add accessType="Allow" users="CONTOSO\\Alice" />
            </authorization>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.authorization_allows_anonymous_users" not in _rule_ids(result)


def test_authorization_allows_all_after_anonymous_deny_silent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
                <add accessType="Allow" users="*" />
            </authorization>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.authorization_allows_anonymous_users" not in _rule_ids(result)


def test_basic_auth_without_ssl_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="None" />
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.basic_auth_without_ssl" in _rule_ids(result)


def test_basic_auth_with_ssl_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl,Ssl128" />
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.basic_auth_without_ssl" not in _rule_ids(result)


def test_inherited_basic_auth_with_location_ssl_override_fires(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl,Ssl128" />
            <authentication>
                <basicAuthentication enabled="true" />
            </authentication>
        </security>
    </system.webServer>
    <location path="private">
        <system.webServer>
            <security>
                <access sslFlags="None" />
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "iis.basic_auth_without_ssl"
    ]
    assert len(findings) == 1
    assert "private" in findings[0].description


def test_request_filtering_max_url_too_high_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" maxUrl="8192" maxQueryString="2048" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_max_url_too_high" in _rule_ids(result)


def test_request_filtering_max_query_string_invalid_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" maxUrl="4096" maxQueryString="unbounded" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_max_query_string_too_high" in _rule_ids(result)


def test_request_filtering_length_limits_safe_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" maxUrl="4096" maxQueryString="2048" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    rule_ids = _rule_ids(result)
    assert "iis.request_filtering_max_url_too_high" not in rule_ids
    assert "iis.request_filtering_max_query_string_too_high" not in rule_ids


def test_file_extensions_allow_unlisted_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <fileExtensions allowUnlisted="true" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.file_extensions_allow_unlisted" in _rule_ids(result)


def test_file_extensions_allow_unlisted_false_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <fileExtensions allowUnlisted="false" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.file_extensions_allow_unlisted" not in _rule_ids(result)


def test_isapi_cgi_restrictions_allow_unlisted_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <isapiCgiRestriction
                notListedIsapisAllowed="true"
                notListedCgisAllowed="true"
            />
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "iis.isapi_cgi_restrictions_allow_unlisted"
    ]
    assert len(findings) == 1
    assert "notListedIsapisAllowed" in findings[0].description
    assert "notListedCgisAllowed" in findings[0].description


def test_isapi_cgi_restrictions_allow_unlisted_false_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <isapiCgiRestriction
                notListedIsapisAllowed="false"
                notListedCgisAllowed="false"
            />
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.isapi_cgi_restrictions_allow_unlisted" not in _rule_ids(result)
