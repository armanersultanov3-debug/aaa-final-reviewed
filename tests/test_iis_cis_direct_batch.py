from tests.iis_helpers import AnalysisResult, Path, analyze_iis_config, parse_iis_config
from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection
from webconf_audit.local.iis.parser import IISChildElement, IISConfigDocument, IISSourceRef
from webconf_audit.local.iis.rules.auth_policy import find_authorization_policy_missing
from webconf_audit.local.iis.rules.request_filtering_policy import (
    find_request_filtering_max_query_string_missing,
    find_request_filtering_max_url_missing,
    find_request_filtering_remove_server_header_disabled,
)


def _assert_no_analysis_issues(result: AnalysisResult) -> None:
    assert not result.issues, f"Unexpected analysis issues: {result.issues}"


def _rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def _effective_section(
    *,
    tag: str,
    suffix: str,
    location_path: str | None,
    source_path: str,
    xml_path: str,
    children: list[IISChildElement] | None = None,
) -> IISEffectiveSection:
    return IISEffectiveSection(
        tag=tag,
        section_path_suffix=suffix,
        attributes={},
        children=children or [],
        location_path=location_path,
        origin_chain=[IISSourceRef(file_path=source_path, xml_path=xml_path)],
    )


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
    assert "iis.authorization_policy_missing" not in _rule_ids(result)


def test_authorization_policy_missing_fires_when_no_authorization_section(
    tmp_path: Path,
) -> None:
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
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.authorization_policy_missing" in _rule_ids(result)


def test_authorization_policy_missing_fires_when_rules_are_empty(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <clear />
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
        if finding.rule_id == "iis.authorization_policy_missing"
    ]
    assert len(findings) == 1
    assert "authorization" in (findings[0].location.xml_path or "")


def test_authorization_policy_missing_is_scoped_per_location(
    tmp_path: Path,
) -> None:
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
    <location path="admin">
        <system.webServer>
            <security>
                <authorization>
                    <add accessType="Deny" users="?" />
                </authorization>
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
        if finding.rule_id == "iis.authorization_policy_missing"
    ]
    assert len(findings) == 1
    assert "location" not in (findings[0].location.xml_path or "")


def test_authorization_policy_uses_iis_url_authorization_when_aspnet_exists(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
            </authorization>
        </security>
    </system.webServer>
    <system.web>
        <authorization>
            <allow users="*" />
        </authorization>
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.authorization_policy_missing" not in _rule_ids(result)


def test_raw_authorization_policy_empty_finding_is_deduplicated_for_locations() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <clear />
            </authorization>
        </security>
    </system.webServer>
    <location path="admin">
        <system.webServer>
            <security>
                <requestFiltering />
            </security>
        </system.webServer>
    </location>
    <location path="admin/reports">
        <system.webServer>
            <security>
                <requestFiltering />
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="web.config",
    )

    findings = find_authorization_policy_missing(doc)

    assert [finding.rule_id for finding in findings] == [
        "iis.authorization_policy_missing",
    ]
    assert "authorization" in (findings[0].location.xml_path or "")


def test_authorization_policy_remove_only_location_keeps_parent_explicit_rules(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
            </authorization>
        </security>
    </system.webServer>
    <location path="admin">
        <system.webServer>
            <security>
                <authorization>
                    <remove users="CONTOSO\\LegacyUser" />
                </authorization>
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))
    raw_findings = find_authorization_policy_missing(
        parse_iis_config(config, file_path="web.config"),
    )

    _assert_no_analysis_issues(result)
    assert "iis.authorization_policy_missing" not in _rule_ids(result)
    assert raw_findings == []


def test_authorization_policy_remove_only_location_uses_effective_parent_rules(
    tmp_path: Path,
) -> None:
    machine_config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
            </authorization>
        </security>
    </system.webServer>
</configuration>
"""
    web_config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="admin">
        <system.webServer>
            <security>
                <authorization>
                    <remove users="CONTOSO\\LegacyUser" />
                </authorization>
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    machine_path = tmp_path / "machine.config"
    web_path = tmp_path / "web.config"
    machine_path.write_text(machine_config, encoding="utf-8")
    web_path.write_text(web_config, encoding="utf-8")

    result = analyze_iis_config(str(web_path), machine_config_path=str(machine_path))

    _assert_no_analysis_issues(result)
    assert "iis.authorization_policy_missing" not in _rule_ids(result)


def test_authorization_policy_inherited_empty_parent_still_fires(
    tmp_path: Path,
) -> None:
    machine_config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <clear />
            </authorization>
        </security>
    </system.webServer>
</configuration>
"""
    web_config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <location path="admin">
        <system.webServer>
            <security>
                <requestFiltering />
            </security>
        </system.webServer>
    </location>
</configuration>
"""
    machine_path = tmp_path / "machine.config"
    web_path = tmp_path / "web.config"
    machine_path.write_text(machine_config, encoding="utf-8")
    web_path.write_text(web_config, encoding="utf-8")

    result = analyze_iis_config(str(web_path), machine_config_path=str(machine_path))

    _assert_no_analysis_issues(result)
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "iis.authorization_policy_missing"
    ]
    assert any('location path "admin"' in finding.description for finding in findings)


def test_authorization_policy_empty_inherited_section_reports_affected_scope() -> None:
    doc = IISConfigDocument(
        root_tag="configuration",
        config_kind="web",
        sections=[],
        file_path="web.config",
    )
    authorization = _effective_section(
        tag="authorization",
        suffix="/authorization",
        location_path=None,
        source_path="machine.config",
        xml_path="configuration/system.webServer/security/authorization",
        children=[IISChildElement(tag="clear")],
    )
    system_webserver = _effective_section(
        tag="system.webServer",
        suffix="/system.webServer",
        location_path="admin",
        source_path="web.config",
        xml_path='configuration/location[@path="admin"]/system.webServer',
    )
    effective_config = IISEffectiveConfig(
        global_sections={authorization.section_path_suffix: authorization},
        location_sections={
            "admin": {system_webserver.section_path_suffix: system_webserver},
        },
    )

    findings = find_authorization_policy_missing(doc, effective_config=effective_config)

    assert [finding.rule_id for finding in findings] == [
        "iis.authorization_policy_missing",
    ]
    assert 'location path "admin"' in findings[0].description


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


def test_authorization_allows_anonymous_after_anonymous_deny_silent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authorization>
                <add accessType="Deny" users="?" />
                <add accessType="Allow" users="?" />
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
                <requestLimits maxAllowedContentLength="4194304" maxUrl="4096 " maxQueryString=" 2048" />
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
    assert "iis.request_filtering_max_url_missing" not in rule_ids
    assert "iis.request_filtering_max_query_string_missing" not in rule_ids


def test_request_filtering_length_limits_missing_fire(tmp_path: Path) -> None:
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
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    rule_ids = _rule_ids(result)
    assert "iis.request_filtering_max_url_missing" in rule_ids
    assert "iis.request_filtering_max_query_string_missing" in rule_ids


def test_request_filtering_missing_request_limits_fires_length_limits(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering removeServerHeader="true" />
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    rule_ids = _rule_ids(result)
    assert "iis.request_filtering_max_url_missing" in rule_ids
    assert "iis.request_filtering_max_query_string_missing" in rule_ids


def test_raw_request_filtering_remove_server_header_inherits_parent_true() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering removeServerHeader="true" />
        </security>
    </system.webServer>
    <location path="admin">
        <system.webServer>
            <security>
                <requestFiltering allowHighBitCharacters="false" />
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="web.config",
    )

    findings = find_request_filtering_remove_server_header_disabled(doc)

    assert findings == []


def test_raw_request_limits_missing_checks_inherited_length_attributes() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxUrl="4096" maxQueryString="2048" />
            </requestFiltering>
        </security>
    </system.webServer>
    <location path="uploads">
        <system.webServer>
            <security>
                <requestFiltering>
                    <requestLimits maxAllowedContentLength="4194304" />
                </requestFiltering>
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="web.config",
    )

    assert find_request_filtering_max_url_missing(doc) == []
    assert find_request_filtering_max_query_string_missing(doc) == []


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


def test_request_filtering_remove_server_header_disabled_fires(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering removeServerHeader="false">
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_remove_server_header_disabled" in _rule_ids(result)


def test_request_filtering_remove_server_header_true_silent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering removeServerHeader="true">
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_remove_server_header_disabled" not in _rule_ids(result)


def test_request_filtering_remove_server_header_absent_fires(
    tmp_path: Path,
) -> None:
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
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.request_filtering_remove_server_header_disabled" in _rule_ids(result)


def test_request_filtering_remove_server_header_location_override_fires(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering removeServerHeader="true" />
        </security>
    </system.webServer>
    <location path="private">
        <system.webServer>
            <security>
                <requestFiltering removeServerHeader="false" />
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
        if finding.rule_id == "iis.request_filtering_remove_server_header_disabled"
    ]
    assert len(findings) == 1
    assert "private" in findings[0].description


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
