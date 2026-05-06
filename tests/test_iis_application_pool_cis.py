from tests.iis_helpers import AnalysisResult, Path, analyze_iis_config


def _assert_no_analysis_issues(result: AnalysisResult) -> None:
    assert not result.issues, f"Unexpected analysis issues: {result.issues}"


def _rule_findings(result: AnalysisResult, rule_id: str):
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def test_application_pool_identity_fires_for_explicit_unsafe_pool(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <applicationPools>
            <add name="LegacyPool">
                <processModel identityType="NetworkService" />
            </add>
            <add name="SafePool">
                <processModel identityType="ApplicationPoolIdentity" />
            </add>
        </applicationPools>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(
        result,
        "iis.application_pool_identity_not_application_pool_identity",
    )
    assert len(findings) == 1
    assert "LegacyPool" in findings[0].description
    assert "NetworkService" in findings[0].description
    assert findings[0].metadata["application_pool"] == "LegacyPool"
    assert findings[0].location is not None
    assert findings[0].location.xml_path.endswith("/applicationPools/add/processModel")


def test_application_pool_identity_uses_unsafe_defaults(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <applicationPools>
            <add name="InheritedPool" />
            <applicationPoolDefaults>
                <processModel identityType="SpecificUser" />
            </applicationPoolDefaults>
        </applicationPools>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(
        result,
        "iis.application_pool_identity_not_application_pool_identity",
    )
    assert len(findings) == 1
    assert "InheritedPool" in findings[0].description
    assert "applicationPoolDefaults" in findings[0].description
    assert findings[0].metadata["inherited_from_defaults"] is True


def test_application_pool_identity_silent_for_safe_default(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <applicationPools>
            <add name="SafePool" />
            <applicationPoolDefaults>
                <processModel identityType="ApplicationPoolIdentity" />
            </applicationPoolDefaults>
        </applicationPools>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    assert not _rule_findings(
        result,
        "iis.application_pool_identity_not_application_pool_identity",
    )


def test_sites_share_application_pool_fires_across_sites(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Site One" id="1">
                <application path="/" applicationPool="SharedPool" />
            </site>
            <site name="Site Two" id="2">
                <application path="/" applicationPool="SharedPool" />
            </site>
            <site name="Site Three" id="3">
                <application path="/" applicationPool="UniquePool" />
            </site>
        </sites>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(result, "iis.sites_share_application_pool")
    assert len(findings) == 1
    assert "SharedPool" in findings[0].description
    assert "Site One" in findings[0].description
    assert "Site Two" in findings[0].description
    assert set(findings[0].metadata["sites"]) == {"Site One", "Site Two"}


def test_sites_share_application_pool_silent_for_distinct_pools(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Site One" id="1">
                <application path="/" applicationPool="PoolOne" />
            </site>
            <site name="Site Two" id="2">
                <application path="/" applicationPool="PoolTwo" />
            </site>
        </sites>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    assert not _rule_findings(result, "iis.sites_share_application_pool")


def test_sites_share_default_application_pool_when_application_pool_absent(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.applicationHost>
        <sites>
            <site name="Site One" id="1">
                <application path="/" />
            </site>
            <site name="Site Two" id="2">
                <application path="/" />
            </site>
        </sites>
    </system.applicationHost>
</configuration>
"""
    config_path = tmp_path / "applicationHost.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(result, "iis.sites_share_application_pool")
    assert len(findings) == 1
    assert findings[0].metadata["application_pool"] == "DefaultAppPool"


def test_anonymous_auth_specific_user_fires_for_iusr(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" userName="IUSR" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(result, "iis.anonymous_auth_uses_specific_user")
    assert len(findings) == 1
    assert "IUSR" in findings[0].description
    assert findings[0].metadata["anonymous_user"] == "IUSR"


def test_anonymous_auth_specific_user_silent_for_blank_user_name(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" userName="" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    assert not _rule_findings(result, "iis.anonymous_auth_uses_specific_user")


def test_anonymous_auth_specific_user_silent_for_blank_user_name_with_password(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" userName="" password="secret" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    assert not _rule_findings(result, "iis.anonymous_auth_uses_specific_user")


def test_anonymous_auth_specific_user_fires_for_password_only_without_user_name(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="true" password="secret" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    findings = _rule_findings(result, "iis.anonymous_auth_uses_specific_user")
    assert len(findings) == 1
    assert findings[0].metadata["anonymous_user"] == "<password set with blank userName>"


def test_anonymous_auth_specific_user_silent_when_disabled(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <authentication>
                <anonymousAuthentication enabled="false" userName="IUSR" />
            </authentication>
        </security>
    </system.webServer>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path), use_tls_registry=False)

    _assert_no_analysis_issues(result)
    assert not _rule_findings(result, "iis.anonymous_auth_uses_specific_user")
