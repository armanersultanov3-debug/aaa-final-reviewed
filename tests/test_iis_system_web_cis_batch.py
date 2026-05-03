import pytest

from tests.iis_helpers import AnalysisResult, Path, analyze_iis_config


def _assert_no_analysis_issues(result: AnalysisResult) -> None:
    assert not result.issues, f"Unexpected analysis issues: {result.issues}"


def _rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_forms_auth_protection_unsafe_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms protection="None" />
        </authentication>
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.forms_auth_protection_unsafe" in _rule_ids(result)


def test_forms_auth_protection_all_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms protection="All" />
        </authentication>
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.forms_auth_protection_unsafe" not in _rule_ids(result)


def test_credentials_clear_format_and_stored_credentials_fire(
    tmp_path: Path,
) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms>
                <credentials passwordFormat="Clear">
                    <user name="alice" password="secret" />
                </credentials>
            </forms>
        </authentication>
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    rule_ids = _rule_ids(result)
    assert "iis.credentials_password_format_clear" in rule_ids
    assert "iis.credentials_stored_in_config" in rule_ids


def test_credentials_without_user_password_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication>
            <forms>
                <credentials passwordFormat="SHA1">
                    <user name="alice" />
                </credentials>
            </forms>
        </authentication>
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    rule_ids = _rule_ids(result)
    assert "iis.credentials_password_format_clear" not in rule_ids
    assert "iis.credentials_stored_in_config" not in rule_ids


def test_http_cookies_http_only_disabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpCookies httpOnlyCookies="false" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.http_cookies_http_only_disabled" in _rule_ids(result)


def test_http_cookies_http_only_true_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <httpCookies httpOnlyCookies="true" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.http_cookies_http_only_disabled" not in _rule_ids(result)


def test_deployment_retail_not_enabled_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <deployment retail="false" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.deployment_retail_not_enabled" in _rule_ids(result)


def test_deployment_retail_true_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <deployment retail="true" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.deployment_retail_not_enabled" not in _rule_ids(result)


def test_trust_level_full_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trust level="Full" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.trust_level_full" in _rule_ids(result)


def test_trust_level_medium_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <trust level="Medium" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.trust_level_full" not in _rule_ids(result)


def test_machine_key_validation_weak_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <machineKey validation="SHA1" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.machine_key_validation_weak" in _rule_ids(result)


def test_machine_key_validation_aes_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <machineKey validation="AES" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.machine_key_validation_weak" in _rule_ids(result)


def test_machine_key_validation_sha256_without_hmac_fires(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <machineKey validation="SHA256" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.machine_key_validation_weak" in _rule_ids(result)


@pytest.mark.parametrize(
    "validation",
    ["HMACSHA256", "HMACSHA384", "HMACSHA512"],
)
def test_machine_key_validation_hmac_silent(
    tmp_path: Path,
    validation: str,
) -> None:
    config = f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <machineKey validation="{validation}" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.machine_key_validation_weak" not in _rule_ids(result)


def test_machine_key_validation_absent_silent(tmp_path: Path) -> None:
    config = """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <machineKey decryption="AES" />
    </system.web>
</configuration>
"""
    config_path = tmp_path / "web.config"
    config_path.write_text(config, encoding="utf-8")

    result = analyze_iis_config(str(config_path))

    _assert_no_analysis_issues(result)
    assert "iis.machine_key_validation_weak" not in _rule_ids(result)

