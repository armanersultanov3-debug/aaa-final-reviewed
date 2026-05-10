from webconf_audit.local.apache.rules.custom_log_missing import (
    find_custom_log_missing,
)
from webconf_audit.local.apache.rules.error_log_missing import (
    find_error_log_missing,
)
from tests.apache_helpers import parse_apache_config


def _parse(config_text: str):
    return parse_apache_config(config_text, file_path="httpd.conf")


def test_error_log_present_top_level_only_silent_when_vhost_has_none() -> None:
    findings = find_error_log_missing(
        _parse(
            "ErrorLog logs/error.log\n"
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_error_log_present_top_level_and_vhost_silent() -> None:
    findings = find_error_log_missing(
        _parse(
            "ErrorLog logs/error.log\n"
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "    ErrorLog logs/example-error.log\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_error_log_missing_top_level_present_in_vhost_silent() -> None:
    findings = find_error_log_missing(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "    ErrorLog logs/example-error.log\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_error_log_missing_both_finding_on_vhost() -> None:
    findings = find_error_log_missing(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.error_log_missing"
    assert finding.title == "Missing ErrorLog directive"
    assert finding.location is not None
    assert finding.location.file_path == "httpd.conf"
    assert finding.location.line == 1
    assert finding.metadata["scope_name"] == "example.test"


def test_custom_log_present_top_level_only_silent_when_vhost_has_none() -> None:
    findings = find_custom_log_missing(
        _parse(
            "CustomLog logs/access.log combined\n"
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_custom_log_present_top_level_and_vhost_silent() -> None:
    findings = find_custom_log_missing(
        _parse(
            "CustomLog logs/access.log combined\n"
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "    CustomLog logs/example-access.log combined\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_custom_log_missing_top_level_present_in_vhost_silent() -> None:
    findings = find_custom_log_missing(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "    CustomLog logs/example-access.log combined\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_custom_log_missing_both_finding_on_vhost() -> None:
    findings = find_custom_log_missing(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName example.test\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.custom_log_missing"
    assert finding.title == "Missing CustomLog directive"
    assert finding.location is not None
    assert finding.location.file_path == "httpd.conf"
    assert finding.location.line == 1
    assert finding.metadata["scope_name"] == "example.test"


def test_error_log_missing_single_server_no_vhosts_top_level_finding() -> None:
    findings = find_error_log_missing(_parse("ServerTokens Prod\n"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.error_log_missing"
    assert finding.title == "Missing ErrorLog directive"
    assert finding.location is not None
    assert finding.location.file_path == "httpd.conf"
    assert finding.location.line == 1
    assert "scope_name" not in finding.metadata


def test_custom_log_missing_single_server_no_vhosts_top_level_finding() -> None:
    findings = find_custom_log_missing(_parse("ServerTokens Prod\n"))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.custom_log_missing"
    assert finding.title == "Missing CustomLog directive"
    assert finding.location is not None
    assert finding.location.file_path == "httpd.conf"
    assert finding.location.line == 1
    assert "scope_name" not in finding.metadata
