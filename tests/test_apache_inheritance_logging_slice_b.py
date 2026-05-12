from webconf_audit.local.apache.rules.error_log_unsafe_destination import (
    find_error_log_unsafe_destination,
)
from webconf_audit.local.apache.rules.log_level_too_restrictive import (
    find_log_level_too_restrictive,
)
from tests.apache_helpers import parse_apache_config


def _parse(config_text: str):
    return parse_apache_config(config_text, file_path="httpd.conf")


def _location_tuple(finding):
    assert finding.location is not None
    return finding.location.file_path, finding.location.line


def _cause_key_tuple(finding):
    location = _location_tuple(finding)
    assert finding.effective_cause_key == (location[0], str(location[1]))


def test_error_log_unsafe_top_level_inherited_by_all_vhosts_one_finding() -> None:
    findings = find_error_log_unsafe_destination(
        _parse(
            "ErrorLog /dev/null\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:8080>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    _cause_key_tuple(findings[0])
    assert findings[0].metadata["scope_name"] == "global"
    assert findings[0].metadata["affected_scopes"] == [
        "alpha.test",
        "beta.test",
        "*:8080",
    ]


def test_error_log_unsafe_top_level_one_vhost_overrides_safe() -> None:
    findings = find_error_log_unsafe_destination(
        _parse(
            "ErrorLog /dev/null\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    ErrorLog logs/beta-error.log\n"
            "</VirtualHost>\n"
            "<VirtualHost *:8080>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    _cause_key_tuple(findings[0])
    assert findings[0].metadata["scope_name"] == "global"
    assert findings[0].metadata["affected_scopes"] == ["alpha.test", "*:8080"]


def test_error_log_unsafe_only_in_one_vhost() -> None:
    findings = find_error_log_unsafe_destination(
        _parse(
            "ErrorLog logs/error.log\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    ErrorLog /dev/null\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 7)
    _cause_key_tuple(findings[0])
    assert findings[0].metadata == {"scope_name": "beta.test"}


def test_error_log_unsafe_in_multiple_vhosts() -> None:
    findings = find_error_log_unsafe_destination(
        _parse(
            "ErrorLog logs/error.log\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    ErrorLog\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    ErrorLog /dev/null\n"
            "</VirtualHost>\n"
        )
    )

    assert [
        (_location_tuple(finding), finding.metadata)
        for finding in findings
    ] == [
        (("httpd.conf", 4), {"scope_name": "alpha.test"}),
        (("httpd.conf", 8), {"scope_name": "beta.test"}),
    ]
    for finding in findings:
        _cause_key_tuple(finding)


def test_error_log_safe_everywhere_no_findings() -> None:
    findings = find_error_log_unsafe_destination(
        _parse(
            "ErrorLog logs/error.log\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    ErrorLog logs/beta-error.log\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_error_log_unsafe_single_server_no_vhosts_top_level_finding() -> None:
    findings = find_error_log_unsafe_destination(_parse("ErrorLog /dev/null\n"))

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    _cause_key_tuple(findings[0])
    assert findings[0].metadata == {}


def test_log_level_too_restrictive_top_level_inherited_by_all_vhosts_one_finding() -> None:
    findings = find_log_level_too_restrictive(
        _parse(
            "LogLevel error\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:8080>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    assert findings[0].metadata["scope_name"] == "global"
    assert findings[0].metadata["affected_scopes"] == [
        "alpha.test",
        "beta.test",
        "*:8080",
    ]


def test_log_level_too_restrictive_top_level_one_vhost_overrides_safe() -> None:
    findings = find_log_level_too_restrictive(
        _parse(
            "LogLevel crit\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    LogLevel warn\n"
            "</VirtualHost>\n"
            "<VirtualHost *:8080>\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    assert findings[0].metadata["scope_name"] == "global"
    assert findings[0].metadata["affected_scopes"] == ["alpha.test", "*:8080"]


def test_log_level_too_restrictive_only_in_one_vhost() -> None:
    findings = find_log_level_too_restrictive(
        _parse(
            "LogLevel notice\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    LogLevel ssl:crit\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 7)
    assert findings[0].metadata == {"scope_name": "beta.test"}
    assert "crit" in findings[0].description


def test_log_level_too_restrictive_in_multiple_vhosts() -> None:
    findings = find_log_level_too_restrictive(
        _parse(
            "LogLevel notice\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    LogLevel alert\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    LogLevel ssl:emerg\n"
            "</VirtualHost>\n"
        )
    )

    assert [
        (_location_tuple(finding), finding.metadata)
        for finding in findings
    ] == [
        (("httpd.conf", 4), {"scope_name": "alpha.test"}),
        (("httpd.conf", 8), {"scope_name": "beta.test"}),
    ]


def test_log_level_safe_everywhere_no_findings() -> None:
    findings = find_log_level_too_restrictive(
        _parse(
            "LogLevel notice\n"
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    LogLevel warn\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_log_level_too_restrictive_single_server_no_vhosts_top_level_finding() -> None:
    findings = find_log_level_too_restrictive(_parse("LogLevel error\n"))

    assert len(findings) == 1
    assert _location_tuple(findings[0]) == ("httpd.conf", 1)
    assert findings[0].metadata == {}
