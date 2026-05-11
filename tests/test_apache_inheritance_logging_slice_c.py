from webconf_audit.local.apache.rules.log_format_missing_fields import (
    find_log_format_missing_fields,
)
from webconf_audit.local.apache.rules.missing_log_format import (
    find_missing_log_format,
)
from tests.apache_helpers import parse_apache_config


_COMPLETE_FORMAT = (
    "%a %u %t %r %>s %b %{Referer}i %{User-Agent}i "
    "%{X-Request-ID}i %{X-Forwarded-For}i %D"
)
_INCOMPLETE_FORMAT = "%h %t %r %>s"


def _parse(config_text: str):
    return parse_apache_config(config_text, file_path="httpd.conf")


def _location_tuple(finding):
    assert finding.location is not None
    return finding.location.file_path, finding.location.line


def test_vhost_inherits_top_level_default_format_silent() -> None:
    findings = find_missing_log_format(
        _parse(
            f'LogFormat "{_COMPLETE_FORMAT}"\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    CustomLog logs/alpha-access.log\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_vhost_overrides_default_format_silent() -> None:
    findings = find_missing_log_format(
        _parse(
            f'LogFormat "{_INCOMPLETE_FORMAT}"\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    LogFormat "{_COMPLETE_FORMAT}"\n'
            "    CustomLog logs/alpha-access.log\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_vhost_customlog_references_undefined_named_format_finding() -> None:
    findings = find_missing_log_format(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.missing_log_format"
    assert _location_tuple(finding) == ("httpd.conf", 3)
    assert finding.metadata == {
        "scope_name": "alpha.test",
        "format_name": "audit",
    }


def test_vhost_customlog_inline_format_silent() -> None:
    findings = find_missing_log_format(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    CustomLog logs/alpha-access.log "{_COMPLETE_FORMAT}"\n'
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_top_level_only_no_vhost_no_logformat_finding() -> None:
    findings = find_missing_log_format(
        _parse("CustomLog logs/access.log audit\n")
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "apache.missing_log_format"
    assert _location_tuple(finding) == ("httpd.conf", 1)
    assert "scope_name" not in finding.metadata
    assert finding.metadata["format_name"] == "audit"


def test_top_level_logformat_then_vhost_redefines_same_name_uses_vhost_definition() -> None:
    missing_log_format_findings = find_missing_log_format(
        _parse(
            f'LogFormat "{_COMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
        )
    )
    missing_fields_findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_COMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert missing_log_format_findings == []
    assert len(missing_fields_findings) == 1
    finding = missing_fields_findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 5)
    assert finding.metadata == {
        "scope_name": "alpha.test",
        "format_name": "audit",
    }


def test_required_fields_present_in_top_level_used_by_vhost_silent() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_COMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_required_fields_missing_in_top_level_finding_for_each_vhost() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    CustomLog logs/beta-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert [
        (_location_tuple(finding), finding.metadata)
        for finding in findings
    ] == [
        (
            ("httpd.conf", 4),
            {"scope_name": "alpha.test", "format_name": "audit"},
        ),
        (
            ("httpd.conf", 8),
            {"scope_name": "beta.test", "format_name": "audit"},
        ),
    ]


def test_vhost_overrides_format_with_complete_fields_silent() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    LogFormat "{_COMPLETE_FORMAT}" audit\n'
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert findings == []


def test_vhost_overrides_format_with_incomplete_fields_finding_only_for_that_vhost() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_COMPLETE_FORMAT}" audit\n'
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "    CustomLog logs/alpha-access.log audit\n"
            "</VirtualHost>\n"
            "<VirtualHost *:80>\n"
            "    ServerName beta.test\n"
            "    CustomLog logs/beta-access.log audit\n"
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 5)
    assert finding.metadata == {
        "scope_name": "alpha.test",
        "format_name": "audit",
    }


def test_inline_format_in_customlog_evaluated_directly() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            "<VirtualHost *:80>\n"
            "    ServerName alpha.test\n"
            f'    CustomLog logs/alpha-access.log "{_INCOMPLETE_FORMAT}"\n'
            "</VirtualHost>\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 3)
    assert finding.metadata == {
        "scope_name": "alpha.test",
        "format_name": "<inline>",
    }


def test_single_server_no_vhost_evaluates_top_level() -> None:
    findings = find_log_format_missing_fields(
        _parse(
            f'LogFormat "{_INCOMPLETE_FORMAT}" audit\n'
            "CustomLog logs/access.log audit\n"
        )
    )

    assert len(findings) == 1
    finding = findings[0]
    assert _location_tuple(finding) == ("httpd.conf", 2)
    assert "scope_name" not in finding.metadata
    assert finding.metadata["format_name"] == "audit"
