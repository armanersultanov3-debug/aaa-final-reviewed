from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdSourceSpan,
)
from webconf_audit.local.lighttpd.rules.directive_value_utils import (
    directive_location,
)

from tests.lighttpd_helpers import Path, analyze_lighttpd_config


_BASE = (
    'server.tag = ""\n'
    'server.errorlog = "/var/log/lighttpd/error.log"\n'
    "server.max-connections = 1024\n"
    "server.max-request-size = 1024\n"
)


def _analyze(tmp_path: Path, config_text: str):
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path))


def _analyze_host(tmp_path: Path, config_text: str, *, host: str | None):
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path), host=host)


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_lighttpd_flags_unsafe_content_security_policy(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'setenv.add-response-header = ( "Content-Security-Policy" => "default-src *; script-src \'unsafe-inline\'" )\n',
    )

    assert "lighttpd.content_security_policy_unsafe" in _rule_ids(result)


def test_lighttpd_accepts_baseline_content_security_policy(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + (
            'setenv.add-response-header = ( "Content-Security-Policy" => '
            '"default-src \'self\'; frame-ancestors \'self\'; script-src \'self\'; report-uri /csp" )\n'
        ),
    )

    assert "lighttpd.content_security_policy_unsafe" not in _rule_ids(result)


def test_lighttpd_flags_unsafe_x_frame_options(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "X-Frame-Options" => "ALLOWALL" )\n',
    )

    assert "lighttpd.x_frame_options_unsafe" in _rule_ids(result)


def test_lighttpd_accepts_safe_x_frame_options(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'setenv.add-response-header = ( "X-Frame-Options" => "SAMEORIGIN" )\n',
    )

    assert "lighttpd.x_frame_options_unsafe" not in _rule_ids(result)


def test_lighttpd_flags_unlimited_max_request_size(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + "server.max-request-size = 0\n",
    )

    assert "lighttpd.max_request_size_unlimited" in _rule_ids(result)


def test_lighttpd_flags_too_large_max_request_size(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + "server.max-request-size = 204800\n",
    )

    assert "lighttpd.max_request_size_too_large" in _rule_ids(result)


def test_lighttpd_flags_too_large_request_field_size(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + "server.max-request-field-size = 131072\n",
    )

    assert "lighttpd.max_request_field_size_too_large" in _rule_ids(result)


def test_lighttpd_flags_idle_timeout_policy_outliers(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + "server.max-keep-alive-idle = 60\n"
        + "server.max-read-idle = 120\n"
        + "server.max-write-idle = 720\n"
        + "server.max-keep-alive-requests = 0\n",
    )

    assert {
        "lighttpd.max_keep_alive_idle_too_high",
        "lighttpd.max_read_idle_too_high",
        "lighttpd.max_write_idle_too_high",
        "lighttpd.max_keep_alive_requests_unlimited",
    }.issubset(_rule_ids(result))


def test_lighttpd_accepts_default_or_lower_idle_timeout_policy(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + "server.max-keep-alive-idle = 5\n"
        + "server.max-read-idle = 60\n"
        + "server.max-write-idle = 360\n"
        + "server.max-keep-alive-requests = 1000\n",
    )

    assert {
        "lighttpd.max_keep_alive_idle_too_high",
        "lighttpd.max_read_idle_too_high",
        "lighttpd.max_write_idle_too_high",
        "lighttpd.max_keep_alive_requests_unlimited",
    }.isdisjoint(_rule_ids(result))


def test_lighttpd_flags_mod_webdav_loaded(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.modules += ( "mod_webdav" )\n',
    )

    assert "lighttpd.mod_webdav_enabled" in _rule_ids(result)


def test_lighttpd_flags_webdav_write_access(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules += ( "mod_webdav" )\n'
        + 'webdav.activate = "enable"\n',
    )

    assert "lighttpd.webdav_write_access_enabled" in _rule_ids(result)


def test_lighttpd_accepts_readonly_webdav(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules += ( "mod_webdav" )\n'
        + 'webdav.activate = "enable"\n'
        + 'webdav.is-readonly = "enable"\n',
    )

    assert "lighttpd.webdav_write_access_enabled" not in _rule_ids(result)


def test_lighttpd_request_size_quality_respects_host_context(
    tmp_path: Path,
) -> None:
    config = (
        _BASE
        + '$HTTP["host"] == "upload.example.test" {\n'
        + "    server.max-request-size = 204800\n"
        + "}\n"
    )

    upload = _analyze_host(tmp_path, config, host="upload.example.test")
    other = _analyze_host(tmp_path, config, host="www.example.test")

    assert "lighttpd.max_request_size_too_large" in _rule_ids(upload)
    assert "lighttpd.max_request_size_too_large" not in _rule_ids(other)


def test_lighttpd_missing_request_limits_respect_host_conditional_values(
    tmp_path: Path,
) -> None:
    config = (
        'server.tag = ""\n'
        'server.errorlog = "/var/log/lighttpd/error.log"\n'
        + '$HTTP["host"] == "limited.example.test" {\n'
        + "    server.max-connections = 1024\n"
        + "    server.max-request-size = 1024\n"
        + "}\n"
    )

    limited = _analyze_host(tmp_path, config, host="limited.example.test")
    other = _analyze_host(tmp_path, config, host="www.example.test")
    default = _analyze(tmp_path, config)

    assert "lighttpd.max_connections_missing" not in _rule_ids(limited)
    assert "lighttpd.max_request_size_missing" not in _rule_ids(limited)
    assert "lighttpd.max_connections_missing" in _rule_ids(other)
    assert "lighttpd.max_request_size_missing" in _rule_ids(other)
    assert "lighttpd.max_connections_missing" in _rule_ids(default)
    assert "lighttpd.max_request_size_missing" in _rule_ids(default)


def test_lighttpd_directive_location_handles_missing_source_span() -> None:
    directive = LighttpdAssignmentNode(
        name="server.max-request-size",
        value="0",
        operator="=",
        source=LighttpdSourceSpan(),
    )

    location = directive_location(directive)

    assert location.file_path == "<unknown>"
    assert location.line == 0
    assert location.details == "Source location unavailable in Lighttpd AST."
