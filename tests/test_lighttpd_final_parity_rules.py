from tests.lighttpd_helpers import Path, analyze_lighttpd_config


_BASE = (
    'server.tag = ""\n'
    'server.errorlog = "/var/log/lighttpd/error.log"\n'
    "server.max-connections = 1024\n"
    "server.max-request-size = 1024\n"
)

_SAFE_HEADERS = (
    'setenv.add-response-header = ( "Content-Security-Policy" => '
    '"default-src \'self\'; frame-ancestors \'self\'; script-src \'self\'; report-uri /csp", '
    '"X-Frame-Options" => "SAMEORIGIN", '
    '"Referrer-Policy" => "strict-origin-when-cross-origin", '
    '"Permissions-Policy" => "geolocation=(), camera=()" )\n'
)

def _analyze(tmp_path: Path, config_text: str):
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(config_text, encoding="utf-8")
    return analyze_lighttpd_config(str(config_path))


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_lighttpd_flags_missing_header_policy_parity(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE)

    assert {
        "lighttpd.missing_content_security_policy",
        "lighttpd.missing_x_frame_options",
        "lighttpd.missing_referrer_policy",
        "lighttpd.missing_permissions_policy",
    }.issubset(_rule_ids(result))


def test_lighttpd_accepts_safe_header_policy_parity(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + _SAFE_HEADERS)

    assert {
        "lighttpd.missing_content_security_policy",
        "lighttpd.missing_x_frame_options",
        "lighttpd.missing_referrer_policy",
        "lighttpd.referrer_policy_unsafe",
        "lighttpd.missing_permissions_policy",
        "lighttpd.permissions_policy_unsafe",
    }.isdisjoint(_rule_ids(result))


def test_lighttpd_flags_unsafe_referrer_and_permissions_policy(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + (
            'setenv.add-response-header = ( "Referrer-Policy" => "unsafe-url", '
            '"Permissions-Policy" => "geolocation=*" )\n'
        ),
    )

    assert "lighttpd.referrer_policy_unsafe" in _rule_ids(result)
    assert "lighttpd.permissions_policy_unsafe" in _rule_ids(result)


def test_lighttpd_flags_auth_require_without_backend(tmp_path: Path) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules += ( "mod_auth" )\n'
        + 'auth.require = ( "/private" => ( "method" => "basic", "realm" => "private", "require" => "valid-user" ) )\n',
    )

    assert "lighttpd.auth_backend_missing" in _rule_ids(result)


def test_lighttpd_flags_file_auth_backend_without_userfile(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules += ( "mod_auth" )\n'
        + 'auth.backend = "htpasswd"\n'
        + 'auth.require = ( "/private" => ( "method" => "basic", "realm" => "private", "require" => "valid-user" ) )\n',
    )

    assert "lighttpd.auth_backend_userfile_missing" in _rule_ids(result)


def test_lighttpd_accepts_file_auth_backend_with_userfile(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.modules += ( "mod_auth" )\n'
        + 'auth.backend = "htpasswd"\n'
        + 'auth.backend.htpasswd.userfile = "/etc/lighttpd/.htpasswd"\n'
        + 'auth.require = ( "/private" => ( "method" => "basic", "realm" => "private", "require" => "valid-user" ) )\n',
    )

    assert {
        "lighttpd.auth_backend_missing",
        "lighttpd.auth_backend_userfile_missing",
    }.isdisjoint(_rule_ids(result))
