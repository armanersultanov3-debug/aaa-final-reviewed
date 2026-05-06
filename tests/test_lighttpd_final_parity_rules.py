from tests.lighttpd_helpers import Path, analyze_lighttpd_config
from webconf_audit.models import AnalysisResult


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

_FULL_ACCESS_DENY = (
    'url.access-deny = ( ".inc", ".bak", ".old", ".backup", ".orig", '
    '".save", ".swp", ".tmp", ".sql", ".conf", ".ini", ".log", ".env", '
    '".DS_Store", "Thumbs.db", "composer.json", "composer.lock", '
    '"package-lock.json", ".npmrc", ".yarnrc", ".idea", ".vscode", '
    '".git", ".svn" )\n'
)


def _analyze(tmp_path: Path, config_text: str) -> AnalysisResult:
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


def test_lighttpd_unsafe_header_policy_uses_header_location(
    tmp_path: Path,
) -> None:
    spacer = "# keep the unsafe header away from the default location\n"
    config = (
        _BASE
        + spacer
        + 'setenv.add-response-header = ( "Referrer-Policy" => "unsafe-url" )\n'
    )

    result = _analyze(tmp_path, config)
    finding = next(
        finding
        for finding in result.findings
        if finding.rule_id == "lighttpd.referrer_policy_unsafe"
    )

    assert finding.location is not None
    assert finding.location.line == 6


def test_lighttpd_flags_sensitive_path_category_gaps(tmp_path: Path) -> None:
    result = _analyze(tmp_path, _BASE + 'url.access-deny = ( ".inc" )\n')

    assert {
        "lighttpd.backup_temp_files_access_not_denied",
        "lighttpd.config_data_files_access_not_denied",
        "lighttpd.generated_artifacts_access_not_denied",
        "lighttpd.vcs_metadata_access_not_denied",
    }.issubset(_rule_ids(result))


def test_lighttpd_accepts_complete_sensitive_path_deny_policy(
    tmp_path: Path,
) -> None:
    result = _analyze(tmp_path, _BASE + _FULL_ACCESS_DENY)

    assert {
        "lighttpd.backup_temp_files_access_not_denied",
        "lighttpd.config_data_files_access_not_denied",
        "lighttpd.generated_artifacts_access_not_denied",
        "lighttpd.vcs_metadata_access_not_denied",
    }.isdisjoint(_rule_ids(result))


def test_lighttpd_flags_named_http_host_without_https_redirect(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE + 'server.name = "example.test"\n' + "server.port = 80\n",
    )

    assert "lighttpd.missing_http_to_https_redirect" in _rule_ids(result)


def test_lighttpd_accepts_named_http_host_with_https_redirect(
    tmp_path: Path,
) -> None:
    result = _analyze(
        tmp_path,
        _BASE
        + 'server.name = "example.test"\n'
        + "server.port = 80\n"
        + 'server.modules += ( "mod_redirect" )\n'
        + 'url.redirect = ( "^/(.*)$" => "https://example.test/$1" )\n',
    )

    assert "lighttpd.missing_http_to_https_redirect" not in _rule_ids(result)


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
