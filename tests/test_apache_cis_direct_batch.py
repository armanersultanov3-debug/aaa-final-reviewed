from tests.apache_helpers import Path, _safe_apache_config, analyze_apache_config
from webconf_audit.local.apache.effective import ApacheVirtualHostContext
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheDirectiveNode
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)

SAFE_TLS_VHOST_LINES = [
    "Listen 127.0.0.1:443 https",
    "<VirtualHost *:443>",
    "    ServerName secure.test",
    "    SSLEngine On",
    "    SSLCertificateFile conf/server.crt",
    "    SSLCertificateKeyFile conf/server.key",
    "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
    "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
    "    SSLHonorCipherOrder On",
    "    SSLCompression Off",
    "    SSLInsecureRenegotiation Off",
    "    SSLUseStapling On",
    "    SSLStaplingCache shmcb:logs/ssl_stapling(32768)",
    "    SSLSessionCache shmcb:logs/ssl_scache(512000)",
    "</VirtualHost>",
]
SAFE_HSTS_LINE = (
    '    Header always set Strict-Transport-Security "max-age=31536000; '
    'includeSubDomains"'
)
_APACHE_REDIRECT_NOISE_RULE_IDS = frozenset(
    {
        "apache.limit_request_body_missing_or_invalid",
        "apache.limit_request_fields_missing_or_invalid",
        "apache.missing_permissions_policy_header",
        "apache.missing_referrer_policy_header",
        "apache.missing_x_frame_options_header",
    }
)


def test_analyze_apache_config_reports_unapproved_require_method(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    Require method GET POST OPTIONS DELETE",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" in _rule_ids(findings)


def test_analyze_apache_config_reports_limitexcept_allowing_trace(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    <LimitExcept GET POST OPTIONS TRACE>",
            "        Require all denied",
            "    </LimitExcept>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" in _rule_ids(findings)


def test_analyze_apache_config_accepts_safe_method_policies(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    Require method GET HEAD POST OPTIONS",
            "    <Limit PUT DELETE PATCH>",
            "        Require all denied",
            "    </Limit>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" not in _rule_ids(findings)


def test_analyze_apache_config_does_not_flag_require_method_inside_requireany(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAny>",
            "        Require method GET POST DELETE",
            "        Require all granted",
            "    </RequireAny>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" not in _rule_ids(findings)


def test_analyze_apache_config_does_not_flag_nested_require_method_inside_requireany(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            '<Location "/api">',
            "    <RequireAny>",
            "        <IfModule mod_authz_core.c>",
            "            Require method GET POST DELETE",
            "        </IfModule>",
            "        Require all granted",
            "    </RequireAny>",
            "</Location>",
        ),
    )

    assert "apache.http_method_policy_allows_unapproved" not in _rule_ids(findings)


def test_analyze_apache_config_reports_weak_ssl_cipher_suite(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={"cipher_suite": "    SSLCipherSuite RC4-SHA"}
        ),
    )

    rule_ids = _rule_ids(findings)
    assert "apache.ssl_cipher_suite_weak" in rule_ids
    assert "universal.weak_tls_ciphers" not in rule_ids


def test_analyze_apache_config_reports_broad_all_ssl_cipher_suite(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(replacements={"cipher_suite": "    SSLCipherSuite ALL"}),
    )

    assert "apache.ssl_cipher_suite_weak" in _rule_ids(findings)


def test_analyze_apache_config_reports_cipher_suite_without_forward_secrecy(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={"cipher_suite": "    SSLCipherSuite AES256-GCM-SHA384"}
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.ssl_cipher_suite_weak"
    ]
    assert len(matching) == 1
    assert "forward secrecy" in matching[0].description


def test_analyze_apache_config_reports_cipher_suite_without_aead(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={
                "cipher_suite": "    SSLCipherSuite ECDHE-RSA-AES256-SHA384"
            }
        ),
    )

    matching = [
        finding
        for finding in findings
        if finding.rule_id == "apache.ssl_cipher_suite_weak"
    ]
    assert len(matching) == 1
    assert "AEAD" in matching[0].description


def test_analyze_apache_config_accepts_strong_ssl_cipher_suite(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config())

    assert "apache.ssl_cipher_suite_weak" not in _rule_ids(findings)


def test_analyze_apache_config_reports_missing_hsts_on_tls_virtualhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config(omit={"hsts"}))

    rule_ids = _rule_ids(findings)
    assert "apache.missing_hsts_header" in rule_ids
    assert "universal.missing_hsts" not in rule_ids


def test_analyze_apache_config_accepts_hsts_always_policy(tmp_path: Path) -> None:
    findings = _analyze_config(tmp_path, _safe_tls_config())

    rule_ids = _rule_ids(findings)
    assert "apache.missing_hsts_header" not in rule_ids
    assert "apache.hsts_header_unsafe" not in rule_ids


def test_analyze_apache_config_reports_hsts_short_max_age(tmp_path: Path) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={
                "hsts": '    Header always set Strict-Transport-Security "max-age=300"'
            }
        ),
    )

    rule_ids = _rule_ids(findings)
    assert "apache.hsts_header_unsafe" in rule_ids
    assert "apache.missing_hsts_header" not in rule_ids


def test_analyze_apache_config_reports_hsts_when_only_onsuccess(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_tls_config(
            replacements={
                "hsts": '    Header set Strict-Transport-Security "max-age=31536000"'
            }
        ),
    )

    assert "apache.missing_hsts_header" in _rule_ids(findings)


def test_analyze_apache_config_does_not_report_hsts_for_http_only(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            'Header always set Strict-Transport-Security "max-age=300"'
        ),
    )

    rule_ids = _rule_ids(findings)
    assert "apache.missing_hsts_header" not in rule_ids
    assert "apache.hsts_header_unsafe" not in rule_ids


def test_analyze_apache_config_does_not_apply_hsts_policy_to_matching_http_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _redirect_pair_config(
            '    Header always set Strict-Transport-Security "max-age=300"'
        ),
    )

    rule_ids = _rule_ids(findings)
    assert "apache.missing_hsts_header" not in rule_ids
    assert "apache.hsts_header_unsafe" not in rule_ids


def test_analyze_apache_config_reports_http_vhost_without_https_redirect(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(tmp_path, _redirect_pair_config())

    assert "apache.missing_http_to_https_redirect" in _rule_ids(findings)


def test_analyze_apache_config_matches_unnamed_default_tls_vhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
            "    SSLHonorCipherOrder On",
            SAFE_HSTS_LINE,
            "</VirtualHost>",
        ),
    )

    assert "apache.missing_http_to_https_redirect" in _rule_ids(findings)


def test_analyze_apache_config_matches_tls_wildcard_alias(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    ServerAlias *.example.test",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
            "    SSLHonorCipherOrder On",
            SAFE_HSTS_LINE,
            "</VirtualHost>",
        ),
    )

    assert "apache.missing_http_to_https_redirect" in _rule_ids(findings)


def test_analyze_apache_config_matches_default_tls_vhost_syntax(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "Listen 127.0.0.1:443 https",
            "<VirtualHost 127.0.0.1:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
            "<VirtualHost _default_:443>",
            "    SSLEngine On",
            "    SSLCertificateFile conf/server.crt",
            "    SSLCertificateKeyFile conf/server.key",
            "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
            "    SSLHonorCipherOrder On",
            SAFE_HSTS_LINE,
            "</VirtualHost>",
        ),
    )

    assert "apache.missing_http_to_https_redirect" in _rule_ids(findings)


def test_analyze_apache_config_accepts_redirect_directive_to_https(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _redirect_pair_config("    Redirect permanent / https://app.example.test/"),
    )

    assert "apache.missing_http_to_https_redirect" not in _rule_ids(findings)


def test_analyze_apache_config_accepts_rewrite_rule_to_https(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _redirect_pair_config(
            "    RewriteEngine On",
            "    RewriteRule ^ https://app.example.test%{REQUEST_URI} [R=301,L]",
        ),
    )

    assert "apache.missing_http_to_https_redirect" not in _rule_ids(findings)


def test_analyze_apache_config_accepts_rewritecond_https_off_redirect_only_vhost(
    tmp_path: Path,
) -> None:
    config = _redirect_noise_config(
        "    RewriteEngine On",
        "    RewriteCond %{HTTPS} off",
        "    RewriteRule ^ https://app.example.test%{REQUEST_URI} [R=301,L]",
    )

    findings = _analyze_config(tmp_path, config)

    http_vhost_rule_ids = _rule_ids_at_line(
        findings, _line_number(config, "<VirtualHost *:80>")
    )
    assert http_vhost_rule_ids.isdisjoint(_APACHE_REDIRECT_NOISE_RULE_IDS)
    assert "apache.missing_http_to_https_redirect" not in http_vhost_rule_ids


def test_analyze_apache_config_reports_partial_https_redirect_as_missing_full_redirect(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _redirect_pair_config(
            "    Redirect permanent /old https://app.example.test/new"
        ),
    )

    assert "apache.missing_http_to_https_redirect" in _rule_ids(findings)


def test_analyze_apache_config_does_not_emit_content_noise_for_redirect_only_vhost(
    tmp_path: Path,
) -> None:
    config = _redirect_noise_config(
        "    Redirect permanent / https://app.example.test/"
    )

    findings = _analyze_config(tmp_path, config)

    http_vhost_rule_ids = _rule_ids_at_line(
        findings, _line_number(config, "<VirtualHost *:80>")
    )
    tls_vhost_rule_ids = _rule_ids_at_line(
        findings, _line_number(config, "<VirtualHost *:443>")
    )
    assert http_vhost_rule_ids.isdisjoint(_APACHE_REDIRECT_NOISE_RULE_IDS)
    assert "apache.missing_http_to_https_redirect" not in http_vhost_rule_ids
    assert "apache.missing_x_frame_options_header" in tls_vhost_rule_ids
    assert "apache.limit_request_body_missing_or_invalid" in tls_vhost_rule_ids


def test_analyze_apache_config_treats_metadata_only_wrapper_as_redirect_neutral(
    tmp_path: Path,
) -> None:
    config = _redirect_noise_config(
        "    Redirect permanent / https://app.example.test/",
        "    <IfModule mod_rewrite.c>",
        "        RewriteEngine On",
        "    </IfModule>",
    )

    findings = _analyze_config(tmp_path, config)

    http_vhost_rule_ids = _rule_ids_at_line(
        findings, _line_number(config, "<VirtualHost *:80>")
    )
    assert http_vhost_rule_ids.isdisjoint(_APACHE_REDIRECT_NOISE_RULE_IDS)
    assert "apache.missing_http_to_https_redirect" not in http_vhost_rule_ids


def test_analyze_apache_config_keeps_content_checks_for_partial_redirect_vhost(
    tmp_path: Path,
) -> None:
    config = _redirect_noise_config(
        "    DocumentRoot /var/www/app",
        "    Redirect permanent /old https://app.example.test/new",
    )

    findings = _analyze_config(tmp_path, config)

    http_vhost_rule_ids = _rule_ids_at_line(
        findings, _line_number(config, "<VirtualHost *:80>")
    )
    assert "apache.missing_x_frame_options_header" in http_vhost_rule_ids
    assert "apache.limit_request_body_missing_or_invalid" in http_vhost_rule_ids


def test_apache_redirect_only_virtualhost_uses_listen_address_fallback() -> None:
    node = ApacheBlockNode(
        name="VirtualHost",
        args=["*:80"],
        children=[
            ApacheDirectiveNode(
                name="Redirect",
                args=["permanent", "/", "https://app.example.test/"],
            )
        ],
    )
    context = ApacheVirtualHostContext(
        server_name="app.example.test",
        server_aliases=[],
        listen_address="*:80",
        node=node,
        listen_addresses=(),
    )

    assert is_redirect_only_virtualhost(context)


def test_analyze_apache_config_ignores_http_only_virtualhost(
    tmp_path: Path,
) -> None:
    findings = _analyze_config(
        tmp_path,
        _safe_apache_config(
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
        ),
    )

    assert "apache.missing_http_to_https_redirect" not in _rule_ids(findings)


def _safe_tls_config(
    *,
    omit: set[str] | None = None,
    replacements: dict[str, str] | None = None,
) -> str:
    omitted = omit or set()
    overrides = replacements or {}
    lines = []
    for line in SAFE_TLS_VHOST_LINES:
        key = "cipher_suite" if "SSLCipherSuite" in line else None
        if key is not None and key in omitted:
            continue
        lines.append(overrides.get(key, line) if key else line)
        if line.strip() == "SSLSessionCache shmcb:logs/ssl_scache(512000)":
            if "hsts" not in omitted:
                lines.append(overrides.get("hsts", SAFE_HSTS_LINE))
    return _safe_apache_config(*lines)


def _redirect_pair_config(*http_vhost_lines: str) -> str:
    http_lines = [
        "<VirtualHost *:80>",
        "    ServerName app.example.test",
        *http_vhost_lines,
        "</VirtualHost>",
    ]
    tls_lines = [
        "Listen 127.0.0.1:443 https",
        "<VirtualHost *:443>",
        "    ServerName app.example.test",
        "    SSLEngine On",
        "    SSLCertificateFile conf/server.crt",
        "    SSLCertificateKeyFile conf/server.key",
        "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
        "    SSLHonorCipherOrder On",
        SAFE_HSTS_LINE,
        "</VirtualHost>",
    ]
    return _safe_apache_config(*(http_lines + tls_lines))


def _redirect_noise_config(*http_vhost_lines: str) -> str:
    lines = [
        "ServerSignature Off",
        "TraceEnable Off",
        "ServerTokens Prod",
        "ErrorLog logs/error_log",
        "CustomLog logs/access_log combined",
        "ErrorDocument 404 /custom404.html",
        "ErrorDocument 500 /custom500.html",
        "LogLevel notice",
        "HttpProtocolOptions Strict Require1.0",
        "Listen 127.0.0.1:80",
        "Listen 127.0.0.1:443 https",
        "",
        "<VirtualHost *:80>",
        "    ServerName app.example.test",
        *http_vhost_lines,
        "</VirtualHost>",
        "<VirtualHost *:443>",
        "    ServerName app.example.test",
        "    SSLEngine On",
        "    SSLCertificateFile conf/server.crt",
        "    SSLCertificateKeyFile conf/server.key",
        "    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        "    SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!3DES",
        "    SSLHonorCipherOrder On",
        "</VirtualHost>",
        '<FilesMatch "^\\.ht">',
        "    Require all denied",
        "</FilesMatch>",
        '<FilesMatch "\\.(bak|conf|ini|log|old|orig|save|sql|swp|tmp)$">',
        "    Require all denied",
        "</FilesMatch>",
        '<DirectoryMatch "/\\.(git|svn)(/|$)">',
        "    Require all denied",
        "</DirectoryMatch>",
        "<Directory />",
        "    AllowOverride None",
        "</Directory>",
    ]
    return "\n".join(lines)


def _analyze_config(tmp_path: Path, config: str):
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(config, encoding="utf-8")
    result = analyze_apache_config(str(config_path))
    assert result.issues == []
    return result.findings


def _rule_ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def _rule_ids_at_line(findings, line: int) -> set[str]:
    return {
        finding.rule_id
        for finding in findings
        if finding.location is not None and finding.location.line == line
    }


def _line_number(config: str, marker: str) -> int:
    for idx, line in enumerate(config.splitlines(), start=1):
        if line == marker:
            return idx
    raise AssertionError(f"Marker not found: {marker}")
