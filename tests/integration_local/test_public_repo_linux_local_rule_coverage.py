from __future__ import annotations

import json
import os
import subprocess
import textwrap
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest

from webconf_audit.rule_registry import registry


_ROOT = Path(__file__).resolve().parents[2]
_DEMO_ROOT = _ROOT / "demo" / "local_admin"
_DOCKER_ROOT = Path(__file__).resolve().parent / "docker_public_repo"
_PUBLIC_REPO_URL = "https://github.com/Armanyich/external-tests.git"


def _resolve_public_repo_ref() -> str:
    configured_ref = os.environ.get("WEBCONF_AUDIT_PUBLIC_REPO_REF")
    if configured_ref:
        return configured_ref
    return "master"


PUBLIC_REPO_REF = _resolve_public_repo_ref()
_PROJECT_NAME = "webconf_audit_public_repo_local_rules_it"
_READINESS_URLS: tuple[str, ...] = (
    "http://127.0.0.1:19180/",
    "http://127.0.0.1:19182/server-status",
)

_APACHE_MODULE_LINES: tuple[str, ...] = (
    'ServerRoot "/usr/local/apache2/conf"',
    "Listen 80",
    'PidFile "/tmp/httpd.pid"',
    "LoadModule mpm_event_module ../modules/mod_mpm_event.so",
    "LoadModule authn_core_module ../modules/mod_authn_core.so",
    "LoadModule authn_file_module ../modules/mod_authn_file.so",
    "LoadModule authz_core_module ../modules/mod_authz_core.so",
    "LoadModule authz_host_module ../modules/mod_authz_host.so",
    "LoadModule authz_user_module ../modules/mod_authz_user.so",
    "LoadModule auth_basic_module ../modules/mod_auth_basic.so",
    "LoadModule access_compat_module ../modules/mod_access_compat.so",
    "LoadModule log_config_module ../modules/mod_log_config.so",
    "LoadModule dir_module ../modules/mod_dir.so",
    "LoadModule alias_module ../modules/mod_alias.so",
    "LoadModule autoindex_module ../modules/mod_autoindex.so",
    "LoadModule status_module ../modules/mod_status.so",
    "LoadModule info_module ../modules/mod_info.so",
    "LoadModule cgi_module ../modules/mod_cgi.so",
    "LoadModule include_module ../modules/mod_include.so",
    "LoadModule headers_module ../modules/mod_headers.so",
    "LoadModule rewrite_module ../modules/mod_rewrite.so",
    "LoadModule unixd_module ../modules/mod_unixd.so",
    "ServerName localhost",
    "User daemon",
    "Group daemon",
    'DocumentRoot "/usr/local/apache2/htdocs"',
    r'LogFormat "%h %l %u %t \"%r\" %>s %b" common',
)


@dataclass(frozen=True)
class Scenario:
    service: str
    name: str
    config_filename: str
    config_text: str
    expected_rule_ids: frozenset[str]
    native_validation_should_pass: bool
    extra_files: tuple[tuple[str, str], ...] = ()

    def scenario_root(self) -> Path:
        return Path("/scenarios") / self.service / self.name

    def config_path(self) -> str:
        return str(self.scenario_root() / self.config_filename).replace("\\", "/")

    def analyzer_command(self) -> tuple[str, ...]:
        return (
            "webconf-audit",
            f"analyze-{self.service}",
            self.config_path(),
            "--format",
            "json",
        )

    def validation_command(self) -> tuple[str, ...]:
        config_path = self.config_path()
        if self.service == "nginx":
            return ("nginx", "-t", "-c", config_path)
        if self.service == "apache":
            return ("httpd", "-t", "-f", config_path)
        if self.service == "lighttpd":
            return ("lighttpd", "-tt", "-f", config_path)
        raise ValueError(f"Unsupported service: {self.service}")


def _run_command(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _is_full_git_sha(ref: str) -> bool:
    return len(ref) == 40 and all(
        char in "0123456789abcdefABCDEF" for char in ref
    )


def _expected_public_repo_commit() -> str:
    if _is_full_git_sha(PUBLIC_REPO_REF):
        return PUBLIC_REPO_REF.lower()

    result = _run_command("git", "ls-remote", _PUBLIC_REPO_URL, PUBLIC_REPO_REF)
    assert result.returncode == 0, result.stdout + result.stderr

    matches = [line.split(maxsplit=1) for line in result.stdout.splitlines()]
    assert matches, result.stdout + result.stderr

    peeled_tag = next(
        (commit for commit, ref_name in matches if ref_name.endswith("^{}")),
        None,
    )
    if peeled_tag:
        return peeled_tag
    return matches[0][0]


def _docker_available() -> bool:
    return _run_command("docker", "info").returncode == 0


def _require_docker() -> None:
    if not _docker_available():
        pytest.skip("Docker Engine is required for Linux local integration tests")


def _run_compose(
    *args: str,
    compose_file: Path,
) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "compose",
        "-p",
        _PROJECT_NAME,
        "-f",
        str(compose_file),
        *args,
    ]
    return _run_command(*command)


def _compose_exec(
    service: str,
    *args: str,
    compose_file: Path,
) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "compose",
        "-p",
        _PROJECT_NAME,
        "-f",
        str(compose_file),
        "exec",
        "-T",
        service,
        *args,
    ]
    return _run_command(*command)


def _wait_for_url(url: str, timeout_seconds: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: str | None = None

    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
                if response.status < 500:
                    return
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = str(exc)
        except OSError as exc:
            last_error = str(exc)
        time.sleep(0.5)

    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


def _read_url_text(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=5.0) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, body


def _nginx_http_config(*blocks: str) -> str:
    http_body = "\n".join(textwrap.indent(block.strip(), "    ") for block in blocks)
    return (
        "worker_processes 1;\n\n"
        "events {\n"
        "    worker_connections 1024;\n"
        "}\n\n"
        "http {\n"
        f"{http_body}\n"
        "}\n"
    )


def _nginx_server_block(*lines: str) -> str:
    body = "\n".join(f"    {line}" for line in lines)
    return f"server {{\n{body}\n}}"


def _apache_live_config(
    *body_lines: str,
    include_backup_restriction: bool,
) -> str:
    lines = [*_APACHE_MODULE_LINES, *body_lines]
    if include_backup_restriction:
        lines.extend(
            (
                '<FilesMatch "\\.(bak|old|swp)$">',
                "    Require all denied",
                "</FilesMatch>",
            )
        )
    return "\n".join(lines) + "\n"


def _lighttpd_config(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def _nginx_scenarios() -> tuple[Scenario, ...]:
    broad = Scenario(
        service="nginx",
        name="broad",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 80;",
                "listen 80;",
                "server_tokens on;",
                "autoindex on;",
                'auth_basic "Restricted";',
                "client_body_timeout 60s;",
                "client_header_timeout 25s;",
                "send_timeout 60s;",
                "keepalive_timeout 65s;",
                "client_max_body_size 0;",
                "large_client_header_buffers 2 1k;",
                "location /listing/ { autoindex on; }",
                "location /static/ { alias /srv/static; }",
                "location /admin/ {",
                "    allow all;",
                "    deny all;",
                "}",
                "location /upload/ { root /srv/uploads; }",
                "location / { if ($request_method = POST) { return 405; } }",
            ),
            _nginx_server_block(
                "listen 443 ssl;",
                "ssl_protocols TLSv1 TLSv1.2;",
                "ssl_session_tickets off;",
                "ssl_stapling on;",
            ),
            _nginx_server_block(
                "listen 443 ssl;",
                "ssl_protocols TLSv1.2;",
                "ssl_stapling off;",
            ),
        ),
        expected_rule_ids=frozenset(
            {
                "nginx.alias_without_trailing_slash",
                "nginx.allow_all_with_deny_all",
                "nginx.autoindex_on",
                "nginx.client_body_timeout_too_high",
                "nginx.client_header_timeout_too_high",
                "nginx.client_max_body_size_unlimited",
                "nginx.duplicate_listen",
                "nginx.executable_scripts_allowed_in_uploads",
                "nginx.if_in_location",
                "nginx.keepalive_timeout_too_high",
                "nginx.large_client_header_buffers_too_restrictive",
                "nginx.missing_allowed_methods_restriction_for_uploads",
                "nginx.missing_auth_basic_user_file",
                "nginx.missing_http_method_restrictions",
                "nginx.missing_ssl_certificate",
                "nginx.send_timeout_too_high",
                "nginx.ssl_session_cache_missing",
                "nginx.ssl_session_tickets_disabled",
                "nginx.ssl_session_timeout_missing_or_invalid",
                "nginx.ssl_stapling_disabled",
                "nginx.ssl_stapling_missing_resolver",
                "nginx.ssl_stapling_without_verify",
                "nginx.weak_ssl_protocols",
            }
        ),
        native_validation_should_pass=False,
    )
    admin_proxy = Scenario(
        service="nginx",
        name="admin_proxy",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 80;",
                "location /admin {",
                "    proxy_pass http://127.0.0.1:9000;",
                "}",
            )
        ),
        expected_rule_ids=frozenset(
            {"nginx.missing_access_restrictions_on_sensitive_locations"}
        ),
        native_validation_should_pass=True,
    )
    zones_missing = Scenario(
        service="nginx",
        name="zones_missing",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 80;",
                "limit_req zone=perip burst=10;",
                "limit_conn addr 10;",
            )
        ),
        expected_rule_ids=frozenset(
            {
                "nginx.missing_limit_conn_zone",
                "nginx.missing_limit_req_zone",
            }
        ),
        native_validation_should_pass=False,
    )
    cert_no_key = Scenario(
        service="nginx",
        name="cert_no_key",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 443 ssl;",
                "ssl_certificate cert.pem;",
                "ssl_ciphers HIGH:!aNULL:!MD5;",
            )
        ),
        expected_rule_ids=frozenset(
            {
                "nginx.missing_ssl_certificate_key",
                "nginx.missing_ssl_prefer_server_ciphers",
            }
        ),
        native_validation_should_pass=False,
    )
    log_format_missing = Scenario(
        service="nginx",
        name="log_format_missing",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 80;",
                "access_log /var/log/nginx/access.log main;",
            )
        ),
        expected_rule_ids=frozenset({"nginx.missing_log_format"}),
        native_validation_should_pass=False,
    )
    log_format_missing_fields = Scenario(
        service="nginx",
        name="log_format_missing_fields",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            'log_format weakfmt "$remote_addr";',
            _nginx_server_block(
                "listen 80;",
                "access_log /var/log/nginx/access.log weakfmt;",
            ),
        ),
        expected_rule_ids=frozenset({"nginx.log_format_missing_fields"}),
        native_validation_should_pass=True,
    )
    policy_controls = Scenario(
        service="nginx",
        name="policy_controls",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            "limit_req_zone $server_name zone=slow:10m rate=0r/s;",
            "limit_conn_zone $server_name zone=addr:10m;",
            _nginx_server_block(
                "listen 80 default_server;",
                "server_name _;",
                "error_log /dev/null crit;",
                "add_header Content-Security-Policy \"script-src 'unsafe-inline'\";",
                "add_header Referrer-Policy origin;",
                "limit_req zone=missing burst=5;",
                "limit_conn addr 0;",
                "location /api {",
                "    limit_except GET POST DELETE { deny all; }",
                "}",
            ),
            _nginx_server_block(
                "listen 80;",
                "server_name app.example.test;",
            ),
        ),
        expected_rule_ids=frozenset(
            {
                "nginx.content_security_policy_missing_reporting_endpoint",
                "nginx.content_security_policy_unsafe",
                "nginx.default_server_not_rejecting_unknown_hosts",
                "nginx.error_log_too_restrictive",
                "nginx.http_method_policy_allows_unapproved",
                "nginx.limit_conn_invalid_limit",
                "nginx.limit_conn_zone_not_per_ip",
                "nginx.limit_req_unknown_zone",
                "nginx.limit_req_zone_invalid_rate",
                "nginx.limit_req_zone_not_per_ip",
                "nginx.missing_http_to_https_redirect",
                "nginx.referrer_policy_unsafe",
            }
        ),
        native_validation_should_pass=False,
    )
    tls_intent = Scenario(
        service="nginx",
        name="tls_intent_without_config",
        config_filename="nginx.conf",
        config_text=_nginx_http_config(
            _nginx_server_block(
                "listen 443 ssl;",
            )
        ),
        expected_rule_ids=frozenset(
            {
                "nginx.missing_ssl_protocols",
                "universal.tls_intent_without_config",
            }
        ),
        native_validation_should_pass=False,
    )
    return (
        broad,
        admin_proxy,
        zones_missing,
        cert_no_key,
        log_format_missing,
        log_format_missing_fields,
        policy_controls,
        tls_intent,
    )


def _apache_scenarios() -> tuple[Scenario, ...]:
    broad = Scenario(
        service="apache",
        name="broad",
        config_filename="httpd.conf",
        config_text=_apache_live_config(
            "ServerSignature On",
            "ServerTokens Full",
            "TraceEnable On",
            '<Directory "/usr/local/apache2/htdocs">',
            "    AllowOverride All",
            "    Options Indexes Includes ExecCGI MultiViews",
            "    IndexOptions FancyIndexing ScanHTMLTitles",
            "</Directory>",
            '<Location "/server-status">',
            "    SetHandler server-status",
            "</Location>",
            include_backup_restriction=False,
        ),
        expected_rule_ids=frozenset(
            {
                "apache.allowoverride_all_in_directory",
                "apache.backup_temp_files_not_restricted",
                "apache.custom_log_missing",
                "apache.error_document_404_missing",
                "apache.error_document_500_missing",
                "apache.error_log_missing",
                "apache.index_options_fancyindexing_enabled",
                "apache.index_options_scanhtmltitles_enabled",
                "apache.limit_request_body_missing_or_invalid",
                "apache.limit_request_fields_missing_or_invalid",
                "apache.options_execcgi_enabled",
                "apache.options_includes_enabled",
                "apache.options_indexes",
                "apache.options_multiviews_enabled",
                "apache.server_signature_not_off",
                "apache.server_status_exposed",
                "apache.server_tokens_not_prod",
                "apache.trace_enable_not_off",
            }
        ),
        native_validation_should_pass=False,
    )
    server_info_and_directory = Scenario(
        service="apache",
        name="server_info_and_directory",
        config_filename="httpd.conf",
        config_text=_apache_live_config(
            "ServerSignature Off",
            "ServerTokens Prod",
            "TraceEnable Off",
            "LimitRequestBody 1048576",
            "LimitRequestFields 100",
            'ErrorLog "/proc/self/fd/2"',
            'CustomLog "/proc/self/fd/1" common',
            'ErrorDocument 404 "/custom404.html"',
            'ErrorDocument 500 "/custom500.html"',
            'DocumentRoot "/scenarios/apache/server_info_and_directory/www"',
            '<Directory "/scenarios/apache/server_info_and_directory/www">',
            "    Options -Indexes",
            "</Directory>",
            '<Location "/server-info">',
            "    SetHandler server-info",
            "</Location>",
            include_backup_restriction=True,
        ),
        expected_rule_ids=frozenset(
            {
                "apache.directory_without_allowoverride",
                "apache.server_info_exposed",
            }
        ),
        native_validation_should_pass=True,
        extra_files=(("www/index.html", "<html><body>server-info scenario</body></html>\n"),),
    )
    htaccess_bundle = Scenario(
        service="apache",
        name="htaccess_bundle",
        config_filename="httpd.conf",
        config_text=_apache_live_config(
            "ServerSignature Off",
            "ServerTokens Prod",
            "TraceEnable Off",
            "LimitRequestBody 1048576",
            "LimitRequestFields 100",
            'ErrorLog "/proc/self/fd/2"',
            'CustomLog "/proc/self/fd/1" common',
            'ErrorDocument 404 "/custom404.html"',
            'ErrorDocument 500 "/custom500.html"',
            'DocumentRoot "/scenarios/apache/htaccess_bundle/www"',
            '<Directory "/scenarios/apache/htaccess_bundle/www">',
            "    AllowOverride All",
            "</Directory>",
            include_backup_restriction=True,
        ),
        expected_rule_ids=frozenset(
            {
                "apache.allowoverride_all_in_directory",
                "apache.htaccess_auth_without_require",
                "apache.htaccess_contains_security_directive",
                "apache.htaccess_disables_security_headers",
                "apache.htaccess_enables_cgi",
                "apache.htaccess_enables_directory_listing",
                "apache.htaccess_rewrite_without_limit",
                "apache.htaccess_weakens_security",
            }
        ),
        native_validation_should_pass=True,
        extra_files=(
            ("www/index.html", "<html><body>htaccess bundle</body></html>\n"),
            (
                "www/.htaccess",
                (
                    'AuthType Basic\n'
                    'AuthName "Restricted"\n'
                    "Header unset X-Frame-Options\n"
                    "Options +Indexes +ExecCGI\n"
                    "RewriteEngine On\n"
                    "RewriteRule ^foo$ /bar [R=302,L]\n"
                ),
            ),
        ),
    )
    policy_controls = Scenario(
        service="apache",
        name="policy_controls",
        config_filename="httpd.conf",
        config_text=_apache_live_config(
            "ErrorLog /dev/null",
            "LogLevel emerg",
            "Timeout 600",
            "KeepAlive Off",
            "KeepAliveTimeout 120",
            "MaxKeepAliveRequests 10",
            "LimitRequestLine 16384",
            "LimitRequestFieldSize 32768",
            "FileETag INode MTime Size",
            'LogFormat "%h" weak',
            'CustomLog "/proc/self/fd/1" weak',
            'CustomLog "/proc/self/fd/1" ghost',
            'Header always set Content-Security-Policy "default-src \'self\'"',
            'Header always set X-Frame-Options "ALLOW-FROM https://example.test"',
            'Header always set Referrer-Policy "unsafe-url"',
            'Header always set Permissions-Policy "geolocation=*"',
            '<Location "/api">',
            "    Require all granted",
            "</Location>",
            '<Location "/admin">',
            "    <LimitExcept GET POST DELETE>",
            "        Require all denied",
            "    </LimitExcept>",
            "</Location>",
            "<VirtualHost *:80>",
            "    ServerName app.example.test",
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    ServerName app.example.test",
            "    SSLEngine On",
            "    SSLCipherSuite RC4-SHA",
            "    SSLProtocol all",
            "    SSLCompression On",
            "    SSLInsecureRenegotiation On",
            "    SSLHonorCipherOrder Off",
            "    SSLUseStapling On",
            '    Header always set Strict-Transport-Security "max-age=300"',
            "</VirtualHost>",
            "<VirtualHost *:443>",
            "    ServerName missing.example.test",
            "    SSLEngine On",
            "</VirtualHost>",
            include_backup_restriction=True,
        ),
        expected_rule_ids=frozenset(
            {
                "apache.content_security_policy_missing_reporting_endpoint",
                "apache.error_log_unsafe_destination",
                "apache.file_etag_inodes",
                "apache.hsts_header_unsafe",
                "apache.http_method_policy_allows_unapproved",
                "apache.keepalive_disabled",
                "apache.keepalive_timeout_too_high",
                "apache.limit_request_field_size_too_high",
                "apache.limit_request_line_too_high",
                "apache.log_format_missing_fields",
                "apache.log_level_too_restrictive",
                "apache.max_keepalive_requests_too_low",
                "apache.missing_hsts_header",
                "apache.missing_http_method_restrictions",
                "apache.missing_http_to_https_redirect",
                "apache.missing_log_format",
                "apache.permissions_policy_unsafe",
                "apache.referrer_policy_unsafe",
                "apache.ssl_cipher_suite_missing",
                "apache.ssl_cipher_suite_weak",
                "apache.ssl_compression_enabled",
                "apache.ssl_honor_cipher_order_not_on",
                "apache.ssl_insecure_renegotiation_enabled",
                "apache.ssl_protocol_missing_or_weak",
                "apache.ssl_session_cache_missing",
                "apache.ssl_session_cache_timeout_missing_or_invalid",
                "apache.ssl_stapling_cache_missing",
                "apache.ssl_use_stapling_not_on",
                "apache.timeout_too_high",
                "apache.x_frame_options_unsafe",
            }
        ),
        native_validation_should_pass=False,
    )
    return broad, server_info_and_directory, htaccess_bundle, policy_controls


def _lighttpd_scenarios() -> tuple[Scenario, ...]:
    broad = Scenario(
        service="lighttpd",
        name="broad",
        config_filename="lighttpd.conf",
        config_text=_lighttpd_config(
            'server.modules = ( "mod_dirlisting", "mod_status", "mod_cgi", "mod_accesslog", "mod_openssl", "mod_setenv" )',
            'server.document-root = "/var/www/localhost/htdocs"',
            "server.port = 443",
            'server.tag = "lighttpd"',
            'index-file.names = ( "index.html" )',
            'status.status-url = "/server-status"',
            'ssl.cipher-list = "RC4-SHA:AES128"',
            'setenv.add-response-header = ( "Content-Security-Policy" => "default-src \'self\'" )',
            'dir-listing.activate = "enable"',
        ),
        expected_rule_ids=frozenset(
            {
                "lighttpd.access_log_missing",
                "lighttpd.content_security_policy_missing_reporting_endpoint",
                "lighttpd.dir_listing_enabled",
                "lighttpd.error_log_missing",
                "lighttpd.max_connections_missing",
                "lighttpd.max_request_size_missing",
                "lighttpd.missing_strict_transport_security",
                "lighttpd.missing_x_content_type_options",
                "lighttpd.mod_cgi_enabled",
                "lighttpd.mod_status_public",
                "lighttpd.server_tag_not_blank",
                "lighttpd.ssl_engine_not_enabled",
                "lighttpd.url_access_deny_missing",
                "lighttpd.weak_ssl_cipher_list",
            }
        ),
        native_validation_should_pass=True,
    )
    ssl_enabled_missing_pem_and_honor = Scenario(
        service="lighttpd",
        name="ssl_enabled_missing_pem_and_honor",
        config_filename="lighttpd.conf",
        config_text=_lighttpd_config(
            'server.modules = ( "mod_openssl" )',
            'server.document-root = "/var/www/localhost/htdocs"',
            "server.port = 443",
            'server.errorlog = "/var/log/lighttpd/error.log"',
            'server.tag = ""',
            'ssl.engine = "enable"',
        ),
        expected_rule_ids=frozenset(
            {
                "lighttpd.ssl_honor_cipher_order_missing",
                "lighttpd.ssl_pemfile_missing",
                "lighttpd.ssl_protocol_policy_missing_or_weak",
            }
        ),
        native_validation_should_pass=False,
    )
    return broad, ssl_enabled_missing_pem_and_honor


def _all_scenarios() -> tuple[Scenario, ...]:
    return (*_nginx_scenarios(), *_apache_scenarios(), *_lighttpd_scenarios())


def _write_scenarios(root: Path, scenarios: tuple[Scenario, ...]) -> None:
    for scenario in scenarios:
        scenario_dir = root / scenario.service / scenario.name
        scenario_dir.mkdir(parents=True, exist_ok=True)
        (scenario_dir / scenario.config_filename).write_text(
            scenario.config_text,
            encoding="utf-8",
        )
        for relative_path, content in scenario.extra_files:
            target = scenario_dir / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")


def _compose_file_text(scenarios_root: Path, public_repo_commit: str) -> str:
    return (
        textwrap.dedent(
            f"""
            services:
              nginx:
                build:
                  context: "{(_DOCKER_ROOT / 'nginx').as_posix()}"
                  args:
                    PUBLIC_REPO_URL: "{_PUBLIC_REPO_URL}"
                    PUBLIC_REPO_REF: "{public_repo_commit}"
                    PUBLIC_REPO_CACHE_KEY: "{public_repo_commit}"
                image: webconf-audit-public-repo-nginx-it
                container_name: webconf-audit-public-repo-nginx-it
                ports:
                  - "19180:80"
                volumes:
                  - "{(_DEMO_ROOT / 'nginx').as_posix()}:/etc/nginx:ro"
                  - "{(scenarios_root / 'nginx').as_posix()}:/scenarios/nginx:ro"

              apache:
                build:
                  context: "{(_DOCKER_ROOT / 'apache').as_posix()}"
                  args:
                    PUBLIC_REPO_URL: "{_PUBLIC_REPO_URL}"
                    PUBLIC_REPO_REF: "{public_repo_commit}"
                    PUBLIC_REPO_CACHE_KEY: "{public_repo_commit}"
                image: webconf-audit-public-repo-apache-it
                container_name: webconf-audit-public-repo-apache-it
                ports:
                  - "19181:80"
                volumes:
                  - "{(_DEMO_ROOT / 'apache' / 'conf').as_posix()}:/usr/local/apache2/conf:ro"
                  - "{(_DEMO_ROOT / 'apache' / 'htdocs').as_posix()}:/usr/local/apache2/htdocs:ro"
                  - "{(scenarios_root / 'apache').as_posix()}:/scenarios/apache:ro"

              lighttpd:
                build:
                  context: "{(_DOCKER_ROOT / 'lighttpd').as_posix()}"
                  args:
                    PUBLIC_REPO_URL: "{_PUBLIC_REPO_URL}"
                    PUBLIC_REPO_REF: "{public_repo_commit}"
                    PUBLIC_REPO_CACHE_KEY: "{public_repo_commit}"
                image: webconf-audit-public-repo-lighttpd-it
                container_name: webconf-audit-public-repo-lighttpd-it
                ports:
                  - "19182:8080"
                volumes:
                  - "{(_DEMO_ROOT / 'lighttpd').as_posix()}:/etc/lighttpd:ro"
                  - "{(scenarios_root / 'lighttpd').as_posix()}:/scenarios/lighttpd:ro"
            """
        ).strip()
        + "\n"
    )


def _expected_local_rule_ids(server_type: str) -> set[str]:
    load_map = {
        "nginx": "webconf_audit.local.nginx.rules",
        "apache": "webconf_audit.local.apache.rules",
        "lighttpd": "webconf_audit.local.lighttpd.rules",
    }
    registry.ensure_loaded(load_map[server_type])
    return {
        meta.rule_id
        for meta in registry.list_rules(category="local", server_type=server_type)
    }


def _expected_universal_rule_ids() -> set[str]:
    registry.ensure_loaded("webconf_audit.local.rules.universal")
    return {
        meta.rule_id
        for meta in registry.list_rules(category="universal")
    }


@pytest.fixture(scope="session")
def public_repo_linux_local_rule_stack(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, object]:
    _require_docker()

    scenarios = _all_scenarios()
    public_repo_commit = _expected_public_repo_commit()
    fixture_root = tmp_path_factory.mktemp("public_repo_local_linux")
    scenarios_root = fixture_root / "scenarios"
    compose_file = fixture_root / "docker-compose.yml"

    _write_scenarios(scenarios_root, scenarios)
    compose_file.write_text(
        _compose_file_text(scenarios_root, public_repo_commit),
        encoding="utf-8",
    )

    _run_compose("down", "-v", "--remove-orphans", compose_file=compose_file)
    up = _run_compose("up", "-d", "--build", compose_file=compose_file)
    if up.returncode != 0:
        raise RuntimeError(
            "docker compose up failed:\n"
            f"STDOUT:\n{up.stdout}\n"
            f"STDERR:\n{up.stderr}"
        )

    try:
        for url in _READINESS_URLS:
            _wait_for_url(url)
        yield {
            "compose_file": compose_file,
            "public_repo_commit": public_repo_commit,
            "scenarios": scenarios,
        }
    finally:
        down = _run_compose("down", "-v", "--remove-orphans", compose_file=compose_file)
        if down.returncode != 0:
            raise RuntimeError(
                "docker compose down failed:\n"
                f"STDOUT:\n{down.stdout}\n"
                f"STDERR:\n{down.stderr}"
            )


def test_public_repo_origin_is_configured_in_all_linux_services(
    public_repo_linux_local_rule_stack: dict[str, object],
) -> None:
    compose_file = public_repo_linux_local_rule_stack["compose_file"]
    expected_commit = public_repo_linux_local_rule_stack["public_repo_commit"]

    for service in ("nginx", "apache", "lighttpd"):
        result = _compose_exec(
            service,
            "git",
            "-C",
            "/opt/webconf-audit-src",
            "remote",
            "get-url",
            "origin",
            compose_file=compose_file,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stdout.strip() == _PUBLIC_REPO_URL

        ref_result = _compose_exec(
            service,
            "git",
            "-C",
            "/opt/webconf-audit-src",
            "rev-parse",
            "HEAD",
            compose_file=compose_file,
        )
        assert ref_result.returncode == 0, ref_result.stdout + ref_result.stderr
        assert ref_result.stdout.strip() == expected_commit


@pytest.mark.parametrize(
    ("url", "expected_fragment"),
    [
        ("http://127.0.0.1:19180/", "Thank you for using nginx."),
        ("http://127.0.0.1:19182/server-status", "Server-Status"),
    ],
)
def test_public_repo_demo_services_respond_over_http(
    public_repo_linux_local_rule_stack: dict[str, object],
    url: str,
    expected_fragment: str,
) -> None:
    status, body = _read_url_text(url)
    assert status == 200
    assert expected_fragment in body


def test_public_repo_linux_local_rule_pack_coverage(
    public_repo_linux_local_rule_stack: dict[str, object],
) -> None:
    compose_file = public_repo_linux_local_rule_stack["compose_file"]
    scenarios = public_repo_linux_local_rule_stack["scenarios"]

    seen_server_rules = {
        "nginx": set(),
        "apache": set(),
        "lighttpd": set(),
    }
    seen_universal_rules: set[str] = set()

    # Some scenarios are intentionally boot-blocking: they model incomplete
    # TLS or rate-limit configuration that the analyzer must still detect in
    # local mode even though the server binary rejects them at startup.
    for scenario in scenarios:
        validation = _compose_exec(
            scenario.service,
            *scenario.validation_command(),
            compose_file=compose_file,
        )
        if scenario.native_validation_should_pass:
            assert validation.returncode == 0, (
                f"{scenario.service}/{scenario.name} should be native-valid.\n"
                f"STDOUT:\n{validation.stdout}\nSTDERR:\n{validation.stderr}"
            )
        else:
            assert validation.returncode != 0, (
                f"{scenario.service}/{scenario.name} should be boot-blocking.\n"
                f"STDOUT:\n{validation.stdout}\nSTDERR:\n{validation.stderr}"
            )

        analysis = _compose_exec(
            scenario.service,
            *scenario.analyzer_command(),
            compose_file=compose_file,
        )
        assert analysis.returncode == 0, (
            f"Analyzer failed for {scenario.service}/{scenario.name}.\n"
            f"STDOUT:\n{analysis.stdout}\nSTDERR:\n{analysis.stderr}"
        )

        report = json.loads(analysis.stdout)
        # The top-level JSON payload deduplicates some universal findings in
        # favor of more specific server rules. For full rule-pack coverage we
        # need the raw findings from the single analysis result instead.
        finding_ids = {
            finding["rule_id"]
            for finding in report["results"][0]["findings"]
        }

        assert scenario.expected_rule_ids <= finding_ids, (
            f"{scenario.service}/{scenario.name} missed expected findings: "
            f"{sorted(scenario.expected_rule_ids - finding_ids)}\n"
            f"Observed: {sorted(finding_ids)}"
        )

        seen_server_rules[scenario.service].update(
            rule_id
            for rule_id in finding_ids
            if rule_id.startswith(f"{scenario.service}.")
        )
        seen_universal_rules.update(
            rule_id for rule_id in finding_ids if rule_id.startswith("universal.")
        )

    for server_type, seen_ids in seen_server_rules.items():
        expected_ids = _expected_local_rule_ids(server_type)
        assert expected_ids <= seen_ids, (
            f"{server_type} local rule-pack not fully covered.\n"
            f"Missing: {sorted(expected_ids - seen_ids)}"
        )

    expected_universal_ids = _expected_universal_rule_ids()
    assert expected_universal_ids <= seen_universal_rules, (
        "Universal local rules not fully covered.\n"
        f"Missing: {sorted(expected_universal_ids - seen_universal_rules)}"
    )
