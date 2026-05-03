from pathlib import Path

import pytest

from webconf_audit.local.apache import analyze_apache_config
from webconf_audit.local.apache.effective import (
    build_effective_config,
    build_server_effective_config,
    extract_virtualhost_contexts,
    select_applicable_virtualhosts,
)
from webconf_audit.local.apache.htaccess import (
    ALL_OVERRIDE_CATEGORIES,
    HtaccessFile,
    discover_htaccess_files,
    extract_allowoverride,
    filter_htaccess_by_allowoverride,
)
from webconf_audit.local.apache.parser import ApacheBlockNode, ApacheParseError, parse_apache_config
from webconf_audit.local.apache.rules.context_sensitive_directive_utils import (
    find_context_sensitive_directives,
)
from webconf_audit.local.apache.rules.htaccess_weakens_security import (
    find_htaccess_weakens_security,
)

_SAFE_SECURITY_HEADER_LINES = {
    "x-content-type-options": "Header set X-Content-Type-Options nosniff",
    "x-frame-options": "Header set X-Frame-Options SAMEORIGIN",
    "content-security-policy": (
        "Header set Content-Security-Policy "
        "\"default-src 'self'; frame-ancestors 'self'\""
    ),
    "referrer-policy": "Header set Referrer-Policy strict-origin-when-cross-origin",
    "permissions-policy": (
        'Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"'
    ),
}
_SAFE_SECURITY_HEADER_ALWAYS_LINES = {
    header: line.replace("Header set ", "Header always set ", 1)
    for header, line in _SAFE_SECURITY_HEADER_LINES.items()
}
_SAFE_SECURITY_HEADER_BASELINE_LINES = [
    _SAFE_SECURITY_HEADER_ALWAYS_LINES["x-frame-options"],
    *[
        line
        for header in _SAFE_SECURITY_HEADER_LINES
        if header != "x-frame-options"
        for line in (
            _SAFE_SECURITY_HEADER_LINES[header],
            _SAFE_SECURITY_HEADER_ALWAYS_LINES[header],
        )
    ],
]
_SAFE_APACHE_CIS_LOG_LINES = [
    "LogLevel notice",
]
_SAFE_APACHE_CIS_HTTP_PROTOCOL_LINES = [
    "HttpProtocolOptions Strict Require1.0",
]
_SAFE_APACHE_CIS_ALLOWOVERRIDE_LINES = [
    "<Directory />",
    "    AllowOverride None",
    "</Directory>",
]
_SAFE_APACHE_CIS_SENSITIVE_FILE_LINES = [
    '<FilesMatch "^\\.ht">',
    "    Require all denied",
    "</FilesMatch>",
    '<FilesMatch "\\.(conf|ini|log|orig|save|sql|tmp)$">',
    "    Require all denied",
    "</FilesMatch>",
    '<DirectoryMatch "/\\.(git|svn)(/|$)">',
    "    Require all denied",
    "</DirectoryMatch>",
]
_SAFE_APACHE_CIS_BASELINE_LINES = [
    *_SAFE_APACHE_CIS_LOG_LINES,
    *_SAFE_APACHE_CIS_HTTP_PROTOCOL_LINES,
    *_SAFE_APACHE_CIS_ALLOWOVERRIDE_LINES,
    *_SAFE_APACHE_CIS_SENSITIVE_FILE_LINES,
]


def _with_backup_files_restriction(
    config_text: str,
    *,
    include_security_headers: bool = True,
    include_cis_allowoverride_root: bool = True,
    include_cis_http_protocol: bool = True,
) -> str:
    security_headers = (
        "\n" + "\n".join(_SAFE_SECURITY_HEADER_BASELINE_LINES)
        if include_security_headers
        else ""
    )
    cis_lines = [
        *_SAFE_APACHE_CIS_LOG_LINES,
        *(
            _SAFE_APACHE_CIS_HTTP_PROTOCOL_LINES
            if include_cis_http_protocol
            else []
        ),
        *(
            _SAFE_APACHE_CIS_ALLOWOVERRIDE_LINES
            if include_cis_allowoverride_root
            else []
        ),
        *_SAFE_APACHE_CIS_SENSITIVE_FILE_LINES,
    ]
    return config_text.rstrip("\n") + security_headers + (
        '\n<FilesMatch "\\.(bak|old|swp)$">\n'
        "    Require all denied\n"
        "</FilesMatch>\n"
        + "\n".join(cis_lines)
    )


def _safe_apache_config(*extra_lines: str) -> str:
    lines = [
        "ServerSignature Off",
        "TraceEnable Off",
        "ServerTokens Prod",
        "LimitRequestBody 102400",
        "LimitRequestFields 100",
        "ErrorLog logs/error_log",
        "CustomLog logs/access_log combined",
        "ErrorDocument 404 /custom404.html",
        "ErrorDocument 500 /custom500.html",
        "Listen 80",
    ]
    lines.extend(extra_lines)
    return _with_backup_files_restriction("\n".join(lines))


def _safe_apache_config_without_headers(
    *extra_lines: str,
    omit_headers: set[str] | None = None,
) -> str:
    omit = {header.lower() for header in omit_headers or set()}
    base_lines = _safe_apache_config().splitlines()
    omitted_lines = set()
    for header in omit:
        omitted_lines.update(
            line
            for line in (
                _SAFE_SECURITY_HEADER_LINES.get(header),
                _SAFE_SECURITY_HEADER_ALWAYS_LINES.get(header),
            )
            if line is not None and line in base_lines
        )
    filtered_lines = [line for line in base_lines if line not in omitted_lines]
    for extra_line in extra_lines:
        filtered_lines.extend(extra_line.splitlines())
    return "\n".join(filtered_lines)


def _safe_apache_config_without_security_headers(*extra_lines: str) -> str:
    return _safe_apache_config_without_headers(
        *extra_lines,
        omit_headers=set(_SAFE_SECURITY_HEADER_LINES),
    )


def _safe_apache_config_with_late_lines(*extra_lines: str) -> str:
    config = _safe_apache_config()
    marker = '\n<FilesMatch "\\.(bak|old|swp)$">'
    if marker not in config:
        raise AssertionError(
            "_safe_apache_config_with_late_lines: expected backup-files marker "
            f"{marker!r} to be present in the safe base config so that late "
            "lines can be inserted before the FilesMatch block."
        )
    return config.replace(marker, "\n" + "\n".join(extra_lines) + marker, 1)


def _analyze_with_htaccess(
    tmp_path: Path,
    htaccess_text: str,
    *,
    allowoverride: str | None = "All",
    config_prefix: str = "",
    config_suffix: str = "",
):
    web_dir = tmp_path / "www"
    web_dir.mkdir()
    (web_dir / ".htaccess").write_text(htaccess_text, encoding="utf-8")

    directory_lines = [f'<Directory "{_posix_path(web_dir)}">']
    if allowoverride is not None:
        directory_lines.append(f"    AllowOverride {allowoverride}")
    directory_lines.append("</Directory>")

    config_parts = [
        config_prefix.rstrip("\n"),
        "\n".join(directory_lines),
        "ServerSignature Off",
        "ServerTokens Prod",
        "TraceEnable Off",
        "LimitRequestBody 102400",
        "LimitRequestFields 100",
        "ErrorLog logs/error_log",
        "CustomLog logs/access_log combined",
        'ErrorDocument 404 "/error/404.html"',
        'ErrorDocument 500 "/error/500.html"',
        config_suffix.rstrip("\n"),
    ]

    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction("\n".join(part for part in config_parts if part)),
        encoding="utf-8",
    )
    return analyze_apache_config(str(config_path)), web_dir


def _posix_path(p: Path) -> str:
    """Return forward-slash path string safe for embedding in Apache config text."""
    return str(p).replace("\\", "/")


def _make_vh_override_config(
    tmp_path: Path,
    *,
    global_options: str,
    vh_options: str,
) -> str:
    """Create a config where a global <Directory> sets options and a VH overrides."""
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        _with_backup_files_restriction(
            "\n".join([
                "ServerSignature Off",
                "TraceEnable Off",
                "ServerTokens Prod",
                "LimitRequestBody 102400",
                "LimitRequestFields 100",
                "ErrorLog logs/error_log",
                "CustomLog logs/access_log combined",
                'ErrorDocument 404 "/error/404.html"',
                'ErrorDocument 500 "/error/500.html"',
                '<Directory "/var/www">',
                f"    {global_options}",
                "</Directory>",
                "<VirtualHost *:80>",
                "    ServerName safe.test",
                '    <Directory "/var/www">',
                f"        {vh_options}",
                "    </Directory>",
                "</VirtualHost>",
            ])
        ),
        encoding="utf-8",
    )
    return str(config_path)


__all__ = [
    "ALL_OVERRIDE_CATEGORIES",
    "ApacheBlockNode",
    "ApacheParseError",
    "HtaccessFile",
    "Path",
    "analyze_apache_config",
    "build_effective_config",
    "build_server_effective_config",
    "discover_htaccess_files",
    "extract_allowoverride",
    "extract_virtualhost_contexts",
    "filter_htaccess_by_allowoverride",
    "find_context_sensitive_directives",
    "find_htaccess_weakens_security",
    "parse_apache_config",
    "pytest",
    "select_applicable_virtualhosts",
    "_SAFE_SECURITY_HEADER_ALWAYS_LINES",
    "_SAFE_SECURITY_HEADER_BASELINE_LINES",
    "_SAFE_SECURITY_HEADER_LINES",
    "_SAFE_APACHE_CIS_BASELINE_LINES",
    "_SAFE_APACHE_CIS_ALLOWOVERRIDE_LINES",
    "_SAFE_APACHE_CIS_HTTP_PROTOCOL_LINES",
    "_SAFE_APACHE_CIS_LOG_LINES",
    "_SAFE_APACHE_CIS_SENSITIVE_FILE_LINES",
    "_analyze_with_htaccess",
    "_make_vh_override_config",
    "_posix_path",
    "_safe_apache_config",
    "_safe_apache_config_with_late_lines",
    "_safe_apache_config_without_headers",
    "_safe_apache_config_without_security_headers",
    "_with_backup_files_restriction",
]
