import threading
from pathlib import Path

import pytest

from webconf_audit.local.load_context import LoadContext
from webconf_audit.local.nginx import analyze_nginx_config
from webconf_audit.local.nginx.include import resolve_includes
from webconf_audit.local.nginx.parser.parser import NginxParser, NginxTokenizer
from webconf_audit.models import AnalysisResult


def _safe_server_block(
    *directives: str,
    include_http_redirect: bool = False,
    include_rate_limits: bool = False,
) -> str:
    safe_directives = (
        "server_name example.com;",
        "add_header X-Content-Type-Options nosniff;",
        "add_header X-Frame-Options DENY;",
        "add_header Referrer-Policy strict-origin-when-cross-origin always;",
        "add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'; form-action 'self'; report-to csp-endpoint\" always;",
        "add_header Permissions-Policy geolocation=();",
        'add_header X-XSS-Protection "1; mode=block";',
        "client_max_body_size 10m;",
        "client_body_timeout 10s;",
        "client_header_timeout 10s;",
        "send_timeout 10s;",
        "keepalive_timeout 10s;",
        "ssl_stapling on;",
        "ssl_stapling_verify on;",
        "ssl_session_cache shared:SSL:10m;",
        "ssl_session_timeout 10m;",
        "resolver 1.1.1.1;",
        "access_log /var/log/nginx/access.log;",
        "error_log /var/log/nginx/error.log warn;",
        "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header X-Forwarded-Proto $scheme;",
        "location ~ /\\. {",
        "    deny all;",
        "}",
        "location ~ \\.(bak|old|backup|orig|save)$ {",
        "    deny all;",
        "}",
        "location ~ ~$ {",
        "    deny all;",
        "}",
    )
    rate_limit_directives = (
        ("limit_req zone=perip burst=10;", "limit_conn addr 10;")
        if include_rate_limits
        else ()
    )
    redirect_directives = (
        ("return 301 https://$host$request_uri;",) if include_http_redirect else ()
    )
    lines = safe_directives + directives + redirect_directives + rate_limit_directives

    return "server {\n" + "".join(f"    {line}\n" for line in lines) + "}\n"

def _http_block(*blocks: str) -> str:
    content_blocks = (_safe_http_log_format(), _safe_http_limit_zones()) + blocks
    content = "".join(
        "".join(f"    {line}\n" for line in block.splitlines())
        for block in content_blocks
    )

    return f"http {{\n{content}}}\n"

def _safe_http_log_format() -> str:
    return (
        'log_format main "$time_iso8601 $remote_addr $remote_user '
        '$request $status $http_user_agent";'
    )

def _safe_http_limit_zones() -> str:
    return (
        "limit_req_zone $binary_remote_addr zone=perip:10m rate=10r/s;\n"
        "limit_conn_zone $binary_remote_addr zone=addr:10m;"
    )


def _line_number(config_text: str, needle: str, *, occurrence: int = 1) -> int:
    seen = 0
    for line_number, line in enumerate(config_text.splitlines(), start=1):
        if needle in line:
            seen += 1
            if seen == occurrence:
                return line_number
    raise AssertionError(f"Could not find occurrence {occurrence} of {needle!r}")


__all__ = [
    "AnalysisResult",
    "LoadContext",
    "NginxParser",
    "NginxTokenizer",
    "Path",
    "_http_block",
    "_line_number",
    "_safe_http_limit_zones",
    "_safe_http_log_format",
    "_safe_server_block",
    "analyze_nginx_config",
    "pytest",
    "resolve_includes",
    "threading"
]
