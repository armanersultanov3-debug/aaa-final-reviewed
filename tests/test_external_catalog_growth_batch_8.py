from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_NGINX_CONFIG_BODY = (
    "worker_processes auto;\n"
    "events { worker_connections 1024; }\n"
    "http {\n"
    "    server { listen 80; root /usr/share/nginx/html; }\n"
    "}\n"
)

_APACHE_CONFIG_BODY = (
    'ServerRoot "/usr/local/apache2"\n'
    "Listen 80\n"
    "LoadModule mpm_event_module modules/mod_mpm_event.so\n"
    "<VirtualHost *:80>\n"
    '    DocumentRoot "/usr/local/apache2/htdocs"\n'
    "    CustomLog logs/access_log combined\n"
    "</VirtualHost>\n"
)

_LIGHTTPD_CONFIG_BODY = (
    'server.modules = ( "mod_access", "mod_accesslog" )\n'
    'server.document-root = "/var/www/html"\n'
    "server.port = 80\n"
)

_CONFIG_CASES = [
    (
        "external.nginx_config_exposed",
        ["/nginx.conf", "/conf/nginx.conf", "/etc/nginx/nginx.conf"],
        _NGINX_CONFIG_BODY,
    ),
    (
        "external.apache_config_exposed",
        [
            "/httpd.conf",
            "/apache2.conf",
            "/conf/httpd.conf",
            "/conf/apache2.conf",
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
        ],
        _APACHE_CONFIG_BODY,
    ),
    (
        "external.lighttpd_config_exposed",
        ["/lighttpd.conf", "/conf/lighttpd.conf", "/etc/lighttpd/lighttpd.conf"],
        _LIGHTTPD_CONFIG_BODY,
    ),
]

_BODY_MARKER_NEGATIVES = [
    (
        "external.nginx_config_exposed",
        "/nginx.conf",
        "events { worker_connections 1024; }\n",
    ),
    (
        "external.apache_config_exposed",
        "/httpd.conf",
        "Listen 80\n",
    ),
    (
        "external.lighttpd_config_exposed",
        "/lighttpd.conf",
        "server.port = 80\n",
    ),
    (
        "external.nginx_config_exposed",
        "/nginx.conf",
        "<html>This page mentions nginx.conf but is not a config file.</html>",
    ),
    (
        "external.apache_config_exposed",
        "/httpd.conf",
        "<html>This page mentions httpd.conf but is not a config file.</html>",
    ),
    (
        "external.lighttpd_config_exposed",
        "/lighttpd.conf",
        "<html>This page mentions lighttpd.conf but is not a config file.</html>",
    ),
]


def _probe(
    path: str,
    *,
    status_code: int = 200,
    body_snippet: str,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type="text/plain",
        body_snippet=body_snippet,
    )


@pytest.mark.parametrize(("rule_id", "paths", "body_snippet"), _CONFIG_CASES)
def test_catalog_growth_batch_8_web_server_config_files_fire_on_markers(
    monkeypatch,
    rule_id: str,
    paths: list[str],
    body_snippet: str,
) -> None:
    for path in paths:
        result = _analyze_with_probe_attempts(
            monkeypatch,
            [_https_probe_with_headers(), _http_redirect_probe()],
            sensitive_path_probes=[_probe(path, body_snippet=body_snippet)],
        )

        findings = [finding for finding in result.findings if finding.rule_id == rule_id]
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert findings[0].location.target == f"https://example.com{path}"
        assert findings[0].location.details == path


@pytest.mark.parametrize(("rule_id", "paths", "body_snippet"), _CONFIG_CASES)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_8_web_server_config_files_skip_blocked_or_missing_status(
    monkeypatch,
    rule_id: str,
    paths: list[str],
    body_snippet: str,
    status_code: int,
) -> None:
    for path in paths:
        result = _analyze_with_probe_attempts(
            monkeypatch,
            [_https_probe_with_headers(), _http_redirect_probe()],
            sensitive_path_probes=[
                _probe(path, status_code=status_code, body_snippet=body_snippet)
            ],
        )

        assert rule_id not in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(("rule_id", "path", "body_snippet"), _BODY_MARKER_NEGATIVES)
def test_catalog_growth_batch_8_web_server_config_files_require_config_markers(
    monkeypatch,
    rule_id: str,
    path: str,
    body_snippet: str,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path, body_snippet=body_snippet)],
    )

    assert rule_id not in {finding.rule_id for finding in result.findings}
