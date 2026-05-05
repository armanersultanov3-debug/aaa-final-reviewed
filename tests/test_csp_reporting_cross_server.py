from __future__ import annotations

from tests.apache_helpers import Path, analyze_apache_config
from tests.external_helpers import _analyze_with_probe_attempts, _https_probe_with_headers
from tests.lighttpd_helpers import analyze_lighttpd_config
from tests.nginx_helpers import analyze_nginx_config
from webconf_audit.local.iis import analyze_iis_config

RULE_IDS = {
    "external": "external.content_security_policy_missing_reporting_endpoint",
    "nginx": "nginx.content_security_policy_missing_reporting_endpoint",
    "apache": "apache.content_security_policy_missing_reporting_endpoint",
    "lighttpd": "lighttpd.content_security_policy_missing_reporting_endpoint",
    "iis": "iis.content_security_policy_missing_reporting_endpoint",
}

_BASELINE_CSP = "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'"


def _rule_ids(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_external_csp_without_reporting_endpoint_fires(monkeypatch) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(content_security_policy_header=_BASELINE_CSP)],
    )

    assert result.issues == []
    assert RULE_IDS["external"] in _rule_ids(result)


def test_external_csp_with_report_to_is_silent(monkeypatch) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [
            _https_probe_with_headers(
                content_security_policy_header=f"{_BASELINE_CSP}; report-to csp-endpoint"
            )
        ],
    )

    assert result.issues == []
    assert RULE_IDS["external"] not in _rule_ids(result)


def test_external_csp_with_report_uri_is_silent(monkeypatch) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [
            _https_probe_with_headers(
                content_security_policy_header=f"{_BASELINE_CSP}; report-uri /csp-report"
            )
        ],
    )

    assert result.issues == []
    assert RULE_IDS["external"] not in _rule_ids(result)


def test_nginx_csp_without_reporting_endpoint_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name example.test;\n"
        f"        add_header Content-Security-Policy \"{_BASELINE_CSP}\" always;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["nginx"] in _rule_ids(result)


def test_nginx_csp_with_report_uri_is_silent(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    server {\n"
        "        listen 443 ssl;\n"
        "        server_name example.test;\n"
        f"        add_header Content-Security-Policy \"{_BASELINE_CSP}; report-uri /csp-report\" always;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["nginx"] not in _rule_ids(result)


def test_apache_csp_without_reporting_endpoint_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                "Listen 127.0.0.1:443",
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                f'Header always set Content-Security-Policy "{_BASELINE_CSP}"',
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["apache"] in _rule_ids(result)


def test_apache_csp_with_report_to_is_silent(tmp_path: Path) -> None:
    config_path = tmp_path / "httpd.conf"
    config_path.write_text(
        "\n".join(
            (
                "Listen 127.0.0.1:443",
                "ServerSignature Off",
                "ServerTokens Prod",
                "TraceEnable Off",
                f'Header always set Content-Security-Policy "{_BASELINE_CSP}; report-to csp-endpoint"',
            )
        ),
        encoding="utf-8",
    )

    result = analyze_apache_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["apache"] not in _rule_ids(result)


def test_lighttpd_csp_without_reporting_endpoint_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        "server.port = 443\n"
        'ssl.engine = "enable"\n'
        'setenv.add-response-header = ( "Content-Security-Policy" => "'
        f'{_BASELINE_CSP}" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["lighttpd"] in _rule_ids(result)


def test_lighttpd_csp_with_report_uri_is_silent(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        "server.port = 443\n"
        'ssl.engine = "enable"\n'
        'setenv.add-response-header = ( "Content-Security-Policy" => "'
        f'{_BASELINE_CSP}; report-uri /csp-report" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["lighttpd"] not in _rule_ids(result)


def test_lighttpd_csp_mixed_reporting_endpoints_still_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "lighttpd.conf"
    config_path.write_text(
        "server.port = 443\n"
        'ssl.engine = "enable"\n'
        'setenv.add-response-header = ( '
        '"Content-Security-Policy" => "'
        f'{_BASELINE_CSP}; report-uri /csp-report", '
        '"Content-Security-Policy" => "'
        f'{_BASELINE_CSP}" )\n',
        encoding="utf-8",
    )

    result = analyze_lighttpd_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["lighttpd"] in _rule_ids(result)


def test_iis_csp_without_reporting_endpoint_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="{_BASELINE_CSP}" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["iis"] in _rule_ids(result)


def test_iis_csp_with_report_to_is_silent(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="{_BASELINE_CSP}; report-to csp-endpoint" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["iis"] not in _rule_ids(result)


def test_iis_csp_mixed_reporting_endpoints_still_fires(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <add name="Content-Security-Policy" value="{_BASELINE_CSP}; report-uri /csp-report" />
        <add name="Content-Security-Policy" value="{_BASELINE_CSP}" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert result.issues == []
    assert RULE_IDS["iis"] in _rule_ids(result)
