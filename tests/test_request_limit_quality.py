from tests.iis_helpers import AnalysisResult as IISAnalysisResult
from tests.iis_helpers import Path, analyze_iis_config
from tests.nginx_helpers import AnalysisResult as NginxAnalysisResult
from tests.nginx_helpers import analyze_nginx_config
from webconf_audit.local.iis.parser import parse_iis_config
from webconf_audit.local.iis.rules.request_filtering_policy import (
    find_file_extensions_allow_unlisted,
)


def _rule_ids(result: IISAnalysisResult | NginxAnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_nginx_reports_excessive_client_max_body_size(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_max_body_size 512m;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, NginxAnalysisResult)
    assert result.issues == []
    assert "nginx.client_max_body_size_too_large" in _rule_ids(result)


def test_nginx_client_max_body_size_uses_last_directive(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_max_body_size 0;\n"
        "    client_max_body_size 10m;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, NginxAnalysisResult)
    assert result.issues == []
    rule_ids = _rule_ids(result)
    assert "nginx.client_max_body_size_unlimited" not in rule_ids
    assert "nginx.client_max_body_size_too_large" not in rule_ids


def test_nginx_reports_excessive_client_header_buffer_size(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_header_buffer_size 128k;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, NginxAnalysisResult)
    assert result.issues == []
    assert "nginx.client_header_buffer_size_too_large" in _rule_ids(result)


def test_nginx_reports_excessive_large_client_header_buffers(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    large_client_header_buffers 16 64k;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, NginxAnalysisResult)
    assert result.issues == []
    assert "nginx.large_client_header_buffers_too_large" in _rule_ids(result)


def test_nginx_accepts_moderate_request_limit_values(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 80;\n"
        "    client_max_body_size 50m;\n"
        "    client_header_buffer_size 8k;\n"
        "    large_client_header_buffers 4 8k;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))

    assert isinstance(result, NginxAnalysisResult)
    assert result.issues == []
    rule_ids = _rule_ids(result)
    assert "nginx.client_max_body_size_too_large" not in rule_ids
    assert "nginx.client_header_buffer_size_too_large" not in rule_ids
    assert "nginx.large_client_header_buffers_too_large" not in rule_ids


def test_iis_reports_file_extensions_default_from_request_filtering(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, IISAnalysisResult)
    assert result.issues == []
    rule_ids = _rule_ids(result)
    assert "iis.file_extensions_allow_unlisted" in rule_ids


def test_iis_reports_file_extensions_default_allow_unlisted(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <fileExtensions />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, IISAnalysisResult)
    assert result.issues == []
    assert "iis.file_extensions_allow_unlisted" in _rule_ids(result)


def test_iis_reports_inherited_file_extensions_default_at_location(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits maxAllowedContentLength="4194304" />
                <fileExtensions />
            </requestFiltering>
        </security>
    </system.webServer>
    <location path="private">
        <system.webServer>
            <security>
                <requestFiltering removeServerHeader="true" />
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, IISAnalysisResult)
    assert result.issues == []
    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "iis.file_extensions_allow_unlisted"
    ]
    assert any("private" in finding.description for finding in findings)


def test_iis_raw_file_extensions_missing_uses_location_inheritance() -> None:
    doc = parse_iis_config(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <fileExtensions allowUnlisted="false" />
            </requestFiltering>
        </security>
    </system.webServer>
    <location path="private/child">
        <system.webServer>
            <security>
                <requestFiltering removeServerHeader="true" />
            </security>
        </system.webServer>
    </location>
</configuration>
""",
        file_path="web.config",
    )

    findings = find_file_extensions_allow_unlisted(doc)

    assert not findings


def test_iis_accepts_complete_request_filtering_policy(tmp_path: Path) -> None:
    config_path = tmp_path / "web.config"
    config_path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.webServer>
        <security>
            <requestFiltering>
                <requestLimits
                    maxAllowedContentLength="4194304"
                    maxUrl="4096"
                    maxQueryString="2048"
                />
                <fileExtensions allowUnlisted="false" />
            </requestFiltering>
        </security>
    </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )

    result = analyze_iis_config(str(config_path))

    assert isinstance(result, IISAnalysisResult)
    assert result.issues == []
    rule_ids = _rule_ids(result)
    assert "iis.request_filtering_max_url_too_high" not in rule_ids
    assert "iis.request_filtering_max_query_string_too_high" not in rule_ids
    assert "iis.file_extensions_allow_unlisted" not in rule_ids
