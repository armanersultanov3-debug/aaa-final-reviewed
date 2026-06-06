from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_APP_SETTINGS_BODY = (
    '{"ConnectionStrings":{"DefaultConnection":"Server=db;Database=app;"},'
    '"Logging":{"LogLevel":{"Default":"Information"}},'
    '"AllowedHosts":"*"}'
)

_CATALOG_GROWTH_BATCH_7_CASES = [
    "/appsettings.json",
    "/appsettings.Development.json",
    "/appsettings.Production.json",
    "/appsettings.Staging.json",
    "/config.json",
    "/settings.json",
]


def _probe(
    path: str,
    *,
    status_code: int = 200,
    body_snippet: str = _APP_SETTINGS_BODY,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type="application/json",
        body_snippet=body_snippet,
    )


@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_7_CASES)
def test_catalog_growth_batch_7_application_settings_json_fires_on_marker_response(
    monkeypatch,
    path: str,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path)],
    )

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.application_settings_json_exposed"
    ]
    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_7_CASES)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_7_application_settings_json_skips_blocked_or_missing_status(
    monkeypatch,
    path: str,
    status_code: int,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path, status_code=status_code)],
    )

    assert "external.application_settings_json_exposed" not in {
        finding.rule_id for finding in result.findings
    }


@pytest.mark.parametrize(
    "body_snippet",
    [
        '{"status":"ok","version":"1.0"}',
        '{"ConnectionStrings":{"DefaultConnection":"Server=db;"}}',
        '{"Logging":{"LogLevel":{"Default":"Information"}}}',
        "This document mentions appsettings.json but is not JSON.",
    ],
)
@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_7_CASES)
def test_catalog_growth_batch_7_application_settings_json_requires_config_markers(
    monkeypatch,
    path: str,
    body_snippet: str,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path, body_snippet=body_snippet)],
    )

    assert "external.application_settings_json_exposed" not in {
        finding.rule_id for finding in result.findings
    }
