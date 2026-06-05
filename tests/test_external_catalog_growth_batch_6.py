from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_SOURCEMAP_BODY = (
    '{"version":3,"sources":["webpack://app/src/main.ts"],'
    '"names":["bootstrap"],"mappings":"AAAA"}'
)

_CATALOG_GROWTH_BATCH_6_CASES = [
    "/app.js.map",
    "/main.js.map",
    "/bundle.js.map",
    "/index.js.map",
    "/js/app.js.map",
    "/assets/app.js.map",
    "/static/js/main.js.map",
    "/dist/bundle.js.map",
]


def _probe(
    path: str,
    *,
    status_code: int = 200,
    body_snippet: str = _SOURCEMAP_BODY,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type="application/json",
        body_snippet=body_snippet,
    )


@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_6_CASES)
def test_catalog_growth_batch_6_sourcemaps_fire_on_marker_response(
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
        if finding.rule_id == "external.javascript_sourcemap_exposed"
    ]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_6_CASES)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_6_sourcemaps_skip_blocked_or_missing_status(
    monkeypatch,
    path: str,
    status_code: int,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path, status_code=status_code)],
    )

    assert "external.javascript_sourcemap_exposed" not in {
        finding.rule_id for finding in result.findings
    }


@pytest.mark.parametrize(
    "body_snippet",
    [
        '{"version":3,"status":"ok"}',
        '{"sources":["src/main.ts"],"mappings":"AAAA"}',
        "This page explains what JavaScript source maps are.",
    ],
)
@pytest.mark.parametrize("path", _CATALOG_GROWTH_BATCH_6_CASES)
def test_catalog_growth_batch_6_sourcemaps_require_source_map_markers(
    monkeypatch,
    path: str,
    body_snippet: str,
) -> None:
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_probe(path, body_snippet=body_snippet)],
    )

    assert "external.javascript_sourcemap_exposed" not in {
        finding.rule_id for finding in result.findings
    }
