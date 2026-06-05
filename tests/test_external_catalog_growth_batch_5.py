from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_CATALOG_GROWTH_BATCH_5_CASES = [
    (
        "/Pipfile",
        "text/plain",
        "[packages]\nrequests = \"*\"\n",
        "Pipfile documentation without dependency markers",
    ),
    (
        "/Pipfile.lock",
        "application/json",
        '{"_meta": {"pipfile-spec": 6}, "default": {"requests": {}}}',
        '{"status": "ok"}',
    ),
    (
        "/Gemfile",
        "text/plain",
        'source "https://rubygems.org"\ngem "rails"\n',
        "Gemfile notes without executable dependency syntax",
    ),
    (
        "/Gemfile.lock",
        "text/plain",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n",
        "plain text without lockfile markers",
    ),
    (
        "/go.mod",
        "text/plain",
        "module example.com/service\n\ngo 1.23\n",
        "Go module documentation page",
    ),
    (
        "/go.sum",
        "text/plain",
        "github.com/gin-gonic/gin v1.10.0 h1:abcdef\n",
        "plain checksum description",
    ),
    (
        "/Cargo.toml",
        "text/plain",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
        "Cargo configuration notes",
    ),
    (
        "/Cargo.lock",
        "text/plain",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n",
        "package list without lockfile marker",
    ),
]


def _probe(
    path: str,
    *,
    status_code: int = 200,
    content_type: str = "text/plain",
    body_snippet: str,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type=content_type,
        body_snippet=body_snippet,
    )


@pytest.mark.parametrize(
    ("path", "content_type", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_5_CASES,
)
def test_catalog_growth_batch_5_dependency_manifests_fire_on_marker_response(
    monkeypatch,
    path: str,
    content_type: str,
    marker_body: str,
    non_marker_body: str,
) -> None:
    del non_marker_body

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(path, content_type=content_type, body_snippet=marker_body),
        ],
    )

    findings = [
        finding
        for finding in result.findings
        if finding.rule_id == "external.dependency_manifest_exposed"
    ]
    assert len(findings) == 1
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize(
    ("path", "content_type", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_5_CASES,
)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_5_dependency_manifests_skip_blocked_or_missing_status(
    monkeypatch,
    path: str,
    content_type: str,
    marker_body: str,
    non_marker_body: str,
    status_code: int,
) -> None:
    del non_marker_body

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(
                path,
                status_code=status_code,
                content_type=content_type,
                body_snippet=marker_body,
            ),
        ],
    )

    assert "external.dependency_manifest_exposed" not in {
        finding.rule_id for finding in result.findings
    }


@pytest.mark.parametrize(
    ("path", "content_type", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_5_CASES,
)
def test_catalog_growth_batch_5_dependency_manifests_require_marker_response(
    monkeypatch,
    path: str,
    content_type: str,
    marker_body: str,
    non_marker_body: str,
) -> None:
    del marker_body

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(path, content_type=content_type, body_snippet=non_marker_body),
        ],
    )

    assert "external.dependency_manifest_exposed" not in {
        finding.rule_id for finding in result.findings
    }
