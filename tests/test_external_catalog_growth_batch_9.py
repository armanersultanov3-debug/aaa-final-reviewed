from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_CATALOG_GROWTH_BATCH_9_CASES = [
    (
        "/pom.xml",
        "application/xml",
        (
            "<project><modelVersion>4.0.0</modelVersion><dependencies>"
            "<dependency><groupId>org.springframework</groupId>"
            "<artifactId>spring-core</artifactId><version>6.1.0</version>"
            "</dependency></dependencies></project>"
        ),
        "<project><dependencies><dependency></dependencies></project>",
    ),
    (
        "/build.gradle",
        "text/plain",
        (
            "plugins { id 'java' }\n"
            "dependencies { implementation 'org.springframework:spring-core:6.1.0' }\n"
        ),
        "Gradle build file notes without dependency declarations",
    ),
    (
        "/build.gradle",
        "text/plain",
        "dependencies { annotationProcessor 'org.projectlombok:lombok:1.18.32' }\n",
        "dependencies { if (project.hasProperty('demo')) { println 'demo' } }\n",
    ),
    (
        "/build.gradle.kts",
        "text/plain",
        (
            "plugins { java }\n"
            'dependencies { implementation("org.springframework:spring-core:6.1.0") }\n'
        ),
        "Gradle Kotlin DSL notes without dependency declarations",
    ),
    (
        "/packages.config",
        "application/xml",
        '<packages><package id="Newtonsoft.Json" version="13.0.3" /></packages>',
        "<packages></packages>",
    ),
    (
        "/Directory.Packages.props",
        "application/xml",
        (
            '<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json" '
            'Version="13.0.3" /></ItemGroup></Project>'
        ),
        '<Project><ItemGroup><PackageVersion Include="Newtonsoft.Json"',
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
    _CATALOG_GROWTH_BATCH_9_CASES,
)
def test_catalog_growth_batch_9_dependency_manifests_fire_on_marker_response(
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
    _CATALOG_GROWTH_BATCH_9_CASES,
)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_9_dependency_manifests_skip_blocked_or_missing_status(
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
    _CATALOG_GROWTH_BATCH_9_CASES,
)
def test_catalog_growth_batch_9_dependency_manifests_require_marker_response(
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
