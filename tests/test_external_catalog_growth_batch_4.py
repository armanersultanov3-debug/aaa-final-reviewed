from tests.external_helpers import (
    SensitivePathProbe,
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    pytest,
)


_CATALOG_GROWTH_BATCH_4_CASES = [
    (
        "/.env.local",
        "external.env_file_exposed",
        "text/plain",
        "APP_ENV=local\nSECRET_KEY=abc123\n",
        None,
        "<html>Application home</html>",
        None,
    ),
    (
        "/.env.production",
        "external.env_file_exposed",
        "text/plain",
        "APP_ENV=production\nDATABASE_URL=postgres://example\n",
        None,
        "<html>Application home</html>",
        None,
    ),
    (
        "/.env.staging",
        "external.env_file_exposed",
        "text/plain",
        "APP_ENV=staging\nREDIS_URL=redis://cache\n",
        None,
        "<html>Application home</html>",
        None,
    ),
    (
        "/database.sql",
        "external.database_dump_exposed",
        "text/plain",
        "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n",
        None,
        "plain text without SQL dump markers",
        None,
    ),
    (
        "/mysql.sql",
        "external.database_dump_exposed",
        "text/plain",
        "-- MySQL dump 10.13\nCREATE TABLE sessions (id int);\n",
        None,
        "plain text without SQL dump markers",
        None,
    ),
    (
        "/production.sql",
        "external.database_dump_exposed",
        "text/plain",
        "BEGIN TRANSACTION;\nCREATE TABLE orders (id int);\n",
        None,
        "plain text without SQL dump markers",
        None,
    ),
    (
        "/pnpm-lock.yaml",
        "external.dependency_manifest_exposed",
        "text/yaml",
        "lockfileVersion: '9.0'\npackages:\n  /flask/3.0.0: {}\n",
        None,
        "name: public page\n",
        None,
    ),
    (
        "/poetry.lock",
        "external.dependency_manifest_exposed",
        "text/plain",
        '[[package]]\nname = "typer"\nversion = "0.12.0"\n',
        None,
        'name = "not a lockfile"\n',
        None,
    ),
    (
        "/requirements.txt",
        "external.dependency_manifest_exposed",
        "text/plain",
        "Django==5.0.4\nrequests>=2.31\n",
        None,
        "This page lists project requirements in prose.",
        None,
    ),
    (
        "/backup.7z",
        "external.backup_archive_exposed",
        "application/octet-stream",
        None,
        b"7z\xbc\xaf\x27\x1c\x00\x04",
        None,
        b"<html>Custom page</html>",
    ),
    (
        "/backup.rar",
        "external.backup_archive_exposed",
        "application/octet-stream",
        None,
        b"Rar!\x1a\x07\x01\x00",
        None,
        b"<html>Custom page</html>",
    ),
]


def _probe(
    path: str,
    *,
    status_code: int = 200,
    content_type: str | None = "text/plain",
    body_snippet: str | None = None,
    raw_body_prefix: bytes | None = None,
) -> SensitivePathProbe:
    return SensitivePathProbe(
        url=f"https://example.com{path}",
        path=path,
        status_code=status_code,
        content_type=content_type,
        body_snippet=body_snippet,
        raw_body_prefix=raw_body_prefix,
    )


@pytest.mark.parametrize(
    (
        "path",
        "rule_id",
        "content_type",
        "marker_body",
        "marker_raw_prefix",
        "non_marker_body",
        "non_marker_raw_prefix",
    ),
    _CATALOG_GROWTH_BATCH_4_CASES,
)
def test_catalog_growth_batch_4_fires_on_marker_response(
    monkeypatch,
    path: str,
    rule_id: str,
    content_type: str,
    marker_body: str | None,
    marker_raw_prefix: bytes | None,
    non_marker_body: str | None,
    non_marker_raw_prefix: bytes | None,
) -> None:
    del non_marker_body, non_marker_raw_prefix

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(
                path,
                content_type=content_type,
                body_snippet=marker_body,
                raw_body_prefix=marker_raw_prefix,
            )
        ],
    )

    findings = [finding for finding in result.findings if finding.rule_id == rule_id]
    assert len(findings) == 1
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize(
    (
        "path",
        "rule_id",
        "content_type",
        "marker_body",
        "marker_raw_prefix",
        "non_marker_body",
        "non_marker_raw_prefix",
    ),
    _CATALOG_GROWTH_BATCH_4_CASES,
)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_4_does_not_fire_on_blocked_or_missing_status(
    monkeypatch,
    path: str,
    rule_id: str,
    content_type: str,
    marker_body: str | None,
    marker_raw_prefix: bytes | None,
    non_marker_body: str | None,
    non_marker_raw_prefix: bytes | None,
    status_code: int,
) -> None:
    del non_marker_body, non_marker_raw_prefix

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(
                path,
                status_code=status_code,
                content_type=content_type,
                body_snippet=marker_body,
                raw_body_prefix=marker_raw_prefix,
            )
        ],
    )

    assert rule_id not in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    (
        "path",
        "rule_id",
        "content_type",
        "marker_body",
        "marker_raw_prefix",
        "non_marker_body",
        "non_marker_raw_prefix",
    ),
    _CATALOG_GROWTH_BATCH_4_CASES,
)
def test_catalog_growth_batch_4_requires_marker_response(
    monkeypatch,
    path: str,
    rule_id: str,
    content_type: str,
    marker_body: str | None,
    marker_raw_prefix: bytes | None,
    non_marker_body: str | None,
    non_marker_raw_prefix: bytes | None,
) -> None:
    del marker_body, marker_raw_prefix

    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _probe(
                path,
                content_type=content_type,
                body_snippet=non_marker_body,
                raw_body_prefix=non_marker_raw_prefix,
            )
        ],
    )

    assert rule_id not in {finding.rule_id for finding in result.findings}
