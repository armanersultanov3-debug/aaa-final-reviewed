from tests.external_helpers import (
    _analyze_with_probe_attempts,
    _http_redirect_probe,
    _https_probe_with_headers,
    _sensitive_path_probe,
    pytest,
)


_CATALOG_GROWTH_BATCH_1_CASES = [
    (
        "/storage/logs/laravel.log",
        "external.laravel_storage_logs_exposed",
        "[2026-05-13 12:00:00] local.ERROR: RuntimeException: boom",
        "<html>Application home</html>",
    ),
    (
        "/_profiler/empty/search/results?limit=10",
        "external.symfony_profiler_exposed",
        "<title>Profiler</title><div>Symfony-Debug-Toolbar</div>",
        "<html>Application home</html>",
    ),
    (
        "/adminer.php",
        "external.adminer_panel_exposed",
        "<title>Login - Adminer</title>",
        "<html>Database admin</html>",
    ),
    (
        "/phpmyadmin/index.php",
        "external.phpmyadmin_dashboard_exposed",
        "server_sql.php server_status.php server_variables.php server_databases.php",
        "<html>phpMyAdmin login</html>",
    ),
    (
        "/actuator/env",
        "external.springboot_actuator_env_exposed",
        (
            '{"activeProfiles":["prod"],"propertySources":[{"name":"applicationConfig: "'
            ' "[classpath:/application.properties]"}],"server.port":{"value":"8080"}}'
        ),
        '{"message":"ok"}',
    ),
    (
        "/wp-config.php.bak",
        "external.wordpress_wp_config_bak_exposed",
        "<?php define('DB_NAME', 'wordpress'); define('DB_PASSWORD', 'secret');",
        "<?php echo 'ok'; ?>",
    ),
    (
        "/wp-config.php~",
        "external.wordpress_wp_config_tilde_exposed",
        "<?php define('DB_NAME', 'wordpress'); define('DB_PASSWORD', 'secret');",
        "<?php echo 'ok'; ?>",
    ),
    (
        "/searchreplacedb2.php",
        "external.searchreplacedb2_exposed",
        "<h1>Safe Search Replace</h1><p>Database details</p>",
        "<html>Maintenance page</html>",
    ),
    (
        "/webpack.config.js",
        "external.webpack_config_exposed",
        "module.exports = { entry: './src/index.js', output: {} };",
        "const value = 1;",
    ),
    (
        "/webpack.mix.js",
        "external.webpack_mix_exposed",
        "const mix = require('laravel-mix'); mix.js('resources/js/app.js', 'public/js');",
        "const app = require('./app');",
    ),
]


@pytest.mark.parametrize(
    ("path", "rule_id", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_1_CASES,
)
def test_catalog_growth_batch_1_fires_on_marker_body(
    monkeypatch,
    path: str,
    rule_id: str,
    marker_body: str,
    non_marker_body: str,
) -> None:
    del non_marker_body
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_sensitive_path_probe(path, body_snippet=marker_body)],
    )

    findings = [finding for finding in result.findings if finding.rule_id == rule_id]
    assert len(findings) == 1
    assert findings[0].location.target == f"https://example.com{path}"
    assert findings[0].location.details == path


@pytest.mark.parametrize(
    ("path", "rule_id", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_1_CASES,
)
@pytest.mark.parametrize("status_code", [403, 404])
def test_catalog_growth_batch_1_does_not_fire_on_blocked_or_missing_status(
    monkeypatch,
    path: str,
    rule_id: str,
    marker_body: str,
    non_marker_body: str,
    status_code: int,
) -> None:
    del non_marker_body
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[
            _sensitive_path_probe(path, status_code=status_code, body_snippet=marker_body)
        ],
    )

    assert rule_id not in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    ("path", "rule_id", "marker_body", "non_marker_body"),
    _CATALOG_GROWTH_BATCH_1_CASES,
)
def test_catalog_growth_batch_1_requires_marker_body(
    monkeypatch,
    path: str,
    rule_id: str,
    marker_body: str,
    non_marker_body: str,
) -> None:
    del marker_body
    result = _analyze_with_probe_attempts(
        monkeypatch,
        [_https_probe_with_headers(), _http_redirect_probe()],
        sensitive_path_probes=[_sensitive_path_probe(path, body_snippet=non_marker_body)],
    )

    assert rule_id not in {finding.rule_id for finding in result.findings}
