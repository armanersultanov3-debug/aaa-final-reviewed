# Testing Real-World-Like Web Server Configs

This project includes two complementary local validation datasets:

- `demo/real_world_configs/` contains small public-source-derived examples for
  broad analyzer smoke validation across Nginx, Apache, Lighttpd, and IIS.
- `tests/fixtures/webserver-configs/` contains security-focused known-bad and
  known-good fixtures with explicit expected findings for regression tests.

Both datasets are defensive academic validation material for hardening research.
They are not a target list, and they do not require scanning third-party systems.

## Security Corpus Layout

```text
tests/fixtures/webserver-configs/
  nginx/
    vulnerable/
    secure/
  apache/
    vulnerable/
    secure/
  external-targets/
    badssl.json
  metadata/
    cases.json
```

`metadata/cases.json` is the authoritative index. Each case records:

- `id`
- `server_type`
- `profile` (`vulnerable`, `secure`, or `edge-case`)
- `source` and `source_url`
- license or license note
- short description
- fixture entrypoint
- whether the config is original or synthetic-derived
- notes about modifications
- references
- `expected_findings`
- optional `expected_absent_rule_ids`

The fixtures are intentionally small. Where a public repository has no obvious
license, or where the original file is larger than needed, the corpus stores a
small synthetic-derived fixture instead of a verbatim copy.

## Sources Used

The security corpus uses these sources as public references:

- Detectify vulnerable-nginx and Detectify's Nginx misconfiguration research
- Vulhub Nginx insecure-configuration examples
- tkmru Nginx alias traversal sample
- Gixy rule concepts for Nginx misconfiguration analysis
- DevSec nginx-baseline and apache-baseline
- CIS Apache HTTP Server Benchmark as hardening category reference
- OWASP Secure Headers Project
- Apache HTTP Server Security Tips and .htaccess documentation
- Mozilla SSL Configuration Generator
- testssl.sh and SSL Labs Rating Guide for TLS categories
- badssl.com for optional external TLS reference endpoints

## Covered Error Classes

Nginx fixtures cover:

- alias/trailing-slash path mistakes
- proxy blocks missing source IP/protocol forwarding headers
- autoindex enabled
- server token disclosure
- unsafe default server behavior
- sensitive locations missing access restrictions or IP filtering
- missing request rate/connection limits
- missing browser security headers
- weak TLS protocol policy
- missing HTTP/2 on TLS listener
- missing HSTS on TLS listener

Apache fixtures cover:

- `Options Indexes`
- `Options ExecCGI`
- broad `AllowOverride All`
- risky `.htaccess` overrides
- rewrite rules without conditions
- disabled security headers from `.htaccess`
- exposed `server-status`
- `ServerTokens Full` and `ServerSignature On`
- weak TLS protocol/cipher configuration
- TLS compression
- insecure TLS renegotiation

The secure baseline fixtures are positive controls. Tests assert that they do
not produce high or critical findings and that selected known-bad rule IDs stay
absent. They do not require a zero-finding report because the local hardening
rules intentionally include conservative low/medium heuristics.

## Known Reference Gaps

Some source classes are represented as documentation/reference notes, but are
not asserted as expected findings because webconf-audit does not currently have
dedicated local rules for them:

- Nginx CRLF/HTTP response splitting via `return ... $uri`
- user-controlled `proxy_pass` SSRF patterns
- Host header spoofing in local Nginx config
- `merge_slashes off`
- raw backend response reading
- the exact classic Gixy alias traversal shape where `location /static` maps to
  `alias /path/`

These gaps are useful future rule candidates, but tests should not pretend that
the current analyzer detects them.

## Run Static Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_webserver_config_security_corpus.py
```

This runs only local static analyzers against committed fixtures. It does not
make network requests.

To run the broader public-source-derived smoke dataset:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_real_world_config_fixtures.py
```

## Optional External Reference Tests

External reference tests are disabled by default:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/integration_optional_external/test_external_reference_targets.py
```

Expected default result: skipped tests.

To run them intentionally:

```powershell
$env:RUN_EXTERNAL_TESTS = "1"
.\.venv\Scripts\python.exe -m pytest -q tests/integration_optional_external/test_external_reference_targets.py
Remove-Item Env:\RUN_EXTERNAL_TESTS
```

These tests only use `badssl.com` endpoints that exist specifically for TLS
validation, and call `analyze_external_target(..., scan_ports=False)`. Do not add
random public hosts or IP addresses.

## Local Docker Scenarios

The repository already has localhost-only Docker-backed external integration
tests under `tests/integration_external/`. Those tests use local containers and
are separate from the static security corpus above.

If a future fixture needs external-mode validation, prefer a local container in
that integration harness over a public target. Keep the static fixture and
expected local findings in `tests/fixtures/webserver-configs/` so the normal
test suite remains offline.

## Adding a Fixture

1. Add the config under the matching server/profile directory.
2. Add a case entry to `tests/fixtures/webserver-configs/metadata/cases.json`.
3. Use `synthetic-derived` unless you are copying a small file under a clearly
   compatible license.
4. Replace real domains, tokens, credentials, certificates, and private paths
   with placeholders.
5. Run the targeted test and inspect the observed rule IDs.
6. Add only stable expected findings. Do not assert exact total finding counts.
7. For secure baselines, assert absence of selected known-bad rules and rely on
   the high/critical guard instead of expecting zero findings.

Findings are heuristic rule results for hardening research. They are not a final
security verdict on any real deployment.
