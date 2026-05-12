# webconf-audit

A security auditing tool for web server configurations.

`webconf-audit` has two independent analysis modes:

- **Local** — static analysis of configuration files on the host that
  runs the web server.
- **External** — black-box probing of a running web endpoint over the
  network using observable HTTP, HTTPS, and TLS signals.

## Supported servers

Local analysis covers four web servers:

- Nginx
- Apache HTTP Server
- Lighttpd
- Microsoft IIS

External probing is server-agnostic; a few checks are activated only
after fingerprinting identifies the underlying server (for example,
Apache `mod_status` exposure or IIS detailed error pages).

## Installation

`webconf-audit` requires Python 3.10 or later.

```bash
pip install .
```

The package exposes a `webconf-audit` console entry point. Every
command is also available via `python -m webconf_audit.cli`.

## Quick start

### Local analysis

```bash
webconf-audit analyze-nginx /etc/nginx/nginx.conf
webconf-audit analyze-apache /etc/apache2/httpd.conf
webconf-audit analyze-lighttpd /etc/lighttpd/lighttpd.conf
webconf-audit analyze-iis C:\inetpub\wwwroot\web.config
webconf-audit analyze-iis C:\inetpub\wwwroot\web.config --tls-registry schannel.json
```

### External analysis

```bash
webconf-audit analyze-external https://example.com
webconf-audit analyze-external example.com --ports 80,443,8443
webconf-audit analyze-external example.com --no-scan-ports
```

### Output formats

Every `analyze-*` command supports text (default) and JSON output:

```bash
webconf-audit analyze-nginx config.conf --format json
webconf-audit analyze-external example.com -f json
webconf-audit analyze-nginx config.conf --group-by standard
webconf-audit analyze-nginx config.conf --group-repeated
```

The JSON envelope contains a generation timestamp, a summary, the
per-target results, the deduplicated findings list, repeated finding groups
under `finding_groups`, standards references under each finding and the
top-level `standards` summary, and the issues list.

Use `--group-repeated` with text output to collapse repeated findings that
share the same rule, severity, recommendation, and report grouping cause while
preserving each exact source location.

Use `--group-by standard` with text output to review findings by mapped
standards such as CWE, OWASP Top 10, and OWASP ASVS. Findings with no mapped
standard are grouped under `Unmapped`.

### CI gating

Every `analyze-*` command can act as a CI gate with `--fail-on`:

```bash
webconf-audit analyze-nginx nginx.conf --fail-on medium
webconf-audit analyze-external example.com --fail-on high --format json
```

Exit codes in CI-gating mode:

- `0` - analysis completed and no findings at or above the selected severity
  were found.
- `1` - analysis produced an execution or configuration error.
- `2` - analysis completed and at least one finding met the selected severity
  threshold.

JSON findings include a stable `fingerprint` field that is designed for CI,
suppressions, and baseline/diff reporting.

When `--fail-on` is used, `.webconf-audit-ignore.yml` is read from the current
working directory if it exists. Suppressions require `rule_id`, either a
`fingerprint` or locator fields, a human-readable `reason`, and an `expires`
date. Expired suppressions stop hiding findings and are reported as analysis
issues.

```yaml
suppressions:
  - rule_id: nginx.server_tokens_on
    source: nginx.conf
    line: 12
    reason: Accepted for staging until the shared image is rebuilt.
    expires: 2026-05-31
```

Use `--suppressions <path>` to point at a non-default suppression file. Full CI
examples are available in [docs/ci-integration.md](docs/ci-integration.md).

### Baseline and diff mode

Use `--write-baseline` to capture the current accepted finding set:

```bash
webconf-audit analyze-nginx nginx.conf --write-baseline webconf-audit-baseline.json
```

Use `--baseline` to compare a later run against that known state. Text output
shows a short diff summary, and JSON output includes `new_findings`,
`unchanged_findings`, `resolved_findings`, and `suppressed_findings`.

```bash
webconf-audit analyze-nginx nginx.conf --baseline webconf-audit-baseline.json
```

CI can block only new debt with `--fail-on-new` while leaving existing baseline
findings unchanged:

```bash
webconf-audit analyze-nginx nginx.conf --baseline webconf-audit-baseline.json --fail-on-new medium
```

## Local analysis pipeline

Each local analyzer:

1. Reads the main configuration file passed on the command line.
2. Resolves includes or rebuilds the inheritance chain.
3. Builds an effective configuration where the server model
   requires it.
4. Runs server-specific rules over the parsed/effective form.
5. Runs universal rules over a normalized representation shared by
   all four servers.
6. Returns a structured result with findings, technical issues, and
   source metadata.

What each analyzer handles:

- **Nginx** — tokenizer, parser, `include` resolution with glob
  support and cycle detection, AST traversal, source-location
  tracking on every directive.
- **Apache** — `Include` and `IncludeOptional` resolution,
  `.htaccess` discovery from `Directory` blocks and `DocumentRoot`,
  `AllowOverride` filtering, per-`VirtualHost` analysis contexts,
  `Location` and `LocationMatch` layering, header merge semantics.
- **Lighttpd** — variable expansion, `include` resolution,
  `include_shell` handling (skipped with a warning by default, with
  explicit opt-in execution via `--execute-shell`),
  conditional blocks such as `$HTTP["host"] == "..."`, optional
  per-host targeted analysis via `--host`.
- **IIS** — safe XML parsing through `defusedxml`, three-level
  inheritance chain `machine.config` → `applicationHost.config`
  → `web.config`, `<add>` / `<remove>` / `<clear>` collection
  semantics, `<location>` inheritance, `--machine-config` option for
  explicit base config selection, and Windows SChannel TLS registry
  enrichment by default on Windows hosts. Use `--tls-registry <path>`
  for a JSON export from the target IIS server or `--no-tls-registry`
  to disable live registry enrichment.

Each finding records severity, description, remediation hint, and a
source reference: file and line for text configurations, file and XML
path for IIS, observable endpoint or header for external mode.

## External analysis

External mode probes a target without access to its configuration. It
performs:

- Port discovery for bare-host targets (default ports: 80, 443, 8080,
  8443, 8000, 8888, 3000, 5000, 9443; can be overridden with
  `--ports` or disabled with `--no-scan-ports`).
- HTTP and HTTPS probing with `HEAD` → `GET` fallback plus a separate
  `OPTIONS` flow.
- TLS enrichment: negotiated protocol and cipher, supported TLS
  versions, certificate chain completeness, SAN extraction.
- Server fingerprinting from response headers, default error pages,
  and reactions to deliberately malformed requests.
- Sensitive-path probing for paths such as `/.git/HEAD`, `/.env`,
  `/.htaccess`, `/phpinfo.php`, `/web.config`, `/robots.txt`,
  `/sitemap.xml`.
- Redirect chain analysis: loops, scheme switches, off-domain hops.

External rules cover HTTPS availability and HSTS, common security
headers, server identification, cookies, CORS, HTTP methods,
sensitive paths, TLS protocol versions, and certificate validity.

## Rule catalog

The rule catalog is browsable through the CLI:

```bash
webconf-audit list-rules
webconf-audit list-rules --category local --server-type nginx
webconf-audit list-rules --severity high --tag tls
webconf-audit list-rules --format json
```

Filters: `--category` (`local`, `external`, `universal`),
`--server-type` (`nginx`, `apache`, `lighttpd`, `iis`),
`--severity` (`critical`, `high`, `medium`, `low`, `info`),
`--tag`.

Use `--format json` to get a machine-readable inventory with the full
`RuleMeta` payload (rule_id, severity, category, server_type,
input_kind, tags, standards, order, etc.). The full inventory and the
standards mapping plan live in [docs/rule-coverage.md](docs/rule-coverage.md).

The catalog currently contains 373 rules:

| Category | Rules |
|----------|------:|
| Local — Nginx | 83 |
| Local — Apache | 84 |
| Local — Lighttpd | 49 |
| Local — IIS | 52 |
| Universal (local) | 13 |
| External | 92 |

## Reporting

Results are aggregated into a `ReportData` structure with a summary by
severity, analysis mode, server type, and mapped standards. Two output
formatters are available:

- `TextFormatter` — human-readable command-line output.
- `JsonFormatter` — machine-readable output suitable for downstream
  tooling.

Universal rule findings are deduplicated when a more specific
server-specific rule has already reported the same issue at the same
location.

## Demo

A working local-analysis demo with reproducible Docker-based syntax
checks is provided in `demo/local_admin/`. See
[demo/local_admin/README.md](demo/local_admin/README.md) for the
full walkthrough.

A separate defensive validation dataset with public-source-derived config
fixtures lives in [demo/real_world_configs/](demo/real_world_configs/).
Security-focused known-bad/known-good fixture testing is documented in
[docs/testing-real-world-configs.md](docs/testing-real-world-configs.md).

## Roadmap

The current development plan is tracked in
[docs/roadmap.md](docs/roadmap.md).

## Development

Install the development dependency group:

```bash
uv sync --group dev --locked
```

Run the same fast checks as the pull-request CI workflow:

```bash
uv run --locked ruff check .
uv run --locked python -m compileall -q src
uv run --locked pytest tests --ignore=tests/integration_external --ignore=tests/integration_local --ignore=tests/integration_rule_coverage -q
uv run --locked webconf-audit list-rules
```

Run the Docker-backed integration slice when Docker Engine is available:

```bash
uv run --locked pytest tests/integration_external tests/integration_local tests/integration_rule_coverage -q
```
