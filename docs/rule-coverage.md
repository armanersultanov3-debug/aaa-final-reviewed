# Rule Coverage

This document is the inventory and (eventually) standards mapping for every
rule shipped by webconf-audit. It supports Stage 2 of the project roadmap
(standards-driven rule expansion) by giving us a single place to see what we
already cover and where the gaps are.

## How this file is generated

The inventory tables below are derived from the rule registry. To regenerate
them after adding or modifying rules, dump the registry to JSON:

```bash
webconf-audit list-rules --format json > rule-inventory.json
```

The JSON payload contains every RuleMeta field
(`rule_id`, `title`, `severity`, `description`, `recommendation`,
`category`, `server_type`, `input_kind`, `tags`, `condition`, `order`)
and is the source of truth for tooling. The tables here are kept in sync with
that output and may include hand-curated columns (CWE, OWASP, ASVS, CIS) that
the CLI does not own.

A pytest sync check (`tests/test_rule_coverage_doc.py`) runs in CI and fails
if a registered rule is missing from this document, if the document mentions
an unknown rule, or if the `Total rules` / per-group `Count` numbers drift
from the registry. PRs that change the rule registry must also update this
file.

## Summary

Total rules: **303**

| Dimension | Counts |
| --- | --- |
| Category | local (217), external (73), universal (13) |
| Severity | high (15), medium (107), low (170), info (11) |
| Input kind | ast (149), probe (73), effective (56), normalized (13), htaccess (6), mixed (6) |

## Inventory tables

Columns:

- **Rule ID** -- canonical identifier in the registry.
- **Severity** -- default severity assigned to findings produced by the rule.
- **Input** -- RuleMeta.input_kind (data the runner consumes).
- **Tags** -- registry tags used for filtering (`webconf-audit list-rules --tag ...`).
- **CWE / OWASP / ASVS / CIS** -- standards mapping. Filled per server family as
  Stage 2 step 3 progresses. A cell stays empty (`-`) when no honest mapping
  exists; CIS for universal rules delegates to the per-server tables because
  CIS benchmarks are vendor-specific.

### Universal Rules

Count: 13

Stage 2 step 3 mapping: **complete** for this group. CIS / vendor cells say
`_see vendor sections_` because each universal rule reduces to a
server-specific configuration check (Apache, Nginx, Lighttpd, or IIS) and the
matching CIS benchmark item lives in the corresponding server-family table.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `universal.tls_intent_without_config` | high | normalized | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | _see vendor sections_ |
| `universal.weak_tls_protocol` | medium | normalized | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | _see vendor sections_ |
| `universal.weak_tls_ciphers` | medium | normalized | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: conservative cipher-string posture checks) | _see vendor sections_ |
| `universal.missing_hsts` | medium | normalized | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | _see vendor sections_ |
| `universal.missing_x_content_type_options` | low | normalized | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.4 | _see vendor sections_ |
| `universal.missing_x_frame_options` | low | normalized | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | _see vendor sections_ |
| `universal.missing_content_security_policy` | low | normalized | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: presence only) | _see vendor sections_ |
| `universal.missing_referrer_policy` | low | normalized | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | _see vendor sections_ |
| `universal.referrer_policy_unsafe` | low | normalized | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | _see vendor sections_ |
| `universal.permissions_policy_unsafe` | low | normalized | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.6 (related: wildcard / ineffective policy quality) | _see vendor sections_ |
| `universal.directory_listing_enabled` | medium | normalized | access | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | _see vendor sections_ |
| `universal.server_identification_disclosed` | low | normalized | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | _see vendor sections_ |
| `universal.listen_on_all_interfaces` | info | normalized | network | - | - | - | _see vendor sections_ |

Mapping rationale (universal rules):

- `tls_intent_without_config` -- a listener advertises HTTPS but no TLS is
  configured, so traffic would travel in cleartext: CWE-319, OWASP A02
  (cryptographic failures).
- `weak_tls_protocol`, `universal.weak_tls_ciphers` -- enabling
  SSLv2/SSLv3/TLSv1.0/1.1 or weak TLS cipher components is the textbook case
  of CWE-327 (broken / risky cryptographic algorithm), which OWASP groups under
  A02. The cipher rule is a conservative posture check, not just a
  RC4/DES/3DES/MD5 substring match: it also flags concrete cipher-suite
  selectors without forward secrecy or AEAD while deferring full runtime
  negotiation and vendor-specific policy depth to the server sections.
- `missing_hsts` -- without HSTS a site can be downgraded to plain HTTP and
  expose credentials in cleartext (CWE-319). Practitioners normally treat the
  missing header itself as a misconfiguration (A05) rather than a primary
  crypto failure.
- `missing_x_content_type_options`, `missing_content_security_policy` -- both
  are protective response headers; their absence is best modelled as a
  generic protection-mechanism failure (CWE-693). OWASP A05 covers the
  hardening-headers category.
- `missing_x_frame_options` -- direct match for CWE-1021 (improper
  restriction of rendered UI layers / clickjacking).
- `missing_referrer_policy` -- the referrer header has nuanced semantics and
  no single CWE maps cleanly to "policy not set"; we leave CWE empty and keep
  OWASP A05 because the rule is a hardening-config check.
- `referrer_policy_unsafe`, `permissions_policy_unsafe` -- conservative
  quality checks for already-configured hardening headers. They flag weak
  Referrer-Policy values and ineffective / wildcard Permissions-Policy grants
  without trying to become a full per-response browser policy validator.
- `directory_listing_enabled` -- direct match for CWE-548 (exposure of
  information through directory listing). Categorised as A05 (misconfig)
  because the rule fires only when the operator explicitly enables listing.
- `server_identification_disclosed` -- CWE-200 (information exposure) is the
  honest weakness class; OWASP A05 covers it as a hardening item.
- `listen_on_all_interfaces` -- info-only finding describing a deployment
  hint, not a vulnerability. Both CWE and OWASP cells stay empty by design.

### Nginx (Local)

Count: 77

Stage 2 mapping status: **CWE / OWASP complete; CIS existing-rule reference
pass complete** for this group. CIS references come from a full walk-through
of the *CIS NGINX Benchmark v3.0.0* (the `CIS NGINX v3.0.0` source listed on
[cisecurity.org](https://www.cisecurity.org/benchmark/nginx)). Cells that
remain empty under `CIS / Vendor` describe rules that are operational
anti-patterns, deprecated controls, or scoped narrower / wider than any
specific CIS recommendation; the gap table after the rationale lists what
the benchmark covers but webconf-audit does not.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `nginx.alias_without_trailing_slash` | medium | ast | - | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - | - |
| `nginx.allow_all_with_deny_all` | medium | ast | - | [CWE-863](https://cwe.mitre.org/data/definitions/863.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - | - |
| `nginx.auth_basic_over_http` | medium | ast | auth, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | - |
| `nginx.autoindex_on` | medium | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | - |
| `nginx.content_security_policy_missing_reporting_endpoint` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.7 (partial: reporting endpoint directive only) | CIS NGINX v3.0.0 §5.3.2 (partial: CSP reporting endpoint only) |
| `nginx.content_security_policy_unsafe` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: baseline directives and unsafe script tokens only) | CIS NGINX v3.0.0 §5.3.2 (partial: baseline policy quality checks) |
| `nginx.default_server_not_rejecting_unknown_hosts` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §2.4.2 (partial: validates configured `default_server` rejection behavior) |
| `nginx.duplicate_listen` | low | ast | - | - | - | - | - |
| `nginx.error_log_too_restrictive` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.3 (partial: detects `/dev/null` and overly restrictive levels) |
| `nginx.executable_scripts_allowed_in_uploads` | medium | ast | - | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | [A04:2021](https://owasp.org/Top10/A04_2021-Insecure_Design/) | - | - |
| `nginx.http_method_policy_allows_unapproved` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §5.1.2 (partial: detects unsafe explicit `limit_except` allowlists) |
| `nginx.if_in_location` | low | ast | - | - | - | - | - |
| `nginx.missing_access_log` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.2 |
| `nginx.missing_access_restrictions_on_sensitive_locations` | low | ast | - | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - | CIS NGINX v3.0.0 §5.1.1 (partial: detects any access control on sensitive paths, not specifically `allow`/`deny` IP filters) |
| `nginx.missing_allowed_methods_restriction_for_uploads` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §5.1.2 (partial: scoped to upload-like locations) |
| `nginx.missing_auth_basic_user_file` | medium | ast | - | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | - |
| `nginx.missing_backup_file_deny` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `nginx.missing_client_body_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §5.2.1 (partial: directive presence only; does not validate benchmark timeout value) |
| `nginx.missing_client_header_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §5.2.1 (partial: directive presence only; does not validate benchmark timeout value) |
| `nginx.missing_client_max_body_size` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.2 (partial: directive presence only; does not validate benchmark size policy) |
| `nginx.missing_content_security_policy` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: presence only) | CIS NGINX v3.0.0 §5.3.2 (partial: presence only) |
| `nginx.missing_error_log` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.3 (partial: directive presence; does not validate `info` log level) |
| `nginx.missing_generated_artifact_deny` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §2.5.3 (partial: generated/dependency artifact deny-list coverage beyond VCS metadata) |
| `nginx.missing_hidden_files_deny` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §2.5.3 |
| `nginx.missing_hsts_header` | medium | ast | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS NGINX v3.0.0 §4.1.8 (partial: header presence only; does not validate HSTS policy value) |
| `nginx.hsts_header_unsafe` | medium | ast | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 (partial: local max-age / includeSubDomains validation) | CIS NGINX v3.0.0 section 4.1.8 (partial: local HSTS policy value check) |
| `nginx.missing_http2_on_tls_listener` | low | ast | - | - | - | - | - |
| `nginx.missing_http_method_restrictions` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §5.1.2 (partial: scoped to sensitive locations and `limit_except`, not a full approved-method policy) |
| `nginx.missing_http_to_https_redirect` | low | ast | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 (partial: named HTTP server blocks only) | CIS NGINX v3.0.0 §4.1.1 (partial: local redirect directive check) |
| `nginx.missing_keepalive_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §2.4.3 (partial: directive presence; does not validate `<= 10` value) |
| `nginx.missing_limit_conn` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.4 (partial: directive presence only; does not validate per-IP key or numeric limit) |
| `nginx.missing_limit_conn_zone` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.4 (supporting directive; presence only) |
| `nginx.missing_limit_req` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.5 (partial: directive presence only; does not validate per-IP key or rate policy) |
| `nginx.missing_limit_req_zone` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.5 (supporting directive; presence only) |
| `nginx.limit_conn_invalid_limit` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.4 |
| `nginx.limit_conn_zone_not_per_ip` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.4 |
| `nginx.limit_req_unknown_zone` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.5 |
| `nginx.limit_req_zone_invalid_rate` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.5 |
| `nginx.limit_req_zone_not_per_ip` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.5 |
| `nginx.log_format_missing_fields` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.1 (partial: validates recommended field presence) |
| `nginx.missing_log_format` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.1 (partial: named custom log_format references; does not validate detailed log fields) |
| `nginx.missing_permissions_policy` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `nginx.permissions_policy_unsafe` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.6 (related: wildcard / ineffective policy quality) | - |
| `nginx.missing_referrer_policy` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | CIS NGINX v3.0.0 §5.3.3 (partial: header presence only; does not validate policy value) |
| `nginx.missing_send_timeout` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §2.4.4 (partial: directive presence; does not validate `<= 10` value) |
| `nginx.missing_server_name` | low | ast | - | - | - | - | - |
| `nginx.missing_ssl_certificate` | low | ast | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | - |
| `nginx.missing_ssl_certificate_key` | low | ast | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | - |
| `nginx.ssl_ciphers_weak` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: conservative local cipher-string posture checks) | CIS NGINX v3.0.0 §4.1.5 (partial: weak components plus explicit FS / AEAD posture; not full SSL Labs validation) |
| `nginx.ssl_conf_command_tls_compression_enabled` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.5 (partial: explicit local OpenSSL option only) | NIST SP 800-52 Rev. 2 §3.6 (partial: local `ssl_conf_command Options Compression` only) |
| `nginx.ssl_conf_command_unsafe_renegotiation_enabled` | high | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.5 (partial: explicit local OpenSSL option only) | NIST SP 800-52 Rev. 2 §3.5 (partial: local `ssl_conf_command Options UnsafeLegacyRenegotiation` only) |
| `nginx.missing_ssl_ciphers` | medium | ast | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS NGINX v3.0.0 §4.1.5 (partial: directive presence; does not validate cipher list against the benchmark recommendation) |
| `nginx.missing_ssl_protocols` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 (partial: protocol policy presence only) | CIS NGINX v3.0.0 §4.1.4 (partial: directive presence; weak values handled by `nginx.weak_ssl_protocols`) |
| `nginx.missing_ssl_prefer_server_ciphers` | low | ast | - | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | - |
| `nginx.missing_x_content_type_options` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.4 | CIS NGINX v3.0.0 §5.3.1 |
| `nginx.missing_x_frame_options` | low | ast | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `nginx.missing_x_xss_protection` | low | ast | headers | - | - | - | - |
| `nginx.proxy_missing_source_ip_headers` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS NGINX v3.0.0 §3.4 (partial: `proxy_pass` source header forwarding) |
| `nginx.referrer_policy_unsafe` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 (partial: value and `always` checks) | CIS NGINX v3.0.0 §5.3.3 (partial: policy value and `always`) |
| `nginx.ssl_session_cache_missing` | low | ast | tls | - | - | - | CIS NGINX v3.0.0 §4.1.10 (partial: local `ssl_session_cache` presence / disabled-state check) |
| `nginx.ssl_session_timeout_missing_or_invalid` | low | ast | tls | - | - | - | CIS NGINX v3.0.0 §4.1.9 (partial: explicit non-zero timeout of 10 minutes or less) |
| `nginx.sensitive_location_missing_ip_filter` | low | ast | - | [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | [A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) | - | CIS NGINX v3.0.0 §5.1.1 (partial: validates restrictive `allow`/`deny` IP filters on sensitive paths that already have an access control, including `satisfy any` auth bypasses) |
| `nginx.server_tokens_on` | low | ast | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS NGINX v3.0.0 §2.5.1 |
| `nginx.ssl_stapling_missing_resolver` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §4.1.7 (partial: resolver presence requirement only) |
| `nginx.ssl_stapling_without_verify` | low | ast | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS NGINX v3.0.0 §4.1.7 (partial: stapling verification requirement) |
| `nginx.weak_ssl_protocols` | medium | ast | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS NGINX v3.0.0 §4.1.4 |
| `nginx.client_body_timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §5.2.1 (partial: validates global/server timeout values; scoped upload-location exceptions remain operator policy) |
| `nginx.client_header_timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §5.2.1 |
| `nginx.keepalive_timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §2.4.3 |
| `nginx.send_timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS NGINX v3.0.0 §2.4.4 |
| `nginx.client_max_body_size_unlimited` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 §5.2.2 (partial: detects disabled body-size enforcement, not application-specific maximums) |
| `nginx.client_max_body_size_too_large` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 section 5.2.2 (partial: conservative over-100 MB signal; application-specific upload policy remains operator-owned) |
| `nginx.client_header_buffer_size_too_large` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 section 5.2.3 (partial: conservative request-header buffer allocation signal) |
| `nginx.ssl_session_tickets_disabled` | low | ast | - | - | - | - | CIS NGINX v3.0.0 §4.1.11 |
| `nginx.large_client_header_buffers_too_restrictive` | low | ast | - | - | - | - | CIS NGINX v3.0.0 §5.2.3 (partial: detects values below the default 4 8k; documented lower limits remain operator policy) |
| `nginx.large_client_header_buffers_too_large` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS NGINX v3.0.0 section 5.2.3 (partial: conservative count / size / total allocation thresholds) |
| `nginx.ssl_stapling_disabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §4.1.7 (detects missing or off `ssl_stapling` in TLS server blocks) |

Mapping rationale (nginx rules):

- `alias_without_trailing_slash` -- a misconfigured `alias` allows path
  traversal outside the intended root: CWE-22 (path traversal), OWASP A01.
- `allow_all_with_deny_all` -- conflicting `allow all` / `deny all` directives
  let nginx pick the first match, so the intended access rules can be
  bypassed: CWE-863 (incorrect authorization), OWASP A01.
- `autoindex_on` -- direct match for CWE-548; categorised as A05 because the
  default is safe and the operator must explicitly enable listing.
- `duplicate_listen`, `if_in_location`, `missing_http2_on_tls_listener`,
  `missing_server_name` -- operational anti-patterns and best-practice
  hints, not vulnerabilities; CWE/OWASP cells stay empty.
- `default_server_not_rejecting_unknown_hosts` -- a default virtual host that
  serves unknown names can expose the wrong application or default content.
  This is best represented as OWASP A05 hardening rather than a precise CWE.
- `executable_scripts_allowed_in_uploads` -- upload directories that also
  serve PHP/CGI are the textbook CWE-434 (unrestricted upload of dangerous
  file types). Categorised as OWASP A04 (insecure design): the issue is the
  combination of upload + script execution, not a single misconfig.
- `missing_access_log`, `missing_error_log`, `missing_log_format`,
  `error_log_too_restrictive`, `log_format_missing_fields`,
  `proxy_missing_source_ip_headers` -- without useful logs and source-IP
  context you cannot detect or investigate attacks: CWE-778, OWASP A09.
- `missing_access_restrictions_on_sensitive_locations` -- /admin, /private,
  /backup left open to the public: CWE-284 (improper access control),
  OWASP A01.
- `missing_allowed_methods_restriction_for_uploads`,
  `missing_http_method_restrictions` -- not pinning the allowed HTTP methods
  exposes CWE-650 (trusting HTTP permission methods), tracked as
  OWASP A05.
- `missing_auth_basic_user_file` -- enabling `auth_basic` without
  `auth_basic_user_file` leaves the location effectively unauthenticated:
  CWE-287 (improper authentication), OWASP A07.
- `missing_backup_file_deny`, `missing_hidden_files_deny`,
  `missing_generated_artifact_deny` -- direct match for CWE-538
  (file/directory information exposure); OWASP A05.
- `missing_client_body_timeout`, `missing_client_header_timeout`,
  `missing_keepalive_timeout`, `missing_send_timeout` -- absence of
  per-connection timeouts lets slow-loris-style clients hold sockets open
  forever: CWE-400 (uncontrolled resource consumption). OWASP cells empty
  because the 2021 Top 10 has no clean home for DoS hardening.
- `client_body_timeout_too_high`, `client_header_timeout_too_high`,
  `keepalive_timeout_too_high`, `send_timeout_too_high` -- overly high
  timeout values keep slow connections open longer than the CIS hardening
  guidance recommends: CWE-400. OWASP cells empty for the same DoS-hardening
  reason.
- `missing_client_max_body_size`, `missing_limit_conn`, `missing_limit_conn_zone`,
  `missing_limit_req`, `missing_limit_req_zone`,
  `client_max_body_size_unlimited`, `client_max_body_size_too_large`,
  `client_header_buffer_size_too_large`, `large_client_header_buffers_too_large`,
  `limit_conn_invalid_limit`, `limit_conn_zone_not_per_ip`,
  `limit_req_unknown_zone`, `limit_req_zone_invalid_rate`,
  `limit_req_zone_not_per_ip` -- no upper
  bound / rate limit on bodies, connections, or requests: CWE-770 (allocation
  without limits or throttling). OWASP cells empty for the same reason.
- `missing_content_security_policy`, `content_security_policy_unsafe`,
  `content_security_policy_missing_reporting_endpoint`,
  `missing_x_content_type_options`, `missing_permissions_policy` --
  protective response headers; CWE-693 (protection mechanism failure),
  OWASP A05.
- `auth_basic_over_http` -- Basic authentication on a plain HTTP
  content-serving scope sends reusable credentials without transport
  confidentiality: CWE-319, OWASP A02.
- `missing_hsts_header`, `hsts_header_unsafe` -- missing HSTS or a short /
  incomplete HSTS policy allows downgrade to HTTP: CWE-319, OWASP A05.
- `missing_http_to_https_redirect` -- leaving a named HTTP virtual host
  reachable without an HTTPS redirect keeps a cleartext channel available:
  CWE-319, OWASP A02.
- `missing_referrer_policy`, `referrer_policy_unsafe` -- as in the universal
  table, no clean CWE maps to "policy not set" or to every unsafe policy
  value; we only keep OWASP A05.
- `missing_ssl_certificate`, `missing_ssl_certificate_key` -- listening on
  443 with `ssl` but no cert / key configured leaves the listener unable to
  establish TLS, so HTTPS to it fails: CWE-319, OWASP A02. As with the
  lighttpd `ssl_pemfile_missing` rule, the failure mode is connection
  refusal, not silent downgrade.
- `missing_ssl_ciphers`, `missing_ssl_protocols` -- relying on the OpenSSL
  default cipher list or implicit TLS protocol defaults can keep weak
  cryptographic posture available on older builds: CWE-327, OWASP A02.
- `missing_ssl_prefer_server_ciphers` -- letting the client drive cipher
  selection enables downgrade attacks: CWE-757 (less-secure algorithm during
  negotiation), OWASP A02.
- `missing_x_frame_options` -- direct match for CWE-1021 (clickjacking),
  OWASP A05.
- `missing_x_xss_protection` -- the X-XSS-Protection header is deprecated and
  modern browsers ignore it; we keep the rule for legacy hardening but leave
  CWE/OWASP empty rather than mapping to controls that no longer apply.
- `server_tokens_on` -- nginx version disclosure: CWE-200, OWASP A05.
- `ssl_stapling_disabled` -- a TLS server block without `ssl_stapling on`
  silently skips OCSP stapling, leaving clients to fetch revocation status
  themselves; the CIS guidance treats this as a hardening misconfig, so CWE
  stays empty and OWASP A05 covers it.
- `ssl_stapling_missing_resolver` -- enabling `ssl_stapling` without a
  resolver silently disables stapling, but it is a configuration mistake
  rather than a vulnerability class; CWE empty, OWASP A05 (misconfig).
- `ssl_stapling_without_verify` -- accepting OCSP responses without
  validation is CWE-295 (improper certificate validation), OWASP A02.
- `weak_ssl_protocols` -- SSLv2 / SSLv3 / TLSv1.0 / TLSv1.1 are textbook CWE-327,
  OWASP A02 (matches the universal `weak_tls_protocol` rule).
- `large_client_header_buffers_too_restrictive` -- values below the
  Nginx default can reject legitimate request URIs or headers; this is an
  availability / compatibility hardening signal, so CWE and OWASP stay empty.
- `ssl_session_tickets_disabled` -- explicitly disabling TLS 1.3 session
  tickets breaks the CIS session-resumption recommendation, but it is not a
  weakness class by itself; CWE and OWASP stay empty.
- `ssl_session_cache_missing`, `ssl_session_timeout_missing_or_invalid` --
  explicit TLS session cache and timeout policy are benchmark hardening
  posture rather than direct weakness classes; CWE and OWASP stay empty.
- `ssl_conf_command_tls_compression_enabled`,
  `ssl_conf_command_unsafe_renegotiation_enabled` -- explicit OpenSSL
  `ssl_conf_command Options` settings that re-enable TLS compression or unsafe
  legacy renegotiation weaken the TLS channel: CWE-327, OWASP A02.

Nginx CIS v3.0.0 gap table:

| CIS section | Gap type | Current coverage / follow-up |
| --- | --- | --- |
| §1.1.1, §1.2.1, §1.2.2 | `out-of-scope` | Installation, repository, and package-version posture need host/package-manager inventory, which is outside web-server config / safe external analysis. |
| §2.1.1 | `research` | Dynamic module minimization needs an allowed-module policy before a rule can decide which `load_module` entries are unnecessary. |
| §2.2.1-§2.2.3 | `out-of-scope` | Service-account user, lock state, and shell require OS account inspection, which is outside the tool scope. |
| §2.3.1-§2.3.3 | `out-of-scope` | Ownership, permissions, and PID-file checks require filesystem metadata, which is outside the tool scope. |
| §2.4.1 | `research` | Authorized listening ports require an environment-specific approved-port policy. |
| §2.4.2 | `manual-context` | Current coverage validates configured `default_server` rejection behavior through `return 400`/`403`/`404`/`444` or `ssl_reject_handshake on`; absent-default-server policy and runtime invalid-Host behavior remain environment-specific. |
| §2.5.2 | `probe-depth` | Default error and index page content needs response-body probing or filesystem content inspection. |
| §2.5.4 | `parser-depth` | Reverse-proxy disclosure checks need proxy-header semantics beyond the current generic header rules. |
| §3.1 | `manual-context` | Current coverage validates named custom `log_format` references and recommended request/source/status/user-agent fields on referenced formats. Plain `access_log` entries that use Nginx's default format are not flagged; organisation-specific JSON/escape policy remains manual. |
| §3.3 | `manual-context` | Current coverage checks `error_log` presence and flags `/dev/null` plus overly restrictive `error`/`crit`/`alert`/`emerg` levels; final `warn`/`notice`/`info` level choice remains policy. |
| §3.4 | `parser-depth` | Current coverage checks common `proxy_pass` source-IP headers; FastCGI, gRPC, trust-chain, and privacy semantics remain follow-up parser/effective-config work. |
| §4.1.1 | `probe-depth` | Current coverage checks named local HTTP server blocks that redirect with `return` to HTTPS; runtime redirect probes can corroborate later. |
| §4.1.2 | `probe-depth` | Trusted certificate and chain validation is runtime/certificate data, not fully knowable from local `ssl_certificate` paths alone. |
| §4.1.3 | `out-of-scope` | Private-key permission checks require filesystem metadata, which is outside web-server config / safe external analysis. |
| §4.1.5 | `direct-rule` | Covered by `nginx.missing_ssl_ciphers` plus `nginx.ssl_ciphers_weak` for conservative weak-component / FS / AEAD cipher-string posture; runtime negotiation and full SSL Labs-style validation remain out of scope for local-only analysis. |
| §4.1.6 | `research` | TLS 1.3 Diffie-Hellman awareness is mostly operational guidance; define a scanner signal before adding a rule. |
| §4.1.9, §4.1.10 | `direct-rule` | Covered by `nginx.ssl_session_timeout_missing_or_invalid` and `nginx.ssl_session_cache_missing` for local `http` / `server` scopes; upstream proxy TLS trust checks need their own benchmark mapping if added later. |
| §4.1.12 | `research` | HTTP/3 configuration is version/build dependent; define supported directive signals before mapping it. |
| §5.1.1 | `manual-context` | Current coverage checks missing sensitive-location access controls and flags non-IP controls, deny-only exclusions, and `satisfy any` auth bypasses that lack an effective restrictive `allow`/`deny all` policy. Full coverage still depends on the operator's sensitive-path catalogue and runtime location matching. |
| §5.1.2 | `direct-rule` | Current coverage checks missing sensitive/upload-like `limit_except` blocks and unsafe explicit `limit_except` allowlists. Remaining work needs a site-wide approved-method policy model plus equivalent `if`/`map`/`return` patterns. |
| §5.2.4-§5.2.5 | `manual-context` | Current connection/rate-limit rules now check presence, defined zones, per-IP keys, positive connection limits, and positive request rates; remaining CIS judgment is whether the chosen values and application scopes are reasonable for the deployment. |
| §5.3.2, §5.3.3 | `manual-context` | Current coverage checks CSP/Referrer-Policy presence plus baseline CSP directives, unsafe script tokens, Referrer-Policy values, and `always`; full app-specific CSP semantics remain manual. |
| §6 | `out-of-scope` | The benchmark reserves Mandatory Access Control and points to OS/IdP/application sources rather than an Nginx config check. |

### Apache (Local)

Count: 70

Stage 2 mapping status: **CWE / OWASP complete; CIS existing-rule reference
pass complete** for this group. CIS references come from a full walk-through
of the *CIS Apache HTTP Server 2.4 Benchmark v2.3.0* (the Apache HTTP Server
source listed on
[cisecurity.org](https://www.cisecurity.org/benchmark/apache_http_server)).
Cells that remain empty under `CIS / Vendor` describe rules that are
operational anti-patterns, deprecated controls, or scoped narrower / wider
than any specific CIS recommendation; the gap table after the rationale lists
what the benchmark covers but webconf-audit does not. Rules that are
best-practice / organisational (e.g. demanding explicit `AllowOverride`,
requiring `ErrorDocument`) leave CWE empty when no clean weakness class fits,
and `htaccess_*` rules are typed to the override-driven weakness they create
rather than to ".htaccess" itself.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `apache.allowoverride_all_in_directory` | medium | ast | - | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §4.4 (partial: detects broad or inherited `AllowOverride`, not full `AllowOverride None` policy for every directory) |
| `apache.allowoverride_not_none` | medium | ast | - | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §4.3/§4.4 (partial: validates OS-root baseline presence and explicit non-`None` Directory scopes) |
| `apache.basic_auth_over_http` | medium | ast | auth, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | - |
| `apache.backup_temp_files_not_restricted` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.13 (partial: common backup/temp file patterns only) |
| `apache.content_security_policy_missing_reporting_endpoint` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.7 (partial: reporting endpoint directive only) | - |
| `apache.custom_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.3 (partial: `CustomLog` presence only; does not validate log format or destination policy) |
| `apache.directory_without_allowoverride` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §4.4 (partial: explicitness heuristic; does not require `AllowOverride None`) |
| `apache.error_document_404_missing` | low | ast | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `apache.error_document_500_missing` | low | ast | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `apache.error_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.1 (partial: `ErrorLog` presence only; does not validate filename or severity level) |
| `apache.error_log_unsafe_destination` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.1 (partial: detects `/dev/null` or missing `ErrorLog` destination) |
| `apache.generated_artifacts_not_restricted` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: generated/dependency artifact deny-list coverage) |
| `apache.ht_files_not_restricted` | medium | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: `.ht*` deny-list coverage) |
| `apache.htaccess_auth_without_require` | medium | htaccess | htaccess | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | - |
| `apache.htaccess_disables_security_headers` | medium | htaccess | htaccess, headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.16/§5.17/§5.18/§7.11 (partial: detects `.htaccess` unsetting selected security headers, not full header policy configuration) |
| `apache.htaccess_enables_cgi` | medium | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.3 (partial: `.htaccess`-driven `ExecCGI`, not full Options minimization) |
| `apache.htaccess_enables_directory_listing` | medium | htaccess | htaccess | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: `.htaccess`-driven directory listing, not full Options policy) |
| `apache.htaccess_contains_security_directive` | medium | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §4.4 (partial: `.htaccess` governance signal, not direct `AllowOverride None` validation) |
| `apache.htaccess_rewrite_without_limit` | low | htaccess | htaccess | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `apache.htaccess_weakens_security` | high | mixed | htaccess | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §8.2 (partial: `.htaccess` can re-enable signature disclosure; not the primary directive check) |
| `apache.index_options_fancyindexing_enabled` | low | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: directory-listing detail option only) |
| `apache.index_options_scanhtmltitles_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: directory-listing detail option only) |
| `apache.limit_request_body_missing_or_invalid` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §10.4 |
| `apache.limit_request_fields_missing_or_invalid` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §10.2 |
| `apache.log_format_missing_fields` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.3 (partial: named `LogFormat` field coverage for used formats) |
| `apache.log_level_too_restrictive` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.1 (partial: flags explicit overly restrictive `LogLevel`) |
| `apache.missing_log_format` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §6.3 (partial: named `CustomLog` format definition coverage) |
| `apache.options_execcgi_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: specific `Options ExecCGI` token only) |
| `apache.options_includes_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: specific `Options Includes` token only) |
| `apache.options_indexes` | medium | ast | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: specific `Options Indexes` token only) |
| `apache.options_multiviews_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.1/§5.2/§5.3 (partial: specific `Options MultiViews` token only) |
| `apache.server_info_exposed` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | CIS Apache HTTP Server 2.4 v2.3.0 §2.8 (partial: detects exposed `/server-info`, not loaded-module inventory) |
| `apache.server_signature_not_off` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Apache HTTP Server 2.4 v2.3.0 §8.2 |
| `apache.server_status_exposed` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | CIS Apache HTTP Server 2.4 v2.3.0 §2.4 (partial: detects exposed `/server-status`, not loaded-module inventory) |
| `apache.server_tokens_not_prod` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Apache HTTP Server 2.4 v2.3.0 §8.1 (partial: enforces `Prod`; benchmark also allows `ProductOnly`) |
| `apache.sensitive_config_files_not_restricted` | low | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: config/data/temp extension deny-list coverage) |
| `apache.trace_enable_not_off` | low | ast | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.4 | CIS Apache HTTP Server 2.4 v2.3.0 §5.8 |
| `apache.http_protocol_options_unsafe` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.9 |
| `apache.listen_requires_explicit_address` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.15 |
| `apache.ip_based_requests_allowed` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.14 (partial: top-level `ServerName` rewrite policy signal only) |
| `apache.default_tls_vhost_not_rejecting_unknown_hosts` | low | ast | tls | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.14 (partial: first/default TLS VirtualHost catch-all rejection only) |
| `apache.vcs_metadata_not_restricted` | medium | ast | - | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.1 | CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: `.git` / `.svn` deny-list coverage) |
| `apache.file_etag_inodes` | low | ast | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §8.4 |
| `apache.timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §9.1 (partial: explicit directive values only) |
| `apache.keepalive_disabled` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §9.2 (partial: explicit directive values only) |
| `apache.max_keepalive_requests_too_low` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §9.3 (partial: explicit directive values only) |
| `apache.keepalive_timeout_too_high` | low | ast | - | [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §9.4 (partial: explicit directive values only) |
| `apache.limit_request_line_too_high` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §10.1 (partial: explicit directive values only) |
| `apache.limit_request_field_size_too_high` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §10.3 (partial: explicit directive values only) |
| `apache.missing_x_frame_options_header` | low | ast | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.16 |
| `apache.x_frame_options_unsafe` | low | ast | headers | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.16 (partial: validates `DENY` / `SAMEORIGIN` values) |
| `apache.missing_referrer_policy_header` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | CIS Apache HTTP Server 2.4 v2.3.0 §5.17 |
| `apache.referrer_policy_unsafe` | low | ast | headers | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 (partial: value check only) | CIS Apache HTTP Server 2.4 v2.3.0 §5.17 (partial: validates `no-referrer` / `strict-origin-when-cross-origin` values) |
| `apache.missing_permissions_policy_header` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.18 (presence only; policy value remains application-specific) |
| `apache.permissions_policy_unsafe` | low | ast | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.18 (partial: flags wildcard feature grants; detailed allowlist choices remain application-specific) |
| `apache.missing_http_method_restrictions` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.7 (partial: sensitive `Location` / `LocationMatch` scopes only) |
| `apache.http_method_policy_allows_unapproved` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §5.7 (partial: explicit method allowlists only) |
| `apache.ssl_protocol_missing_or_weak` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS Apache HTTP Server 2.4 v2.3.0 §7.1 (partial: local `SSLProtocol` presence and weak-version checks) |
| `apache.ssl_cipher_suite_missing` | low | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: cipher policy presence only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.4 (partial: `SSLCipherSuite` presence only) |
| `apache.ssl_cipher_suite_weak` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: weak-pattern detection only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.4 (partial: weak local cipher components; does not prove full benchmark cipher posture) |
| `apache.ssl_honor_cipher_order_not_on` | medium | ast | tls | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: server preference only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.5 |
| `apache.ssl_compression_enabled` | medium | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §7.6 |
| `apache.ssl_insecure_renegotiation_enabled` | high | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Apache HTTP Server 2.4 v2.3.0 §7.7 |
| `apache.ssl_use_stapling_not_on` | low | ast | tls | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-12.1.4 (partial: local directive only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.10 (partial: `SSLUseStapling` only) |
| `apache.ssl_stapling_cache_missing` | low | ast | tls | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-12.1.4 (partial: local cache directive only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.10 (partial: cache presence when stapling is enabled) |
| `apache.ssl_session_cache_missing` | low | ast | tls | - | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §7.12 (partial: `SSLSessionCache` presence / disabled-state check) |
| `apache.ssl_session_cache_timeout_missing_or_invalid` | low | ast | tls | - | - | - | CIS Apache HTTP Server 2.4 v2.3.0 §7.12 (partial: `SSLSessionCacheTimeout` presence and maximum value) |
| `apache.missing_hsts_header` | medium | ast | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS Apache HTTP Server 2.4 v2.3.0 §7.11 (partial: `Header always` presence on detected TLS scopes) |
| `apache.hsts_header_unsafe` | medium | ast | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 (partial: local max-age / includeSubDomains validation) | CIS Apache HTTP Server 2.4 v2.3.0 section 7.11 (partial: local HSTS policy value check; preload remains an operator policy choice) |
| `apache.missing_http_to_https_redirect` | low | ast | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 (partial: matching named VirtualHosts only) | CIS Apache HTTP Server 2.4 v2.3.0 §7.1 (partial: local redirect directive check) |

Mapping rationale (apache rules):

- `allowoverride_all_in_directory`, `allowoverride_not_none` -- broad,
  inherited, missing OS-root, or explicit non-`None` `AllowOverride` settings
  let `.htaccess` files grant or weaken authorization, mod_rewrite, or
  options: CWE-732 (incorrect permission assignment for critical resource),
  OWASP A05.
- `backup_temp_files_not_restricted`, `ht_files_not_restricted`,
  `generated_artifacts_not_restricted`,
  `sensitive_config_files_not_restricted`, `vcs_metadata_not_restricted` --
  no deny-list for backup/temp files, `.ht*` files, generated/dependency
  artifacts, VCS metadata, or sensitive config/data extensions can expose
  static files that should never be served:
  CWE-538 / CWE-540, OWASP A05.
- `custom_log_missing`, `error_log_missing`, `error_log_unsafe_destination`,
  `log_level_too_restrictive`, `missing_log_format`,
  `log_format_missing_fields` -- absent, discarded, overly quiet, undefined,
  or low-detail logs defeat incident response: CWE-778 (insufficient logging),
  OWASP A09.
- `directory_without_allowoverride` -- a `<Directory>` block without an
  explicit `AllowOverride` makes the override behaviour depend on
  inherited / default settings, which is a maintainability and review hazard
  rather than a weakness class. CWE empty, OWASP A05 (best-practice
  misconfig).
- `error_document_404_missing`, `error_document_500_missing` -- without a
  custom `ErrorDocument`, Apache renders the default page that may include
  build / module details: CWE-209 (information exposure through an error
  message), OWASP A05.
- `htaccess_auth_without_require` -- declaring `AuthType` / `AuthName`
  without a matching `Require` leaves the realm effectively open: CWE-287
  (improper authentication), OWASP A07.
- `htaccess_disables_security_headers` -- `Header unset` against security
  response headers turns the protection off: CWE-693 (protection mechanism
  failure), OWASP A05.
- `missing_x_frame_options_header`, `x_frame_options_unsafe` -- absent or
  obsolete frame embedding policy leaves the application frameable by hostile
  pages: CWE-1021, OWASP A05.
- `missing_referrer_policy_header`, `referrer_policy_unsafe` -- Referrer-Policy
  is a hardening header with nuanced privacy tradeoffs, so CWE stays empty and
  OWASP A05 covers the configuration weakness.
- `missing_permissions_policy_header`, `permissions_policy_unsafe` -- absent
  or overly broad Permissions-Policy leaves browser feature access governed by
  defaults or wildcard grants rather than explicit least-privilege policy:
  CWE-693, OWASP A05.
- `htaccess_enables_cgi`, `options_execcgi_enabled`, `options_includes_enabled`
  -- enabling CGI / SSI from `.htaccess` or `Options` is an attack-surface
  increase, not a textbook weakness class. CWE empty, OWASP A05.
- `htaccess_enables_directory_listing`, `index_options_fancyindexing_enabled`,
  `options_indexes` -- direct match for CWE-548 (directory listing); OWASP
  A05.
- `htaccess_contains_security_directive` -- moving security directives into
  `.htaccess` instead of the main config is a governance / review issue, not
  a weakness class. CWE empty, OWASP A05.
- `htaccess_rewrite_without_limit` -- `RewriteRule` without a guarding
  `RewriteCond` is a heuristic for rewrite logic that may run more broadly
  than intended; we keep CWE empty because the practical risk is
  case-by-case, OWASP A05 (best-practice misconfig).
- `htaccess_weakens_security` -- `.htaccess` re-enables `ServerSignature`
  after the main config disabled it: CWE-200 (information exposure),
  OWASP A05.
- `index_options_scanhtmltitles_enabled` -- enables Apache to scan HTML
  files for titles when rendering a directory listing; only matters once
  listing is already on, so we keep CWE empty and tag OWASP A05.
- `limit_request_body_missing_or_invalid`, `limit_request_fields_missing_or_invalid`
  -- absence of `LimitRequestBody` / `LimitRequestFields`, `0`, invalid
  values, or values above the CIS limit lets clients send arbitrarily large
  bodies or header lists: CWE-770 (allocation of resources without limits or
  throttling). OWASP empty (no clean DoS-hardening home in the 2021 Top 10).
- `options_multiviews_enabled` -- content negotiation can expose unintended
  files (e.g. backup variants), but this is about default behaviour rather
  than a single weakness; CWE empty, OWASP A05.
- `server_info_exposed`, `server_status_exposed`,
  `server_signature_not_off`, `server_tokens_not_prod` -- all leak server
  build / module / runtime information: CWE-200 (information exposure),
  OWASP A05.
- `trace_enable_not_off` -- `TraceEnable On` keeps the HTTP `TRACE` method
  available, the classic vector for cross-site tracing (XST) which lets an
  attacker echo back `Authorization` / `Cookie` headers: CWE-200 (information
  exposure), OWASP A05.
- `http_protocol_options_unsafe` -- absent, incomplete, or unsafe
  `HttpProtocolOptions` leaves Apache without an explicit strict HTTP parser
  and HTTP/1.0+ request baseline. This is a configuration hardening item, so
  CWE stays empty and OWASP A05 carries the mapping.
- `listen_requires_explicit_address` -- port-only, hostname, wildcard, or
  all-zero `Listen` bindings can expose Apache on unintended interfaces. This
  is a deployment hardening issue rather than a weakness class, so CWE stays
  empty and OWASP A05 carries the mapping.
- `ip_based_requests_allowed` -- a named top-level Apache server context
  without a defensive rewrite policy can still serve IP-based or unexpected
  `Host` requests. The rule is a hardening signal, so CWE stays empty and
  OWASP A05 carries the mapping.
- `default_tls_vhost_not_rejecting_unknown_hosts` -- the first TLS
  `VirtualHost` for an address is Apache's default for unmatched host names;
  serving real content there can expose the wrong site. This is a virtual-host
  precision hardening signal, so CWE stays empty and OWASP A05 carries the
  mapping.
- `missing_http_method_restrictions`,
  `http_method_policy_allows_unapproved` -- sensitive scopes with no method
  restriction, or explicit method allowlists that still include unapproved
  verbs, leave unexpected HTTP methods governed by broader server defaults:
  CWE-650, OWASP A05.
- `file_etag_inodes` -- inode-derived ETag values expose filesystem metadata:
  CWE-200, OWASP A05.
- `timeout_too_high`, `keepalive_disabled`,
  `max_keepalive_requests_too_low`, `keepalive_timeout_too_high` -- Apache
  timeout / connection reuse values outside the CIS posture increase DoS
  exposure: CWE-400. OWASP empty for the same DoS-hardening reason used by the
  Nginx timeout rules.
- `limit_request_line_too_high`, `limit_request_field_size_too_high` -- overly
  large request line or header field limits can pass oversized input to
  downstream applications: CWE-770.
- `ssl_protocol_missing_or_weak`, `ssl_cipher_suite_missing`,
  `ssl_cipher_suite_weak`, `ssl_honor_cipher_order_not_on`,
  `ssl_compression_enabled`, and `ssl_insecure_renegotiation_enabled` --
  missing or weak local TLS protocol, cipher, and negotiation directives
  weaken cryptographic posture: CWE-327 or CWE-757 where applicable,
  OWASP A02.
- `basic_auth_over_http` -- Basic authentication outside a TLS VirtualHost can
  expose reusable credentials over cleartext HTTP: CWE-319, OWASP A02.
- `missing_hsts_header`, `hsts_header_unsafe` -- missing HSTS or a short /
  incomplete HSTS policy lets browsers fall back to cleartext HTTP after an
  active downgrade opportunity: CWE-319, OWASP A05.
- `missing_http_to_https_redirect` -- a named HTTP virtual host with a
  matching TLS virtual host but no redirect leaves users exposed to cleartext
  fallback: CWE-319, OWASP A02.
- `ssl_use_stapling_not_on`, `ssl_stapling_cache_missing` -- local OCSP
  stapling policy is a TLS hardening signal; CWE stays empty and OWASP A05
  covers the misconfiguration.
- `ssl_session_cache_missing`,
  `ssl_session_cache_timeout_missing_or_invalid` -- missing TLS session cache
  or timeout policy is operational / benchmark posture rather than a direct
  weakness class; CWE and OWASP stay empty.

CIS Apache HTTP Server 2.4 v2.3.0 gap table:

| CIS section | Gap type | Current coverage / follow-up |
| --- | --- | --- |
| §1.1-§1.3 | `out-of-scope` | Planning, single-use host posture, and package-source verification need host and deployment inventory, which is outside the tool scope. |
| §2.1-§2.9 | `parser-depth` | Module minimization needs reliable module inventory from `LoadModule` / build data; current status/info rules only partially cover exposed endpoints. |
| §3.1-§3.13 | `out-of-scope` | Service account, shell/lock state, ownership, permissions, lock/PID/scoreboard files, and writable directory controls need OS/filesystem metadata, which is outside the tool scope. |
| §4.1-§4.2 | `parser-depth` | General access-control posture needs richer effective `Require`/legacy access semantics before broad claims are safe. |
| §4.3-§4.4 | `direct-rule` | `apache.allowoverride_not_none` now validates the OS-root `AllowOverride None` baseline and explicit non-`None` Directory scopes; `directory_without_allowoverride` still tracks non-root explicitness where default/inherited semantics remain ambiguous. |
| §5.1-§5.3 | `direct-rule` | Existing `Options` rules cover risky tokens individually; full coverage needs an allowed-options policy per directory class. |
| §5.4-§5.6 | `probe-depth` | Default HTML and default CGI sample content require response-body probing or filesystem-content inspection. |
| §5.7 | `direct-rule` | `apache.missing_http_method_restrictions` covers missing method policy on sensitive `Location` / `LocationMatch` scopes, and `apache.http_method_policy_allows_unapproved` catches explicit allowlists that still permit unapproved methods; a full site-wide approved-method policy model remains future work. |
| §5.9 | `covered` | `apache.http_protocol_options_unsafe` validates effective `HttpProtocolOptions Strict Require1.0` across global and VirtualHost scopes. |
| §5.10-§5.13 | `direct-rule` | Backup/temp, `.ht*`, `.git` / `.svn`, and broader sensitive extension deny-list checks are now present; remaining precision work is environment-specific path policy. |
| §5.14-§5.15 | `direct-rule` | `apache.ip_based_requests_allowed` checks named top-level server contexts for the expected rewrite-based IP request denial signal, `apache.default_tls_vhost_not_rejecting_unknown_hosts` checks first/default TLS VirtualHosts for whole-scope rejection, and `apache.listen_requires_explicit_address` flags port-only, hostname, wildcard, and all-zero `Listen` bindings. Remaining precision work is rewrite module inventory, broader non-TLS VirtualHost allowed-host policy, and deployment-specific exceptions. |
| §5.16-§5.18 | `direct-rule` | Primary frame, Referrer-Policy, and Permissions-Policy header checks are now present for server and VirtualHost scopes. Permissions-Policy wildcard grants are flagged; remaining work is application-specific allowlist judgment and deeper per-directory / runtime response validation. |
| §6.1, §6.3 | `direct-rule` | Log coverage now includes `ErrorLog` / `CustomLog` presence, `/dev/null` destinations, restrictive `LogLevel`, undefined named formats, and required fields for used `LogFormat` definitions; syslog/storage policy is out of scope. |
| §6.2, §6.4-§6.5 | `out-of-scope` | Syslog facility, rotation/storage, and patch posture need host/package/log-management context, which is outside the tool scope. |
| §6.6-§6.7 | `parser-depth` | ModSecurity and CRS checks need module/package/config inventory beyond current parser rules. |
| §7.1, §7.4-§7.12 | `direct-rule` | Apache TLS directive coverage now includes `SSLProtocol`, `SSLCipherSuite`, conservative weak cipher / FS / AEAD posture, `SSLHonorCipherOrder`, `SSLCompression`, `SSLInsecureRenegotiation`, `SSLUseStapling`, `SSLStaplingCache`, `SSLSessionCache`, `SSLSessionCacheTimeout`, local HSTS policy, and matching-vhost HTTP redirects; remaining work is runtime negotiation evidence and certificate-chain probing. |
| §7.2 | `probe-depth` | Trusted certificate and chain validation needs runtime certificate probing rather than local path presence alone. |
| §7.3 | `out-of-scope` | Private-key protection needs filesystem ownership and permission metadata, which is outside web-server config / safe external analysis. |
| §8.3 | `probe-depth` | Default Apache content removal needs response-body probing or filesystem-content inspection. |
| §8.4 | `covered` | `apache.file_etag_inodes` detects explicit `FileETag` values that include inode data. |
| §9.1-§9.4 | `direct-rule` | Apache timeout and keepalive value checks now cover explicit `Timeout`, `KeepAlive`, `MaxKeepAliveRequests`, and `KeepAliveTimeout` directives; missing/default policy remains a future precision decision. |
| §9.5-§9.6 | `parser-depth` | `RequestReadTimeout` header/body validation depends on module/default semantics and needs richer module inventory before broad findings are safe. |
| §10.1-§10.4 | `direct-rule` | Request-limit threshold checks now cover `LimitRequestLine`, `LimitRequestFields`, `LimitRequestFieldSize`, and `LimitRequestBody`, with explicit-value limitations documented in the rule rows. |
| §11.1-§11.4, §12.1-§12.3 | `out-of-scope` | SELinux and AppArmor posture require host security-framework inspection, which is outside the tool scope. |

### Lighttpd (Local)

Count: 23

Stage 2 step 3 mapping: **complete** for this group. There is no official
*CIS Lighttpd Benchmark*, so CIS-specific claims stay empty. Where vendor or
DevSec baseline guidance from
[lighttpd.net wiki](https://redmine.lighttpd.net/projects/lighttpd/wiki)
applies, it is documented as substitute vendor guidance rather than an
official CIS mapping.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `lighttpd.access_log_format_missing_fields` | low | effective | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | - |
| `lighttpd.access_log_missing` | low | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | - |
| `lighttpd.basic_auth_over_http` | medium | effective | auth, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | - |
| `lighttpd.dir_listing_enabled` | medium | effective | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | - |
| `lighttpd.error_log_missing` | medium | ast | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | - |
| `lighttpd.max_connections_missing` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | - |
| `lighttpd.max_request_size_missing` | low | ast | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | - |
| `lighttpd.content_security_policy_missing_reporting_endpoint` | low | effective | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.7 (partial: reporting endpoint directive only) | - |
| `lighttpd.missing_http_method_restrictions` | low | ast | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | DevSec lighttpd-baseline lighttpd-05 (partial: explicit dangerous-method deny policy signal) |
| `lighttpd.missing_strict_transport_security` | medium | effective | headers | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | - |
| `lighttpd.missing_x_content_type_options` | medium | effective | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.4 | - |
| `lighttpd.mod_cgi_enabled` | low | ast | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `lighttpd.mod_status_public` | medium | effective | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | - |
| `lighttpd.server_tag_not_blank` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `lighttpd.ssl_engine_not_enabled` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | - |
| `lighttpd.ssl_compression_enabled` | medium | effective | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.5 (partial: explicit local OpenSSL option only) | NIST SP 800-52 Rev. 2 §3.6 (partial: local `ssl.openssl.ssl-conf-cmd` only) |
| `lighttpd.ssl_honor_cipher_order_missing` | medium | effective | tls | [CWE-757](https://cwe.mitre.org/data/definitions/757.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | - |
| `lighttpd.ssl_insecure_renegotiation_enabled` | high | effective | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.5 (partial: explicit local OpenSSL / deprecated mitigation directives only) | NIST SP 800-52 Rev. 2 §3.5 (partial: local `UnsafeLegacyRenegotiation` / disabled renegotiation mitigation only) |
| `lighttpd.ssl_pemfile_missing` | high | ast | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | - |
| `lighttpd.ssl_protocol_policy_missing_or_weak` | medium | effective | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 (partial: local protocol policy only) | - |
| `lighttpd.strict_transport_security_unsafe` | medium | effective | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 (partial: local max-age / includeSubDomains validation) | - |
| `lighttpd.url_access_deny_missing` | medium | ast | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `lighttpd.weak_ssl_cipher_list` | high | ast | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: weak-pattern detection only) | - |

Mapping rationale (lighttpd rules):

- `access_log_missing`, `access_log_format_missing_fields`,
  `error_log_missing` -- without access/error logs, or with low-detail
  access log formats, an
  operator cannot detect or investigate attacks: textbook CWE-778
  (insufficient logging), grouped under OWASP A09 (security logging and
  monitoring failures).
- `dir_listing_enabled` -- direct match for CWE-548. Categorised as A05
  (misconfig) because lighttpd defaults are safe; the finding fires only
  when the operator explicitly enables `dir-listing.activate`.
- `max_connections_missing`, `max_request_size_missing` -- absence of
  `server.max-connections` / `server.max-request-size` lets clients exhaust
  connections or memory: CWE-770 (allocation of resources without limits).
  We leave the OWASP cell empty: denial-of-service hardening does not have
  a clean mapping in the 2021 Top 10, and forcing it under A05 would
  overstretch the category.
- `basic_auth_over_http` -- Basic authentication without SSL can expose
  reusable credentials over cleartext HTTP: CWE-319, OWASP A02.
- `missing_http_method_restrictions` -- no explicit dangerous-method deny
  policy can leave TRACE, PUT, DELETE, CONNECT, PATCH, or WebDAV-like methods
  reachable: CWE-650, OWASP A05.
- `missing_strict_transport_security`,
  `strict_transport_security_unsafe` -- without HSTS, or with a short /
  incomplete HSTS policy, clients can be downgraded to plaintext (CWE-319).
  Tracked as A05 (hardening header misconfiguration), matching the universal HSTS rule's mapping.
- `missing_x_content_type_options` -- missing protective response header:
  CWE-693 (protection mechanism failure), OWASP A05.
- `mod_cgi_enabled` -- enabling `mod_cgi` is not a vulnerability per se, it
  is an attack-surface increase that violates least-privilege deployment.
  No single CWE maps cleanly, so the CWE cell stays empty; OWASP A05 covers
  it as a hardening item ("only enable modules you actually need").
- `mod_status_public`, `server_tag_not_blank` -- both leak server-internal
  information to unauthenticated clients: CWE-200 (information exposure),
  OWASP A05.
- `ssl_engine_not_enabled` -- a virtual host advertised over HTTPS but with
  `ssl.engine = "disable"` does not establish TLS correctly: CWE-319,
  OWASP A02.
- `ssl_honor_cipher_order_missing` -- letting the client pick the cipher
  exposes the server to downgrade attacks: CWE-757 (selection of
  less-secure algorithm during negotiation), OWASP A02.
- `ssl_pemfile_missing` -- TLS enabled but no certificate path configured:
  the listener cannot complete a TLS handshake, so HTTPS to that listener
  fails outright. We keep CWE-319 / OWASP A02 because the rule still flags a
  broken cryptographic deployment, but the failure mode is connection refusal,
  not an automatic downgrade to plaintext.
- `ssl_protocol_policy_missing_or_weak` -- TLS without an explicit modern
  protocol policy, or with legacy SSL/TLS protocol versions enabled, leaves
  cryptographic negotiation on weak defaults: CWE-327, OWASP A02.
- `ssl_compression_enabled`, `ssl_insecure_renegotiation_enabled` -- explicit
  OpenSSL options or deprecated mitigation toggles that enable TLS compression
  or unsafe legacy renegotiation weaken the TLS channel: CWE-327, OWASP A02.
- `url_access_deny_missing` -- without `url.access-deny` for `.bak`, `.sql`,
  `.conf`, `.log`, the server can hand out backup/configuration files:
  CWE-538 (file and directory information exposure), OWASP A05.
- `weak_ssl_cipher_list` -- enabling RC4/DES/3DES/MD5/NULL/EXPORT cipher
  tokens is the textbook CWE-327 (broken / risky cryptographic algorithm),
  OWASP A02.

### IIS (Local)

Count: 47

Stage 2 mapping status: **CWE / OWASP / ASVS complete; CIS existing-rule
reference pass complete** for this group. CIS references come from a full
walk-through of the *CIS Microsoft IIS 10 Benchmark v1.2.1*. That benchmark's
transport-encryption chapter includes host-level SChannel registry policy, so
SChannel-backed universal TLS mappings are listed in a separate IIS/SChannel
table below rather than treated as IIS XML controls. Unsupported CIS IIS 7/8
archive PDFs remain historical context only.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `iis.directory_browse_enabled` | medium | effective | - | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.3 | CIS Microsoft IIS 10 v1.2.1 §1.3 |
| `iis.http_errors_detailed` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-16.5.1 (partial: detailed errors only) | CIS Microsoft IIS 10 v1.2.1 §3.4 |
| `iis.custom_errors_off` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-16.5.1 (partial: detailed errors only) | CIS Microsoft IIS 10 v1.2.1 §3.3 |
| `iis.asp_script_error_sent_to_browser` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-16.5.1 (partial: detailed errors only) | CIS Microsoft IIS 10 v1.2.1 §3.4 (partial: classic ASP browser errors are the same detailed-error exposure; benchmark audits IIS HTTP errors) |
| `iis.compilation_debug_enabled` | medium | effective | - | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.2 | CIS Microsoft IIS 10 v1.2.1 §3.2 |
| `iis.trace_enabled` | medium | effective | - | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.2 | CIS Microsoft IIS 10 v1.2.1 §3.5 |
| `iis.http_runtime_version_header_enabled` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `iis.request_filtering_allow_double_escaping` | medium | effective | - | [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.5 |
| `iis.request_filtering_allow_high_bit` | low | effective | - | [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.4 |
| `iis.ssl_not_required` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | CIS Microsoft IIS 10 v1.2.1 §2.6 (partial: rule enforces `sslFlags` for access sections generally; benchmark scopes Basic Authentication) |
| `iis.ssl_weak_cipher_strength` | low | effective | tls | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: IIS cipher strength flag only) | - |
| `iis.logging_not_configured` | medium | effective | - | [CWE-778](https://cwe.mitre.org/data/definitions/778.html) | [A09:2021](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §5.2 (partial: rule checks logging present/enabled, not the full advanced logging field set) |
| `iis.max_allowed_content_length_missing` | low | effective | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Microsoft IIS 10 v1.2.1 §4.1 (partial: requires a positive limit but does not validate the benchmark size) |
| `iis.missing_hsts_header` | medium | effective | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: header presence only) |
| `iis.hsts_header_unsafe` | medium | effective | headers, tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 (partial: local max-age / includeSubDomains validation) | CIS Microsoft IIS 10 v1.2.1 section 7.1 (partial: local HSTS policy value check) |
| `iis.forms_auth_require_ssl_missing` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | CIS Microsoft IIS 10 v1.2.1 §2.3 |
| `iis.schannel_tls12_not_enabled` | medium | mixed | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS Microsoft IIS 10 v1.2.1 §7.6 (partial: SChannel registry/export evidence only) |
| `iis.schannel_weak_protocol_enabled` | medium | mixed | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS Microsoft IIS 10 v1.2.1 §7.1-§7.5 (partial: SChannel registry/export evidence only) |
| `iis.schannel_aes128_enabled` | medium | mixed | tls | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: registry cipher toggle only) | CIS Microsoft IIS 10 v1.2.1 §7.10 |
| `iis.schannel_aes256_not_enabled` | medium | mixed | tls | [CWE-326](https://cwe.mitre.org/data/definitions/326.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: registry cipher toggle only) | CIS Microsoft IIS 10 v1.2.1 §7.11 |
| `iis.schannel_cipher_suite_order_not_preferred` | medium | mixed | tls | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: preferred-order prefix only) | CIS Microsoft IIS 10 v1.2.1 §7.12 (partial: validates CIS preferred prefix in `Functions`) |
| `iis.session_state_cookieless` | medium | effective | - | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §3.6 |
| `iis.webdav_module_enabled` | medium | effective | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §1.7 |
| `iis.cgi_handler_enabled` | medium | effective | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.8 (partial: detects CGI handler module presence, not the full handler permission matrix) |
| `iis.handler_write_script_execute_enabled` | medium | effective | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.8 |
| `iis.custom_headers_expose_server` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Microsoft IIS 10 v1.2.1 §3.11 (partial: covers server-revealing custom headers, not the native `Server` header removal path) |
| `iis.content_security_policy_missing_reporting_endpoint` | low | effective | headers | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.7 (partial: reporting endpoint directive only) | - |
| `iis.anonymous_auth_enabled` | medium | effective | - | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §2.1/§2.2 (partial: rule detects anonymous auth combined with named auth, not a full authorization-policy audit) |
| `iis.authorization_allows_anonymous_users` | medium | effective | - | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §2.1/§2.2 (partial: detects explicit `users="*"` / `users="?"` allow rules) |
| `iis.basic_auth_without_ssl` | medium | effective | tls | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | CIS Microsoft IIS 10 v1.2.1 §2.6 |
| `iis.request_filtering_max_url_too_high` | low | effective | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Microsoft IIS 10 v1.2.1 §4.2 (partial: explicit unsafe local `maxUrl` values only) |
| `iis.request_filtering_max_query_string_too_high` | low | effective | - | [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | - | - | CIS Microsoft IIS 10 v1.2.1 §4.3 (partial: explicit unsafe local `maxQueryString` values only) |
| `iis.file_extensions_allow_unlisted` | medium | effective | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.7 (partial: explicit true or missing/default `allowUnlisted` policy where requestFiltering is present) |
| `iis.isapi_cgi_restrictions_allow_unlisted` | medium | effective | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §4.9/§4.10 (partial: explicit unlisted ISAPI/CGI allowance only) |
| `iis.request_filtering_remove_server_header_disabled` | low | effective | disclosure | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Microsoft IIS 10 v1.2.1 §3.12 (partial: explicit `removeServerHeader="false"` values only) |
| `iis.forms_auth_protection_unsafe` | medium | effective | - | [CWE-311](https://cwe.mitre.org/data/definitions/311.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §2.5 (partial: explicit non-`All` forms protection only) |
| `iis.credentials_password_format_clear` | medium | effective | - | [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §2.7 |
| `iis.credentials_stored_in_config` | medium | effective | - | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §2.8 |
| `iis.http_cookies_http_only_disabled` | medium | effective | - | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §3.7 (partial: explicit `httpOnlyCookies="false"` only) |
| `iis.deployment_retail_not_enabled` | medium | effective | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §3.1 (partial: explicit `retail="false"` only) |
| `iis.trust_level_full` | medium | effective | - | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §3.10 (partial: explicit `trust level="Full"` only) |
| `iis.machine_key_validation_weak` | medium | effective | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §3.9 (partial: explicit validation algorithms other than SHA-2 HMAC only) |
| `iis.machine_key_legacy_validation_weak` | medium | effective | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | CIS Microsoft IIS 10 v1.2.1 §3.8 (partial: explicit unsafe values in legacy ASP.NET 2.0/3.5 context only) |
| `iis.binding_without_host_header` | low | ast | - | - | - | - | CIS Microsoft IIS 10 v1.2.1 §1.2 (partial: detects HTTP/HTTPS bindings without host names; deliberate catch-all binding policy remains operator-specific) |
| `iis.application_pool_identity_not_application_pool_identity` | medium | ast | - | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §1.4 (partial: explicit app-pool/default `identityType` values only) |
| `iis.sites_share_application_pool` | medium | ast | - | [CWE-668](https://cwe.mitre.org/data/definitions/668.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §1.5 (partial: detects pools assigned under more than one site; shared-hosting exceptions remain operator-specific) |
| `iis.anonymous_auth_uses_specific_user` | medium | effective | - | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS Microsoft IIS 10 v1.2.1 §1.6 (partial: explicit non-empty `userName` values, or password values when `userName` is not explicitly blank) |

Mapping rationale (iis rules):

- `directory_browse_enabled` -- direct match for CWE-548 (directory listing);
  OWASP A05.
- `http_errors_detailed`, `custom_errors_off`,
  `asp_script_error_sent_to_browser` -- detailed-error / verbose-error
  configurations expose stack traces, file paths, and SQL fragments to
  unauthenticated users: CWE-209 (information exposure through an error
  message), OWASP A05.
- `compilation_debug_enabled` -- ASP.NET compiled in debug mode keeps
  symbols and timing-sensitive paths in the deployed binaries: CWE-489
  (active debug code), OWASP A05.
- `trace_enabled` -- ASP.NET request tracing exposes per-request payload to
  developers and, in misconfigured deployments, to attackers: CWE-215
  (insertion of sensitive information into debugging code), OWASP A05.
- `http_runtime_version_header_enabled`, `custom_headers_expose_server` --
  `X-AspNet-Version` and similar custom headers leak runtime / build info:
  CWE-200 (information exposure), OWASP A05.
- `request_filtering_allow_double_escaping`,
  `request_filtering_allow_high_bit` -- both relax IIS request-filtering
  rules around URL encoding so multi-encoded or non-ASCII characters slip
  through, which historically enabled path-traversal and filter-bypass
  attacks: CWE-176 (improper handling of Unicode encoding), OWASP A05.
- `ssl_not_required` -- a site that does not enforce `SslRequire` accepts
  plaintext HTTP for the same routes: CWE-319 (cleartext transmission of
  sensitive information), OWASP A02.
- `ssl_weak_cipher_strength` -- a `<security:access sslFlags=...>` value
  that does not pin a minimum cipher strength leaves weak ciphers
  acceptable: CWE-326 (inadequate encryption strength), OWASP A02.
- `logging_not_configured` -- no `<httpLogging>` / `<httpErrors>` logging
  defeats incident response: CWE-778, OWASP A09.
- `max_allowed_content_length_missing` -- no `maxAllowedContentLength`
  ceiling lets a client send arbitrarily large bodies: CWE-770. OWASP cell
  empty (no clean DoS-hardening home in the 2021 Top 10).
- `missing_hsts_header`, `hsts_header_unsafe` -- matches the universal HSTS
  rule family and flags absent or incomplete local HSTS policy: CWE-319,
  OWASP A05 (misconfig).
- `forms_auth_require_ssl_missing` -- `<forms requireSSL="false">` lets the
  authentication ticket cookie travel in cleartext: CWE-319, OWASP A02.
- `schannel_tls12_not_enabled` -- known SChannel protocol evidence without
  TLS 1.2 support leaves IIS below the benchmark transport baseline:
  CWE-327, OWASP A02.
- `schannel_weak_protocol_enabled` -- known SChannel protocol evidence with
  SSLv2, SSLv3, TLS 1.0, or TLS 1.1 enabled leaves IIS on legacy transport
  negotiation: CWE-327, OWASP A02.
- `schannel_aes128_enabled`, `schannel_aes256_not_enabled` -- known SChannel
  cipher toggle evidence that leaves AES 128/128 enabled or AES 256/256
  unavailable weakens the configured transport baseline: CWE-326, OWASP A02.
- `schannel_cipher_suite_order_not_preferred` -- a non-preferred SChannel
  cipher-suite order can prioritize weaker choices over stronger suites:
  CWE-327, OWASP A02.
- `session_state_cookieless` -- cookieless session state embeds the session
  identifier in the URL, leaking it via Referer headers, browser history,
  proxy logs, and copy/paste: CWE-598 (use of GET method with sensitive
  query strings), OWASP A07 (session management failure).
- `webdav_module_enabled`, `cgi_handler_enabled`, and
  `handler_write_script_execute_enabled` -- enabling WebDAV, legacy CGI
  handlers, or writable executable handler paths is an attack-surface
  increase, not a textbook weakness class. CWE empty, OWASP A05.
- `anonymous_auth_enabled` -- the rule fires only when anonymous
  authentication is enabled *together with* another scheme. The anonymous
  module wins the auth handshake first, so authenticated checks downstream
  do not run: CWE-287 (improper authentication), OWASP A07.
- `authorization_allows_anonymous_users` -- explicit `users="*"` or
  `users="?"` allow rules grant access to all or anonymous users, which is
  an authorization-policy failure in the authentication/authorization
  control family: CWE-287, OWASP A07.
- `basic_auth_without_ssl` -- Basic authentication depends on TLS to keep
  reusable credentials confidential. Enabling it without an `Ssl` access
  requirement is cleartext credential exposure: CWE-319, OWASP A02.
- `request_filtering_max_url_too_high`,
  `request_filtering_max_query_string_too_high` -- excessive request target
  sizes can amplify resource consumption, so these map to CWE-770. OWASP is
  left empty because the 2021 Top 10 has no precise resource-limit category.
- `file_extensions_allow_unlisted`,
  `isapi_cgi_restrictions_allow_unlisted` -- both disable allow-list style
  request filtering / executable restrictions, which is best represented as
  protection mechanism failure: CWE-693, OWASP A05.
- `request_filtering_remove_server_header_disabled` -- explicit native IIS
  `Server` header emission leaks server technology information: CWE-200,
  OWASP A05.
- `forms_auth_protection_unsafe` -- forms authentication cookies without
  both encryption and validation are sensitive data sent without the expected
  cryptographic protection: CWE-311, OWASP A02.
- `credentials_password_format_clear` -- cleartext forms-credential storage
  is direct password storage without hashing: CWE-256, OWASP A02.
- `credentials_stored_in_config` -- reusable credentials embedded in
  configuration are hard-coded credentials: CWE-798, OWASP A07.
- `http_cookies_http_only_disabled` -- direct cookie-hardening match for
  CWE-1004; OWASP A05 because the finding is a security configuration issue.
- `deployment_retail_not_enabled` -- disabling ASP.NET retail mode can expose
  debug or detailed error behavior in production: CWE-209, OWASP A05.
- `trust_level_full` -- full trust grants broader runtime privileges than the
  application may need: CWE-250, OWASP A05.
- `machine_key_validation_weak` and
  `machine_key_legacy_validation_weak` -- explicit validation algorithms
  outside the expected modern SHA-2 HMAC or legacy AES/SHA1 baselines
  undermine MachineKey integrity protection: CWE-327, OWASP A02.
- `binding_without_host_header` -- hostless HTTP/HTTPS bindings can make a
  site answer unexpected Host headers on the same IP and port. This maps to
  CIS IIS host-header hardening, but CWE/OWASP stay empty because deliberate
  catch-all binding policy is deployment-specific.
- `application_pool_identity_not_application_pool_identity` -- app pools
  running as NetworkService, LocalSystem, LocalService, or SpecificUser grant
  broader process identity rights than the benchmark's ApplicationPoolIdentity
  baseline: CWE-250, OWASP A05.
- `sites_share_application_pool` -- assigning one app pool to applications
  under multiple sites weakens isolation between those sites, so this is
  mapped as resource exposure across the wrong isolation boundary: CWE-668,
  OWASP A05.
- `anonymous_auth_uses_specific_user` -- a non-empty anonymous-auth
  `userName` makes anonymous requests impersonate a separate account instead
  of the app pool identity; password-only evidence is flagged only when
  `userName` is not explicitly blank. CWE-250, OWASP A05.

IIS / SChannel mappings for universal rules:

| Rule ID | Source split | CIS / Vendor mapping |
| --- | --- | --- |
| `universal.directory_listing_enabled` | IIS XML / effective config | CIS Microsoft IIS 10 v1.2.1 §1.3 |
| `universal.missing_hsts` | IIS XML / effective config | CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: header presence only) |
| `universal.server_identification_disclosed` | IIS response-header policy | CIS Microsoft IIS 10 v1.2.1 §3.11/§3.12 (partial: local rules cover X-Powered-By / ASP.NET family headers and explicit native `Server` header removal disablement) |
| `universal.weak_tls_protocol` | Windows SChannel registry enrichment for IIS TLS normalization | CIS Microsoft IIS 10 v1.2.1 §7.2/§7.3/§7.4/§7.5 (partial: detects enabled weak protocols) |
| `universal.weak_tls_ciphers` | Windows SChannel registry enrichment for IIS TLS normalization | CIS Microsoft IIS 10 v1.2.1 §7.7/§7.8/§7.9 (partial: detects weak-pattern ciphers) |

IIS CIS v1.2.1 / Windows source-of-truth gap table:

| CIS section | Gap type | Current coverage / follow-up |
| --- | --- | --- |
| §1.1, Windows Server host hardening | `out-of-scope` | Web-root partitioning, OS service posture, filesystem ACLs, and broader Windows Server host baseline checks are outside web-server config / safe external analysis. |
| §1.2 | `covered` | `iis.binding_without_host_header` detects HTTP/HTTPS bindings without host names; deliberate catch-all binding policy remains operator-specific. |
| §1.4/§1.5/§1.6 | `partial` | `iis.application_pool_identity_not_application_pool_identity`, `iis.sites_share_application_pool`, and `iis.anonymous_auth_uses_specific_user` cover explicit app-pool identities, cross-site shared pools, and explicit specific anonymous users. Follow-up remains for deeper default materialization and deployment-specific shared-hosting exceptions. |
| §2.1/§2.2 | `partial` | `iis.anonymous_auth_enabled` and `iis.authorization_allows_anonymous_users` cover common anonymous/authenticated mixups and explicit wildcard/anonymous allow rules; full authorization default semantics remain parser-policy follow-up. |
| §2.5/§2.7/§2.8 | `partial` | `iis.forms_auth_protection_unsafe`, `iis.credentials_password_format_clear`, and `iis.credentials_stored_in_config` cover explicit unsafe forms credential settings; broader inherited/default policy remains follow-up. |
| §2.6 | `covered` | `iis.basic_auth_without_ssl` checks Basic Authentication together with the effective `access sslFlags` requirement; `iis.ssl_not_required` remains a broader access-section signal. |
| §3.1/§3.7/§3.8/§3.9/§3.10/§3.12 | `partial` | `iis.deployment_retail_not_enabled`, `iis.http_cookies_http_only_disabled`, `iis.machine_key_legacy_validation_weak`, `iis.machine_key_validation_weak`, `iis.trust_level_full`, and `iis.request_filtering_remove_server_header_disabled` cover explicit unsafe values; absence-complete/default policy and runtime native-header verification remain follow-up. |
| §4.2/§4.3/§4.7/§4.9/§4.10 | `partial` | `iis.request_filtering_max_url_too_high`, `iis.request_filtering_max_query_string_too_high`, `iis.file_extensions_allow_unlisted`, and `iis.isapi_cgi_restrictions_allow_unlisted` cover explicit unsafe values; `fileExtensions` also covers missing/default allow-unlisted policy when `requestFiltering` is present. `maxUrl` / `maxQueryString` missing attributes stay silent because IIS defaults match the benchmark ceilings. |
| §4.8 | `covered` | `iis.handler_write_script_execute_enabled` detects handler `accessPolicy` values that grant Write together with Script or Execute; `iis.cgi_handler_enabled` remains an extra CGI handler signal. |
| §4.11/§5.1/§5.3 | `out-of-scope` | Dynamic IP restrictions, log location, and ETW logging depend on server-level feature / filesystem state beyond current XML signals and are outside the tool scope. |
| §6.1/§6.2 | `out-of-scope` | FTP encryption and FTP logon attempt restrictions stay outside the web-server HTTP configuration scope unless FTP analysis becomes a product goal. |
| §7.1-§7.6/§7.10/§7.11/§7.12 | `partial` | `iis.schannel_weak_protocol_enabled`, `iis.schannel_tls12_not_enabled`, `iis.schannel_aes128_enabled`, `iis.schannel_aes256_not_enabled`, and `iis.schannel_cipher_suite_order_not_preferred` cover known SChannel registry/export evidence; runtime negotiation evidence and complete source collection remain follow-up. |
| CIS IIS 7/8 archive PDFs | `research` | Local archive PDFs are historical context only; they must not become primary references unless a future PR explicitly scopes legacy IIS. |

### External (Probe-based)

Count: 73

Stage 2 step 3 mapping: **CWE / OWASP complete** for this group. External
probes are black-box runtime checks that do not align with config-level CIS
Benchmarks as a primary source, so the `CIS / Vendor` column is empty by
default for this group. As a follow-up of `STD-GAP-035` from
`docs/benchmarks-covering.md`, a small set of external rules whose runtime
signal corroborates a specific CIS benchmark section now carries a
**cross-source partial** annotation in the `CIS / Vendor` column. Each such
entry is explicitly marked `(partial: runtime evidence; primary CIS
reference at <local rule>)` so it never claims standalone CIS coverage and
always points back to the config-level rule that owns the primary mapping.
Their natural standards companions are the OWASP Cheat Sheet Series and
[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)
verification requirements, which are now recorded in the `ASVS` column when the
current probe signal provides honest direct or partial coverage. Info-only
probes that describe
expected, public-by-design endpoints (`robots.txt`, `sitemap.xml`,
permissive 302 redirects, OPTIONS responses) leave CWE, OWASP, and ASVS empty.

| Rule ID | Severity | Input | Tags | CWE | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `external.nginx.version_disclosed_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `external.nginx.default_welcome_page` | medium | probe | - | [CWE-1188](https://cwe.mitre.org/data/definitions/1188.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.apache.version_disclosed_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `external.apache.mod_status_public` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | - |
| `external.apache.etag_inode_disclosure` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.iis.aspnet_version_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Microsoft IIS 10 v1.2.1 §3.11 (partial: runtime evidence; primary CIS reference at `iis.custom_headers_expose_server`) |
| `external.iis.detailed_error_page` | medium | probe | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-16.5.1 (partial: detailed errors only) | CIS Microsoft IIS 10 v1.2.1 §3.4 (partial: runtime evidence; primary CIS reference at `iis.http_errors_detailed`) |
| `external.lighttpd.version_in_server_header` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `external.lighttpd.mod_status_public` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | - |
| `external.cookie_missing_secure_on_https` | low | probe | - | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.3.1 (partial: attribute only) | - |
| `external.cookie_missing_httponly` | low | probe | - | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.3.2 | - |
| `external.cookie_missing_samesite` | low | probe | - | [CWE-1275](https://cwe.mitre.org/data/definitions/1275.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.3.4 (partial: attribute only) | - |
| `external.cookie_samesite_none_without_secure` | low | probe | - | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.3.4 (partial: SameSite=None Secure coupling only) | - |
| `external.cors_wildcard_origin` | low | probe | - | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.2 (partial: runtime wildcard detection only) | - |
| `external.cors_wildcard_with_credentials` | medium | probe | - | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.2 (partial: runtime wildcard detection only) | - |
| `external.server_version_disclosed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `external.x_powered_by_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | - |
| `external.x_aspnet_version_header_present` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.6 | CIS Microsoft IIS 10 v1.2.1 §3.11 (partial: runtime evidence; primary CIS reference at `iis.custom_headers_expose_server`) |
| `external.x_frame_options_missing` | low | probe | - | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.x_frame_options_invalid` | low | probe | - | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.x_content_type_options_missing` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.4 | CIS NGINX v3.0.0 §5.3.1 (partial: runtime evidence; primary CIS reference at `nginx.missing_x_content_type_options`) |
| `external.x_content_type_options_invalid` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.4 | CIS NGINX v3.0.0 §5.3.1 (partial: runtime evidence; primary CIS reference at `nginx.missing_x_content_type_options`) |
| `external.content_security_policy_missing` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: missing/unsafe checks only) | - |
| `external.content_security_policy_unsafe_inline` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: missing/unsafe checks only) | - |
| `external.content_security_policy_unsafe_eval` | medium | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: missing/unsafe checks only) | - |
| `external.content_security_policy_missing_frame_ancestors` | low | probe | - | [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.6 | - |
| `external.content_security_policy_object_src_not_none` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: object-src minimum quality) | - |
| `external.content_security_policy_base_uri_not_restricted` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.3 (partial: base-uri minimum quality) | - |
| `external.content_security_policy_missing_reporting_endpoint` | low | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.7 (partial: reporting endpoint directive only) | - |
| `external.referrer_policy_missing` | info | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | - |
| `external.referrer_policy_unsafe` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.5 | - |
| `external.permissions_policy_missing` | info | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.coep_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.coop_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.8 (partial: observed responses only) | - |
| `external.corp_missing` | info | probe | - | [CWE-693](https://cwe.mitre.org/data/definitions/693.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.https_not_available` | medium | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | CIS NGINX v3.0.0 §4.1.1; CIS Apache HTTP Server 2.4 v2.3.0 §7.1; CIS Microsoft IIS 10 v1.2.1 §2.6 (partial: runtime evidence; primary CIS references at local TLS-required / SSL-engine rules) |
| `external.http_not_redirected_to_https` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.1 | CIS NGINX v3.0.0 §4.1.1; CIS Apache HTTP Server 2.4 v2.3.0 §7.1 (partial: runtime evidence; primary CIS references at `nginx.missing_http_to_https_redirect` / `apache.missing_http_to_https_redirect`) |
| `external.hsts_header_missing` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS NGINX v3.0.0 §4.1.8; CIS Apache HTTP Server 2.4 v2.3.0 §7.11; CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: runtime evidence; primary CIS references at local HSTS rules) |
| `external.hsts_header_invalid` | medium | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS NGINX v3.0.0 §4.1.8; CIS Apache HTTP Server 2.4 v2.3.0 §7.11; CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: runtime evidence; primary CIS references at local HSTS rules) |
| `external.hsts_max_age_too_short` | low | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS NGINX v3.0.0 §4.1.8; CIS Apache HTTP Server 2.4 v2.3.0 §7.11; CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: runtime evidence; primary CIS references at local HSTS rules) |
| `external.hsts_missing_include_subdomains` | info | probe | - | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-3.4.1 | CIS NGINX v3.0.0 §4.1.8; CIS Apache HTTP Server 2.4 v2.3.0 §7.11; CIS Microsoft IIS 10 v1.2.1 §7.1 (partial: runtime evidence; primary CIS references at local HSTS rules) |
| `external.http_redirect_not_permanent` | info | probe | - | - | - | - | - |
| `external.trace_method_allowed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.4 | CIS Apache HTTP Server 2.4 v2.3.0 §5.8 (partial: runtime evidence; primary CIS reference at `apache.trace_enable_not_off`) |
| `external.allow_header_dangerous_methods` | medium | probe | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §5.1.2; CIS Apache HTTP Server 2.4 v2.3.0 §5.7 (partial: runtime evidence; primary CIS references at `nginx.missing_http_method_restrictions` / `apache.missing_http_method_restrictions`) |
| `external.options_method_exposed` | info | probe | - | - | - | - | - |
| `external.dangerous_http_methods_enabled` | medium | probe | - | [CWE-650](https://cwe.mitre.org/data/definitions/650.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | CIS NGINX v3.0.0 §5.1.2; CIS Apache HTTP Server 2.4 v2.3.0 §5.7 (partial: runtime evidence; primary CIS references at `nginx.missing_http_method_restrictions` / `apache.missing_http_method_restrictions`) |
| `external.trace_method_exposed_via_options` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.4 | CIS Apache HTTP Server 2.4 v2.3.0 §5.8 (partial: runtime evidence; primary CIS reference at `apache.trace_enable_not_off`) |
| `external.webdav_methods_exposed` | medium | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.git_metadata_exposed` | high | probe | - | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.1 | CIS NGINX v3.0.0 §2.5.3; CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: runtime evidence; primary CIS references at `nginx.missing_hidden_files_deny` / `apache.vcs_metadata_not_restricted`) |
| `external.server_status_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | CIS Apache HTTP Server 2.4 v2.3.0 §2.4 (partial: runtime evidence; primary CIS reference at `apache.server_status_exposed`) |
| `external.server_info_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | CIS Apache HTTP Server 2.4 v2.3.0 §2.8 (partial: runtime evidence; primary CIS reference at `apache.server_info_exposed`) |
| `external.nginx_status_exposed` | low | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.5 | CIS NGINX v3.0.0 §2.5.4 (partial: runtime evidence; reverse-proxy disclosure scope; CIS section is `parser-depth` at config level) |
| `external.env_file_exposed` | high | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.htaccess_exposed` | medium | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.htpasswd_exposed` | high | probe | - | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) | [A07:2021](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/) | - | - |
| `external.wordpress_admin_panel_exposed` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.phpinfo_exposed` | medium | probe | - | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.2 | - |
| `external.elmah_axd_exposed` | medium | probe | - | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.2 | - |
| `external.trace_axd_exposed` | high | probe | - | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.2 | - |
| `external.web_config_exposed` | high | probe | - | [CWE-538](https://cwe.mitre.org/data/definitions/538.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.robots_txt_exposed` | info | probe | - | - | - | - | - |
| `external.sitemap_xml_exposed` | info | probe | - | - | - | - | - |
| `external.svn_metadata_exposed` | medium | probe | - | [CWE-540](https://cwe.mitre.org/data/definitions/540.html) | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | ASVS v5.0.0-13.4.1 | CIS NGINX v3.0.0 §2.5.3; CIS Apache HTTP Server 2.4 v2.3.0 §5.10-§5.13 (partial: runtime evidence; primary CIS references at `nginx.missing_hidden_files_deny` / `apache.vcs_metadata_not_restricted`) |
| `external.certificate_expired` | high | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.2 | - |
| `external.certificate_expires_soon` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | - | - |
| `external.tls_certificate_self_signed` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.2 | - |
| `external.tls_1_0_supported` | high | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS NGINX v3.0.0 §4.1.4; CIS Apache HTTP Server 2.4 v2.3.0 §7.1; CIS Microsoft IIS 10 v1.2.1 §7.4 (partial: runtime evidence; primary CIS references at `nginx.weak_ssl_protocols` / `apache.ssl_protocol_missing_or_weak` / `iis.schannel_weak_protocol_enabled`) |
| `external.tls_1_1_supported` | medium | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.1 | CIS NGINX v3.0.0 §4.1.4; CIS Apache HTTP Server 2.4 v2.3.0 §7.1; CIS Microsoft IIS 10 v1.2.1 §7.5 (partial: runtime evidence; primary CIS references at `nginx.weak_ssl_protocols` / `apache.ssl_protocol_missing_or_weak` / `iis.schannel_weak_protocol_enabled`) |
| `external.tls_1_3_not_supported` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.weak_cipher_suite` | high | probe | - | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.1.2 (partial: weak-pattern detection only) | CIS NGINX v3.0.0 §4.1.5; CIS Apache HTTP Server 2.4 v2.3.0 §7.4; CIS Microsoft IIS 10 v1.2.1 §7.7-§7.9 (partial: runtime evidence; primary CIS references at `universal.weak_tls_ciphers` / `nginx.ssl_ciphers_weak` / `apache.ssl_cipher_suite_weak` / `lighttpd.weak_ssl_cipher_list`) |
| `external.cert_chain_incomplete` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.2 | - |
| `external.cert_chain_length_unusual` | low | probe | - | - | [A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | - | - |
| `external.cert_san_mismatch` | medium | probe | - | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | [A02:2021](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/) | ASVS v5.0.0-12.2.2 | - |

Mapping rationale (external probes), grouped by pattern:

- **Server fingerprinting** -- the per-server `*.version_disclosed_in_server_header`
  family (`external.nginx.*`, `external.apache.*`, `external.iis.*`,
  `external.lighttpd.*`), plus `external.server_version_disclosed`,
  `external.x_powered_by_header_present`,
  `external.x_aspnet_version_header_present`,
  `external.iis.aspnet_version_header_present`,
  `external.apache.etag_inode_disclosure`,
  `external.phpinfo_exposed`, `external.nginx_status_exposed`,
  `external.apache.mod_status_public`, `external.lighttpd.mod_status_public`,
  `external.server_info_exposed`, `external.server_status_exposed`,
  `external.trace_method_allowed`, `external.trace_method_exposed_via_options`
  -- all leak server / runtime / module information to unauthenticated
  clients: CWE-200, OWASP A05.
- `external.nginx.default_welcome_page` -- the unconfigured-default page
  proves the server still runs in a stock state: CWE-1188 (insecure default
  initialization of resource), OWASP A05.
- `external.iis.detailed_error_page`, `external.elmah_axd_exposed` -- public
  detailed error pages or error logs expose stack traces and SQL fragments:
  CWE-209 (information exposure through an error message), OWASP A05.
- `external.trace_axd_exposed` -- ASP.NET `trace.axd` exposes per-request
  payloads and developer-only data: CWE-215 (insertion of sensitive
  information into debugging code), OWASP A05.
- **Cookie hardening** (`cookie_missing_secure_on_https`,
  `cookie_samesite_none_without_secure`) -- direct match for CWE-614
  (sensitive cookie in HTTPS session without Secure attribute);
  (`cookie_missing_httponly`) -- CWE-1004; (`cookie_missing_samesite`) --
  CWE-1275. All under OWASP A05 (hardening misconfiguration). Cookie
  hardening also lives in OWASP A07 conceptually, but A05 is the more
  honest fit because the rules check transport configuration rather than
  authentication failure.
- **CORS** (`cors_wildcard_origin`, `cors_wildcard_with_credentials`) --
  CWE-942 (permissive cross-domain policy with untrusted domains),
  OWASP A05.
- **Hardening response headers**
  (`x_frame_options_missing`, `x_frame_options_invalid`) -- CWE-1021
  (clickjacking protection failure);
  (`external.content_security_policy_missing_frame_ancestors`) --
  `frame-ancestors` is the CSP control that restricts which parent documents
  can embed the application. When an observed CSP omits this directive, the
  application can still be framed by unrelated origins, increasing
  clickjacking risk; this maps to CWE-1021, OWASP A05:2021, and ASVS
  v5.0.0-3.4.6;
  (`x_content_type_options_missing/invalid`,
  `content_security_policy_missing`,
  `content_security_policy_unsafe_inline`,
  `content_security_policy_unsafe_eval`,
  `external.content_security_policy_object_src_not_none`,
  `external.content_security_policy_base_uri_not_restricted`,
  `external.content_security_policy_missing_reporting_endpoint`,
  `coep_missing`, `coop_missing`, `corp_missing`) -- CWE-693 (protection
  mechanism failure) because the protection control is absent or
  weakened. OWASP A05.
- `referrer_policy_*`, `permissions_policy_missing` -- as in the universal
  table, no clean CWE for "policy not set / unsafe"; we keep OWASP A05.
- **HTTPS / HSTS** (`https_not_available`, `http_not_redirected_to_https`,
  `hsts_header_missing`, `hsts_header_invalid`, `hsts_max_age_too_short`,
  `hsts_missing_include_subdomains`) -- without HTTPS or proper HSTS the
  channel is downgradeable to plaintext: CWE-319. The two transport
  rules (`https_not_available`, `http_not_redirected_to_https`) sit under
  A02 (cryptographic failures); the HSTS-policy rules are hardening
  misconfigurations under A05.
- `http_redirect_not_permanent` -- cosmetic / SEO-style finding (302
  instead of 301); no security weakness.
- **HTTP method exposure** (`allow_header_dangerous_methods`,
  `dangerous_http_methods_enabled`) -- CWE-650 (trusting HTTP permission
  methods on the server side), OWASP A05;
  (`webdav_methods_exposed`) -- attack-surface increase rather than a
  weakness class, CWE empty, OWASP A05;
  (`options_method_exposed`) -- info-level observation, no
  CWE/OWASP.
- **Sensitive paths** (`git_metadata_exposed`, `svn_metadata_exposed`) --
  CWE-540 (inclusion of sensitive information in source code);
  (`env_file_exposed`, `htaccess_exposed`, `web_config_exposed`) -- CWE-538
  (file/directory information exposure);
  (`htpasswd_exposed`) -- CWE-522 (insufficiently protected credentials),
  OWASP A07;
  (`external.wordpress_admin_panel_exposed`) -- operational guidance for an
  exposed WordPress admin panel, not a weakness class (CWE empty, OWASP A05);
  `robots_txt_exposed` and `sitemap_xml_exposed` are public-by-design and
  stay empty for both CWE and OWASP.
- **TLS protocols / ciphers** (`tls_1_0_supported`, `tls_1_1_supported`,
  `weak_cipher_suite`) -- CWE-327, OWASP A02. (`tls_1_3_not_supported`,
  `cert_chain_length_unusual`) -- operational gaps, not weakness classes;
  CWE empty, OWASP A05.
- **Certificate validity** (`certificate_expired`,
  `certificate_expires_soon`, `tls_certificate_self_signed`,
  `cert_chain_incomplete`, `cert_san_mismatch`) -- a public-facing server
  whose certificate cannot be validated by mainstream clients pushes those
  clients into either accepting an unsafe channel or refusing to connect:
  CWE-295 (improper certificate validation, used as the umbrella class for
  the server-side configuration error), OWASP A02.

## OWASP Cheat Sheet Series companions

The [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) is a
living reference: individual cheat sheets are versioned independently and are
updated continuously, so they do not fit a per-row standards column the same
way CWE / OWASP Top 10 / ASVS / CIS do. Per `STD-GAP-027` from
`docs/benchmarks-covering.md`, cheat sheets are recorded here as
**topic-grouped companions**: each cheat sheet appears once with the rule
IDs whose existing signal honestly aligns with the cheat sheet's
recommendations. A rule can appear under several cheat sheets when its
signal supports more than one recommendation.

| Cheat Sheet | Topic | Aligned rules |
| --- | --- | --- |
| [HTTP Security Response Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | response-header hardening (catch-all) | universal: `missing_hsts`, `missing_x_content_type_options`, `missing_x_frame_options`, `missing_content_security_policy`, `missing_referrer_policy`; nginx: `missing_*_header` family, `content_security_policy_unsafe`, `referrer_policy_unsafe`; apache: `missing_*_header` family, `*_unsafe` family, `htaccess_disables_security_headers`; lighttpd: `missing_strict_transport_security`, `missing_x_content_type_options`; iis: `missing_hsts_header`, `custom_headers_expose_server`, `request_filtering_remove_server_header_disabled`; external: all `external.*_missing` / `external.*_invalid` header rules, `external.content_security_policy_*`, `external.coep_missing`, `external.coop_missing`, `external.corp_missing`, `external.permissions_policy_*`, `external.referrer_policy_*` |
| [HTTP Strict Transport Security](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) | HSTS specifics | universal: `missing_hsts`; nginx: `missing_hsts_header`, `hsts_header_unsafe`; apache: `missing_hsts_header`, `hsts_header_unsafe`; lighttpd: `missing_strict_transport_security`, `strict_transport_security_unsafe`; iis: `missing_hsts_header`, `hsts_header_unsafe`; external: `hsts_header_missing`, `hsts_header_invalid`, `hsts_max_age_too_short`, `hsts_missing_include_subdomains` |
| [Transport Layer Security](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | TLS configuration | universal: `tls_intent_without_config`, `weak_tls_protocol`, `weak_tls_ciphers`; nginx: `weak_ssl_protocols`, `missing_ssl_protocols`, `missing_ssl_ciphers`, `missing_ssl_prefer_server_ciphers`, `ssl_conf_command_tls_compression_enabled`, `ssl_conf_command_unsafe_renegotiation_enabled`, `ssl_session_cache_missing`, `ssl_session_timeout_missing_or_invalid`, `ssl_stapling_*` family, `missing_ssl_certificate*`, `missing_http_to_https_redirect`, `missing_http2_on_tls_listener`; apache: `ssl_protocol_missing_or_weak`, `ssl_cipher_suite_*`, `ssl_honor_cipher_order_not_on`, `ssl_compression_enabled`, `ssl_insecure_renegotiation_enabled`, `ssl_use_stapling_not_on`, `ssl_stapling_cache_missing`, `ssl_session_cache_missing`, `ssl_session_cache_timeout_missing_or_invalid`, `missing_http_to_https_redirect`; lighttpd: `ssl_engine_not_enabled`, `ssl_pemfile_missing`, `ssl_protocol_policy_missing_or_weak`, `weak_ssl_cipher_list`, `ssl_honor_cipher_order_missing`, `ssl_compression_enabled`, `ssl_insecure_renegotiation_enabled`; iis: `schannel_*` family, `ssl_not_required`, `ssl_weak_cipher_strength`, `forms_auth_require_ssl_missing`, `basic_auth_without_ssl`; external: `tls_1_0_supported`, `tls_1_1_supported`, `tls_1_3_not_supported`, `weak_cipher_suite`, `https_not_available`, `http_not_redirected_to_https`, `certificate_expired`, `certificate_expires_soon`, `cert_chain_incomplete`, `cert_chain_length_unusual`, `cert_san_mismatch`, `tls_certificate_self_signed` |
| [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | CSP authoring | universal: `missing_content_security_policy`; nginx: `missing_content_security_policy`, `content_security_policy_unsafe`; apache: `htaccess_disables_security_headers` (partial); external: `content_security_policy_missing`, `content_security_policy_unsafe_inline`, `content_security_policy_unsafe_eval`, `content_security_policy_missing_frame_ancestors`, `content_security_policy_object_src_not_none`, `content_security_policy_base_uri_not_restricted` |
| [Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) | CSRF / SameSite cookie posture | external: `cookie_missing_samesite`, `cookie_samesite_none_without_secure` |
| [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | session cookies / forms auth | iis: `session_state_cookieless`, `forms_auth_require_ssl_missing`, `forms_auth_protection_unsafe`, `http_cookies_http_only_disabled`; external: `cookie_missing_secure_on_https`, `cookie_missing_httponly`, `cookie_missing_samesite`, `cookie_samesite_none_without_secure` |
| [Logging](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | access / error logs and log content | nginx: `missing_access_log`, `missing_error_log`, `missing_log_format`, `error_log_too_restrictive`, `log_format_missing_fields`, `proxy_missing_source_ip_headers`; apache: `custom_log_missing`, `error_log_missing`, `error_log_unsafe_destination`, `log_level_too_restrictive`, `log_format_missing_fields`, `missing_log_format`; lighttpd: `access_log_missing`, `access_log_format_missing_fields`, `error_log_missing`; iis: `logging_not_configured` |
| [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | HTTP authentication and credentials over TLS | nginx: `missing_auth_basic_user_file`; iis: `basic_auth_without_ssl`, `anonymous_auth_enabled`, `anonymous_auth_uses_specific_user`, `authorization_allows_anonymous_users`; external: `htpasswd_exposed` |
| [Credential Stuffing Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html) | credential storage at rest | iis: `credentials_password_format_clear`, `credentials_stored_in_config` |
| [Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) | X-Frame-Options / CSP `frame-ancestors` | universal: `missing_x_frame_options`; nginx: `missing_x_frame_options`; apache: `missing_x_frame_options_header`, `x_frame_options_unsafe`; external: `x_frame_options_missing`, `x_frame_options_invalid`, `content_security_policy_missing_frame_ancestors` |
| [Server-Side Headers (HTTP Headers cheat sheet, Server section)](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server) | server / version disclosure removal | nginx: `server_tokens_on`; apache: `server_tokens_not_prod`, `server_signature_not_off`; lighttpd: `server_tag_not_blank`; iis: `custom_headers_expose_server`, `request_filtering_remove_server_header_disabled`, `http_runtime_version_header_enabled`; external: `server_version_disclosed`, `x_powered_by_header_present`, `x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.nginx.version_disclosed_in_server_header`, `external.apache.version_disclosed_in_server_header`, `external.lighttpd.version_in_server_header`, `external.apache.etag_inode_disclosure` |
| [Web Service Security](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html) | HTTP methods / request size limits / dangerous handlers | nginx: `missing_http_method_restrictions`, `missing_allowed_methods_restriction_for_uploads`, `http_method_policy_allows_unapproved`, `missing_client_max_body_size`, `client_max_body_size_unlimited`, `executable_scripts_allowed_in_uploads`; apache: `missing_http_method_restrictions`, `http_method_policy_allows_unapproved`, `trace_enable_not_off`, `limit_request_*`; iis: `request_filtering_*` family, `max_allowed_content_length_missing`, `webdav_module_enabled`, `cgi_handler_enabled`, `handler_write_script_execute_enabled`, `file_extensions_allow_unlisted`, `isapi_cgi_restrictions_allow_unlisted`; external: `trace_method_allowed`, `trace_method_exposed_via_options`, `dangerous_http_methods_enabled`, `webdav_methods_exposed`, `allow_header_dangerous_methods` |
| [File Upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) | upload directories / executable handlers | nginx: `executable_scripts_allowed_in_uploads`, `missing_allowed_methods_restriction_for_uploads`; iis: `handler_write_script_execute_enabled`, `cgi_handler_enabled`, `isapi_cgi_restrictions_allow_unlisted` |
| [Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) | sensitive paths / IP filters / wildcard auth | nginx: `allow_all_with_deny_all`, `missing_access_restrictions_on_sensitive_locations`, `sensitive_location_missing_ip_filter`; apache: `allowoverride_*`, `htaccess_*` family; lighttpd: `url_access_deny_missing`; iis: `authorization_allows_anonymous_users` |
| [Error Handling](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) | detailed errors / debug content | apache: `error_document_404_missing`, `error_document_500_missing`; iis: `http_errors_detailed`, `custom_errors_off`, `asp_script_error_sent_to_browser`, `compilation_debug_enabled`, `trace_enabled`, `deployment_retail_not_enabled`; external: `external.iis.detailed_error_page`, `elmah_axd_exposed`, `trace_axd_exposed`, `phpinfo_exposed` |

Cheat sheet rule semantics:

- a rule listed under several cheat sheets is honest as long as each cheat
  sheet recommends a behaviour the rule's signal partially proves;
- cheat sheets are **not** treated as a primary standard; their references
  do not migrate into a new column. They live only in this consolidated
  block;
- when a future PR adds a rule whose signal already maps to one of these
  cheat sheets, the rule ID is appended to the existing entry rather than a
  new entry being created.

## PCI DSS v4.0.1 mapping

Per `STD-GAP-021` from `docs/benchmarks-covering.md`. Source:
[PCI DSS v4.0.1](https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf),
June 2024. PCI DSS requirements group large families of rules under one
control identifier (e.g. all TLS rules under Req. 4.2.1), so they are
recorded here as a consolidated mapping block instead of a per-row column.

Aligned-rule cells use `(partial: <limit>)` when the rule's signal proves
the requirement only in a narrow scope. Rules that already cover the
requirement directly do not need a partial annotation.

| PCI DSS v4.0.1 requirement | Topic | Aligned rules |
| --- | --- | --- |
| Req. 2.2.1 | Configuration standards developed | catch-all for all hardening rules across `universal.*`, `nginx.*`, `apache.*`, `lighttpd.*`, `iis.*`, and `external.*` |
| Req. 2.2.5 | Insecure services / protocols / daemons disabled | nginx: rules covered under Req. 2.2.6 below; apache: `trace_enable_not_off`, `options_execcgi_enabled`, `options_includes_enabled`, `options_multiviews_enabled`; lighttpd: `mod_cgi_enabled`, `mod_status_public`; iis: `webdav_module_enabled`, `cgi_handler_enabled`, `handler_write_script_execute_enabled`; external: `trace_method_allowed`, `trace_method_exposed_via_options`, `dangerous_http_methods_enabled`, `webdav_methods_exposed`, `allow_header_dangerous_methods`, `external.apache.mod_status_public`, `lighttpd.mod_status_public`, `nginx_status_exposed`, `server_status_exposed`, `server_info_exposed` |
| Req. 2.2.6 | System security parameters configured to prevent misuse | nginx: `server_tokens_on`; apache: `server_tokens_not_prod`, `server_signature_not_off`, `server_status_exposed`, `server_info_exposed`, `file_etag_inodes`; lighttpd: `server_tag_not_blank`; iis: `custom_headers_expose_server`, `request_filtering_remove_server_header_disabled`, `http_runtime_version_header_enabled`, `http_errors_detailed`, `custom_errors_off`, `asp_script_error_sent_to_browser`, `deployment_retail_not_enabled`, `compilation_debug_enabled`, `trace_enabled`; external: `phpinfo_exposed`, `elmah_axd_exposed`, `trace_axd_exposed`, `git_metadata_exposed`, `svn_metadata_exposed`, `web_config_exposed`, `htaccess_exposed`, `env_file_exposed`, `external.iis.detailed_error_page`, `wordpress_admin_panel_exposed`, all `*.version_disclosed_in_server_header`, `x_powered_by_header_present`, `x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.apache.etag_inode_disclosure`, `external.nginx.default_welcome_page` |
| Req. 4.2.1 | Strong cryptography for transmissions over open public networks | universal: `tls_intent_without_config`, `weak_tls_protocol`, `weak_tls_ciphers`, `missing_hsts`; nginx: `weak_ssl_protocols`, `missing_ssl_protocols`, `missing_ssl_ciphers`, `missing_ssl_prefer_server_ciphers`, `ssl_conf_command_tls_compression_enabled`, `ssl_conf_command_unsafe_renegotiation_enabled`, `missing_hsts_header`, `hsts_header_unsafe`, `missing_http_to_https_redirect`, `ssl_stapling_*` family, `missing_ssl_certificate*`, `missing_http2_on_tls_listener`; apache: `ssl_protocol_missing_or_weak`, `ssl_cipher_suite_*`, `ssl_honor_cipher_order_not_on`, `ssl_compression_enabled`, `ssl_insecure_renegotiation_enabled`, `ssl_use_stapling_not_on`, `ssl_stapling_cache_missing`, `missing_hsts_header`, `hsts_header_unsafe`, `missing_http_to_https_redirect`; lighttpd: `ssl_engine_not_enabled`, `ssl_pemfile_missing`, `ssl_protocol_policy_missing_or_weak`, `weak_ssl_cipher_list`, `ssl_honor_cipher_order_missing`, `ssl_compression_enabled`, `ssl_insecure_renegotiation_enabled`, `missing_strict_transport_security`, `strict_transport_security_unsafe`, `basic_auth_over_http`; iis: `schannel_*` family, `ssl_not_required`, `ssl_weak_cipher_strength`, `missing_hsts_header`, `hsts_header_unsafe`, `basic_auth_without_ssl`, `forms_auth_require_ssl_missing`; external: `https_not_available`, `http_not_redirected_to_https`, `tls_1_0_supported`, `tls_1_1_supported`, `weak_cipher_suite`, `hsts_*` family, `cert_*` family, `certificate_*` family, `tls_certificate_self_signed` |
| Req. 6.2.4 | Common attack vectors / hardening for bespoke and custom software | nginx: `executable_scripts_allowed_in_uploads`, `missing_allowed_methods_restriction_for_uploads`; apache: `htaccess_enables_cgi`, `htaccess_enables_directory_listing`, `htaccess_disables_security_headers`, `htaccess_weakens_security`, `htaccess_contains_security_directive`, `htaccess_rewrite_without_limit`, `htaccess_auth_without_require`; iis: `request_filtering_*` family, `file_extensions_allow_unlisted`, `isapi_cgi_restrictions_allow_unlisted`, `handler_write_script_execute_enabled`, `cgi_handler_enabled` |
| Req. 6.4.3 | Public-facing web application — payment-page scripts integrity (CSP / SRI surface) | universal: `missing_content_security_policy`; nginx: `missing_content_security_policy`, `content_security_policy_unsafe`; external: `content_security_policy_missing`, `content_security_policy_unsafe_inline`, `content_security_policy_unsafe_eval`, `content_security_policy_missing_frame_ancestors`, `content_security_policy_object_src_not_none`, `content_security_policy_base_uri_not_restricted` (partial: presence and unsafe-token coverage; SRI / nonce-hash policy is `probe-depth` — see `STD-GAP-013` / `STD-GAP-014`) |
| Req. 8.3.1 | Strong authentication for users / administrators | nginx: `missing_auth_basic_user_file`; iis: `basic_auth_without_ssl`, `anonymous_auth_enabled`, `anonymous_auth_uses_specific_user`, `authorization_allows_anonymous_users`, `forms_auth_require_ssl_missing`; external: `htpasswd_exposed` |
| Req. 8.3.2 | Strong cryptography for transmission of all auth factors | iis: `forms_auth_require_ssl_missing`, `basic_auth_without_ssl`, `forms_auth_protection_unsafe`; external: `cookie_missing_secure_on_https`, `cookie_samesite_none_without_secure` |
| Req. 8.3.5 / 8.3.6 | Authentication credentials protected at rest | iis: `credentials_password_format_clear`, `credentials_stored_in_config`, `machine_key_validation_weak`, `machine_key_legacy_validation_weak`; external: `htpasswd_exposed` |
| Req. 10.2.1 | Audit logs enabled and active | nginx: `missing_access_log`, `missing_error_log`, `error_log_too_restrictive`; apache: `custom_log_missing`, `error_log_missing`, `error_log_unsafe_destination`, `log_level_too_restrictive`; lighttpd: `access_log_missing`, `error_log_missing`; iis: `logging_not_configured` |
| Req. 10.2.2 | Audit logs record specific items (user, event type, date/time, success/failure, origin) | nginx: `missing_log_format`, `log_format_missing_fields`, `proxy_missing_source_ip_headers`; apache: `missing_log_format`, `log_format_missing_fields`; lighttpd: `access_log_format_missing_fields` (partial: presence and field-coverage validation; storage policy and protection are out of scope) |
| Req. 10.5 | Audit log retention and protection | none — `out-of-scope` (filesystem permissions / log rotation outside web server config) |
| Req. 12 (organizational) | Information security policy / process | `out-of-scope` for `webconf-audit` |

Honesty notes:

- PCI DSS Req. 4.2.1 explicitly references "strong cryptography" with TLS
  1.2 minimum and TLS 1.0 / 1.1 prohibited as of 31-Mar-2025; the listed
  rules cover this directly. Forward-secrecy and recommended-suite
  validation deeper than weak-pattern detection remain
  `STD-GAP-014` `probe-depth` follow-up.
- Req. 6.4.3 needs SRI / nonce-hash policy for full coverage; current rules
  cover only presence and unsafe-token detection.
- Req. 10.5 (log protection) is filesystem-level; no current rule has
  visibility.
- Cells without aligned rules stay omitted rather than `-`: the consolidated
  block records only requirements where webconf-audit currently has at
  least one honest signal.

## NIST SP 800-52 Rev. 2 mapping

Per `STD-GAP-016` from `docs/benchmarks-covering.md`. Source:
[NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final),
August 2019. Same consolidation rule as PCI DSS above: TLS-control
families map to large rule groups, so a per-row column would be redundant
with the existing TLS rules under CWE-327 / OWASP A02 / CIS protocol
sections.

| 800-52 Rev. 2 section | Topic | Aligned rules |
| --- | --- | --- |
| §3.1.1 / §3.1.2 | TLS 1.2 mandatory; TLS 1.3 recommended | universal: `weak_tls_protocol`; nginx: `weak_ssl_protocols`, `missing_ssl_protocols`; apache: `ssl_protocol_missing_or_weak`; lighttpd: `ssl_protocol_policy_missing_or_weak`; iis: `schannel_tls12_not_enabled`, `schannel_weak_protocol_enabled`; external: `tls_1_0_supported`, `tls_1_1_supported`, `tls_1_3_not_supported` (info) |
| §3.3.1 | Recommended cipher suites | universal: `weak_tls_ciphers`; nginx: `missing_ssl_ciphers`, `ssl_ciphers_weak`; apache: `ssl_cipher_suite_missing`, `ssl_cipher_suite_weak`; lighttpd: `weak_ssl_cipher_list`; iis: `schannel_aes128_enabled`, `schannel_aes256_not_enabled`, `ssl_weak_cipher_strength`; external: `weak_cipher_suite` (partial: local rules use conservative weak-component / FS / AEAD checks; full runtime recommended-suite validation is `STD-GAP-014` `probe-depth`) |
| §3.3.2 | Server preference order | nginx: `missing_ssl_prefer_server_ciphers`; apache: `ssl_honor_cipher_order_not_on`; lighttpd: `ssl_honor_cipher_order_missing`; iis: `schannel_cipher_suite_order_not_preferred` |
| §3.4 | Server certificate validation | external: `certificate_expired`, `certificate_expires_soon`, `tls_certificate_self_signed`, `cert_chain_incomplete`, `cert_san_mismatch`, `cert_chain_length_unusual` (advisory) |
| §3.5 | Insecure renegotiation disabled | apache: `ssl_insecure_renegotiation_enabled`; nginx: `ssl_conf_command_unsafe_renegotiation_enabled`; lighttpd: `ssl_insecure_renegotiation_enabled` (partial: explicit local directives only) |
| §3.6 | TLS compression disabled | apache: `ssl_compression_enabled`; nginx: `ssl_conf_command_tls_compression_enabled`; lighttpd: `ssl_compression_enabled` (partial: explicit local directives only) |
| §4.2 / §4.3 (OCSP stapling) | Stapling enabled with valid resolver / verify | nginx: `ssl_stapling_disabled`, `ssl_stapling_missing_resolver`, `ssl_stapling_without_verify`; apache: `ssl_use_stapling_not_on`, `ssl_stapling_cache_missing` |
| §4.2.4 (HSTS) | HSTS strongly recommended | universal: `missing_hsts`; nginx: `missing_hsts_header`, `hsts_header_unsafe`; apache: `missing_hsts_header`, `hsts_header_unsafe`; lighttpd: `missing_strict_transport_security`, `strict_transport_security_unsafe`; iis: `missing_hsts_header`, `hsts_header_unsafe`; external: `hsts_header_missing`, `hsts_header_invalid`, `hsts_max_age_too_short`, `hsts_missing_include_subdomains` |
| Top-level "no plaintext fallback" | HTTP→HTTPS / TLS-required posture | universal: `tls_intent_without_config`; nginx: `missing_ssl_certificate`, `missing_ssl_certificate_key`, `missing_http_to_https_redirect`; apache: `missing_http_to_https_redirect`; lighttpd: `ssl_engine_not_enabled`, `ssl_pemfile_missing`; iis: `ssl_not_required`, `basic_auth_without_ssl`, `forms_auth_require_ssl_missing`; external: `https_not_available`, `http_not_redirected_to_https` |

## ФСТЭК «Меры защиты информации в ГИС» mapping

Per `STD-GAP-031` from `docs/benchmarks-covering.md`. Источник: ФСТЭК
России, методический документ «Меры защиты информации в государственных
информационных системах» (11.02.2014, действует), классы мер **ИАФ /
УПД / ОПС / РСБ / АНЗ / ЗИС**. Применяется в связке с Приказами ФСТЭК
№ 17 (ГИС) и № 21 (ИСПДн).

| Мера | Класс | Aligned rules |
| --- | --- | --- |
| ИАФ.1 | Идентификация и аутентификация субъектов доступа | nginx: `missing_auth_basic_user_file`; iis: `basic_auth_without_ssl`, `anonymous_auth_enabled`, `anonymous_auth_uses_specific_user`, `authorization_allows_anonymous_users` |
| ИАФ.6 | Защита аутентификационной информации | iis: `credentials_password_format_clear`, `credentials_stored_in_config`, `forms_auth_require_ssl_missing`, `forms_auth_protection_unsafe`, `basic_auth_without_ssl`, `machine_key_validation_weak`, `machine_key_legacy_validation_weak`; external: `htpasswd_exposed` |
| УПД.5 | Управление доступом субъектов доступа к объектам доступа | nginx: `allow_all_with_deny_all`, `missing_access_restrictions_on_sensitive_locations`, `sensitive_location_missing_ip_filter`, `alias_without_trailing_slash`; apache: `allowoverride_*` family, `htaccess_*` family, `missing_http_method_restrictions`, `http_method_policy_allows_unapproved`; lighttpd: `url_access_deny_missing`; iis: `authorization_allows_anonymous_users`, `anonymous_auth_enabled`; external: `wordpress_admin_panel_exposed` |
| УПД.13 | Реализация защищённого удалённого доступа субъектов доступа | universal: `tls_intent_without_config`, `weak_tls_protocol`, `weak_tls_ciphers`, `missing_hsts`; nginx + apache + lighttpd + iis: same set as in PCI Req. 4.2.1 above; external: same set as in PCI Req. 4.2.1 above |
| ОПС.3 | Идентификация и аутентификация компонентов информационной системы | nginx: `proxy_missing_source_ip_headers` (partial: `parser-depth` для полной модели upstream-trust) |
| РСБ.1 | Определение событий безопасности и их регистрация | nginx: `missing_access_log`, `missing_error_log`; apache: `custom_log_missing`, `error_log_missing`, `error_log_unsafe_destination`; lighttpd: `access_log_missing`, `error_log_missing`; iis: `logging_not_configured` |
| РСБ.3 | Сбор, запись и хранение информации о событиях безопасности | nginx: `missing_log_format`, `log_format_missing_fields`, `error_log_too_restrictive`, `proxy_missing_source_ip_headers`; apache: `missing_log_format`, `log_format_missing_fields`, `log_level_too_restrictive`; lighttpd: `access_log_format_missing_fields` |
| РСБ.7 | Защита информации о событиях безопасности | none — `out-of-scope` (права на лог-файлы / ротация / целостность вне web-server config) |
| АНЗ.1 | Выявление, анализ уязвимостей информационной системы | external: все probes по version-disclosure (`*.version_disclosed_in_server_header`, `server_version_disclosed`, `x_powered_by_header_present`, `x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.apache.etag_inode_disclosure`), debug endpoints (`phpinfo_exposed`, `elmah_axd_exposed`, `trace_axd_exposed`, `external.iis.detailed_error_page`), VCS metadata (`git_metadata_exposed`, `svn_metadata_exposed`), exposed configs (`web_config_exposed`, `htaccess_exposed`, `env_file_exposed`, `htpasswd_exposed`), status endpoints (`server_status_exposed`, `server_info_exposed`, `nginx_status_exposed`, `external.apache.mod_status_public`, `lighttpd.mod_status_public`); local: `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `lighttpd.server_tag_not_blank`, `iis.custom_headers_expose_server` |
| АНЗ.2 | Контроль установки обновлений ПО | none — `out-of-scope` |
| ЗИС.3 | Защита от внешних и внутренних угроз | universal: `listen_on_all_interfaces`; apache: `listen_requires_explicit_address`, `ip_based_requests_allowed`, `default_tls_vhost_not_rejecting_unknown_hosts`; iis: `binding_without_host_header` |
| ЗИС.20 | Защита каналов связи | same set as `УПД.13` (TLS / HSTS / redirect rules) |
| ЗИС.32 | Защита веб-серверов / веб-приложений | catch-all для всех hardening rules (response headers, CSP, sensitive paths, request limits, timeout, request filtering) |

Замечания по честности:

- Меры защиты ФСТЭК сформулированы шире, чем отдельные рулесет-сигналы;
  поэтому для большинства мер указано «aligned» при наличии хотя бы одного
  частичного сигнала. Полное соответствие требует комбинации этих сигналов
  с организационными мерами вне области сканера.
- Меры, требующие OS/package/filesystem inspection (РСБ.7, АНЗ.2), остаются
  вне области инструмента: webconf-audit анализирует web-server config и
  безопасные external-признаки, а не состояние хоста.
- Приказы ФСТЭК № 17 и № 21 определяют, какой состав мер обязателен для
  конкретного класса ГИС / ИСПДн; этот блок только показывает, какие меры
  webconf-audit способен помочь подтвердить.

## Lighttpd vendor reference mapping

Per `STD-GAP-030` from `docs/benchmarks-covering.md`. There is no official
*CIS Lighttpd Benchmark*, so the existing `CIS / Vendor` column for the
Lighttpd table is intentionally left empty (see the intro under
`### Lighttpd (Local)`). Vendor and community baseline references are
recorded here as a topic-grouped block to avoid implying a CIS-style
benchmark mapping in a per-row column.

Sources:

- [DevSec lighttpd-baseline](https://github.com/dev-sec/lighttpd-baseline)
  — community InSpec profile, Apache-2.0 license. Identifiers `lighttpd-NN`
  refer to controls in that profile.
- [lighttpd Security wiki](https://redmine.lighttpd.net/projects/lighttpd/wiki/Docs_Security)
  and the per-module documentation pages on
  [redmine.lighttpd.net](https://redmine.lighttpd.net/projects/lighttpd/wiki).

| Vendor reference | Topic | Aligned rules |
| --- | --- | --- |
| DevSec lighttpd-baseline `lighttpd-01` (server.tag) | server identification removal | `lighttpd.server_tag_not_blank` |
| DevSec lighttpd-baseline `lighttpd-02` (dir-listing) | directory listing disabled | `lighttpd.dir_listing_enabled` |
| DevSec lighttpd-baseline `lighttpd-03` (ssl modes) | TLS configuration baseline | `lighttpd.ssl_engine_not_enabled`, `lighttpd.ssl_pemfile_missing`, `lighttpd.ssl_protocol_policy_missing_or_weak`, `lighttpd.weak_ssl_cipher_list`, `lighttpd.ssl_honor_cipher_order_missing` |
| DevSec lighttpd-baseline `lighttpd-05` (forbidden methods) | HTTP method allowlist | `lighttpd.missing_http_method_restrictions` |
| lighttpd Security wiki — `mod_status` | status endpoint exposure | `lighttpd.mod_status_public` |
| lighttpd Security wiki — `mod_cgi` | least-functionality / CGI | `lighttpd.mod_cgi_enabled` |
| lighttpd Security wiki — `url.access-deny` | sensitive-file deny lists | `lighttpd.url_access_deny_missing` |
| lighttpd `mod_accesslog` documentation | access logging | `lighttpd.access_log_missing`, `lighttpd.access_log_format_missing_fields` |
| lighttpd `server.errorlog` documentation | error logging | `lighttpd.error_log_missing` |
| lighttpd `server.max-connections` documentation | resource limits | `lighttpd.max_connections_missing` |
| lighttpd `server.max-request-size` documentation | request body limits | `lighttpd.max_request_size_missing` |
| lighttpd Security wiki — security response headers via `mod_setenv` | hardening response headers | `lighttpd.missing_strict_transport_security`, `lighttpd.strict_transport_security_unsafe`, `lighttpd.missing_x_content_type_options` |

Notes:

- DevSec is community-maintained, not an authoritative benchmark. References
  are tracked here as `Vendor:` companions, not as primary standards. The
  `CIS / Vendor` column in the inventory table for Lighttpd remains empty.
- The lighttpd wiki pages cited above are stable URLs; if the wiki is
  reorganised, this block must be updated rather than the inventory rows.
- The `lighttpd-05` row is the only DevSec control without a corresponding
  rule in the registry today and is left as a `direct-rule` follow-up.

## ISO/IEC 27002:2022 / ГОСТ Р ИСО/МЭК 27002-2021 mapping

Per `STD-GAP-024` from `docs/benchmarks-covering.md`. ГОСТ Р ИСО/МЭК
27002-2021 — точная локализация ISO/IEC 27002:2022, поэтому идентификаторы
контролов совпадают и записываются в одной строке.

| ISO 27002 control | Topic | Aligned rules |
| --- | --- | --- |
| 5.15 | Access control | same set as ФСТЭК `УПД.5` above |
| 8.5 | Secure authentication | same set as ФСТЭК `ИАФ.1` / `ИАФ.6` above |
| 8.15 | Logging | same set as ФСТЭК `РСБ.1` / `РСБ.3` above |
| 8.16 | Monitoring activities | partial via the same logging rules; full monitoring is application/SOC concern |
| 8.18 | Use of privileged utility programs | apache: `options_execcgi_enabled`, `options_includes_enabled`, `options_multiviews_enabled`; lighttpd: `mod_cgi_enabled`; iis: `webdav_module_enabled`, `cgi_handler_enabled`, `handler_write_script_execute_enabled` |
| 8.20 | Networks security | universal: `listen_on_all_interfaces`; apache: `listen_requires_explicit_address`, `ip_based_requests_allowed`, `default_tls_vhost_not_rejecting_unknown_hosts`; iis: `binding_without_host_header` |
| 8.21 | Security of network services | same set as ФСТЭК `УПД.13` (TLS / HSTS / redirect family) |
| 8.23 | Web filtering | `out-of-scope` |
| 8.24 | Use of cryptography | same set as NIST SP 800-52 Rev. 2 §3.x sections above |
| 8.25 | Secure development life cycle | `out-of-scope` (process) |
| 8.26 | Application security requirements | partial via response-header rules and CSP / cookie rules |
| 8.27 | Secure system architecture and engineering principles | catch-all hardening across all rule families |
| 8.28 | Secure coding | `out-of-scope` |
| 8.29 | Security testing in development and acceptance | `out-of-scope` (process) |

## Secondary tags

Per `STD-GAP-026` (MITRE ATT&CK Enterprise) and `STD-GAP-032` (ФСТЭК БДУ)
from `docs/benchmarks-covering.md`. These are **threat catalogues**, not
defensive standards: they describe attacker techniques and threat models,
not security controls. They are useful as **secondary tags** for telemetry
and SOC context, but they must never replace a primary standards reference.

Architectural decision: secondary tags live in this consolidated block
only. They are not added as a new column to the inventory tables, and they
do not enter `StandardReference` records on rules at this stage. If a
future PR introduces a `tier: primary|secondary` field on
`StandardReference` (for example as part of `STD-GAP-012`), the entries
below become the source of truth for the migration.

### MITRE ATT&CK Enterprise v15

Source: [MITRE ATT&CK Enterprise v15](https://attack.mitre.org/versions/v15/),
released April 2024.

| ATT&CK technique | Topic | Aligned rules (telemetry context) |
| --- | --- | --- |
| [T1190](https://attack.mitre.org/techniques/T1190/) — Exploit Public-Facing Application | exposed sensitive paths / debug / framework leaks | external: `git_metadata_exposed`, `svn_metadata_exposed`, `env_file_exposed`, `web_config_exposed`, `htaccess_exposed`, `phpinfo_exposed`, `elmah_axd_exposed`, `trace_axd_exposed`, `wordpress_admin_panel_exposed`, `external.iis.detailed_error_page` |
| [T1592.002](https://attack.mitre.org/techniques/T1592/002/) — Gather Victim Host Information: Software | server / framework version disclosure | external: `server_version_disclosed`, `x_powered_by_header_present`, `x_aspnet_version_header_present`, `external.iis.aspnet_version_header_present`, `external.nginx.version_disclosed_in_server_header`, `external.apache.version_disclosed_in_server_header`, `external.lighttpd.version_in_server_header`, `external.apache.etag_inode_disclosure`; local: `nginx.server_tokens_on`, `apache.server_tokens_not_prod`, `apache.server_signature_not_off`, `lighttpd.server_tag_not_blank`, `iis.custom_headers_expose_server`, `iis.http_runtime_version_header_enabled`, `iis.request_filtering_remove_server_header_disabled` |
| [T1592.004](https://attack.mitre.org/techniques/T1592/004/) — Client Configurations | server status / info endpoints | external: `server_status_exposed`, `server_info_exposed`, `nginx_status_exposed`, `external.apache.mod_status_public`, `lighttpd.mod_status_public`; local: `apache.server_status_exposed`, `apache.server_info_exposed`, `lighttpd.mod_status_public` |
| [T1213.003](https://attack.mitre.org/techniques/T1213/003/) — Data from Information Repositories: Code Repositories | VCS metadata leaks | external: `git_metadata_exposed`, `svn_metadata_exposed`; local: `nginx.missing_hidden_files_deny`, `apache.vcs_metadata_not_restricted` |
| [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts | credential / password file leak | external: `htpasswd_exposed`; iis: `credentials_password_format_clear`, `credentials_stored_in_config` |
| [T1040](https://attack.mitre.org/techniques/T1040/) — Network Sniffing | plaintext channel exposure | external: `https_not_available`, `http_not_redirected_to_https`; iis: `basic_auth_without_ssl`, `forms_auth_require_ssl_missing`; all HSTS rules across families |
| [T1505.003](https://attack.mitre.org/techniques/T1505/003/) — Server Software Component: Web Shell | upload + execute combination | nginx: `executable_scripts_allowed_in_uploads`; iis: `handler_write_script_execute_enabled`, `cgi_handler_enabled` |
| [T1557](https://attack.mitre.org/techniques/T1557/) — Adversary-in-the-Middle | weak / cleartext TLS | universal: `weak_tls_protocol`, `weak_tls_ciphers`; all per-server weak-protocol / weak-cipher rules; external: `tls_1_0_supported`, `tls_1_1_supported`, `weak_cipher_suite` |
| [T1574](https://attack.mitre.org/techniques/T1574/) — Hijack Execution Flow | writable executable handler paths | iis: `handler_write_script_execute_enabled` |

### ФСТЭК БДУ — Банк данных угроз

Источник: [ФСТЭК России, Банк данных угроз](https://bdu.fstec.ru/),
актуальный реестр угроз `УБИ.NNN`. Это каталог угроз, не мер защиты;
пишется как secondary tag, основной стандарт — ФСТЭК «Меры защиты ГИС»
(см. блок выше).

| УБИ | Заголовок | Aligned rules (telemetry context) |
| --- | --- | --- |
| [УБИ.044](https://bdu.fstec.ru/threat/ubi.044) | Угроза несанкционированного доступа за счёт перехвата сетевого трафика | external: `https_not_available`, `http_not_redirected_to_https`; iis: `basic_auth_without_ssl`, `forms_auth_require_ssl_missing`; все HSTS rules |
| [УБИ.067](https://bdu.fstec.ru/threat/ubi.067) | Угроза неправомерного ознакомления с защищаемой информацией | external: `git_metadata_exposed`, `svn_metadata_exposed`, `env_file_exposed`, `web_config_exposed`, `htaccess_exposed`, `phpinfo_exposed`, `elmah_axd_exposed`, `trace_axd_exposed`, `external.iis.detailed_error_page` |
| [УБИ.072](https://bdu.fstec.ru/threat/ubi.072) | Угроза получения НСД через неподконтрольный канал | universal: `weak_tls_protocol`, `weak_tls_ciphers`; все weak-protocol / weak-cipher rules per server; external: `tls_1_0_supported`, `tls_1_1_supported`, `weak_cipher_suite` |
| [УБИ.121](https://bdu.fstec.ru/threat/ubi.121) | Угроза искажения web-страниц | external: `content_security_policy_*` family, `x_frame_options_*` family, `x_content_type_options_*` family; universal: `missing_content_security_policy`, `missing_x_frame_options`, `missing_x_content_type_options` |
| [УБИ.184](https://bdu.fstec.ru/threat/ubi.184) | Угроза разглашения сведений об учётной записи | external: `htpasswd_exposed`; iis: `credentials_password_format_clear`, `credentials_stored_in_config`, `basic_auth_without_ssl` |

Правила secondary-тегов:

- secondary tag **никогда** не заменяет primary standard. ATT&CK / БДУ
  ссылки могут существовать только в дополнение к CWE / OWASP / ASVS / CIS;
- ATT&CK / БДУ не добавляются ни как новая колонка в inventory tables, ни
  как отдельные `StandardReference` записи на правилах в текущей итерации;
- если в `STD-GAP-012` появится поддержка `tier=secondary` — этот блок
  становится исходником миграции;
- threat-каталоги обновляются чаще, чем benchmark-документы: ATT&CK имеет
  ежегодные релизы, БДУ обновляется регулярно. При изменении версии нужно
  пересмотреть только этот блок, а не строки таблиц.

## Standards mapping plan

Stage 2 step 3 of the roadmap is to map these rules to external standards
only where the mapping is honest:

- **CWE** for rules with a clear weakness class.
- **OWASP** for rules supporting an application security control.
- **CIS / vendor hardening** for rules that mirror configuration-specific
  guidance from CIS benchmarks or vendor hardening guides.

Progress:

- [x] Universal rules (13)
- [x] Nginx local rules (77) — CWE/OWASP filled; CIS existing-rule reference
  pass complete
- [x] Apache local rules (70) — CWE/OWASP filled; CIS existing-rule reference
  pass complete
- [x] Lighttpd local rules (23)
- [x] IIS local rules (47) — CWE/OWASP/ASVS filled; CIS existing-rule reference
  pass complete
- [x] External (probe) rules (73) — CWE/OWASP filled; CIS not applicable (probes)
- [x] ASVS 5.0.0 first-pass references for reviewed direct/partial candidates

Stage 2 step 3 is complete for CWE / OWASP Top 10. This file is already the
canonical rule-level store for those completed mappings. Reviewed ASVS 5.0.0
direct/partial references are now stored in the dedicated `ASVS` column.
Unresolved standards follow-up gaps stay in `docs/standards-roadmap.md`.
CIS references that passed review are copied into the existing
`CIS / Vendor` column.

Each follow-up PR fills one standards family at a time and only writes a CWE,
OWASP Top 10, ASVS, or CIS reference when it is verifiable. Cells without an
honest match stay as `-`.

### Mapping conventions

- **CWE links** point at the canonical entry on
  [cwe.mitre.org](https://cwe.mitre.org/data/definitions/).
- **OWASP** uses the 2021 Top 10 categories
  ([A01](https://owasp.org/Top10/A01_2021-Broken_Access_Control/),
  [A02](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/),
  [A05](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/),
  ...). This column is not used for ASVS requirement IDs.
- **ASVS** references are stored in the separate `ASVS` column. Use versioned
  IDs such as `ASVS v5.0.0-3.4.1`; partial coverage must include a short
  parenthetical limit, for example `ASVS v5.0.0-12.1.2 (partial: weak-pattern
  detection only)`.
- **CIS / vendor hardening** points at a specific section of a CIS Benchmark
  (e.g. *CIS Apache HTTP Server 2.4 Benchmark* §7.6) or an official vendor
  hardening guide. Universal rules delegate to the per-server tables because
  the same conceptual check has different section numbers in each benchmark.
- Cells stay empty (`-`) when no honest match exists; we prefer an empty cell
  to a stretched mapping.
