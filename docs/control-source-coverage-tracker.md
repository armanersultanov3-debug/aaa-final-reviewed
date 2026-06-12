# Control Source Coverage Tracker

This file is the count ledger behind the coverage snapshot in
`docs/benchmarks-covering.md`. It is intentionally narrower than
`docs/rule-coverage.md`: the rule coverage file is the rule-level inventory,
while this tracker explains how the project counts the diploma-style summary
rows.

The current calculation is conservative:

- the denominator contains applicable web-server-visible items only;
- out-of-scope items are removed before counting;
- the numerator contains only fully covered items;
- partial and policy review evidence is recorded, but neither increases the
  full-coverage percentage;
- every applicable source reconciles as
  `Applicable = Full + Partial + policy-review + Uncovered`;
- excluded items are documented separately and do not enter the applicable
  denominator;
- every percentage change must update this file and
  `docs/benchmarks-covering.md` together.

## Snapshot Summary

| Control source | Applicable | Full | Partial | `policy-review` | Uncovered | Full coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CIS NGINX Benchmark v3.0.0 | 15 | 7 | 7 | 1 | 0 | 46.7% |
| CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | 19 | 17 | 2 | 0 | 0 | 89.5% |
| CIS Microsoft IIS 10 Benchmark v1.2.1 | 10 | 8 | 1 | 0 | 1 | 80.0% |
| OWASP Top 10:2025 | 8 | 0 | 8 | 0 | 0 | 0.0% |
| OWASP ASVS v5.0.0 | 22 | 14 | 8 | 0 | 0 | 63.6% |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 | 100.0% |
| PCI DSS v4.0.1 | 11 | 0 | 9 | 0 | 2 | 0.0% |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 | 80.0% |

## Status Vocabulary

| Status | Meaning |
| --- | --- |
| `full` | The project has local, normalized, registry-export, or safe-probe evidence that covers the counted item. |
| `partial` | The project verifies a real narrower signal, but not the complete source requirement. |
| `policy-review` | An opt-in rule surfaces relevant configuration facts, but operator judgment is required before treating them as a defect. |
| `uncovered` | The item remains applicable, but the project has no implemented evidence for it. |
| `excluded` | The item is outside the current denominator because it needs host OS, filesystem, package-manager, application-code, SIEM, or business-policy context. |

`policy-review` is an evidence status, not a registry category or a severity.
The corresponding rules keep their normal execution category and use the
existing `info` severity with the opt-in `policy-review` tag.

## CIS NGINX Benchmark v3.0.0

Applicable count: 15. Full count: 7. Partial count: 7. `policy-review`
count: 1. Uncovered count: 0.

| Counted item | Status | Current basis / next action |
| --- | --- | --- |
| §2.4.2 unknown-host handling | full | `nginx.default_server_not_rejecting_unknown_hosts`, `nginx.default_tls_server_not_rejecting_unknown_hosts`, and runtime corroboration through `external.unknown_host_runtime_response`. |
| §2.5.2 default welcome content | full | Default-content exposure is covered through Nginx external probes. |
| §2.5.4 reverse-proxy disclosure | partial | Existing header, server-status, and runtime disclosure checks verify narrower signals; complete reverse-proxy header semantics are not modeled. |
| §3.1 access log format | partial | Current rules validate log presence, named `log_format` fields, and expose the default format through `nginx.access_log_uses_default_format`; final SIEM/JSON policy remains operator-specific. |
| §3.3 error log level | partial | Harmful missing or overly restrictive levels are covered; final `warn` / `notice` / `info` choice remains policy. |
| §3.4 forwarded source-IP headers | full | `nginx.proxy_missing_source_ip_headers` checks upstream source-IP forwarding for proxy-like upstream directives. |
| §4.1.1 HTTP to HTTPS redirect | full | Local redirect rule plus external no-redirect runtime probes. |
| §4.1.2 trusted certificate chain | partial | Runtime certificate probes provide evidence, but local `ssl_certificate` paths cannot prove every served chain. |
| §4.1.5 cipher policy | full | Conservative local cipher-string checks cover missing and weak cipher posture. |
| §4.1.9 / §4.1.10 TLS session cache and timeout | full | Session cache and timeout rules cover the local HTTP/server scopes. |
| §4.1.12 HTTP/3 / Alt-Svc | `policy-review` | `nginx.http3_alt_svc_review` reports the QUIC listener, effective `http3` state, and effective `Alt-Svc` advertisement when policy review is enabled. Runtime HTTP/3 negotiation is not proven. |
| §5.1.1 sensitive locations | partial | Baseline sensitive-scope checks exist; full credit needs an operator-supplied sensitive path catalog. |
| §5.1.2 HTTP method restrictions | full | Sensitive-scope and whole-scope method-policy rules plus unsafe explicit allowlist checks. |
| §5.2.4 / §5.2.5 connection and rate limit values | partial | Presence and structural checks exist, while opt-in review rules expose selected values; reasonableness depends on workload profile. |
| §5.3.2 / §5.3.3 CSP and Referrer-Policy quality | partial | Baseline header checks and opt-in CSP value review exist; full application-specific policy semantics are not proven. |

Primary exclusions: package source, service account, OS ownership/permissions,
approved-port allowlists, private-key permissions, TLS 1.3 group posture, and
mandatory access-control mechanisms.

## CIS Apache HTTP Server 2.4 Benchmark v2.3.0

Applicable count: 19. Full count: 17. Partial count: 2. `policy-review`
count: 0. Uncovered count: 0.

| Counted item | Status | Current basis / next action |
| --- | --- | --- |
| §2.1-§2.9 module minimization | partial | Visible `LoadModule` inventory and selected risky-module checks exist, but benchmark-wide minimization needs package/build or operator policy. |
| §4.1-§4.2 authorization posture | partial | Effective `Require*` and legacy allow/deny semantics are modeled for current rules; broad server-wide authorization claims still need deployment context. |
| §4.3-§4.4 `AllowOverride` baseline | full | Root and inherited `AllowOverride` checks cover the config-visible baseline. |
| §5.1-§5.3 `Options` baseline | full | Root `Options None`, `ExecCGI`, `Includes`, `Indexes`, `MultiViews`, and subtractive `Options All` semantics are covered. |
| §5.4-§5.6 default content | full | Active `DocumentRoot` default HTML and CGI sample probes exist. |
| §5.7 HTTP method restrictions | full | Sensitive-scope and site-wide method-policy rules are present. |
| §5.9 HTTP protocol options | full | Effective `HttpProtocolOptions Strict Require1.0` coverage exists. |
| §5.10-§5.13 sensitive files | full | Backup/temp, `.ht*`, VCS metadata, sensitive extension, and named environment-path rules are present. |
| §5.14-§5.15 IP request and listen posture | full | IP request denial, catch-all virtual host handling, and explicit listen-address rules are present. |
| §5.16-§5.18 security headers | full | Frame, Referrer-Policy, and Permissions-Policy local checks are present. |
| §6.1 / §6.3 logging | full | `ErrorLog`, `CustomLog`, unsafe destinations, restrictive levels, undefined formats, and field quality are covered. |
| §6.6-§6.7 ModSecurity / CRS | full | `apache.modsecurity_module_missing` and `apache.modsecurity_crs_not_configured` cover visible ModSecurity and CRS inventory. |
| §7.1 / §7.4-§7.12 TLS policy | full | TLS protocol, cipher, ordering, compression, renegotiation, stapling, session cache, HSTS, and redirects are covered. |
| §7.2 certificate validity / upstream trust | full | External certificate probes and Apache SSL proxy trust rules cover observable certificate posture. |
| §8.3 default sample content | full | Local default-content probe covers active document roots. |
| §8.4 FileETag inode leakage | full | `apache.file_etag_inodes`. |
| §9.1-§9.4 timeout / keepalive posture | full | Explicit timeout and keepalive threshold/default-pin checks are present. |
| §9.5-§9.6 request read timeout | full | `RequestReadTimeout` and visible `mod_reqtimeout` semantics are modeled. |
| §10.1-§10.4 request limits | full | Request line, fields, field size, and body limit checks are present. |

Primary exclusions: installation planning, service account and filesystem
permissions, syslog/rotation/storage, private-key filesystem metadata, SELinux,
and AppArmor posture.

## CIS Microsoft IIS 10 Benchmark v1.2.1

Applicable count: 10. Full count: 8. Partial count: 1. `policy-review`
count: 0. Uncovered count: 1.

| Counted item | Status | Current basis / next action |
| --- | --- | --- |
| §1.2 host header bindings | full | `iis.binding_without_host_header`. |
| §1.4 / §1.5 / §1.6 application identity and app pool isolation | full | App-pool identity, cross-site shared pools, and anonymous-user rules consume the effective IIS view. |
| §2.1 / §2.2 authorization and anonymous access | full | Anonymous/authenticated mixups and missing/empty URL authorization policies are covered. |
| §2.5 / §2.7 / §2.8 forms credentials | full | Unsafe forms auth, clear credentials, and credentials stored in config are covered. |
| §2.6 Basic Authentication over non-TLS | full | Basic Auth is checked with effective SSL requirements. |
| §3.1 / §3.7-§3.12 ASP.NET and header hardening | full | Retail mode, cookie flags, MachineKey, trust level, native `Server` header removal, and runtime IIS header corroboration are covered. |
| §4.2 / §4.3 / §4.7 / §4.9 / §4.10 request filtering | full | Unsafe limits, unlisted file extensions, and CGI restriction settings are covered through effective config defaults. |
| §4.8 handler write/script/execute policy | full | `iis.handler_write_script_execute_enabled` plus CGI handler signal. |
| §6.1 / §6.2 FTP encryption and logon restrictions | uncovered | FTP remains applicable to the benchmark calculation, but the project does not parse IIS FTP authorization, logon, or channel-encryption configuration. |
| §7.1-§7.6 / §7.10-§7.12 SChannel TLS | partial | Registry/export evidence and external TLS probes exist; full credit needs deeper SChannel evidence where registry data is incomplete. |

Primary exclusions: broader Windows host hardening, web-root partitions,
filesystem ACLs, Dynamic IP Restrictions feature state, log-location storage,
ETW logging, and legacy IIS 7/8 archive benchmarks.

## OWASP Top 10:2025

Applicable count: 8. Full count: 0. Partial count: 8.

| Counted category | Status | Current basis / next action |
| --- | --- | --- |
| A01:2025 Broken Access Control | partial | Server-side access restrictions, method policy, and exposed admin/status endpoints are visible; application authorization is not. |
| A02:2025 Security Misconfiguration | partial | This is the main project scope, but the current A02 alignment is derived from reviewed A05:2021 mappings rather than independently reviewed full evidence. |
| A03:2025 Software Supply Chain Failures | partial | Exposed dependency manifests and build/deployment artifacts are detected; full supply-chain governance is out of scope. |
| A04:2025 Cryptographic Failures | partial | TLS protocols, ciphers, HSTS, certificate runtime evidence, and plaintext fallback are covered, but the A04 alignment is derived from reviewed A02:2021 mappings and does not prove the whole category. |
| A05:2025 Injection | partial | Server-visible CGI/script/upload/proxy/header risks are covered; application injection sinks are not. |
| A07:2025 Authentication Failures | partial | Basic Auth over HTTP, stored credentials, cookie flags, and exposed credential files are visible; full identity flows are not. |
| A08:2025 Software or Data Integrity Failures | partial | CSP/SRI and exposed CI/build artifacts are visible; full integrity pipeline controls are not. |
| A09:2025 Security Logging and Alerting Failures | partial | Server access/error log posture is visible; alerting, SIEM routing, and incident response are not. |

Excluded categories: A06:2025 and A10:2025 remain outside the web-server
configuration/security-probe perimeter used by this snapshot.

## OWASP ASVS v5.0.0

Applicable count: 22. Full count: 14. Partial count: 8.

This snapshot groups ASVS requirements at the same granularity used by the
pre-diploma summary. `docs/standards-roadmap.md` remains the more detailed
ASVS engineering backlog.

| Counted ASVS group | Status | Current basis / next action |
| --- | --- | --- |
| v5.0.0-3.3.1 / 3.3.2 / 3.3.3 / 3.3.4 cookie attributes | partial | Runtime cookie probes cover observed `Secure`, `HttpOnly`, `SameSite`, `__Secure-`, and `__Host-` prefix contract posture only. |
| v5.0.0-3.4.1 HSTS | full | Universal, local, and external HSTS checks. |
| v5.0.0-3.4.2 CORS | partial | Runtime wildcard/credential checks exist, but application allowlists are not proven. |
| v5.0.0-3.4.3 CSP policy quality | partial | Missing/unsafe CSP, nonce reuse, and cross-origin SRI are covered; full nonce/hash authorization is not. |
| v5.0.0-3.4.4 X-Content-Type-Options | full | Universal, local, and external missing/invalid checks. |
| v5.0.0-3.4.5 Referrer-Policy | full | Missing/unsafe Referrer-Policy checks. |
| v5.0.0-3.4.6 frame-ancestors / framing policy | full | Local family rules and runtime CSP evidence cover missing `frame-ancestors`; deeper CSP quality remains under 3.4.3. |
| v5.0.0-3.4.7 CSP reporting | partial | The rules prove configured reporting syntax or header presence, not successful report delivery or endpoint operation. |
| v5.0.0-3.4.8 COOP | partial | Runtime absence is observable, but document-rendering relevance is not. |
| v5.0.0-3.7.1 auth-required routes over TLS | full | `universal.tls_required_for_authenticated_routes` covers normalized auth scopes across supported local analyzers. |
| v5.0.0-12.1.1 deprecated TLS protocols | full | Local, registry, and external protocol posture checks. |
| v5.0.0-12.1.2 cipher posture | partial | Conservative local and bounded runtime evidence exist; not a full cipher-inventory suite. |
| v5.0.0-12.1.4 OCSP / must-staple | partial | Local stapling and runtime evidence exist; full revocation assurance is not proven. |
| v5.0.0-12.2.1 HTTPS / no cleartext fallback | full | TLS-intent, redirect, HSTS, and external no-HTTPS/no-redirect checks. |
| v5.0.0-12.2.2 certificate posture | full | Runtime expiry, self-signed, chain, SAN, CT, and weak-signature probes. |
| v5.0.0-13.4.1 source control metadata | full | `.git` and `.svn` exposure probes. |
| v5.0.0-13.4.2 production debug features | full | IIS debug/detailed errors plus external debug endpoint probes. |
| v5.0.0-13.4.3 directory listings | full | Universal, local, and runtime directory-listing evidence. |
| v5.0.0-13.4.4 TRACE | full | Local and external TRACE checks. |
| v5.0.0-13.4.5 documentation / monitoring endpoints | full | Status/info endpoint rules plus Swagger UI and OpenAPI/Swagger schema probes. |
| v5.0.0-13.4.6 component/version disclosure | full | Server ID/header/token rules plus dependency-manifest exposure probes. |
| v5.0.0-13.4.7 exposed secret/configuration material | partial | Sensitive config/data deny-lists and safe external artifact probes exist; a full application allowlist model is broader than the current signal. |

The ASVS rows above preserve the snapshot numerator. Broader ASVS follow-up
items, such as CSRF semantics, ECH, IIS MachineKey as a narrow V11 entry,
application logging, and full secret handling, remain documented in
`docs/standards-roadmap.md`.

## NIST SP 800-52 Rev. 2

Applicable count: 10. Full count: 10.

| Counted item | Status | Current basis |
| --- | --- | --- |
| §3.1 TLS version posture | full | Deprecated protocol checks across local, IIS SChannel, and external probes. |
| §3.3.1 recommended cipher posture | full | Weak cipher checks plus AEAD/forward-secrecy runtime evidence. |
| §3.3.2 server cipher preference | full | Local preference directives plus bounded runtime preference evidence. |
| §3.4 certificate validity and chain quality | full | External X.509 probes. |
| §3.5 secure renegotiation | full | Local unsafe-renegotiation rules and external handshake evidence. |
| §3.6 compression | full | Local compression rules and external negotiated-compression evidence. |
| §4.2 OCSP / must-staple | full | Local stapling rules and runtime observations. |
| §4.3 revocation evidence | full | OCSP/stapling and certificate posture evidence. |
| §4.2.4 HSTS | full | Local/universal/external HSTS family. |
| No plaintext fallback | full | Redirect, TLS intent, and external plaintext fallback rules. |

## PCI DSS v4.0.1

Applicable count: 11. Full count: 0. Partial count: 9. Uncovered count: 2.

| Counted requirement | Status | Current basis |
| --- | --- | --- |
| Req. 2.2.1 | partial | Hardening findings are related evidence, but the scanner does not prove that a complete configuration standard is defined, maintained, and applied to every in-scope component. |
| Req. 2.2.5 | partial | Insecure service, protocol, dangerous-method, and WebDAV signals are visible; business justification and complete necessity review are not. |
| Req. 2.2.6 | partial | Selected security parameters, disclosure, default content, and exposed-file conditions are checked; complete in-scope parameter coverage is not proven. |
| Req. 4.2.1 | partial | TLS, HSTS, redirect, and plaintext-fallback evidence is visible, but the scanner cannot determine whether a route carries PAN over an open public network. |
| Req. 6.2.4 | uncovered | Existing server-hardening findings are only related to this software-engineering requirement and do not prove secure development techniques. |
| Req. 6.4.3 | partial | Bounded cross-origin SRI evidence covers one part of payment-page script integrity; CSP posture is related, while authorization and inventory remain unproven. |
| Req. 8.3.1 | partial | Server-visible authentication configuration is checked, but complete authentication-factor protection is not proven. |
| Req. 8.3.2 | partial | Transport and cryptographic protection for server-visible authentication paths is checked; cookie attributes are not counted as this requirement. |
| Req. 8.3.5 / 8.3.6 | uncovered | These requirements concern first-use/reset password handling and password length/composition, which current web-server configuration rules do not observe. |
| Req. 10.2.1 | partial | Logging configuration is visible, but active logging across every in-scope component is not proven. |
| Req. 10.2.2 | partial | Selected access-log fields are checked, but the complete required event and detail semantics are not proven. |

Excluded PCI DSS rows: Req. 10.5 and Req. 12 are process/storage-retention
controls and are not part of the 11-item denominator.

## ISO/IEC 27002:2022

Applicable count: 10. Full count: 8. Partial count: 2.

| Counted control | Status | Current basis / limitation |
| --- | --- | --- |
| 5.15 access control | full | Local access, authorization, authentication, and method restriction signals. |
| 8.5 secure authentication | full | Basic Auth/TLS, credential storage, forms/cookie signals. |
| 8.15 logging | full | Access/error log enablement and field-quality checks. |
| 8.16 monitoring activities | partial | Server/runtime findings support monitoring, but alerting and SOC workflows are outside scope. |
| 8.18 privileged utility programs | partial | CGI/WebDAV/status/default content signals are visible; full utility governance is host/process context. |
| 8.20 network security | full | TLS, listener, redirect, HSTS, and dangerous method rules. |
| 8.21 network services security | full | Weak protocol/cipher and plaintext fallback rules. |
| 8.24 cryptography | full | TLS protocol/cipher/certificate checks. |
| 8.26 application security requirements | full | Security headers, CORS, CSP, cookies, methods, and debug/default exposure signals. |
| 8.27 secure architecture and engineering principles | full | Configuration hardening, least functionality, and exposed sensitive file checks. |

## Recount Guardrail

Before changing the snapshot:

1. Update the counted item table in this file.
2. Recalculate `full / applicable * 100`.
3. Update the summary table in `docs/benchmarks-covering.md`.
4. If a source item changes because of new rule behavior, update
   `docs/rule-coverage.md` and the relevant `STD-GAP-*` row in
   `docs/standards-roadmap.md`.
5. If a source item changes because of scope, state whether the denominator
   changed or only the status changed.

IIS FTP remains deliberately uncovered in this calculation. It stays visible
in the denominator rather than being reclassified as excluded.
