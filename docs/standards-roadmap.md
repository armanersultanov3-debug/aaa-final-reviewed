# Standards Roadmap

This document is the Stage 2 step 4 output for `webconf-audit`. It turns the
rule inventory in `docs/rule-coverage.md` into a reviewable standards backlog
before we add more rules.

The goal is not to maximize rule count. The goal is to decide, for each useful
CWE, OWASP, CIS, ASVS, or vendor hardening item, whether the project can check
it honestly with its current data model or whether deeper parsing, effective
configuration analysis, or external probing is needed first.

## Source Baseline

Sources checked on 2026-04-28:

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/):
  latest stable ASVS is 5.0.0. Future ASVS references must use the versioned
  identifier form, for example `v5.0.0-1.2.5`, because OWASP notes that
  unversioned identifiers follow the latest content.
- [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx): the public
  CIS NGINX page lists NGINX Benchmark 3.0.0 as the current Benchmark PDF
  version.
- [CIS Apache HTTP Server Benchmark](https://www.cisecurity.org/benchmark/apache_http_server):
  the public CIS Apache HTTP Server page lists Apache HTTP Server 2.4 Benchmark
  2.3.0 as the current Benchmark PDF version.
- [CIS Microsoft Windows Server Benchmark](https://www.cisecurity.org/benchmark/microsoft_windows_server):
  the public CIS Windows Server page lists active Windows Server Benchmarks for
  2025, 2022, 2019, 2016, and older versions. These are relevant to
  IIS-adjacent host policy, especially TLS and service hardening.
- [CIS Microsoft IIS Benchmark](https://www.cisecurity.org/benchmark/microsoft_iis):
  the public CIS Microsoft IIS page lists Microsoft IIS 10 Benchmark v1.2.1
  among the current available Benchmark PDF versions. Treat it as the primary
  CIS source for IIS-specific hardening, with Windows Server benchmarks used
  for host and SChannel policy.
- [CIS unsupported Benchmarks](https://www.cisecurity.org/unsupported-cis-benchmarks):
  the public unsupported list can still contain legacy IIS documents. Treat
  unsupported or archived IIS benchmarks as non-authoritative unless a future
  task explicitly scopes them.

The current project inventory is 367 rules (synchronized with
`docs/rule-coverage.md` Total rules header; the registry is the source of
truth and `tests/test_rule_coverage_doc.py` enforces drift between the
registry and `docs/rule-coverage.md`):

- Universal: 13
- Nginx local: 83
- Apache local: 84
- Lighttpd local: 49
- IIS local: 52
- External probes: 86

Stage 2 step 3 is complete for CWE and OWASP Top 10 mapping. Confirmed direct
and partial ASVS candidates are now copied into the dedicated `ASVS` column in
`docs/rule-coverage.md`. CIS NGINX, CIS Apache, and CIS Microsoft IIS 10
existing-rule references plus their server-specific gap tables are recorded in
`docs/rule-coverage.md`. ASVS requirements that need deeper probe/parser
coverage or a stricter policy interpretation stay in the follow-up gap list.

## Mapping Rules

- Cite exact standard versions and exact identifiers. Do not add a CIS, ASVS,
  or vendor reference from memory.
- Store confirmed ASVS references in a dedicated `ASVS` column in
  `docs/rule-coverage.md`, inserted after the existing `OWASP` column. Do not
  append ASVS IDs to the OWASP Top 10 column. Use the exact format
  `ASVS v5.0.0-<requirement-id>`; partial matches must add a short limitation,
  for example `ASVS v5.0.0-12.1.2 (partial: weak-pattern detection only)`.
- Keep cells empty when the mapping is not honest. Operational advice can map
  to vendor hardening without forcing a CWE.
- Do not copy long CIS or ASVS prose into this repository. Use section IDs,
  short titles, and our own summary. Direct quotes are limited to one short
  fragment of 25 words or fewer per standard item, and must include a source
  section ID or URL plus an `evidence_justification` note explaining why the
  exact wording is needed.
- Prefer existing local parser/effective-config data over raw string matching.
- Prefer external probe rules only when the configured intent cannot prove the
  runtime behavior.
- Mark host-level requirements as out of scope for this product line.

Future ASVS row shape:

| Rule ID | OWASP | ASVS | CIS / Vendor |
| --- | --- | --- | --- |
| `external.hsts_missing` | `[A05:2021](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)` | `ASVS v5.0.0-3.4.1` | `-` |

Summary template for standards candidates:

- Standard ID and short title.
- Scanner signal that can prove or disprove the item.
- Gap label from the table below.
- Source section ID or URL.
- Visibility limits and false-positive risk.
- Optional `evidence_justification` when a short quote is unavoidable.

## Gap Types

Use these labels in follow-up PRs:

| Label | Meaning | Expected next action |
| --- | --- | --- |
| `covered` | Existing rule already checks the item honestly. | Add the standard reference to `docs/rule-coverage.md`. |
| `direct-rule` | Current parser/probe data is enough. | Add a focused rule and tests. |
| `parser-depth` | The rule needs better AST/effective-config semantics first. | Improve parser/effective analysis, then add the rule. |
| `probe-depth` | The rule needs richer runtime probing first. | Improve external probe collection, then add the rule. |
| `out-of-scope` | The item is outside web server config/probing. | Document why it is excluded. |
| `research` | The source or interpretation is not stable enough yet. | Verify source text before implementation. |

## Work Order

1. Map existing rules to ASVS 5.0.0 where the match is direct. This document is
   the source of truth while references are still candidates. Only after review
   should confirmed rule-level references be copied into the dedicated `ASVS`
   column in `docs/rule-coverage.md`.
2. Walk CIS NGINX Benchmark v3.0.0 and fill Nginx CIS matches plus a Nginx gap
   table.
3. Walk CIS Apache HTTP Server 2.4 Benchmark v2.3.0 and fill Apache CIS matches
   plus an Apache gap table.
4. Walk CIS Microsoft IIS 10 Benchmark v1.2.1 and record the IIS XML,
   SChannel, host-policy, vendor-doc, and legacy-source split in
   `docs/rule-coverage.md`.
5. Add standards metadata to rule definitions only after the doc mapping is
   stable enough to avoid churn in CLI output.
6. Implement new rules in small PRs. If a candidate needs parser or probe
   depth, land that depth first.

## Server Standards Planning Pass

The CIS Nginx, CIS Apache, and IIS / Windows source-of-truth work can share one
short planning PR because all three are standards triage, not rule
implementation. That PR must not populate `docs/rule-coverage.md` with final
CIS references. Final section identifiers and verified mappings are reserved
for the follow-up server-family mapping PRs after the planning pass. The
planning PR's job is to make those later mapping PRs boring: clear inputs,
clear gap labels, and no hidden standards assumptions.

The planning-pass portion of a PR must stay documentation-only: it must not
change the rule registry, add or remove rule IDs, modify rule behavior, or
change rule metadata such as severity, tags, descriptions, conditions, or
recommendations. Planning artifacts such as gap tables, checklists, source
links, and ordering notes are allowed.

Inside `docs/rule-coverage.md` the same documentation-only fence applies:
in a planning PR only **candidate / tentative** standards entries are
allowed in the gap tables, and they must be visibly marked as such; final
section identifiers and verified CIS mappings are reserved for the
follow-up CIS-mapping PRs. As a concrete shape, a candidate entry should
look like a row that flags itself, for example
`| ... | _candidate: CIS NGINX Benchmark §X.Y_ | _planning_ |` rather
than a clean `[CIS NGINX 2.5.1]` link. Anything that would imply a
finalized mapping — such as adding a verified `[CIS ...]` link in the
existing rule rows of `docs/rule-coverage.md` — must be deferred to the
follow-up PR for that server family.

Planning output for CIS NGINX Benchmark v3.0.0:

- confirm the benchmark version and source link used for the walk;
- list the existing Nginx rules that are likely CIS-backed, including
  `nginx.server_tokens_on`, `nginx.autoindex_on`, logging, TLS protocol/cipher,
  request-size, and access-control rules;
- split candidate work into `covered`, `direct-rule`, `parser-depth`,
  `out-of-scope`, and `research`;
- keep host ownership, package, service user, and filesystem layout guidance
  outside the product scope.

Planning output for CIS Apache HTTP Server 2.4 Benchmark v2.3.0:

- confirm the benchmark version and source link used for the walk;
- list the existing Apache rules that are likely CIS-backed, including
  `apache.server_tokens_not_prod`, `apache.server_signature_not_off`,
  `apache.trace_enable_not_off`, `apache.options_indexes`, status/info
  exposure, request limits, and logging;
- separate checks that the current directive parser can support from checks
  that need better module inventory, include handling, or effective-config
  semantics;
- keep operating-system permissions, package ownership, service layout, and
  filesystem hardening outside the product scope.

Planning output for IIS / Windows Server:

- treat active CIS Microsoft IIS 10 Benchmark v1.2.1 as the primary source for
  IIS XML and IIS feature policy;
- treat the CIS Microsoft IIS 10 Benchmark v1.2.1 transport-encryption chapter
  as the source for the current SChannel registry mappings because it contains
  the IIS-focused SSL/TLS protocol and cipher controls used by the scanner;
- treat active CIS Microsoft Windows Server Benchmarks as the future source
  family for broader host policy that is not covered by IIS XML or the IIS 10
  transport-encryption chapter;
- use Microsoft documentation for implementation details when CIS wording is
  too broad for a scanner signal;
- treat unsupported or archived CIS IIS documents as historical context only,
  not primary compliance references, unless a future PR explicitly scopes them.

Mapping output for IIS / Windows Server:

- `docs/rule-coverage.md` now maps existing IIS XML/effective-config rules to
  CIS Microsoft IIS 10 Benchmark v1.2.1 where the signal is direct or honestly
  partial.
- Universal TLS rules backed by IIS SChannel registry enrichment are documented
  in an IIS/SChannel mini-table instead of being mixed into the IIS XML rule
  rows.
- Legacy CIS IIS 7/8 archive PDFs are explicitly research-only historical
  context.

The combined planning PR is complete when it records the follow-up PR order and
the expected artifact for each family:

| Follow-up | Artifact | Rule changes allowed? |
| --- | --- | --- |
| CIS Nginx mapping | Nginx CIS references plus a Nginx-specific gap table | No new rules |
| CIS Apache mapping | Apache CIS references plus an Apache-specific gap table | No new rules |
| IIS / Windows mapping | IIS XML references, IIS/SChannel universal mappings, and legacy-CIS source split | No new rules |

`No new rules` means no adding or removing rule IDs and no changes to rule
behavior or signal detection. Updating standards references for existing
rules and filling standards gap tables is allowed **only inside
documentation** — that is, in `docs/rule-coverage.md`, this file
(`docs/standards-roadmap.md`), and any planning gap tables. The same
follow-up PRs must not modify the rule registry, rule metadata
(severity, tags, descriptions, conditions, recommendations), or any code
that affects rule behavior or signal detection. Code-level changes for
new rules belong to the rule-implementation PRs that follow this
mapping work, not to the mapping PRs themselves.

## ASVS 5.0.0 First Pass

This first ASVS pass is intentionally limited to requirements that a web server
configuration analyzer or black-box HTTP/TLS probe can observe. ASVS remains an
application verification standard; `webconf-audit` should only claim coverage
when the scanner can see the relevant deployment signal.

Primary ASVS chapters for the current rule set:

- [V3 Web Frontend Security](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md)
- [V12 Secure Communication](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x21-V12-Secure-Communication.md)
- [V13 Configuration](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md)
- [V16 Security Logging and Error Handling](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md)

The confirmed direct and partial candidates below are copied into the `ASVS`
column in `docs/rule-coverage.md`. Requirements that need new probe depth,
parser depth, or stricter policy interpretation remain in the follow-up gap
list; host OS posture is documented as out of scope.

### Direct Coverage Candidates (partial where noted)

These requirements have enough current signal to justify adding ASVS references
to `docs/rule-coverage.md` after review. Items marked partial need the stated
limit recorded with the reference or moved to the gap list:

- `v5.0.0-12.1.1` - TLS protocol version posture. Covered by weak protocol
  rules such as `universal.weak_tls_protocol`, `nginx.weak_ssl_protocols`,
  and external TLS protocol probes.
- `v5.0.0-12.1.2` - recommended cipher suite posture. Partial coverage:
  current rules detect known-weak cipher patterns via
  `universal.weak_tls_ciphers`, `lighttpd.weak_ssl_cipher_list`, and
  `external.weak_cipher_suite`, but do not yet prove full recommended-suite
  posture, forward secrecy, or server preference.
- `v5.0.0-12.2.1` - HTTPS must not fall back to cleartext. Covered by
  HTTPS/TLS intent and redirect findings such as
  `universal.tls_intent_without_config`, `external.https_not_available`, and
  `external.http_not_redirected_to_https`.
- `v5.0.0-12.2.2` - publicly trusted certificate posture. Covered by
  certificate probes including `external.tls_certificate_self_signed`,
  `external.cert_chain_incomplete`, `external.cert_san_mismatch`,
  and `external.certificate_expired`.
- `v5.0.0-3.3.1`, `v5.0.0-3.3.2`, and `v5.0.0-3.3.4` - observable cookie
  security attributes. Partial coverage: external cookie rules check `Secure`,
  `SameSite`, `SameSite=None` plus `Secure`, `HttpOnly`, and the browser
  prefix contract for `__Host-` / `__Secure-` cookies. They still do not
  prove wider application-side session semantics beyond the observed
  `Set-Cookie` posture.
- `v5.0.0-3.4.1` - HSTS response header. Covered by universal, local, and
  external HSTS rules, including max-age and includeSubDomains probes.
- `v5.0.0-3.4.2` - CORS origin restrictions. Partial coverage: runtime probes
  detect wildcard origins and wildcard origins with credentials, but cannot
  prove an application allowlist or whether a wildcard response contains
  sensitive information.
- `v5.0.0-3.4.3` - CSP response header. Partial coverage: current rules detect
  missing CSP, unsafe-inline / unsafe-eval, effective `object-src 'none'`,
  restricted `base-uri`, and repeated nonce reuse across HTTPS responses when
  nonce-based allowlisting is present. They still do not inspect HTML/script
  bodies to prove whether nonce/hash authorization is required or whether SRI
  is deployed.
- `v5.0.0-3.4.7` - CSP reporting endpoint. Partial coverage: local Nginx,
  Apache, Lighttpd, IIS, and external probes now flag a configured CSP that
  lacks `report-uri` / `report-to`; this does not verify endpoint delivery or
  application-side report processing.
- `v5.0.0-3.4.4` - `X-Content-Type-Options: nosniff`. Covered by universal,
  local, and external missing/invalid header checks.
- `v5.0.0-3.4.5` - Referrer-Policy. Covered by missing/unsafe Referrer-Policy
  checks where headers are visible.
- `v5.0.0-3.4.8` - COOP. Partial coverage: `external.coop_missing` can flag
  missing COOP on observed runtime responses, but does not determine which
  responses initiate document rendering.
- `v5.0.0-13.4.1` - source control metadata must not be exposed. Covered by
  external `.git` and `.svn` metadata probes.
- `v5.0.0-13.4.2` - production debug features must be disabled. Covered for
  web-server-visible cases such as IIS debug / detailed error settings and
  external debug endpoints (`phpinfo`, ELMAH, ASP.NET trace).
- `v5.0.0-13.4.3` - directory listings must not be exposed unless intended.
  Covered by universal and local directory listing rules.
- `v5.0.0-13.4.4` - TRACE must not be supported in production. Covered by
  Apache/IIS local rules and external TRACE probes.
- `v5.0.0-13.4.5` - documentation and monitoring endpoints should not be
  exposed unless intended. Covered by status/info endpoint rules.
- `v5.0.0-13.4.6` - backend component versions should not be disclosed.
  Covered by server identification, `Server`, `X-Powered-By`,
  `X-AspNet-Version`, and server-token rules.
- `v5.0.0-16.5.1` - generic errors for unexpected/sensitive failures. Partial
  coverage: current rules only see web-server-visible detailed error pages and
  framework diagnostics.

### Partial Or Follow-up Gaps

These ASVS requirements are relevant but should not be marked fully covered
until the listed follow-up exists:

- `v5.0.0-3.4.3` - CSP minimum policy quality is deeper than missing /
  unsafe-inline / unsafe-eval. External probes now check effective
  `object-src 'none'`, restricted `base-uri`, and repeated nonce reuse across
  responses when nonce-based allowlisting is observed; body-aware inline
  script inventory and SRI remain outside the current safe header-only probe.
- `v5.0.0-3.4.6` - ASVS prefers CSP `frame-ancestors`; the external probe
  checks observed CSP responses, and dedicated local Nginx, Apache,
  Lighttpd, and IIS rules now cover missing `frame-ancestors` directives.
  Remaining CSP gaps are limited to body-aware inline-script inventory and
  SRI, not another header-only direct rule.
- `v5.0.0-3.5.1` through `v5.0.0-3.5.3` - CSRF and safe-method semantics are
  application behavior. Existing dangerous-method probes help, but they do not
  prove anti-forgery controls.
- `v5.0.0-3.5.8` - CORP is observable and `external.corp_missing` exists, but
  the rule cannot know whether the response is an authenticated resource.
- `v5.0.0-12.1.2` - forward secrecy and preference order now have partial
  runtime coverage through negotiated-cipher and bounded TLS 1.2 preference
  probes. This is not a full SSL Labs / testssl.sh cipher inventory.
- `v5.0.0-12.1.4` - OCSP stapling now has local Nginx/Apache coverage and
  partial external runtime evidence through `external.ocsp_stapling_not_observed`.
- `v5.0.0-12.1.5` - ECH stays documented as a probe limitation. The current
  safe external probe stack does not evaluate ECH portably, and the project
  should not invent a noisy "ECH missing" finding.
- `v5.0.0-13.4.7` - current partial coverage now includes Nginx/Apache
  sensitive config/data extension deny-lists plus external backup/temp file
  probes. A true positive application allowlist model is still broader than
  the current deny-list/probe signal.
- `v5.0.0-16.1.1` through `v5.0.0-16.4.3` - application security logging
  inventory, event semantics, and log protection are mostly outside current
  web server config/probe visibility. Local access/error-log presence can be
  supporting evidence, not complete ASVS coverage.

## Initial Gap Backlog

These are starting candidates, not final claims that a specific benchmark
section requires the exact rule. Each candidate must be tied to a verified
standard section before implementation.

| ID | Area | Gap type | Priority | Candidate work |
| --- | --- | --- | --- | --- |
| STD-GAP-001 | ASVS 5.0.0 | covered | P1 | First-pass direct/partial references are copied into the dedicated `ASVS` column for already-covered TLS, HTTPS redirect, HSTS, cookie, CORS, security-header, and sensitive-path exposure rules. Remaining ASVS items stay in the follow-up gap list. |
| STD-GAP-002 | Nginx CIS | covered | P1 | Existing-rule CIS references and the Nginx-specific gap table are recorded in `docs/rule-coverage.md` from the CIS NGINX Benchmark v3.0.0 walk. |
| STD-GAP-003 | Nginx CIS | covered | P2 | Unknown-host default-server rejection, first/default TLS catch-all rejection, HTTP redirects, log-format/error-log quality, proxy source-IP headers, CSP/Referrer quality, timeout/body/URI/session-ticket/session-cache/OCSP, core connection/rate-limit validation, sensitive-location IP filter quality, whole-scope request-method policy, unsafe explicit method allowlists, and sensitive config/data extension deny-lists are now present. Remaining work focuses on deeper cipher/TLS posture and context-specific runtime/probe checks rather than another direct local rule. |
| STD-GAP-004 | Nginx CIS | out-of-scope | P3 | Nginx package, service account, file ownership, permissions, private-key permissions, and PID-file recommendations require OS/package/filesystem inspection, which is outside this web-server config / safe external analysis tool. |
| STD-GAP-005 | Apache CIS | covered | P1 | Existing-rule CIS references and the Apache-specific gap table are recorded in `docs/rule-coverage.md` from the CIS Apache HTTP Server 2.4 Benchmark v2.3.0 walk. |
| STD-GAP-006 | Apache CIS | covered | P2 | Apache direct-rule coverage now includes site-wide request-scope method policy, explicit unsafe method allowlists, `AllowOverride None` and OS-root `Options None` baselines, sensitive-file and environment-specific path deny rules, DocumentRoot default-content probing, IP-based request denial, default TLS and non-TLS VirtualHost unknown-host rejection, explicit listen-address policy, log-quality checks, primary security headers including runtime-safe `Permissions-Policy`, timeout/keepalive default pinning, `RequestReadTimeout` module semantics, TLS directive checks including session cache timeout, local HSTS policy, matching-vhost HTTP redirects, and conservative weak cipher / FS / AEAD posture. Remaining runtime corroboration is documented as operator context or external-probe evidence rather than a missing local rule. |
| STD-GAP-007 | Apache CIS | covered | P2 | Explicit `LoadModule` inventory, `IfModule`-aware traversal, HTTPS upstream proxy/TLS directive modeling, request-scope `Location` matching, richer effective `RequireAll` / `RequireAny` IP+method semantics, legacy `Order` / `Allow` / `Deny` / `Satisfy` defaults, and visible ModSecurity / CRS inventory now back the Apache standards rules, including upstream TLS trust checks and current authorization-location coverage. Remaining benchmark follow-up is broader module minimization or deployment-specific authorization context, not an unresolved parser-depth blocker. |
| STD-GAP-008 | IIS / Windows Server | covered | P1 | Existing IIS rule CIS references and IIS/SChannel universal mappings are recorded in `docs/rule-coverage.md` from the CIS Microsoft IIS 10 Benchmark v1.2.1 walk. Broader Windows Server host policy is out of scope. |
| STD-GAP-009 | IIS / vendor docs | direct-rule | P2 | Host-header coverage, application-pool identity, cross-site shared application pools, explicit specific anonymous users, common authorization anonymous-access cases, Basic Authentication SSL coupling, explicit unsafe request-filtering limits/deny-list toggles, forms credential/cookie protection, retail mode, trust level, legacy .NET 3.5 MachineKey validation, SHA-2 HMAC MachineKey validation, handler Write with Script/Execute policy, explicit native `Server` header removal disablement, SChannel TLS 1.2 / AES / cipher-suite-order policy, authorization defaults, `system.web` default/absence policy, and requestFiltering default/absence policy are now covered where the current effective XML model exposes the signal. Remaining follow-up work is runtime native-header verification, deeper application-pool shared-hosting exceptions, and parser/effective-depth only where the current model cannot materialize defaults. |
| STD-GAP-010 | IIS legacy CIS | research | P3 | Source decision recorded: unsupported CIS IIS 7/8 archive PDFs are historical context only and must not be primary references unless a future PR explicitly scopes legacy IIS. |
| STD-GAP-011 | External probes | covered | P1 | First-pass ASVS references are copied into the dedicated `ASVS` column for observable runtime behavior: TLS protocol negotiation, weak cipher negotiation, certificate validity, security headers, dangerous methods, and exposed sensitive files. Deeper TLS probe work is tracked in `STD-GAP-014`. |
| STD-GAP-012 | Standards output | covered | P2 | Typed standards metadata is available on rule registry entries, `list-rules --format json` exposes `standards`, JSON reports include finding-level standards plus a top-level `standards` summary, and text reports support `--group-by standard` without changing rule behavior. Future non-CWE/OWASP/ASVS mappings can add helpers on top of this output path. |
| STD-GAP-013 | ASVS 5.0.0 | covered | P2 | CSP reporting endpoint coverage is present across local Nginx, Apache, Lighttpd, IIS, and external probes; local config coverage now also includes dedicated `frame-ancestors` rules across all four server families, while external runtime coverage includes `__Host-` / `__Secure-` cookie prefix validation plus repeated CSP nonce detection for per-response allowlisting. Remaining CSP honesty notes are limited to HTML/body-aware inline-script inventory and SRI, not another header-only direct rule. |
| STD-GAP-014 | ASVS 5.0.0 | covered | P3 | Deeper external TLS runtime evidence now covers negotiated forward secrecy posture, bounded TLS 1.2 server cipher preference, and OCSP stapling observation. ECH remains a documented limitation rather than a rule because the current safe probe stack cannot evaluate it portably. |
| STD-GAP-015 | External probes | direct-rule | P2 | Initial fixed-path exposure checks are catalog-backed for the existing external mode. Next, expand the catalog only with curated safe Nuclei-style ideas: fixed `GET` / `HEAD` / `OPTIONS` requests, status/header/body matchers, and rule metadata. Exclude fuzzing, payload injection, state-changing methods, OOB callbacks, brute force, and exploit chains; treat Nuclei templates as curated source material rather than a full runtime compatibility target. |

## PR Slicing

Keep standards work small enough for CodeRabbit and human review:

1. ASVS first-pass mapping for already-covered rules in `docs/rule-coverage.md`.
2. Combined CIS / IIS planning pass for the three server-family standards
   tracks above.
3. CIS Nginx mapping and Nginx-specific gap table.
4. CIS Apache mapping and Apache-specific gap table.
5. IIS source-of-truth decision and IIS/Windows mapping.
6. Standards metadata in the rule registry and report formats. Done for the core output path; future PRs may add more standard-family helper functions as new mappings move from docs-only to rule metadata.
7. First new rule PR from the prioritized backlog.
8. External safe-probe catalog PR: move fixed-path external exposure checks
   behind a declarative catalog before importing any Nuclei-inspired checks.
   Follow-up PRs can add curated safe probes to the catalog without adding a
   bespoke finder for each fixed path.

## Acceptance Criteria For New Standards Rules

A standards-driven rule is ready only when:

- the source reference is versioned and exact;
- the rule explains which config/probe signal proves the finding;
- tests include a positive case, negative case, and at least one inherited or
  scoped config case when the server supports inheritance; for probe-based or
  runtime rules, the scoped equivalent can be different observable runtime
  conditions (such as HTTP path, redirect target, endpoint mode, or probe
  result) or a controlled config fixture that changes the observed probe signal
  without relying on host OS inspection;
- external template-style rules are limited to safe, non-mutating probes
  unless a future PR explicitly introduces a separately gated active-scan mode;
- `docs/rule-coverage.md` is updated in the same PR;
- false-positive risk is described when the source item depends on host state
  not visible to the current analyzer.
