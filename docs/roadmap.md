# Roadmap

The project roadmap is now source-first. The main question for new work is not
"what rule can we add next?", but "which source from the practice report or
defense materials are we trying to cover, and what scanner signal can prove the
claim honestly?"

The pre-graduation practice milestone is complete. The current implementation
scope is summarized in [project-status.md](project-status.md), the per-rule
inventory lives in [rule-coverage.md](rule-coverage.md), and standards planning
is split between [standards-roadmap.md](standards-roadmap.md) and
[benchmarks-covering.md](benchmarks-covering.md).

## Source Coverage Direction

Future work should follow a source-first coverage model:

1. pick an exact source and version;
2. identify the observable scanner signal: parsed directive, effective
   inherited configuration, HTTP/TLS probe result, response header, fixed-path
   exposure, or report metadata;
3. classify the item as `covered`, `partial`, `direct-rule`, `parser-depth`,
   `probe-depth`, `out-of-scope`, or `research`;
4. implement only the smallest rule, parser improvement, probe improvement, or
   documentation change needed for that source item;
5. update the source mapping in the same PR.

The source set represented in the pre-diploma work and defense materials is:

- OWASP Top 10:2025 - current user-facing Top 10 edition used for relevance
  framing and secondary metadata;
- OWASP Top 10:2021 - reviewed primary row-level OWASP mapping until a full
  2025 remap is deliberately performed;
- OWASP ASVS v5.0.0 - main application-security verification benchmark where
  the scanner can observe web-server-visible signals;
- CIS NGINX Benchmark v3.0.0 - Nginx configuration hardening source;
- CIS Apache HTTP Server 2.4 Benchmark v2.3.0 - Apache configuration hardening
  source;
- CIS Microsoft IIS 10 Benchmark v1.2.1 - IIS XML, feature, and SChannel
  hardening source;
- NIST SP 800-52 Rev. 2 - TLS protocol, cipher, certificate, HSTS, OCSP, and
  no-plaintext-fallback reference;
- PCI DSS v4.0.1 - practical compliance benchmark for secure configuration,
  transport protection, authentication-related exposure, and logging;
- ISO/IEC 27002:2022 - broad control reference for access control, logging,
  secure configuration, network security, and cryptographic posture;
- FSTEC - Russian regulatory and threat-catalog reference used as a secondary
  alignment source for access control, TLS, logging, and exposed data;
- OWASP Cheat Sheet Series - practitioner guidance for headers, TLS, logging,
  authentication, access control, CORS, CSP, and error handling;
- Lighttpd vendor references - replacement source for Lighttpd where no CIS
  benchmark exists;
- HTTP Archive Web Almanac 2025 - relevance evidence for current web
  deployment practices and HTTPS/header adoption;
- CISA Proactive Threat Hunt - relevance evidence for real-world hardening
  failures after compromise;
- CVE-2025-59775 - relevance evidence for configuration-dependent Apache HTTP
  Server risk.

HTTP Archive Web Almanac 2025, CISA Proactive Threat Hunt, and CVE-2025-59775
are not compliance benchmarks. They prioritize work and justify relevance, but
they do not create rule coverage claims by themselves. A rule still needs a
scanner signal and, when applicable, a standards mapping.

## Completed Foundation

The foundation needed for source-driven work is already in place:

- repository CI for Python 3.10 through 3.14;
- deterministic local checks via `ruff`, `compileall`, targeted tests,
  rule-registry loading, and release smoke checks;
- CI-oriented CLI behavior through `--fail-on`, `--fail-on-new`,
  suppressions, and stable finding fingerprints;
- baseline and diff reporting for new, unchanged, resolved, and suppressed
  findings;
- profile-based severity calibration with `impact`, `exposure`,
  `exploitability`, `confidence`, and `context_dependency`;
- `--group-by standard`, `--group-repeated`, and `--group-by-cause` report
  modes;
- a declarative external safe-probe catalog for fixed, non-mutating probes;
- `v0.1.1` PyPI publication, MIT licensing, and repeatable release-check
  workflow.

These items are not active roadmap work unless a regression or a concrete
reporting gap appears.

## Source Status Matrix

| Source family | Current mapping surface | Status | Next useful work |
| --- | --- | --- | --- |
| CWE | `docs/rule-coverage.md` per-rule column | Covered across registered rules | Keep synchronized when new rules are added. |
| OWASP Top 10:2021 | `docs/rule-coverage.md` per-rule column | Covered as reviewed primary OWASP mapping | Keep stable until a deliberate 2025 primary remap. |
| OWASP Top 10:2025 | `standards_secondary` JSON metadata | Covered as secondary derived mapping | Add a short migration note when new OWASP categories are introduced. |
| OWASP ASVS v5.0.0 | `ASVS` column and `docs/standards-roadmap.md` | Covered or partial for web-server-visible items | Continue only where the scanner sees a real deployment signal. |
| CIS NGINX v3.0.0 | `CIS / Vendor` column and Nginx gap table | Existing-rule pass complete | Reopen only for concrete parser/probe evidence, not broad host policy. |
| CIS Apache 2.4 v2.3.0 | `CIS / Vendor` column and Apache gap table | Existing-rule pass complete | Reopen only for concrete parser/effective-config improvements. |
| CIS IIS 10 v1.2.1 | `CIS / Vendor` column, IIS/SChannel table | Existing-rule pass complete | Keep IIS XML and SChannel split explicit. |
| NIST SP 800-52 Rev. 2 | Other standards mappings and helper metadata | Covered for current TLS model, partial where runtime evidence is bounded | Improve explanatory notes for partial cipher preference, OCSP, and ECH limits. |
| PCI DSS v4.0.1 | Topic-grouped mapping and helper metadata | Covered for relevant web-server-visible controls | Keep Req. 10 and host/process controls scoped honestly. |
| ISO/IEC 27002:2022 | Topic-grouped mapping and helper metadata | Covered for relevant technical controls | Keep management and SDLC controls out of scanner claims. |
| FSTEC sources | Topic-grouped mapping and secondary tags | Covered for relevant access, TLS, logging, and exposed-data signals | Keep Russian regulatory mappings secondary unless a dedicated audience appears. |
| OWASP Cheat Sheet Series | Topic-grouped companion mapping | Covered as practitioner guidance | Use as practical justification for rules, not as a compliance column. |
| Lighttpd vendor references | Topic-grouped vendor mapping | Covered for current Lighttpd scope | Do not invent a CIS Lighttpd benchmark. |
| MITRE ATT&CK and FSTEC BDU | Secondary tags | Covered as secondary context | Keep as secondary taxonomy only. |
| HTTP Archive, CISA, CVE examples | Relevance evidence in presentation/report materials | Not rule coverage | Use to prioritize and explain relevance, not to inflate coverage. |

## Active Work Lanes

### 1. Source Coverage Hygiene

Keep the three mapping documents aligned:

- `docs/rule-coverage.md` is the canonical per-rule inventory;
- `docs/standards-roadmap.md` is the backlog for canonical standards and gap
  labels;
- `docs/benchmarks-covering.md` is the companion for broader benchmarks,
  secondary sources, and topic-grouped mappings.

Next work:

1. make every active roadmap item point to a source family and gap label;
2. remove stale "missing standard" statements after a mapping is complete;
3. keep `tests/test_rule_coverage_doc.py` green whenever counters or mapping
   surfaces change.

### 2. ASVS And OWASP Alignment

ASVS remains the best source for application-security language, but only part
of it is visible to a web-server configuration and HTTP/TLS probe tool.

Next work:

1. keep ASVS claims limited to observable headers, TLS, cookie posture,
   dangerous methods, exposed files, directory listing, status endpoints,
   version disclosure, and visible error/debug surfaces;
2. keep V11 cryptography claims narrow unless the scanner can see concrete
   server-side cryptographic configuration;
3. keep OWASP Top 10:2025 as secondary metadata until a full primary remap is
   planned and reviewed.

### 3. CIS And Vendor Hardening

CIS mappings should remain configuration-specific and server-specific.

Next work:

1. preserve the split between Nginx, Apache, IIS XML, and IIS/SChannel;
2. use external runtime evidence only as partial support for CIS items when
   local configuration is the primary source;
3. keep Lighttpd tied to vendor and DevSec-style references instead of a
   nonexistent CIS benchmark.

### 4. TLS And Certificate Coverage

TLS work should be driven mainly by NIST SP 800-52 Rev. 2, PCI DSS v4.0.1,
ISO/IEC 27002:2022, FSTEC, ASVS V12, and CIS TLS sections.

Next work:

1. improve report wording around bounded runtime checks, especially server
   cipher preference, OCSP stapling observation, and certificate-chain
   evidence;
2. do not add an "ECH missing" rule until portable safe probing is realistic;
3. keep local TLS checks separate from runtime evidence, especially for IIS
   where SChannel policy often lives outside XML.

### 5. External Safe-Probe Growth

External probes must remain safe, fixed, and non-mutating.

Next work:

1. continue `STD-GAP-015` with small curated batches;
2. prefer path/body/header probes that support ASVS 13.4.x, PCI DSS secure
   configuration, ISO/IEC 27002 exposed-information controls, and FSTEC
   exposed-data mappings;
3. exclude fuzzing, payload injection, brute force, state-changing methods,
   OOB callbacks, authentication bypass attempts, and exploit chains.

### 6. Report Explanations

The project should make source coverage understandable in reports, not only in
documentation.

Next work:

1. make `--group-by standard` explanations clearer for partial mappings;
2. add concise text that explains why some standards appear only in secondary
   metadata;
3. preserve the stable JSON contract unless a new field has a clear consumer.

### 7. Release Operations

The project now has a public PyPI release. The useful near-term work is keeping
release mechanics repeatable and reducing long-lived publishing credentials.

Next work:

1. keep tag-based release checks working;
2. keep changelog entries tied to merged PRs;
3. create GitHub releases for public package milestones;
4. replace account-wide upload tokens with a project-scoped token or PyPI
   Trusted Publishing.

## Deferred Research

New server families, including Caddy, are deferred. The reason is not that they
are unimportant, but that adding a server family expands parser semantics,
fixtures, rule inventory, documentation, and standards mapping at the same
time. The current priority is to make the existing four-server source coverage
defensible.

Caddy can be reopened when at least one of these is true:

- a source family in the practice/report materials explicitly requires it;
- a real user needs Caddy coverage;
- the existing Nginx, Apache, Lighttpd, IIS, external, and standards mapping
  surfaces stay stable across several implementation PRs.

Other deferred or non-canonical sources remain documented in
`docs/benchmarks-covering.md`: NIST SP 800-53 Rev. 5, NIST SP 800-44,
NIST SP 800-63B, CIS Controls v8.1, HIPAA, BSI IT-Grundschutz, FSB/GOST TLS
research, and GOST R 57580.1. They should not drive implementation unless the
target audience changes.

## PR Order

Use this order for the next source-coverage PRs:

1. **Roadmap/source hygiene** - keep this roadmap, `standards-roadmap.md`, and
   `benchmarks-covering.md` aligned around the same source set.
2. **Coverage explanation PR** - improve text explanations for partial source
   coverage, especially NIST/PCI/ISO/FSTEC TLS overlap.
3. **External safe-probe PRs** - add small curated batches that support ASVS
   13.4.x, PCI secure-configuration, ISO exposed-information, and FSTEC exposed
   data mappings.
4. **Report wording PR** - improve `--group-by standard` and
   `--group-by-cause` explanations without changing rule behavior.
5. **Release artifact PR** - keep PyPI metadata, GitHub Release notes, and
   release-check artifacts aligned for the next meaningful milestone.

## Acceptance Criteria

A roadmap item is ready for implementation only when:

- it names the source family and exact version;
- it states the scanner signal that proves the finding;
- it declares whether the claim is full, partial, secondary, out of scope, or
  research-only;
- it has tests for positive, negative, and scoped/inherited behavior when the
  analyzer model supports that;
- it updates the appropriate mapping surface in the same PR;
- it does not convert relevance evidence into a false coverage claim.
