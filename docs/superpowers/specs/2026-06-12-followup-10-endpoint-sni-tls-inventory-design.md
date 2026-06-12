# Follow-up 10: Endpoint/SNI TLS Inventory Design

**Status:** Design specification
**Sequence:** follow-up 10 of 14
**Baseline:** PR #9 at `1e1cbbb` plus accepted follow-ups 01-04
**Program dependency:** follow-up 04 control assessment reporting
**Primary outcome:** assess TLS evidence across an operator-declared, completeness-aware endpoint/SNI inventory without treating one handshake as deployment-wide proof

---

## 1. Inherited State

PR #9 leaves CIS NGINX Benchmark v3.0.0 Section 4.1.2 as `partial`.
The existing external analyzer already provides useful direct observations:

- `analyze_external_target(target, *, scan_ports=False, ports=None)`;
- `ProbeTarget` identities containing scheme, host, port, and path;
- SNI-aware HTTPS handshakes through the target host;
- certificate validity, subject, issuer, SAN, chain depth, and chain
  completeness observations;
- bounded protocol support and TLS 1.2 cipher-preference probes;
- weak negotiated cipher, AEAD, forward-secrecy, compression, secure
  renegotiation, SCT, must-staple, and OCSP stapling observations;
- `probe_attempts[].tls_info` JSON metadata;
- source-level mappings to CIS, ASVS, NIST SP 800-52 Rev. 2, PCI DSS, and
  ISO/IEC 27002.

Those observations are target-local. The current interface does not know:

- whether every externally served TLS endpoint was named;
- whether every SNI name on a shared address was probed;
- whether a DNS name resolves to multiple independently configured edges;
- whether a wildcard certificate represents all deployed names;
- whether a failed connection means an absent endpoint or missing evidence;
- which trust store and certificate-name policy the operator intended;
- whether all mandatory evidence dimensions completed for every inventory
  entry.

The shared foundations from follow-ups 03 and 04 are inherited:

- policy is typed, versioned input rather than a suppression;
- assessments use `pass`, `fail`, `partial`, `review`, `indeterminate`,
  `not-assessed`, and `not-applicable`;
- `pass` is forbidden when mandatory evidence or declared scope is incomplete;
- findings retain severity and remain separate from assessments;
- evidence references preserve target URL, SNI, protocol, and observation.

## 2. Exact Gaps

1. A single hostname or URL is not a complete endpoint inventory.
2. `ProbeTarget.host` currently conflates connection routing, HTTP `Host`, and
   TLS SNI identity.
3. Port discovery can find listening ports but cannot prove that all virtual
   TLS identities on those ports were tested.
4. SAN enumeration cannot be used as inventory discovery. A SAN may include
   retired, internal, wildcard, or non-routed names and may omit separate
   certificates served by other SNI values.
5. DNS enumeration cannot prove completeness and can join evidence from the
   wrong edge, tenant, or environment.
6. Existing TLS metadata records observations but not per-dimension
   completeness.
7. A timeout, TLS alert, unavailable OpenSSL capability, or unsupported probe
   currently lacks a uniform assessment-level indeterminate contract.
8. Revocation-related observations are bounded to stapling and must-staple;
   they do not establish end-to-end revocation assurance.
9. Existing source coverage prose can overread observed certificate evidence
   as complete certificate inventory evidence.

## 3. Goals

- Accept an explicit operator inventory of endpoint and SNI identities.
- Keep connection address, SNI name, HTTP host, and certificate-name
  expectation separate.
- Record whether the operator declares the inventory complete.
- Assess every inventory entry and every required evidence dimension.
- Aggregate only correctly matched evidence from the same inventory identity.
- Return `indeterminate` for incomplete inventory, failed mandatory probes,
  ambiguous identity, or unsupported evidence.
- Reuse the existing safe external TLS probes and findings.
- Preserve individual findings even when the aggregate assessment is
  indeterminate.
- Make coverage claims explicitly conditional on a declared complete
  inventory and completed mandatory observations.

## 4. Non-Goals

- Discovering all public or private DNS names.
- Expanding wildcard DNS or certificate names.
- Certificate Transparency log enumeration.
- Cloud load-balancer, CDN, Kubernetes, or service-mesh API discovery.
- Proving that an operator's completeness declaration is factually exhaustive.
- Full cipher-suite enumeration or every possible client negotiation.
- Acting as a general PKI validator or revocation-status service.
- Replacing application-layer route inventories from follow-up 09.
- Turning absent optional inventory policy into a default finding.
- Implementing IIS FTP probing or changing the IIS FTP coverage decision.

## 5. Design Decisions

### 5.1 Inventory is explicit and operator-owned

The analyzer never infers completeness from DNS, SANs, redirects, port scans,
or server banners. A complete inventory is an operator assertion attached to a
versioned policy section.

### 5.2 Endpoint identity is a tuple

The stable identity is:

`(inventory_id, entry_id, connect_host, connect_port, sni_name, http_host)`

Two entries that differ in any identity field are different evidence scopes.
Evidence from one entry must not satisfy another.

### 5.3 Completeness has two levels

- Inventory completeness: whether the operator declares that all in-scope TLS
  identities are listed.
- Observation completeness: whether each mandatory evidence dimension
  completed for each listed identity.

Both must be complete before the aggregate assessment can pass.

### 5.4 Active observations remain bounded

The feature orchestrates current safe probes. It does not claim exhaustive
protocol or cipher negotiation. Each evidence dimension states its exact
bounded meaning.

## 6. Models And Schema

Follow-up 03 owns the top-level policy envelope. This follow-up makes a strict,
typed extension to that schema by adding an optional
`external.tls_inventories` section. Unknown keys remain rejected; this is not
a free-form policy payload.

```yaml
version: 1
external:
  tls_inventories:
    - id: production-edge
      environment: production
      declared_complete: true
      completeness_attestation:
        asserted_by: platform-team
        asserted_at: "2026-06-12T08:00:00Z"
        basis: load-balancer-listener-export
      trust:
        mode: system
      required_evidence:
        - handshake
        - certificate_name
        - certificate_chain
        - protocol_support
        - negotiated_cipher
        - ocsp_stapling
      entries:
        - id: api-primary
          connect_host: 203.0.113.10
          connect_port: 443
          sni_name: api.example.com
          http_host: api.example.com
          path: /
          expected_certificate_names:
            - api.example.com
```

Required validation:

- IDs are non-empty and unique within their parent.
- `connect_port` is 1 through 65535.
- `path` is absolute and defaults to `/`.
- DNS identities are normalized with IDNA and compared case-insensitively.
- IP literals are canonicalized without reverse DNS.
- `sni_name` is required for certificate-name assessment unless the entry
  explicitly marks that assessment `not-applicable` with a reason.
- `http_host` defaults to `sni_name`, not to `connect_host`.
- duplicate normalized identity tuples are rejected.
- `declared_complete: true` requires attestation metadata.
- unknown evidence dimension names are schema errors.
- inventory files do not contain credentials or private keys.

New domain models:

```python
TLSInventory
TLSInventoryEntry
TLSInventoryCompleteness
TLSObservationRequirement
TLSInventoryEntryResult
TLSObservationState
```

`TLSObservationState` values:

- `observed`;
- `failed`;
- `unavailable`;
- `not-requested`;
- `not-applicable`.

Every entry result contains:

- the normalized identity tuple;
- the exact probe target;
- per-dimension state and reason;
- evidence references into `probe_attempts`;
- related finding fingerprints;
- start/end timestamps;
- limitations.

The inventory analysis report carries the normalized identities,
per-dimension observations, completeness, evidence references, policy
provenance, and execution manifest required by follow-ups 03 and 04. The
separate follow-up 04 assessment artifact then includes:

- source ID and item ID;
- inventory ID;
- ledger status and policy disposition;
- one of the shared assessment statuses;
- inventory completeness;
- observation completeness;
- evidence references;
- missing evidence;
- reasons and limitations.

The assessment engine must not serialize a direct `pass` merely because all
inventory probes produced no findings. The applicable ledger evidence must
have explicit `control-pass` or complete facet-pass semantics, and the ledger
item itself must be `full`.

## 7. CLI And API

Add an additive command rather than making the existing positional target
ambiguous:

```text
webconf-audit analyze-tls-inventory INVENTORY_ID --policy audit-policy.yml
```

The command supports the existing report options:

- `--format`;
- `--fail-on`;
- `--suppressions`;
- `--baseline`;
- `--write-baseline`;
- `--fail-on-new`;
- grouping options.

On `analyze-tls-inventory`, `--fail-on` continues to evaluate findings.
Assessment-status gating remains the responsibility of follow-up 04's separate
`assess --fail-on` option.

To produce a control assessment, the operator writes the versioned analysis
JSON and invokes the existing follow-up 04 command:

```text
webconf-audit assess --report tls-inventory-analysis.json
webconf-audit assess --report tls-inventory-analysis.json \
  --fail-on fail,indeterminate
```

The second command may exit 3 under the follow-up 04 contract while still
writing the complete assessment artifact.

Public API:

```python
def analyze_external_tls_inventory(
    policy: AuditPolicy | str | os.PathLike[str],
    inventory_id: str,
) -> AnalysisResult:
    ...
```

The implementation calls the same lower-level probe functions as
`analyze_external_target`. It must not shell out to a separate scanner.

Existing interfaces remain valid and unchanged:

```python
analyze_external_target(target, *, scan_ports=False, ports=None)
```

```text
webconf-audit analyze-external TARGET
```

## 8. Behavior And Indeterminate States

### 8.1 Entry behavior

- A completed unsafe observation emits the existing finding and marks the
  related subclaim `fail`.
- A completed safe observation can mark only that bounded subclaim `pass`.
- A TCP or TLS failure for an expected endpoint is `indeterminate`, not
  automatically `pass` or `not-applicable`.
- A certificate-name mismatch is `fail`.
- Evidence from a redirect destination does not replace evidence for the
  original entry unless that destination is separately inventoried.
- Multiple A/AAAA addresses require separate entries when they are intended
  as independently assessed edges.
- An inventory entry may be `not-applicable` only through an explicit typed
  applicability declaration and reason.

### 8.2 Aggregate behavior

When the applicable ledger item is `full` and its evidence relation permits
control-level pass semantics, the aggregate result is:

- `fail` when at least one mandatory subclaim has direct failing evidence;
- `indeterminate` when no direct failure exists but inventory completeness or
  any mandatory observation is incomplete, unknown, or conflicting;
- `pass` only when the inventory is declared complete and every mandatory
  subclaim passes for every applicable entry;
- `not-applicable` only when every entry is explicitly not applicable and the
  policy establishes why the inventory itself is not applicable.

Direct failures are not hidden by incomplete evidence. A run may therefore
contain findings plus an aggregate `fail`, or findings plus additional
indeterminate subclaims.

Follow-up 04 caps or redirects the result when broader conditions apply:

- a ledger item still marked `partial` yields at most `partial` for an
  otherwise positive run;
- an operator-review disposition yields `review` unless direct failure or
  indeterminate execution has higher precedence;
- no applicable inventory evidence selected or executed yields
  `not-assessed`;
- related or derived standard mappings cannot independently produce `pass` or
  `fail`;
- an explicitly suppressed direct negative remains `review`, not `pass`.

### 8.3 Mandatory indeterminate cases

- missing or false `declared_complete`;
- missing completeness attestation;
- duplicate or ambiguous identity;
- unresolved policy selector;
- mandatory probe timeout or TLS alert;
- unsupported protocol/cipher probe capability;
- trust-store load failure;
- certificate chain result unavailable;
- OS/network error that prevents a mandatory observation;
- evidence keyed to a different SNI or connection address;
- wildcard-only entry where concrete names are required;
- malformed or future schema version.

## 9. Likely Files

Implementation is expected to touch:

- `src/webconf_audit/policy.py` or the policy package created by follow-up 03;
- `src/webconf_audit/assessment.py` or the assessment package from follow-up 04;
- `src/webconf_audit/external/recon/__init__.py`;
- a focused module such as
  `src/webconf_audit/external/tls_inventory.py`;
- `src/webconf_audit/cli/__init__.py`;
- `src/webconf_audit/report/__init__.py`;
- `src/webconf_audit/models.py` only if follow-up 04 requires additive result
  fields there;
- focused unit and CLI tests;
- coverage ledger and synchronized coverage documentation when the coverage
  gate permits a status change.

The canonical ledger path inherited from follow-up 02 is
`src/webconf_audit/data/control_source_coverage.yml`.

The implementation should avoid an unrelated refactor of the large external
recon module.

## 10. Migration And Backward Compatibility

- Existing external commands and API calls behave exactly as before without
  `analyze-tls-inventory`.
- Existing finding IDs, severities, fingerprints, and metadata fields remain
  stable.
- New inventory and assessment metadata is additive.
- Existing baselines and suppressions continue to match findings.
- Policy absence is not an error for existing commands.
- An explicitly requested missing or malformed policy is exit code 1.
- No source coverage percentage changes merely because the schema or command
  exists.

## 11. Exhaustive Test Plan

### Schema tests

- valid one-entry and multi-entry inventories;
- duplicate IDs and duplicate normalized identities;
- invalid ports, paths, IDNA names, and schema versions;
- completeness true without attestation;
- unknown evidence dimensions;
- missing SNI with and without explicit applicability handling;
- trust-store modes and unreadable trust-store paths.

### Identity tests

- same IP/port with two SNI names stays separate;
- same SNI on two connection addresses stays separate;
- HTTP host differs from SNI without evidence crossover;
- IPv4, IPv6, Unicode DNS, and IDNA normalization;
- redirect and discovered-port evidence cannot satisfy another entry.

### Assessment tests

- all entries safe and complete gives `pass` only with a full ledger item and
  reviewed control-pass evidence semantics;
- one direct failure gives `fail`;
- safe observations plus incomplete inventory gives `indeterminate`;
- one timeout gives `indeterminate`;
- one failure plus another timeout remains `fail` with the timeout recorded;
- all explicitly not applicable gives `not-applicable`;
- a positive complete run remains `partial` while its ledger item is partial;
- no selected inventory evidence gives `not-assessed`;
- operator-review disposition gives `review`;
- unsupported OCSP or cipher-preference tooling blocks pass when mandatory;
- optional evidence failure does not block pass but is recorded as a
  limitation.

### TLS evidence tests

- certificate expiry, SAN mismatch, self-signed certificate, incomplete chain,
  weak signature, and missing SCT evidence;
- TLS 1.0/1.1 support and bounded TLS 1.2/1.3 behavior;
- weak negotiated cipher, non-AEAD, no forward secrecy, compression, and
  insecure renegotiation observations;
- server cipher preference;
- OCSP stapling and must-staple combinations;
- custom and system trust stores.

### CLI/JSON tests

- command selects the requested inventory;
- unknown inventory ID is exit code 1;
- JSON contains identities, per-dimension states, completeness, evidence
  references, assessments, findings, and limitations;
- `--fail-on` remains finding-based;
- old `analyze-external` snapshots remain unchanged.

### Safety and regression tests

- no DNS/SAN wildcard expansion;
- no evidence joining across inventory entries;
- no pass from an empty inventory;
- no percentage increase without ledger and documentation updates;
- full non-integration suite, external integration suite where available,
  Ruff, interrogate, and `git diff --check`.

## 12. Documentation And Coverage Impact

Candidate effects, not pre-approved effects:

- CIS NGINX Section 4.1.2 may move from `partial` to `full` only if its ledger
  subclaims are satisfied by the implemented complete-inventory contract.
- ASVS certificate, protocol, cipher, and revocation groups may be strengthened,
  but bounded cipher and revocation limitations must remain explicit.
- NIST, PCI, and ISO rows must distinguish complete inventory coverage from
  bounded observation coverage.

Required wording:

- "scanner-evidence coverage within the declared endpoint/SNI inventory";
- "bounded TLS observation";
- "operator-declared completeness".

Forbidden wording:

- "all certificates on the domain" based on SAN or DNS discovery;
- "full revocation validation" based only on stapling;
- any claim that the scanner certifies NIST, PCI, ASVS, or ISO compliance.

## 13. Acceptance Criteria

1. A versioned inventory schema separates connection, SNI, HTTP host, and
   expected certificate identity.
2. Completeness is explicit and cannot be inferred.
3. Every mandatory evidence dimension has a recorded terminal state.
4. Evidence cannot cross inventory identities.
5. Incomplete mandatory evidence prevents `pass`.
6. Analysis and the follow-up 04 assessment remain separate artifacts.
7. Existing findings are reused and remain independently visible.
8. Existing external CLI/API behavior remains compatible.
9. Coverage changes satisfy the machine-readable ledger gate.
10. Documentation states the bounded nature of cipher and revocation evidence.
11. No IIS FTP scope or implementation is introduced.

## 14. Dependencies

- Follow-up 03 supplies the typed policy envelope.
- Follow-up 04 supplies control assessment output and evidence references.
- Follow-up 09 may supply related route/header inventory identities but is not
  required for TLS-only entries.
- Follow-up 14 performs the final cross-standard recount.

## 15. Risks

- Operators may overstate inventory completeness.
- Large inventories can make active probing slow.
- DNS rotation can make connection evidence unstable.
- CDN or load-balancer behavior can vary between probe runs.
- Platform TLS libraries may not expose every observation consistently.
- Reviewers may misread a complete declared inventory as independently
  discovered completeness.

Mitigations include explicit attestations, stable identity keys, bounded
concurrency, deterministic result ordering, per-entry timestamps, and strong
limitation wording.

## 16. Rollback

- Remove the additive inventory command and API.
- Remove the policy section and inventory-specific assessment adapter.
- Preserve all pre-existing external probes and findings.
- Revert any source status promotion in the same rollback change.
- Never leave documentation claiming complete inventory support after the
  implementation is removed.

## 17. Reviewer Checklist

- [ ] Inventory completeness is never inferred from DNS, SANs, redirects, or ports.
- [ ] Connection host, SNI, HTTP host, and certificate name are distinct.
- [ ] Duplicate or ambiguous identities are rejected.
- [ ] Mandatory incomplete evidence produces `indeterminate`.
- [ ] A direct unsafe observation still produces a finding.
- [ ] Evidence cannot be joined across entries.
- [ ] Cipher and revocation limitations are explicit.
- [ ] Existing `analyze-external` behavior is unchanged.
- [ ] Ledger and docs change only with implementation evidence.
- [ ] No compliance or certification claim is introduced.
- [ ] IIS FTP remains uncovered and untouched.
