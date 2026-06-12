# Audit Policy Foundation Design

Date: 2026-06-12
Status: proposed
Sequence: follow-up 03 of 14

## Inherited State After PR #8 and PR #9

This design starts from `master` commit
`1e1cbbb7209a199282b28f823a0a7b07cc7df0bc` and assumes follow-ups 01 and 02
have established:

- corrected standard crosswalks;
- declared versus derived mapping provenance;
- a source catalog;
- stable source and counted-item IDs;
- a validated machine-readable coverage ledger;
- the unchanged coverage states `full`, `partial`, `policy-review`,
  `uncovered`, and `excluded`.

PR #9 added `nginx.http3_alt_svc_review` as an opt-in policy-review rule and
kept `policy-review` separate from full or partial detector evidence. The
current registry exposes opt-in tags, and the CLI can request opt-in rule
categories, but there is no durable declaration of:

- which control sources an organization intends to assess;
- which counted items are required, advisory, review-only, or not applicable;
- which target types a policy applies to;
- which opt-in review rules policy requires;
- what evidence is required before a later assessment can report a result;
- which policy version and digest governed an analysis.

The current analysis result can contain findings and issues, but it does not
provide a complete, stable manifest of selected, completed, skipped, and failed
rule execution. Without that manifest, the absence of a finding can be
mistaken for evidence that a control passed.

Known crosswalk drift remains relevant to policy semantics:

- corrected ASVS cookie IDs must be referenced by stable ledger item IDs, not
  copied as free-form policy text;
- CORS `3.4.2` and COOP `3.4.8` must resolve through registry-backed ledger
  evidence;
- ASVS `3.4.7` remains partial even if policy requires it;
- derived OWASP Top 10:2025 mappings cannot become direct evidence through
  policy;
- corrected PCI wording cannot be overridden by a local policy alias.

## Problem

Different environments legitimately have different applicability and evidence
requirements. An Internet-facing NGINX edge, an internal IIS application, and
an offline Apache service should not be assessed against an implicit,
identical organization policy.

Today these decisions are represented through ad hoc command flags, human
expectation, suppression configuration, or post-processing. Those mechanisms
do not provide a typed, reviewable policy contract, and they blur four separate
concepts:

1. project-level source coverage;
2. analyzer rule selection;
3. finding suppression;
4. target-specific control applicability and assessment.

The project needs a declarative policy foundation that preserves these
boundaries, records provenance in analysis output, and supplies enough
execution metadata for follow-up 04 to assess controls conservatively.

## Goals

1. Define a versioned, local, declarative audit policy schema.
2. Bind policies to stable ledger source and item IDs.
3. Express required, advisory, review-only, and not-applicable dispositions.
4. Resolve policy against target mode and server type deterministically.
5. Allow policy to request known opt-in review tags.
6. Record policy ID, version, digest, and resolved scope in analysis metadata.
7. Record a complete rule execution manifest.
8. Validate policy references before analysis starts.
9. Keep findings visible even when policy changes their assessment relevance.
10. Leave global coverage counts unchanged.

## Non-Goals

- Defining a general-purpose policy language.
- Supporting arbitrary expressions, scripts, templates, or remote includes.
- Replacing suppressions, baselines, or severity configuration.
- Hiding findings that are outside policy scope.
- Automatically changing registry mappings or ledger statuses.
- Claiming that no finding means a control passed.
- Defining the final control assessment report; that is follow-up 04.
- Fetching policy, standards, or evidence over the network.
- Supporting inheritance between policy files in schema version 1.
- Implementing organization-specific policy content in the product.

## Exact Sources in Scope

Policy schema version 1 can select only source IDs present in the canonical
follow-up 02 ledger. The initial exact set is:

| Source ID | Edition | Authority |
| --- | --- | --- |
| `cis-nginx-3.0.0` | CIS NGINX Benchmark v3.0.0 | `https://www.cisecurity.org/benchmark/nginx` |
| `cis-apache-http-server-2.4-2.3.0` | CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | `https://www.cisecurity.org/benchmark/apache_http_server` |
| `cis-microsoft-iis-10-1.2.1` | CIS Microsoft IIS 10 Benchmark v1.2.1 | `https://www.cisecurity.org/benchmark/microsoft_iis` |
| `owasp-top10-2025` | OWASP Top 10:2025 | `https://owasp.org/Top10/2025/` |
| `owasp-asvs-5.0.0` | OWASP ASVS 5.0.0 selected web/frontend requirements | `https://github.com/OWASP/ASVS/blob/master/5.0/en/0x12-V3-Web-Frontend-Security.md` |
| `nist-sp-800-52r2` | NIST SP 800-52 Rev. 2 selected requirements | `https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final` |
| `pci-dss-4.0.1` | PCI DSS v4.0.1 selected requirements | `https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf` |
| `iso-iec-27002-2022` | ISO/IEC 27002:2022 selected controls | `https://www.iso.org/standard/75652.html` |

Policy does not reproduce requirement wording. It references ledger item IDs,
whose citations and reviewed scope remain canonical. A later ledger source is
not automatically policy-valid until the policy schema and compatibility tests
accept its ID.

## Conceptual Boundaries

### Coverage Ledger

The ledger answers:

> What portions of a selected external source does this version of the product
> have evidence to inspect?

It is global, package-owned, and cannot be edited by an audit policy.

### Audit Policy

The policy answers:

> For this audit context, which ledger controls are applicable and what
> evidence is required?

It is user-owned and target-specific.

### Suppression

Suppression answers:

> Should a particular finding be muted or marked accepted for operational
> workflow?

Suppression never changes control applicability or proves compliance.

### Assessment

Assessment answers:

> Given the ledger, resolved policy, executed checks, findings, and issues,
> what can be concluded about each control?

That conclusion is produced only by follow-up 04.

## Policy Storage and Discovery

The conventional filename is:

```text
.webconf-audit-policy.yml
```

Schema version 1 does not automatically search parent directories. A policy is
used only when passed explicitly:

```text
--policy PATH
```

This prevents an analysis from silently inheriting a policy from an unrelated
parent checkout or user home directory. A future discovery mechanism requires
a new design.

The policy file is local YAML loaded with the same safe and bounded rules as
the machine-readable coverage ledger.

## Data Model

### Scalar Types

```python
PolicySchemaVersion = Literal[1]
ControlDisposition = Literal[
    "required",
    "advisory",
    "review",
    "not-applicable",
]
EvidenceExpectation = Literal[
    "ledger-default",
    "declared-direct",
    "declared-partial",
    "operator-review",
]
AnalysisMode = Literal["local", "external"]
ServerType = Literal["nginx", "apache", "lighttpd", "iis", "generic"]
RuleSelectionMode = Literal["default", "include"]
```

Policy IDs and profile IDs follow:

```regex
^[a-z0-9][a-z0-9.-]*$
```

### Root Policy

```python
class AuditPolicy(BaseModel):
    schema_version: Literal[1]
    policy_id: str
    policy_version: str
    title: str
    description: str
    defaults: PolicyDefaults
    profiles: tuple[AuditProfile, ...]
    provenance: PolicyProvenance
```

```python
class PolicyDefaults(BaseModel):
    disposition: Literal["required", "advisory"] = "advisory"
    evidence_expectation: Literal["ledger-default"] = "ledger-default"
    include_unmapped_findings: bool = True
    require_complete_execution_manifest: bool = True
```

The schema deliberately does not support a default `not-applicable`. Every
non-applicable decision must name an item and provide a rationale.

### Profile and Selector

```python
class AuditProfile(BaseModel):
    profile_id: str
    title: str
    selectors: tuple[TargetSelector, ...]
    sources: tuple[SourcePolicy, ...]
    requested_opt_in_tags: tuple[str, ...] = ()
```

```python
class TargetSelector(BaseModel):
    mode: AnalysisMode
    server_type: ServerType | None = None
    target_glob: str | None = None
```

Selector rules:

- `server_type` is required for local mode except when an existing analyzer
  can reliably determine it before rule selection;
- `server_type` must be omitted or `generic` for external mode;
- `target_glob` uses a bounded path-segment glob syntax, not regex;
- `**`, character classes, brace expansion, environment variables, and path
  traversal segments are rejected;
- matching uses the normalized user-supplied target label, never filesystem
  traversal to discover more targets;
- more than one matching profile is an error in version 1.

### Source and Control Policy

```python
class SourcePolicy(BaseModel):
    source_id: str
    disposition: Literal["required", "advisory"] | None = None
    controls: tuple[ControlPolicy, ...] = ()
```

```python
class ControlPolicy(BaseModel):
    item_id: str
    disposition: ControlDisposition
    evidence_expectation: EvidenceExpectation = "ledger-default"
    required_rule_ids: tuple[str, ...] = ()
    rationale: str
    ticket_ref: str | None = None
    review_due: date | None = None
```

Rules:

- `source_id` and `item_id` must exist in the canonical ledger;
- an item can be overridden at most once per profile;
- `required_rule_ids` must be listed as evidence for that ledger item;
- a derived-only rule cannot satisfy `declared-direct`;
- `operator-review` requires `disposition == "review"`;
- `not-applicable` requires non-empty rationale and cannot specify
  `required_rule_ids`;
- `review_due` is metadata and does not expire or mutate policy automatically;
- a policy cannot set a stronger coverage status than the ledger;
- free-form standard references are not accepted.

### Provenance

```python
class PolicyProvenance(BaseModel):
    owner: str
    approved_on: date
    change_ref: str
```

The loader computes, but the input file does not declare:

```python
class LoadedPolicyProvenance(BaseModel):
    path: str
    sha256: str
    loaded_at: datetime
```

The hash is computed over the raw policy bytes. The canonical resolved-policy
hash is separately computed over deterministic JSON so equivalent parsed
content can be compared.

## Example Policy Shape

```yaml
schema_version: 1
policy_id: public-web-baseline
policy_version: "2026.06"
title: Public web service audit baseline
description: Required controls for externally reachable production web services.
defaults:
  disposition: advisory
  evidence_expectation: ledger-default
  include_unmapped_findings: true
  require_complete_execution_manifest: true
profiles:
  - profile_id: public-nginx
    title: Public NGINX edge
    selectors:
      - mode: local
        server_type: nginx
        target_glob: production/*
    requested_opt_in_tags:
      - policy-review
    sources:
      - source_id: owasp-asvs-5.0.0
        disposition: required
        controls:
          - item_id: asvs-3.4.7-csp-reporting
            disposition: review
            evidence_expectation: operator-review
            required_rule_ids:
              - nginx.csp_reporting_missing
            rationale: Receiver ownership and operational handling require review.
      - source_id: cis-nginx-3.0.0
        disposition: required
        controls:
          - item_id: cis-nginx-http3-alt-svc
            disposition: review
            evidence_expectation: operator-review
            required_rule_ids:
              - nginx.http3_alt_svc_review
            rationale: HTTP/3 advertisement is an explicit architecture decision.
provenance:
  owner: Security Engineering
  approved_on: 2026-06-12
  change_ref: SEC-2026-104
```

The example does not upgrade ASVS `3.4.7`; it explicitly preserves its partial,
review-dependent nature.

## Resolved Policy Model

Policy resolution produces an immutable model included in analysis metadata:

```python
class ResolvedAuditPolicy(BaseModel):
    schema_version: Literal[1]
    policy_id: str
    policy_version: str
    profile_id: str
    raw_sha256: str
    resolved_sha256: str
    target: ResolvedTarget
    requested_opt_in_tags: tuple[str, ...]
    sources: tuple[ResolvedSourcePolicy, ...]
```

```python
class ResolvedSourcePolicy(BaseModel):
    source_id: str
    controls: tuple[ResolvedControlPolicy, ...]
```

```python
class ResolvedControlPolicy(BaseModel):
    item_id: str
    disposition: ControlDisposition
    evidence_expectation: EvidenceExpectation
    required_rule_ids: tuple[str, ...]
    rationale: str
    inherited_from: Literal["policy-default", "source", "control"]
```

Every applicable ledger item in a selected source is present after resolution.
This makes defaults auditable and prevents omission from being confused with
not-applicable.

## Rule Selection Semantics

Policy can request opt-in tags already known to the registry. It cannot name a
new tag or alter a rule's registry metadata.

Precedence:

1. explicit CLI opt-in tags;
2. resolved policy requested opt-in tags;
3. normal default rule selection.

The effective set is the union. Policy cannot disable a default rule. This
keeps policy from becoming a finding-suppression channel.

`required_rule_ids` are assessment evidence requirements, not an alternate
rule-selection list. If a required rule is unavailable for the selected mode or
server type, analysis records it as skipped or unavailable; validation does not
silently substitute a related rule.

## Rule Execution Manifest

Every analysis result gains additive metadata:

```python
class RuleExecutionManifest(BaseModel):
    schema_version: Literal[1]
    registry_revision: str
    selected_rule_ids: tuple[str, ...]
    completed_rule_ids: tuple[str, ...]
    skipped_rules: tuple[SkippedRule, ...]
    failed_rules: tuple[FailedRule, ...]
```

```python
class SkippedRule(BaseModel):
    rule_id: str
    reason: Literal[
        "mode-incompatible",
        "server-incompatible",
        "input-unavailable",
        "opt-in-not-selected",
        "prerequisite-failed",
    ]
```

```python
class FailedRule(BaseModel):
    rule_id: str
    issue_code: str
    stage: str
```

Invariants:

- selected, completed, skipped, and failed sets do not contain duplicates;
- completed, skipped, and failed are mutually exclusive;
- each completed, skipped, or failed rule was selected or is recorded as an
  explicitly policy-required unavailable rule;
- a rule is completed only when its required input stage ran and the rule
  returned normally;
- an empty finding set is not stored as a pass result;
- composite external execution must still expose per-rule completion;
- parser, probe, normalization, or registry failures are represented at the
  affected rule level where possible.

The manifest is necessary even when no policy is supplied. In that case the
analysis metadata records `audit_policy: null`.

## Application API

```python
def load_audit_policy(path: Path) -> AuditPolicy: ...

def validate_audit_policy(
    policy: AuditPolicy,
    ledger: CoverageLedger,
    registry: RuleRegistry,
) -> tuple[AuditPolicyIssue, ...]: ...

def resolve_audit_policy(
    policy: AuditPolicy,
    target: AuditTarget,
    ledger: CoverageLedger,
) -> ResolvedAuditPolicy: ...

def requested_opt_in_tags(
    resolved_policy: ResolvedAuditPolicy | None,
) -> frozenset[str]: ...

def build_rule_execution_manifest(
    selection: RuleSelection,
    execution_events: Iterable[RuleExecutionEvent],
) -> RuleExecutionManifest: ...

def attach_audit_context(
    result: AnalysisResult,
    policy: ResolvedAuditPolicy | None,
    manifest: RuleExecutionManifest,
) -> AnalysisResult: ...
```

```python
class AuditPolicyIssue(BaseModel):
    code: str
    message: str
    profile_id: str | None = None
    source_id: str | None = None
    item_id: str | None = None
    rule_id: str | None = None
    path: str | None = None
```

Loading, validation, and resolution have no network side effects.

## CLI Design

### Policy Commands

```text
webconf-audit policy validate --policy PATH
webconf-audit policy validate --policy PATH --format json
webconf-audit policy show --policy PATH
webconf-audit policy show --policy PATH --mode local --server-type nginx --target production/edge-01
```

`policy show` without a target displays parsed profiles. With a complete target
selector, it displays the resolved policy and hashes.

### Analysis Commands

Every existing analysis entry point gains:

```text
--policy PATH
```

Examples:

```text
webconf-audit analyze-nginx nginx.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-apache httpd.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-lighttpd lighttpd.conf --policy .webconf-audit-policy.yml
webconf-audit analyze-iis web.config --policy .webconf-audit-policy.yml
webconf-audit analyze-external https://example.test --policy .webconf-audit-policy.yml
```

An explicitly supplied invalid policy is fatal before target analysis begins.
There is no warning-and-fallback behavior.

Exit codes retain existing analyzer semantics. Policy load, validation, or
resolution failure uses the existing input/configuration error code. `policy
validate` uses:

| Code | Meaning |
| --- | --- |
| `0` | Policy is valid |
| `1` | File, YAML, schema, ledger, registry, or resolution failure |
| `2` | Invalid CLI usage |

## Backward Compatibility

- Omitting `--policy` preserves existing rule selection and finding behavior.
- No automatic policy discovery occurs.
- Existing suppressions and baselines retain their current behavior.
- Text finding output remains unchanged unless an existing verbose metadata
  mode elects to show policy provenance.
- JSON output gains additive `audit_policy` and `rule_execution` metadata.
- Existing consumers that ignore unknown JSON keys continue to work.
- The effective rule set can grow only when the user explicitly supplies a
  policy requesting opt-in tags.
- A policy cannot downgrade a registry mapping, mutate a ledger status, or
  rewrite a standard reference.
- Policy schema version 1 rejects unknown fields and future versions.

## Error Handling

Required issue codes include:

```text
policy_file_not_found
policy_file_too_large
policy_yaml_invalid
policy_schema_unsupported
policy_schema_invalid
duplicate_profile_id
duplicate_source_policy
duplicate_control_policy
unknown_source_id
unknown_item_id
item_source_mismatch
unknown_rule_id
rule_not_evidence_for_item
derived_rule_cannot_satisfy_direct
unknown_opt_in_tag
invalid_not_applicable_override
invalid_review_expectation
invalid_target_selector
unsafe_target_glob
no_matching_profile
multiple_matching_profiles
required_rule_unavailable
execution_manifest_incomplete
execution_manifest_overlap
policy_metadata_attach_failed
```

Behavior:

- parse/schema errors stop immediately;
- semantic validation accumulates independent issues;
- no matching profile is fatal when a policy was explicitly supplied;
- multiple matching profiles are always fatal in version 1;
- an unavailable required rule is recorded in the manifest and makes later
  assessment indeterminate or not assessed; analysis may continue if the
  underlying analyzer can still run;
- a failure to create a trustworthy execution manifest makes policy-aware
  analysis fail rather than emit misleading metadata.

Normal CLI output suppresses internal tracebacks. Existing debug behavior may
expose them.

## Security Considerations

- Use safe, bounded YAML parsing.
- Reject custom tags, aliases that exceed bounded expansion, merge keys,
  includes, templates, and environment interpolation.
- Never execute policy content.
- Do not resolve policy URLs or ticket references.
- Do not search parent directories for policies.
- Normalize selector input without opening additional files or traversing
  directories.
- Restrict target globs to a documented bounded syntax.
- Hash raw bytes and canonical resolved JSON with SHA-256.
- Avoid embedding full local policy paths in shareable reports by default;
  include a normalized display path and hash.
- Do not include configuration secrets, probe credentials, headers, or finding
  evidence in policy metadata.
- Escape policy prose in terminal, JSON, and future report renderers.
- Treat policy-requested opt-in checks as potentially active operations; only
  existing safe-probe rules may run, under existing network safety controls.
- Policy cannot expand network targets, redirect scope, or override safe-probe
  restrictions.

## Exact Likely Files

The implementation is expected to add or modify:

```text
src/webconf_audit/audit_policy.py
src/webconf_audit/policy_models.py
src/webconf_audit/execution_manifest.py
src/webconf_audit/models.py
src/webconf_audit/registry.py
src/webconf_audit/cli.py
src/webconf_audit/reporting.py
src/webconf_audit/external/rules/_runner.py
tests/test_audit_policy.py
tests/test_policy_cli.py
tests/test_execution_manifest.py
tests/test_cli_policy_integration.py
tests/test_external_execution_manifest.py
docs/audit-policy.md
docs/report-format.md
README.md
```

Follow-up 02 files are consumed but should not need schema changes unless an
evidence relation required by policy was omitted from the ledger design.

Analyzer-specific files should change only where needed to emit precise
per-rule execution events. Rule detection logic is out of scope.

## Test Matrix

| Area | Case | Expected result |
| --- | --- | --- |
| Loading | Valid version 1 policy | Parses |
| Loading | Missing or oversized file | Fails before analysis |
| Loading | Custom YAML tag, merge key, or expansion abuse | Rejected |
| Schema | Unknown field or schema version | Rejected |
| References | Unknown source/item/rule | Rejected |
| References | Item belongs to another source | Rejected |
| References | Rule is not ledger evidence for item | Rejected |
| ASVS | Policy names corrected cookie item IDs | Resolves |
| ASVS | Free-form stale cookie requirement ID | Schema rejects it |
| ASVS | CORS/COOP item resolves to corrected registry evidence | Resolves |
| ASVS | `3.4.7` requested as review | Remains partial/review-dependent |
| OWASP 2025 | Derived rule requested as declared-direct | Rejected |
| PCI | Policy attempts stale `8.3.5 / 8.3.6` alias | Rejected |
| Defaults | Omitted item inherits source/default disposition | Explicit in resolved model |
| N/A | Item override lacks rationale | Rejected |
| N/A | Policy makes all controls N/A by default | Impossible in schema |
| Selector | Exactly one profile matches | Resolves |
| Selector | No profile matches | Fatal |
| Selector | Two profiles match | Fatal |
| Selector | Unsafe glob | Rejected |
| Opt-in | Policy requests `policy-review` | Tag unioned with CLI selection |
| Opt-in | Unknown tag | Rejected |
| Selection | Policy tries to disable default rule | Unsupported by schema |
| Manifest | Rule completes with no finding | Recorded completed, not passed |
| Manifest | Parser prerequisite fails | Affected rules skipped/failed |
| Manifest | Composite external runner | Per-rule completion retained |
| Manifest | Overlapping completed/skipped sets | Rejected |
| Compatibility | Analyze without policy | Existing selection/output behavior |
| Compatibility | Suppressed finding under policy | Finding remains represented |
| Metadata | Policy hashes and profile included | Deterministic |
| CLI | Invalid explicit policy | Nonzero before target analysis |

Integration fixtures must cover local NGINX, Apache, Lighttpd, IIS, and external
analysis. They must include a zero-finding run to prove that execution metadata,
not finding absence, carries the later assessment signal.

## Documentation Changes

Add `docs/audit-policy.md` covering:

- conceptual boundaries;
- schema reference;
- selector behavior;
- source and control dispositions;
- evidence expectations;
- opt-in tag behavior;
- hashes and provenance;
- complete examples for local and external analysis;
- explicit warning that policy does not change global coverage or suppress
  findings.

Update `docs/report-format.md`:

- document additive `audit_policy` metadata;
- document the `rule_execution` manifest and status meanings;
- state that completed-with-no-finding is not itself a pass.

Update `README.md`:

- add minimal `policy validate`, `policy show`, and `--policy` examples;
- link to the full schema documentation;
- avoid the words certified, compliant, or guaranteed.

Update the coverage documentation only to cross-link the policy boundary. Do
not put target-specific applicability into the global ledger.

## Coverage Impact

This design has no project-level coverage impact.

- Policy cannot edit the ledger.
- `not-applicable` affects only a resolved audit profile.
- Requiring an opt-in rule does not increase source coverage.
- Running more rules does not increase source coverage.
- A policy's stronger evidence expectation may make an assessment less
  conclusive, but it does not lower the package ledger either.
- Corrected ASVS, OWASP 2025, and PCI values from follow-ups 01 and 02 remain
  unchanged.

No coverage numerator may be raised by adding a policy example, policy fixture,
required rule, execution manifest, or successful policy validation. An upgrade
still requires the evidence process defined in follow-up 02.

## Acceptance Criteria

1. A versioned policy schema validates against canonical ledger IDs and the
   live registry.
2. Policy use is explicit through `--policy`; no ambient discovery occurs.
3. Exactly one profile must resolve for the supplied target.
4. Every resolved source includes every applicable ledger item, including
   inherited defaults.
5. `not-applicable` is explicit, item-specific, and justified.
6. Derived OWASP 2025 evidence cannot satisfy a declared-direct expectation.
7. Corrected ASVS and PCI references cannot be bypassed with free-form aliases.
8. Policy may request known opt-in tags but cannot disable default checks.
9. Findings remain visible regardless of policy scope or suppression state.
10. Every analysis emits a complete per-rule execution manifest.
11. Zero findings is never serialized as a control pass.
12. Policy provenance and hashes are deterministic and present in JSON output.
13. Analysis without policy remains backward compatible.
14. No global coverage count or percentage changes.
15. Unit, CLI, analyzer integration, manifest, and security tests pass.

## Dependencies

- Follow-up 01 supplies corrected crosswalk provenance and source validation.
- Follow-up 02 supplies stable source/item IDs and ledger evidence relations.
- Existing Pydantic, PyYAML, Typer, and hashing libraries are sufficient.
- Analyzer orchestration must expose per-rule execution events.
- Follow-up 04 requires the resolved policy and execution manifest defined
  here.

## Rollback

Rollback removes policy-aware behavior without altering evidence:

1. remove `--policy` and the `policy` command group;
2. stop attaching policy metadata;
3. retain the execution manifest if consumers already depend on it, or remove
   it only with a report-schema compatibility decision;
4. retain follow-up 01 crosswalk corrections and follow-up 02 ledger;
5. leave suppressions and normal analyzer defaults unchanged.

Existing policy files are inert when `--policy` is unavailable. Rollback must
not reinterpret them as suppression files or migrate their `not-applicable`
decisions into the global ledger.

## Reviewer Checklist

- [ ] Policy, coverage, suppression, and assessment are kept separate.
- [ ] Policy is explicit and local; there is no parent-directory discovery.
- [ ] YAML parsing is safe and bounded.
- [ ] Source, item, rule, and opt-in tag references are validated.
- [ ] Stable ledger IDs replace free-form standard requirement text.
- [ ] Corrected ASVS cookie/CORS/COOP references are preserved.
- [ ] ASVS `3.4.7` remains partial and review-dependent.
- [ ] Derived OWASP 2025 mappings cannot become direct through policy.
- [ ] Stale PCI `8.3.5 / 8.3.6` wording is rejected.
- [ ] `not-applicable` requires an item-specific rationale.
- [ ] Multiple or zero matching profiles fail clearly.
- [ ] Policy cannot disable default rules or hide findings.
- [ ] Policy opt-in behavior is explicit and deterministic.
- [ ] Per-rule completion, skipping, and failure are all recorded.
- [ ] No-finding is not represented as pass.
- [ ] JSON additions are backward compatible.
- [ ] No global coverage numerator changes.
- [ ] Tests cover all analyzers, zero-finding runs, and unsafe input.
