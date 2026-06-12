# Follow-up 11: Apache Root Authorization Baseline Design

**Status:** Design specification
**Sequence:** follow-up 11 of 14
**Baseline:** PR #9 at `1e1cbbb` plus accepted follow-ups 01-02
**Program dependency:** follow-up 02 machine-readable coverage ledger
**Primary outcome:** directly assess CIS Apache Section 4.1 while keeping Section 4.2 separate and explicitly bounded

---

## 1. Inherited State

PR #9 records one grouped `partial` row for CIS Apache HTTP Server 2.4
Benchmark v2.3.0 Sections 4.1-4.2. The current Apache analyzer already has:

- include-aware AST parsing;
- effective per-vhost analysis contexts;
- root `<Directory />` recognition in the `AllowOverride` and `Options` rule
  families;
- module-aware traversal through selected `<IfModule>` blocks;
- modern authorization helpers for `Require`, `RequireAll`, `RequireAny`, and
  `RequireNone`;
- legacy `Order`, `Allow`, `Deny`, and `Satisfy` modeling used by current
  status/info, method, and IP-policy rules;
- source locations for directives and blocks.

The current implementation does not have a direct rule for the benchmark
requirement that OS-root access be denied by default. Existing authorization
helpers answer narrower questions such as whether a scope guarantees an IP
restriction. They are not a complete, reusable root deny-all evaluator.

CIS Sections 4.1 and 4.2 are different claims:

- Section 4.1 is a configuration-visible baseline: access to the OS root
  directory is denied by default.
- Section 4.2 asks whether appropriate access to web content is allowed. That
  depends on deployment-specific document roots, applications, users, groups,
  authentication, and intended access matrices.

They must no longer be represented as one indivisible evidence claim.

## 2. Exact Gaps

1. There is no direct `apache.*` finding for a missing or permissive OS-root
   authorization baseline.
2. Existing helpers reduce authorization semantics to boolean
   "guarantees restriction" answers and lose indeterminate states.
3. Modern and legacy authorization are not represented by one explicit result
   model.
4. `AuthMerging Off|And|Or` is not modeled for repeated or nested applicable
   sections.
5. Mixing `mod_authz_core` and `mod_access_compat` directives can be
   misinterpreted.
6. Legacy ordering defaults and `Satisfy` can change a deny-all conclusion.
7. Unresolved includes, unsupported expressions, dynamic `<If>`, and ambiguous
   section merge order can create false passes.
8. The coverage ledger groups Section 4.1 and Section 4.2, hiding the fact that
   the first can be direct while the second remains deployment-dependent.
9. A direct Section 4.1 implementation must not be used to claim that all web
   content authorization is appropriate.

## 3. Goals

- Add a direct OS-root authorization baseline rule.
- Evaluate modern and legacy Apache 2.4 authorization semantics.
- Preserve `indeterminate` when the analyzer cannot prove the effective
  result.
- Model `AuthMerging` where statically determinable.
- Detect missing, explicitly permissive, and overwritten root baselines.
- Split CIS Section 4.1 and Section 4.2 into independent ledger records.
- Allow Section 4.1 to become direct/full when its evidence contract is met.
- Keep Section 4.2 partial until a separate deployment authorization policy
  closes all mandatory subclaims.

## 4. Non-Goals

- Proving application-level authorization.
- Determining which users or groups should access each document.
- Creating an operator authorization matrix in this PR.
- Evaluating filesystem ACLs, SELinux, AppArmor, or Unix permissions.
- Executing `httpd`, `apachectl`, shell commands, or configuration-test
  commands.
- Treating every non-deny-all web content scope as unsafe.
- Renaming existing authorization findings.
- Using Section 4.1 evidence to promote Section 4.2.
- Implementing IIS FTP or changing its denominator status.

## 5. Control Split

The machine-readable ledger must contain separate records:

```text
source_id: cis-apache-2.4-2.3.0
item_id: apache-4.1-os-root-access-denied
item_id: apache-4.2-web-content-access
```

Section 4.1 required subclaims:

1. an applicable OS-root `<Directory />` baseline is present;
2. its effective authorization result denies all requests;
3. no later applicable merge makes the baseline permissive;
4. the include and conditional evidence needed for that conclusion is
   complete.

Section 4.2 required subclaims:

1. every served content root is inventoried;
2. intended principals and access conditions are declared;
3. effective authorization matches that declaration;
4. application authorization outside Apache is accounted for.

This PR implements only the Section 4.1 subclaims. Section 4.2 remains
`partial` with exact limitations. The grouped Sections 4.1-4.2 row must not
remain in the final ledger or final Markdown. Any denominator change caused by
splitting the historical grouped item is explicit and is published atomically
by follow-up 14.

## 6. Models And Schema

Introduce a reusable semantic result:

```python
AuthorizationDecision = Literal[
    "deny_all",
    "not_deny_all",
    "indeterminate",
    "not_defined",
]

AuthorizationSyntax = Literal[
    "modern",
    "legacy",
    "mixed",
    "none",
]

@dataclass(frozen=True, slots=True)
class ApacheAuthorizationResult:
    decision: AuthorizationDecision
    syntax: AuthorizationSyntax
    evidence: tuple[SourceRef, ...]
    reasons: tuple[str, ...]
    auth_merging: Literal["off", "and", "or", "not_set", "unknown"]
```

Root scope discovery returns:

```python
@dataclass(frozen=True, slots=True)
class ApacheRootAuthorizationAssessment:
    root_blocks: tuple[ApacheBlockNode, ...]
    effective: ApacheAuthorizationResult
    include_graph_complete: bool
    unsupported_constructs: tuple[SourceRef, ...]
```

The evaluator must be tri-state or four-state throughout. Boolean helpers may
adapt from the richer model, but the root rule must not collapse
`indeterminate` into safe.

## 7. Modern Authorization Semantics

For statically active `mod_authz_core` directives:

- `Require all denied` is `deny_all`.
- `Require all granted` is `not_deny_all`.
- `Require ip`, `host`, `local`, `env`, `method`, valid-user, user, group, or
  another conditional provider is `not_deny_all` for the OS-root baseline
  because at least one request may be authorized.
- unsupported providers or expressions are `indeterminate`.
- `<RequireAll>` is `deny_all` when at least one child is conclusively
  `deny_all`; it is `indeterminate` if no child proves deny-all and at least
  one required child is indeterminate; otherwise it is `not_deny_all`.
- `<RequireAny>` is `deny_all` only when every branch is conclusively
  `deny_all`; one permissive branch makes it `not_deny_all`; an unresolved
  branch with no permissive branch makes it `indeterminate`.
- `<RequireNone>` and negated providers are evaluated only where Apache's
  authorization rules permit a conclusive result. Unsupported combinations
  are `indeterminate`, never assumed deny-all.
- an empty authorization container is `indeterminate`.

`AuthMerging` behavior:

- `Off` is Apache's default for a new authorization section and replaces the
  preceding authorization result at that merge level;
- `And` combines predecessor and current results like `RequireAll`;
- `Or` combines them like `RequireAny`;
- invalid, conditional, or dynamically selected values are `indeterminate`;
- the implementation follows Apache section merge order rather than source
  proximity alone.

## 8. Legacy Authorization Semantics

Legacy modeling applies only to statically active `mod_access_compat`
directives.

Required cases:

- `Order Allow,Deny` has a default deny result when no allow matches.
- `Order Deny,Allow` has a default allow result when no deny/allow rule
  overrides it.
- `Deny from all` and `Allow from all` are modeled in the order defined by the
  selected `Order`.
- specific hosts, networks, and environment predicates are conditional and
  therefore do not prove deny-all unless the final ordering still denies all.
- the last matching directive group wins according to Apache legacy semantics,
  not textual interleaving alone.
- `Satisfy All` requires both host and authentication constraints where
  applicable.
- `Satisfy Any` cannot prove deny-all when another authentication or host path
  could authorize the request.
- missing or invalid `Order`, unsupported legacy tokens, or dynamic predicates
  produce `indeterminate`.

Apache documents that a new section containing legacy access directives does
not inherit legacy directives from a previous section. The evaluator must
respect this reset rather than accidentally carrying legacy state forward.

## 9. Mixed Modern And Legacy Semantics

Modern and legacy directives in the same effective root scope are classified
as `mixed`.

The initial implementation is conservative:

- both families are evaluated separately for diagnostics;
- the combined result is `indeterminate`;
- no safe conclusion is emitted even if one family appears to deny all;
- an analysis issue explains that mixed authorization families are not used
  for benchmark pass evidence.

A later PR may add a proven combined model based on Apache integration tests,
but this PR must not guess.

## 10. Rule, CLI, And API

Add the rule:

```text
apache.os_root_access_not_denied
```

The rule emits a finding when:

- no `<Directory />` block exists and the static include graph is complete;
- the effective root result is `not_deny_all`;
- a later root section or `AuthMerging` result removes the deny-all baseline.

The finding anchors to:

- the permissive winning directive when present;
- the winning root block when policy is missing inside an existing block;
- the analyzed config file when the root block is absent.

Indeterminate analysis is not emitted as the same vulnerability finding. It is
reported through an `AnalysisIssue` such as:

```text
apache_root_authorization_indeterminate
```

and, when follow-up 04 is available, a Section 4.1 assessment with status
`indeterminate`.

The new rule's ledger evidence relation may receive
`absence_semantics="control-pass"` only after tests prove that a completed
rule with no finding covers every Section 4.1 facet for a complete include and
conditional scope. Until that evidence review lands, no-finding remains only
execution evidence and the assessment cannot pass.

No new CLI flag is required:

```text
webconf-audit analyze-apache CONFIG
```

Reusable API:

```python
def evaluate_root_authorization(
    config_ast: ApacheConfigAst,
    *,
    issues: list[AnalysisIssue] | None = None,
) -> ApacheRootAuthorizationAssessment:
    ...
```

## 11. Behavior And Indeterminate States

The assessment column below assumes the implementation PR also establishes a
`full` Section 4.1 ledger item and reviewed `control-pass` absence semantics.
Without those ledger contracts, a safe no-finding run cannot be reported as
`pass`.

| Configuration | Rule result | Assessment result |
| --- | --- | --- |
| `<Directory /> Require all denied` | no finding | pass |
| no root block, complete include graph | finding | fail |
| `Require all granted` | finding | fail |
| `Require ip 10.0.0.0/8` | finding | fail |
| conclusive legacy deny-all | no finding | pass |
| conclusive legacy default allow | finding | fail |
| mixed modern and legacy | no baseline finding | indeterminate |
| unresolved include may contain root policy | no baseline finding | indeterminate |
| unsupported `Require expr` | no baseline finding | indeterminate |
| dynamic `<If>` controls the winning policy | no baseline finding | indeterminate |
| invalid `AuthMerging` | no baseline finding | indeterminate |

An indeterminate result is not a pass. Reports must explain which source
location or missing evidence prevented a conclusion.

Under the full follow-up 04 algorithm:

- a direct unsuppressed root-baseline finding supports `fail`;
- a suppressed direct finding supports `review`, not `pass`;
- a skipped or failed root rule supports `indeterminate`;
- a policy that selects no usable Section 4.1 evidence produces
  `not-assessed`;
- Section 4.2 remains `partial` even when Section 4.1 passes;
- explicit policy non-applicability uses `not-applicable` and does not alter
  the package ledger denominator.

## 12. Likely Files

- `src/webconf_audit/local/apache/rules/_policy_semantics_utils.py`;
- a focused helper such as
  `src/webconf_audit/local/apache/authorization.py`;
- new rule module
  `src/webconf_audit/local/apache/rules/os_root_access_not_denied.py`;
- `src/webconf_audit/local/apache/__init__.py` for issue aggregation if needed;
- `src/webconf_audit/rule_standards.py`;
- focused Apache rule, parser-depth, registry, report, and integration tests;
- machine-readable coverage ledger from follow-up 02;
- `docs/rule-coverage.md`;
- `docs/control-source-coverage-tracker.md`;
- `docs/benchmarks-covering.md`;
- `docs/standards-roadmap.md`;
- repeated rule-count documents if the new rule changes catalog totals.

The canonical ledger path is
`src/webconf_audit/data/control_source_coverage.yml`.

Root-path recognition should be shared with existing `AllowOverride` and
`Options` root rules rather than copied a third time.

## 13. Migration And Backward Compatibility

- `analyze_apache_config` and `analyze-apache` signatures remain unchanged.
- Existing authorization helper behavior remains available to current rules.
- The richer evaluator is additive; existing boolean helpers may delegate to
  it only after regression tests prove equivalent behavior.
- Existing finding IDs are not renamed.
- The new rule adds one catalog entry and therefore requires synchronized rule
  count documentation.
- New analysis issue and assessment fields are additive.
- Existing baseline files do not contain the new finding and therefore treat
  it as new, as expected.
- The Sections 4.1-4.2 grouped coverage record is migrated into two records;
  follow-up 14 publishes the final denominator and percentages.

## 14. Exhaustive Test Plan

### Root scope discovery

- quoted and unquoted `<Directory />`;
- repeated root blocks;
- root block in an included file;
- missing root block with complete includes;
- unresolved mandatory and optional includes;
- non-root absolute directories do not satisfy the rule;
- `<DirectoryMatch>` does not silently substitute for exact OS root;
- inactive and unknown `<IfModule>` branches.

### Modern semantics

- direct granted and denied;
- nested `RequireAll`, `RequireAny`, and supported `RequireNone` cases;
- conditional providers;
- unsupported provider and `Require expr`;
- empty containers;
- negated requirements;
- repeated same-root sections with `AuthMerging Off`, `And`, and `Or`;
- invalid and dynamically selected `AuthMerging`;
- vhost and global section merge ordering.

### Legacy semantics

- every `Order Allow,Deny` and `Order Deny,Allow` default;
- `Allow from all`, `Deny from all`, and specific allow/deny combinations;
- multiple matching directive groups;
- `Satisfy All`, `Satisfy Any`, missing `Satisfy`, and invalid values;
- legacy inheritance reset in a new section;
- inactive `IfModule access_compat_module`.

### Mixed and unknown semantics

- modern plus legacy in one block;
- modern and legacy in merged root blocks;
- unresolved module inventory;
- dynamic `<If>` and unsupported expressions;
- parser or include issues preserve indeterminate.

### Finding and assessment contracts

- exact rule ID, severity, recommendation, and source anchor;
- no finding for conclusive deny-all;
- finding for conclusive permissive or missing baseline;
- no false pass for indeterminate;
- Section 4.1 evidence binding;
- Section 4.2 remains separate and partial;
- JSON and text report wording.

### Regression and integration

- existing status/info, method, IP, `AllowOverride`, and `Options` tests;
- secure and vulnerable real-world Apache fixtures;
- registry and documentation count tests;
- full non-integration suite, Apache integration suite where available, Ruff,
  interrogate, and `git diff --check`.

## 15. Documentation And Coverage Impact

The expected evidence result is:

- CIS Apache Section 4.1: candidate `full` after all direct, merge, and
  incomplete-evidence tests pass;
- CIS Apache Section 4.2: remains `partial`;
- the old grouped Sections 4.1-4.2 row is removed.

This split may change the Apache applicable denominator. The implementation PR
records the structural ledger change, while follow-up 14 performs the final
atomic published recount. Documentation must say that Section 4.1 is a
server-configuration baseline, not proof of appropriate application access.

Cross-standard access-control mappings may reference the new rule, but broad
OWASP and ISO access-control rows remain bounded by application context.

## 16. Acceptance Criteria

1. Section 4.1 and Section 4.2 have separate ledger records.
2. A direct root baseline rule exists with stable source anchors.
3. Modern authorization containers and `AuthMerging` are modeled.
4. Legacy order/default and `Satisfy` semantics are modeled.
5. Mixed or unsupported semantics produce `indeterminate`.
6. Missing root policy fails only when the include graph is sufficiently
   complete to make that conclusion.
7. Section 4.2 remains partial with explicit deployment-context limits.
8. Existing Apache CLI/API behavior is compatible.
9. No broad compliance claim is introduced.
10. IIS FTP remains uncovered and untouched.

## 17. Dependencies

- Follow-up 02 provides separate source item and subclaim records.
- Follow-up 04 may expose the semantic result as a control assessment but is
  not required for the direct finding.
- Follow-up 12 may provide stronger module evidence for `IfModule`, but this
  rule must remain conservative without it.
- Follow-up 14 publishes the final denominator and cross-standard recount.
- Modern authorization behavior is grounded in:
  https://httpd.apache.org/docs/2.4/howto/access.html and
  https://httpd.apache.org/docs/2.4/mod/mod_authz_core.html
- Legacy behavior and inheritance reset are grounded in:
  https://httpd.apache.org/docs/2.4/mod/mod_access_compat.html

## 18. Risks

- Apache section merge ordering is easy to oversimplify.
- Mixed modern/legacy authorization can produce misleading conclusions.
- A missing root block can be hidden in an unresolved include.
- Reviewers may mistake deny-by-default OS root policy for correct document
  authorization.
- Splitting the historical grouped row can create an unnoticed denominator
  change.

Mitigations are explicit semantic states, source-backed merge tests,
indeterminate handling, separate ledger records, and final atomic recount.

## 19. Rollback

- Remove the new rule and richer root evaluator.
- Restore existing helper implementations if delegation was introduced.
- Remove the Section 4.1 direct evidence binding.
- Restore the prior grouped coverage record only as part of the same rollback.
- Revert synchronized rule counts and coverage prose together.

## 20. Reviewer Checklist

- [ ] Section 4.1 and Section 4.2 are independent records.
- [ ] Section 4.2 is not promoted by this work.
- [ ] Root scope is exact and source-traceable.
- [ ] `RequireAll`, `RequireAny`, `RequireNone`, and `AuthMerging` are tested.
- [ ] Legacy `Order`, `Allow`, `Deny`, and `Satisfy` defaults are tested.
- [ ] Mixed modern/legacy semantics cannot produce a false pass.
- [ ] Unresolved includes and dynamic constructs are indeterminate.
- [ ] Missing policy is distinguished from unknown policy.
- [ ] Rule counts and mappings are synchronized.
- [ ] Denominator effects are deferred to and explicit in follow-up 14.
- [ ] No application authorization or compliance claim is made.
- [ ] IIS FTP remains outside scope.
