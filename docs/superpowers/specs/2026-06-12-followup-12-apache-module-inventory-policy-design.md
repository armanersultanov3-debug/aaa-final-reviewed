# Follow-up 12: Apache Module Inventory Policy Design

**Status:** Design specification
**Sequence:** follow-up 12 of 14
**Baseline:** PR #9 at `1e1cbbb` plus accepted follow-ups 01-04
**Program dependencies:** follow-up 03 audit policy and follow-up 04 control assessment reporting
**Primary outcome:** assess Apache module minimization from an explicit operator snapshot and policy without ever executing Apache

---

## 1. Inherited State

PR #9 records CIS Apache HTTP Server 2.4 Benchmark v2.3.0 Sections 2.1-2.9
module minimization as `partial`.

Current Apache analysis provides:

- static parsing of `LoadModule`;
- module-name aliases;
- selected `<IfModule>` traversal;
- rules for visible risky or security-relevant modules, including ModSecurity
  and CRS signals;
- no automatic execution of `httpd` or `apachectl`.

The current `explicit_module_inventory()` is intentionally narrow. It can see
modules named by reachable `LoadModule` directives, but it cannot prove:

- statically compiled modules;
- modules loaded by a generated or unresolved include;
- the runtime module set selected by packaging or service arguments;
- whether the visible configuration is the one used by the running service;
- which modules are approved for the deployment's functionality;
- whether absence from the parsed config means disabled.

The shared policy and assessment foundations are inherited:

- operator policy is typed and separate from suppressions and baselines;
- explicit input can be complete, partial, or unknown;
- missing mandatory evidence produces `indeterminate`;
- assessment status is separate from vulnerability findings.

## 2. Exact Gaps

1. The parsed config is not a complete loaded-module inventory.
2. Static modules cannot be inferred from `LoadModule`.
3. Executing `httpd -M`, `httpd -l`, `apachectl -M`, or an equivalent command
   would introduce binary trust, side effects, platform variance, and
   privilege concerns.
4. The benchmark's least-functionality decision depends on deployment purpose.
5. Existing risky-module rules do not cover the complete Sections 2.1-2.9
   decision set.
6. A complete module list without an operator policy cannot establish which
   modules are required.
7. A policy without a complete module snapshot cannot establish what is
   actually loaded.
8. Snapshot/config conflicts are currently not represented.
9. Missing entries can be incorrectly read as disabled unless completeness is
   explicit.

## 3. Goals

- Accept a versioned module inventory snapshot supplied by the operator.
- Accept module expectations through the shared audit policy.
- Never execute or locate an Apache binary.
- Distinguish loaded, absent, and unknown module evidence.
- Distinguish static, shared, and unknown linkage when supplied.
- Require explicit snapshot completeness before absence-based conclusions.
- Assess required, forbidden, allowed, and unreviewed modules.
- Bind benchmark subclaims to explicit policy decisions.
- Corroborate snapshot evidence with parsed `LoadModule` directives without
  treating config visibility as a substitute for the snapshot.
- Keep default analysis low-noise when snapshot or policy is absent.

## 4. Non-Goals

- Running `httpd`, `apache2`, `apachectl`, package managers, service managers,
  PowerShell, shell scripts, or containers.
- Discovering the executable path.
- Generating the snapshot inside the analyzer.
- Hard-coding one universal minimal module set for all Apache deployments.
- Inspecting package ownership, binary linkage, or filesystem permissions.
- Unloading modules or editing configuration.
- Replacing current direct rules for dangerous module behavior.
- Treating a policy exception as a suppression.
- Implementing IIS FTP or changing its coverage status.

## 5. Mandatory No-Execution Boundary

The implementation must not import or call:

- `subprocess` for Apache inventory collection;
- `os.system`, `os.popen`, or shell wrappers;
- executable discovery such as `shutil.which("httpd")`;
- service-control APIs;
- package-manager APIs;
- remote command execution.

The accepted inputs are only:

1. parsed Apache configuration already supported by the analyzer;
2. an explicit module snapshot file;
3. an explicit operator policy file.

Documentation may show how an operator could collect data outside the tool,
but the analyzer neither recommends nor invokes a privileged command. Snapshot
provenance is descriptive metadata, not executable instructions.

## 6. Snapshot Schema

Use a JSON snapshot so collection output is portable and unambiguous:

```json
{
  "schema_version": 1,
  "kind": "apache-module-inventory",
  "snapshot_id": "prod-web-01-20260612",
  "host": "prod-web-01",
  "captured_at": "2026-06-12T08:00:00Z",
  "apache": {
    "version": "2.4.63",
    "configuration_id": "sha256:..."
  },
  "completeness": {
    "state": "complete",
    "basis": "operator-export-of-effective-loaded-modules"
  },
  "modules": [
    {
      "name": "authz_core_module",
      "state": "loaded",
      "linkage": "static",
      "source": "runtime-snapshot"
    },
    {
      "name": "status_module",
      "state": "absent",
      "linkage": "unknown",
      "source": "complete-snapshot-absence"
    }
  ]
}
```

Allowed completeness states:

- `complete`;
- `partial`;
- `unknown`.

Allowed module states:

- `loaded`;
- `absent`;
- `unknown`.

Allowed linkage values:

- `static`;
- `shared`;
- `unknown`.

Validation rules:

- `schema_version`, `kind`, snapshot ID, host, and capture time are required;
- module names are normalized through the existing alias rules;
- duplicate aliases resolving to conflicting states are rejected;
- `absent` is allowed only when completeness is `complete`;
- omission of a policy-referenced module from a `complete` exhaustive
  loaded-module snapshot is normalized to `absent`;
- omission from a `partial` or `unknown` snapshot is normalized to `unknown`;
- an empty complete snapshot is valid only with an explicit basis and produces
  normal policy failures for required modules;
- unknown fields follow the shared policy/schema compatibility rules;
- malformed explicit snapshots cause exit code 1;
- snapshot age is recorded but is not silently converted into failure.

## 7. Operator Policy Schema

Follow-up 03 owns the envelope. This follow-up makes a strict, typed extension
to the schema by adding an optional `apache.module_inventory` section.
Unknown keys remain rejected and no arbitrary expression language is added.

```yaml
version: 1
apache:
  module_inventory:
    policies:
      - id: production-web
        selectors:
          environment: production
          host: prod-web-01
        inventory_snapshot_id: prod-web-01-20260612
        unlisted_loaded_modules: fail
        benchmark_scope:
          cis_apache_2_4_v2_3_0:
            applicable: true
        modules:
          authz_core_module:
            expectation: required
            rationale: core authorization
          ssl_module:
            expectation: required
            rationale: HTTPS listener
          status_module:
            expectation: forbidden
            rationale: no operational status endpoint on public nodes
          proxy_module:
            expectation: allowed
            rationale: reverse-proxy role
```

Allowed expectations:

- `required`;
- `forbidden`;
- `allowed`;
- `not-applicable`.

`unlisted_loaded_modules` values:

- `fail`;
- `indeterminate`;
- `allow`.

For CIS module-minimization full evidence, the policy must:

- declare whether the benchmark module section applies;
- contain a reviewed decision for every mandatory benchmark subclaim;
- include rationale for every `required`, `allowed`, or `not-applicable`
  decision;
- classify every loaded in-scope module as `required`; an `allowed` loaded
  module is reviewed operator policy but does not prove least functionality;
- use a closed posture (`fail` or an equivalently strict reviewed policy) for
  unlisted loaded modules;
- match exactly one complete snapshot.

The scanner must not convert `allowed` into proof that a module is necessary.
`required` means the deployment expects it; `allowed` means reviewed but not
required by the policy and therefore caps the CIS assessment at `review` or
`partial`.

## 8. Models

```python
ModuleEvidenceState = Literal["loaded", "absent", "unknown"]
ModuleLinkage = Literal["static", "shared", "unknown"]
ModuleExpectation = Literal[
    "required",
    "forbidden",
    "allowed",
    "not-applicable",
]
CompletenessState = Literal["complete", "partial", "unknown"]
ModulePredicateResult = Literal[
    "satisfied",
    "violated",
    "unknown",
    "not-applicable",
]
```

Core models:

```python
ApacheModuleSnapshot
ApacheModuleObservation
ApacheModulePolicy
ApacheModuleExpectationEntry
ApacheModuleComparison
ApacheModuleEvaluation
```

Every comparison contains:

- normalized module identity and original aliases;
- snapshot state and source;
- policy expectation and logical policy key;
- config-visible `LoadModule` evidence, when present;
- predicate result and reason;
- reasons and limitations;
- related findings.

`ApacheModuleEvaluation` is analysis evidence, not a parallel
`ControlAssessment` model. Follow-up 04 alone maps that evidence, ledger
capability, resolved policy, execution state, findings, and suppressions to a
final assessment status.

## 9. CLI And API

Extend the existing command additively:

```text
webconf-audit analyze-apache CONFIG \
  --policy audit-policy.yml \
  --module-inventory apache-modules.json
```

Rules:

- both options are optional;
- `--module-inventory` without a matching module policy parses and reports the
  snapshot as analysis evidence but produces no module-policy control
  conclusion by itself;
- `--policy` with a module policy but no snapshot produces an indeterminate
  evidence record that follow-up 04 maps to `indeterminate`;
- malformed explicit input is exit code 1;
- no option triggers binary execution or auto-discovery.

The versioned analysis JSON is assessed separately:

```text
webconf-audit assess --report apache-analysis.json
webconf-audit assess --report apache-analysis.json \
  --fail-on fail,indeterminate
```

Public API:

```python
def analyze_apache_config(
    config_path: str | os.PathLike[str],
    *,
    enable_policy_review: bool = False,
    policy: AuditPolicy | str | os.PathLike[str] | None = None,
    module_inventory_path: str | os.PathLike[str] | None = None,
) -> AnalysisResult:
    ...
```

Focused loaders:

```python
load_apache_module_snapshot(path) -> ApacheModuleSnapshot
evaluate_apache_modules(snapshot, policy, config_ast) -> ApacheModuleEvaluation
```

## 10. Behavior And Indeterminate States

### 10.1 Module comparison

| Snapshot | Policy | Predicate result |
| --- | --- | --- |
| loaded | required | satisfied |
| loaded | allowed | satisfied for operator policy, insufficient for CIS pass |
| loaded | forbidden | violated |
| absent, complete snapshot | required | violated |
| absent, complete snapshot | forbidden | satisfied |
| unknown or incomplete absence | required/forbidden | unknown |
| any | not applicable | not-applicable with rationale |
| loaded but unlisted | `fail` | violated |
| loaded but unlisted | `indeterminate` | unknown |
| loaded but unlisted | `allow` | insufficient for CIS pass |

### 10.2 Snapshot/config reconciliation

- snapshot loaded plus visible `LoadModule` is corroborating evidence;
- snapshot loaded without visible `LoadModule` is valid for static modules or
  external/generated configuration and is not automatically a conflict;
- complete snapshot absent plus visible active `LoadModule` is conflicting and
  therefore `indeterminate` with an analysis issue;
- partial snapshot omission plus visible `LoadModule` is treated as loaded
  config evidence but cannot make the snapshot complete;
- unresolved include or unknown `<IfModule>` state cannot produce absence
  evidence.

### 10.3 Aggregate assessment

- `fail` if a forbidden module is loaded, a required module is conclusively
  absent, or a closed policy rejects an unlisted loaded module;
- `indeterminate` if no direct failure exists but snapshot completeness,
  policy coverage, selector matching, or evidence reconciliation is incomplete;
- `pass` only with one matching complete snapshot, complete benchmark policy
  decisions, no conflicts, all applicable comparisons passing, a `full`
  ledger item, and explicit pass semantics accepted under follow-up 04;
- `partial` when all observed facets pass but the ledger item remains partial
  or the policy/evidence covers only part of the benchmark group;
- `review` when the policy disposition requires operator review or a direct
  negative is suppressed, or a loaded module is merely `allowed` rather than
  established as required;
- `not-assessed` when no applicable module evidence was selected or executed;
- `not-applicable` only when the benchmark/module policy is explicitly marked
  not applicable with rationale.

Direct existing module findings continue to run regardless of assessment
status. Policy does not suppress them.

## 11. Likely Files

- policy models from follow-up 03;
- assessment models from follow-up 04;
- new module such as
  `src/webconf_audit/local/apache/module_inventory.py`;
- `src/webconf_audit/local/apache/__init__.py`;
- `src/webconf_audit/cli/__init__.py`;
- `src/webconf_audit/report/__init__.py`;
- existing
  `src/webconf_audit/local/apache/rules/_policy_semantics_utils.py` for shared
  alias normalization only;
- focused snapshot, policy, analyzer, CLI, report, and no-execution tests;
- fixture snapshots and policies;
- machine-readable coverage ledger and synchronized coverage docs when the
  coverage gate is satisfied.

The canonical ledger path is
`src/webconf_audit/data/control_source_coverage.yml`.

No production file should add Apache binary execution.

## 12. Migration And Backward Compatibility

- Existing Apache CLI and API calls work without new arguments.
- Existing config-visible module helpers and rules retain their current
  behavior.
- Snapshot/policy assessment is additive and optional.
- Existing suppression and baseline formats are unchanged.
- A snapshot does not silently become a baseline or suppression.
- Unknown schema versions fail explicitly rather than being partially parsed.
- No coverage status changes when only the schema or loader exists.
- Future schema versions must preserve v1 readability or provide an explicit
  migration error.

## 13. Exhaustive Test Plan

### Snapshot parsing

- complete, partial, and unknown snapshots;
- loaded, absent, and unknown states;
- static, shared, and unknown linkage;
- alias normalization;
- duplicate equivalent entries;
- conflicting aliases;
- absent entry in an incomplete snapshot;
- empty complete snapshot;
- invalid timestamps, IDs, kinds, and versions;
- stale snapshot metadata remains visible.

### Policy parsing

- all expectation values;
- missing rationales;
- selector matching and no-match/multi-match;
- each unlisted-module posture;
- complete and incomplete CIS subclaim decisions;
- unknown module aliases and duplicate policy keys.

### Comparison behavior

- every row in the comparison table;
- forbidden static and shared modules;
- required module absence under complete and partial snapshots;
- unlisted loaded modules;
- explicit not-applicable decisions;
- snapshot/config corroboration;
- snapshot/config conflicts;
- unresolved include and `<IfModule>` behavior.

### Aggregate assessment

- complete safe snapshot and policy gives `pass` only when every loaded
  in-scope module is established as required and the ledger permits pass;
- direct policy violation gives `fail`;
- missing snapshot gives `indeterminate`;
- snapshot supplied without a policy records evidence but no module-policy
  conclusion;
- a required module control with no usable policy evidence gives
  `not-assessed`;
- incomplete policy gives `indeterminate`;
- conflict gives `indeterminate`;
- partial ledger capability caps a positive result at `partial`;
- review disposition gives `review`;
- a loaded `allowed` module prevents CIS pass;
- no selected evidence gives `not-assessed`;
- explicit non-applicability gives `not-applicable`;
- existing findings are not suppressed by a passing policy.

### CLI/API/JSON

- both new options independently and together;
- malformed explicit input returns exit code 1;
- JSON includes snapshot provenance, completeness, comparisons, evidence,
  assessments, and limitations;
- default command output remains unchanged without options.

### No-execution tests

- monkeypatch `subprocess.run`, `subprocess.Popen`, `os.system`, `os.popen`, and
  `shutil.which` to fail if called;
- analyze with and without snapshot/policy and assert no call;
- scan production code for Apache executable command strings in execution
  paths;
- verify tests do not require an installed Apache binary.

### Regression and integration

- current module-sensitive rules;
- parser-depth and `IfModule` tests;
- rule registry and documentation counters;
- full non-integration suite, Apache integration suite where applicable, Ruff,
  interrogate, and `git diff --check`.

## 14. Documentation And Coverage Impact

CIS Apache Sections 2.1-2.9 may become assessable for a concrete run only when
both a complete snapshot and complete operator policy are present.

Source capability may move from `partial` to `full` only when the ledger proves
that:

- every mandatory benchmark module subclaim is represented;
- incomplete snapshot/policy input yields `indeterminate`;
- no executable collection path exists;
- all comparison and conflict cases are tested.

Documentation must distinguish:

- config-visible `LoadModule` evidence;
- operator-supplied runtime/build snapshot evidence;
- operator policy;
- concrete run assessment;
- repository source capability.

No prose may imply that Apache is minimal merely because no `LoadModule`
directive was found.

## 15. Acceptance Criteria

1. The analyzer reads a versioned explicit snapshot.
2. The analyzer consumes a typed operator module policy.
3. No Apache binary is executed or discovered.
4. Snapshot absence is meaningful only when completeness is `complete`.
5. Policy, snapshot, explicit pass semantics, and a full ledger item are
   required for aggregate `pass`.
6. Config evidence corroborates but does not replace the snapshot.
7. Conflicts produce `indeterminate`.
8. Existing rules and default CLI behavior remain compatible.
9. Coverage changes satisfy the ledger gate.
10. IIS FTP remains uncovered and untouched.

## 16. Dependencies

- Follow-up 03 provides policy loading, selectors, and validation.
- Follow-up 04 provides assessments and evidence references.
- Follow-up 11 may reuse stronger module-aware conditional semantics but is
  not allowed to weaken the explicit snapshot boundary.
- Follow-up 14 performs the final cross-standard recount.
- Apache's program documentation may be cited for snapshot provenance and
  terminology, but the analyzer must not invoke the documented commands:
  https://httpd.apache.org/docs/2.4/programs/httpd.html

## 17. Risks

- Operator snapshots can be stale or fabricated.
- Alias normalization can merge distinct or vendor-specific module names.
- A policy can approve more modules than least functionality really requires.
- Snapshot and config may describe different service instances.
- Reviewers may assume the tool collected the snapshot itself.

Mitigations include provenance, capture time, host/config identities, explicit
completeness, conflict handling, rationale requirements, and no-execution
tests.

## 18. Rollback

- Remove the additive snapshot and policy options.
- Remove module assessment models and reports.
- Preserve current static `LoadModule` helpers and findings.
- Revert any module coverage promotion in the same rollback.
- Do not retain prose claiming complete inventory support.

## 19. Reviewer Checklist

- [ ] There is no production execution path for `httpd` or related commands.
- [ ] Snapshot and policy are explicit independent inputs.
- [ ] Completeness is typed, not inferred.
- [ ] Static modules can be represented.
- [ ] Missing entries in partial snapshots remain unknown.
- [ ] Every CIS module subclaim requires a policy decision.
- [ ] Snapshot/config conflicts are indeterminate.
- [ ] Existing direct findings are not suppressed.
- [ ] Default Apache analysis remains unchanged.
- [ ] Coverage wording separates capability from run assessment.
- [ ] No compliance claim is introduced.
- [ ] IIS FTP remains outside scope.
