# Follow-up 13: IIS SChannel Evidence v2 Design

**Status:** Design specification
**Sequence:** follow-up 13 of 14
**Baseline:** PR #9 at `1e1cbbb` plus accepted follow-ups 01-04
**Program dependency:** follow-up 04 control assessment reporting
**Primary outcome:** represent SChannel settings as enabled, disabled, default, or unknown with explicit completeness and OS-build context

---

## 1. Inherited State

PR #9 records CIS Microsoft IIS 10 Benchmark v1.2.1 Sections 7.1-7.6 and
7.10-7.12 as `partial`.

The current IIS analyzer can:

- enrich IIS configuration analysis from the live Windows registry;
- read a v1 JSON SChannel export through `--tls-registry`;
- disable live enrichment with `--no-tls-registry`;
- expose enabled protocol and cipher lists plus cipher-suite order;
- run SChannel findings for TLS 1.2, weak protocols, AES 128/256, and preferred
  suite order;
- preserve registry source references and host metadata.

The v1 model is list-based:

```python
IISRegistryTLS(
    protocols_enabled=list[str] | None,
    ciphers_enabled=list[str] | None,
    cipher_suite_order=list[str] | None,
)
```

This loses important meaning. A missing registry value can mean:

- Windows default;
- key absent from a complete collection;
- key not collected;
- permission denied;
- unsupported OS/build;
- malformed export.

List omission therefore cannot safely mean disabled. The current rules can
overstate negative evidence when TLS 1.2 or AES 256 is not listed in a v1
export.

## 2. Exact Gaps

1. Protocol and cipher state is reduced to "listed as enabled" or "not listed".
2. Windows defaults vary by product version and build.
3. The current export has no schema version.
4. It has no OS product/build identity.
5. It has no per-class collection completeness.
6. The live reader cannot distinguish an absent key from an unreadable key.
7. Missing `Enabled` or `DisabledByDefault` values are not represented.
8. Conflicting or malformed DWORD values are not preserved as unknown.
9. Cipher-suite order has no explicit source/completeness state.
10. v1 files must remain readable without preserving false certainty.
11. Current JSON metadata exposes only `*_known` booleans.

## 3. Goals

- Introduce a versioned SChannel export schema v2.
- Normalize protocol and cipher controls to exactly four configuration states:
  `enabled`, `disabled`, `default`, and `unknown`.
- Record OS product, version, build, and update revision where available.
- Record completeness independently for protocols, ciphers, suite order, and
  OS build.
- Preserve raw registry value presence and values for auditability.
- Resolve OS defaults only from a reviewed exact-build support table.
- Return indeterminate when a default cannot be resolved.
- Keep v1 JSON files readable through a conservative adapter.
- Preserve the existing CLI option and analyzer API.
- Remove absence-based false findings.

## 4. Non-Goals

- Declaring every Windows build supported without reviewed default data.
- Querying Windows Update, Microsoft APIs, or the internet at analysis time.
- Changing SChannel registry settings.
- Enumerating client-side protocol policy when the benchmark requires server
  policy.
- Replacing external TLS observations.
- Treating external negotiation as proof of complete registry configuration.
- Preserving v1 false-positive behavior for omitted entries.
- Implementing IIS FTP settings, parsing, probes, or findings.
- Removing IIS FTP from the applicable denominator.

## 5. State Semantics

Canonical state:

```python
SchannelState = Literal["enabled", "disabled", "default", "unknown"]
CompletenessState = Literal["complete", "partial", "unknown"]
EffectiveState = Literal["enabled", "disabled", "unknown"]
```

### 5.1 Protocol state truth table

For server protocol values:

| `Enabled` | `DisabledByDefault` | Collection | State |
| --- | --- | --- | --- |
| nonzero | `0` | values readable | `enabled` |
| `0` | `0`, `1`, or absent | `disabled` |
| absent | absent | complete | `default` |
| absent | absent | partial/unknown | `unknown` |
| nonzero | `1` | any | `unknown` conflict |
| nonzero | absent | any | `unknown` |
| absent | `0` or `1` | any | `unknown` |
| malformed/non-DWORD | any | any | `unknown` |

`default` describes a conclusively observed absence of an explicit override in
a complete collection. It does not require a supported OS build. Every
default entry also has:

```python
default_effective_state: EffectiveState
default_source: str | None
```

An assessment can pass or fail a default only when
`default_effective_state` is known for the exact supported OS build.

### 5.2 Cipher state

For cipher `Enabled`:

- nonzero DWORD: `enabled`;
- zero DWORD: `disabled`;
- absent in a complete collection: `default`;
- absent in partial/unknown collection: `unknown`;
- malformed value: `unknown`.

### 5.3 Cipher-suite order

Suite order is not a binary control and therefore uses:

```python
CipherSuiteOrderSource = Literal["explicit", "default", "unknown"]
```

It still carries the same completeness and OS-build requirements. A default
order is evaluated only when the exact build has a reviewed default list.

## 6. V2 Export Schema

```json
{
  "schema_version": 2,
  "kind": "iis-schannel-evidence",
  "host": "iis-prod-01",
  "captured_at": "2026-06-12T08:00:00Z",
  "os": {
    "product_name": "Windows Server 2022 Datacenter",
    "version": "10.0",
    "build": 20348,
    "ubr": 2527,
    "architecture": "x64"
  },
  "completeness": {
    "os_build": "complete",
    "protocols": "complete",
    "ciphers": "complete",
    "cipher_suite_order": "complete"
  },
  "schannel": {
    "protocols": {
      "TLS 1.2": {
        "server": {
          "enabled": {"present": true, "value": 1},
          "disabled_by_default": {"present": true, "value": 0}
        }
      },
      "TLS 1.0": {
        "server": {
          "enabled": {"present": false},
          "disabled_by_default": {"present": false}
        }
      }
    },
    "ciphers": {
      "AES 256/256": {
        "enabled": {"present": true, "value": 4294967295}
      }
    },
    "cipher_suite_order": {
      "present": true,
      "value": [
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      ]
    }
  },
  "collection_issues": []
}
```

Validation:

- schema version and kind are required;
- OS build is an integer and UBR is optional;
- completeness values use the fixed enum;
- `present: true` requires a correctly typed value;
- `present: false` forbids a value;
- duplicate protocol/cipher names after normalization are rejected;
- unknown protocol/cipher names are preserved but cannot satisfy known CIS
  subclaims without an explicit mapping;
- collection issues downgrade affected completeness;
- a collector cannot declare a class complete while reporting unreadable
  paths in that class;
- normalized state is derived by the loader and is not trusted from input.

## 7. Canonical Models

Introduce a v2 canonical model:

```python
IISSchannelEvidence
SchannelOSIdentity
SchannelCompleteness
SchannelRegistryValue
SchannelProtocolEvidence
SchannelCipherEvidence
SchannelCipherSuiteOrderEvidence
SchannelDefaultCatalogEntry
```

Each protocol/cipher evidence item contains:

- normalized name;
- raw registry values and presence;
- configuration state;
- effective state;
- state reason;
- source path;
- completeness;
- OS-default catalog reference, when used.

The OS-default catalog is a reviewed, static package resource keyed by exact
supported product/build ranges. It must include:

- source URL and review date;
- protocol/cipher/suite default data;
- lower and upper build bounds when Microsoft documents a range;
- tests at each range boundary.

Unknown or unreviewed builds never inherit the nearest build's defaults.

## 8. Live Registry Collection

The live reader must distinguish:

- value present;
- key/value absent;
- access denied;
- unsupported platform;
- malformed value;
- unexpected read error.

The `_RegistryReader` protocol should return a structured read result rather
than `None` for every failure mode.

Live collection also records OS identity using local Windows APIs or registry
values. If OS identity cannot be read:

- explicit enabled/disabled states remain usable;
- absent values in a complete collection remain configuration state
  `default`, but their effective state is `unknown`;
- absent values in an incomplete collection remain configuration state
  `unknown`;
- default-dependent assessments are indeterminate.

Non-Windows behavior remains `(None, [])` unless an explicit export is
supplied.

## 9. V1 Compatibility

V1 files remain readable. Compatibility means input support, not preservation
of conclusions that depended on unsafe omission semantics.

The adapter rules are:

- listed enabled protocols become `enabled`;
- listed enabled ciphers become `enabled`;
- unlisted protocols and ciphers become `unknown`;
- protocol/cipher completeness becomes `partial`;
- OS build becomes unknown;
- an explicit cipher-suite order remains explicit for that evidence class;
- metadata records `input_schema_version: 1` and `adapted_to_v2: true`;
- one warning issue explains that omitted v1 entries cannot prove disabled or
  default state.

Consequences:

- a weak protocol explicitly listed in v1 still produces a finding;
- AES 128 explicitly listed still produces its existing finding;
- missing TLS 1.2 in v1 no longer proves TLS 1.2 disabled;
- missing AES 256 in v1 no longer proves AES 256 disabled;
- an explicit v1 suite order remains assessable;
- aggregate SChannel assessment is normally indeterminate because v1 is
  incomplete.

For source compatibility, retain `IISRegistryTLS` as a deprecated wrapper for
one major release. Existing construction with `protocols_enabled`,
`ciphers_enabled`, and `cipher_suite_order` adapts to v2 partial evidence.
New production code uses `IISSchannelEvidence`.

## 10. CLI And API

The CLI remains:

```text
webconf-audit analyze-iis CONFIG --tls-registry schannel.json
webconf-audit analyze-iis CONFIG --no-tls-registry
```

The loader auto-detects:

- explicit `schema_version: 2`;
- legacy v1 shape with a top-level `schannel` object;
- unsupported explicit versions, which fail with exit code 1.

The analyzer API remains source-compatible:

```python
def analyze_iis_config(
    config_path,
    machine_config_path=None,
    tls_registry_path=None,
    use_tls_registry=True,
    *,
    enable_policy_review=False,
) -> AnalysisResult:
    ...
```

Focused APIs:

```python
load_schannel_export(path) -> IISSchannelEvidence
read_live_schannel() -> tuple[IISSchannelEvidence | None, list[AnalysisIssue]]
resolve_schannel_state(...) -> SchannelState
```

The old `load_registry_export`, `read_live_registry`, and
`resolve_registry_tls` names remain compatibility wrappers during migration.

## 11. Behavior And Indeterminate States

Rules must consume canonical states:

- weak protocol `enabled`: finding;
- weak protocol `disabled`: no finding for that protocol;
- weak protocol `default`: resolve exact-build effective state, then find or
  pass the subclaim;
- weak protocol `unknown`: no absence-based finding; assessment indeterminate;
- TLS 1.2 `disabled`: `iis.schannel_tls12_not_enabled` finding;
- TLS 1.2 `enabled`: pass that subclaim;
- TLS 1.2 `default`: evaluate only through exact-build default data;
- TLS 1.2 `unknown`: no false finding; indeterminate;
- AES and suite-order rules follow the same completeness discipline.

External TLS evidence can corroborate a concrete protocol or cipher
observation, but it does not rewrite registry state or snapshot completeness.
Contradictions are recorded and make the affected aggregate assessment
indeterminate unless direct failing evidence already establishes `fail`.

Aggregate status:

- `fail` when direct complete evidence establishes at least one mandatory
  unsafe state;
- `indeterminate` when no direct failure exists but mandatory states,
  completeness, OS defaults, or suite order remain unresolved;
- `pass` only when every mandatory CIS subclaim is resolved and safe, the
  ledger item is `full`, and its reviewed evidence relation permits pass;
- `partial` when positive evidence covers only facets or the ledger item is
  still partial;
- `review` when operator judgment or a suppression prevents an automated
  conclusion;
- `not-assessed` when no applicable SChannel evidence was selected or
  executed;
- `not-applicable` only through explicit applicability evidence, not because
  registry data is absent.

Without an embedded resolved policy and execution manifest, `analyze-iis`
still emits findings, issues, and v2 evidence metadata, but it does not emit a
follow-up 04 control assessment. The separate `assess --report` command owns
the final status calculation.

## 12. Likely Files

- `src/webconf_audit/local/iis/registry.py`;
- new focused modules such as
  `src/webconf_audit/local/iis/schannel_models.py` and
  `src/webconf_audit/local/iis/schannel_defaults.py`;
- `src/webconf_audit/local/iis/rules/schannel_tls_policy.py`;
- `src/webconf_audit/local/iis/__init__.py`;
- IIS normalizer code that consumes registry TLS evidence;
- `src/webconf_audit/report/__init__.py`;
- v1/v2 fixtures and focused registry, rule, normalizer, CLI, JSON, and live
  reader tests;
- machine-readable coverage ledger and synchronized docs when the coverage
  gate is met.

The canonical ledger path is
`src/webconf_audit/data/control_source_coverage.yml`.

## 13. Migration And Backward Compatibility

- Existing CLI options stay valid.
- Existing v1 files remain readable.
- Existing `IISRegistryTLS` callers receive a deprecation path.
- Existing JSON fields such as `tls_registry_source` remain and gain additive
  v2 details.
- Existing explicitly unsafe v1 evidence continues to produce findings.
- Omission-based v1 findings may disappear because they become indeterminate;
  this is an intentional false-positive correction.
- Baselines containing those omission-based findings naturally report them as
  resolved; release notes must explain why.
- No v2 input is downgraded to v1 list semantics.
- Unknown future versions fail explicitly.

## 14. Exhaustive Test Plan

### V2 schema

- valid complete and partial exports;
- every completeness state;
- every value-presence combination;
- malformed DWORDs and conflicting values;
- duplicate normalized names;
- unknown names preserved;
- collection issue/completeness contradictions;
- unsupported schema versions;
- missing OS identity.

### State truth tables

- every protocol row in Section 5.1;
- cipher enabled/disabled/default/unknown;
- explicit/default/unknown suite order;
- exact-build default resolution;
- unsupported build and range boundaries;
- UBR differences where relevant.

### Live reader

- present, absent, access-denied, malformed, and unexpected-error results;
- OS identity success/failure;
- non-Windows no-op;
- explicit export precedence over live registry;
- no ambient developer registry dependence in tests.

### V1 adapter

- existing fixture shapes;
- listed weak protocol still finds;
- listed AES 128 still finds;
- omitted TLS 1.2 and AES 256 become unknown;
- explicit suite order remains available;
- deprecation/adaptation metadata and warning;
- legacy constructor wrapper.

### Rules and assessments

- safe explicit states;
- unsafe explicit states;
- safe and unsafe exact-build defaults;
- unresolved defaults;
- partial completeness;
- external/local corroboration and contradiction;
- pass/fail/partial/review/indeterminate/not-assessed/not-applicable
  aggregation;
- no false pass from an empty snapshot.

### CLI/API/JSON

- unchanged options and signatures;
- v1/v2 auto-detection;
- malformed/unsupported explicit input exit code 1;
- additive metadata includes schema version, OS build, completeness, states,
  reasons, and default sources;
- text report distinguishes default from unknown.

### Regression and integration

- all current IIS SChannel rules;
- normalizer source anchors;
- corpus fixture migration;
- Windows live tests where available;
- rule registry and coverage guardrails;
- full non-integration suite, IIS integration suite where available, Ruff,
  interrogate, and `git diff --check`.

## 15. Documentation And Coverage Impact

CIS IIS Sections 7.1-7.6 and 7.10-7.12 may move from `partial` to `full` only
after:

- all mandatory protocol, cipher, and suite-order subclaims use v2 states;
- exact-build defaults are bounded and reviewed;
- incomplete evidence produces `indeterminate`;
- v1 omission cannot produce a false conclusion.

Cross-standard TLS rows for ASVS, NIST, PCI, and ISO must be recounted by
follow-up 14. Current 100% rows are not proof of organizational compliance and
must retain scanner-scope wording.

IIS FTP Sections 6.1/6.2 remain:

- `uncovered`;
- applicable;
- in the denominator;
- outside this implementation.

There is no FTP implementation specification in this PR.

## 16. Acceptance Criteria

1. Canonical states are exactly enabled, disabled, default, and unknown.
2. Completeness is explicit per evidence class.
3. OS build is recorded and required for default resolution.
4. Unsupported builds remain unknown.
5. V1 files remain readable through conservative adaptation.
6. Omitted v1 entries cannot prove disabled or default state.
7. Rules no longer fire from absence alone when evidence is incomplete.
8. Existing CLI/API entry points remain compatible.
9. Coverage promotion, if any, satisfies the ledger gate.
10. IIS FTP remains uncovered and in the denominator.

## 17. Dependencies

- Follow-up 04 provides assessment and evidence-reference contracts.
- Follow-up 10 may provide external corroboration but cannot replace SChannel
  completeness.
- Follow-up 14 performs the final CIS/ASVS/NIST/PCI/ISO recount.
- State and default resolution must stay aligned with Microsoft's reviewed
  SChannel registry documentation:
  https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings

## 18. Risks

- Microsoft defaults can change between builds.
- Product names alone are too weak for default resolution.
- Access-denied registry reads can look like absent keys.
- Compatibility consumers may rely on old list fields.
- A static default catalog can become stale.
- Disappearing false-positive findings can surprise baseline users.

Mitigations include exact build keys, source/review dates, boundary tests,
structured read results, compatibility wrappers, warnings, and conservative
unknown states.

## 19. Rollback

- Revert canonical v2 consumption and restore the v1 loader.
- Keep any v2 files explicitly unsupported rather than silently misreading
  them.
- Restore old rule behavior only together with documentation acknowledging its
  omission limitations.
- Revert any coverage promotion and synchronized cross-standard prose.
- Do not alter IIS FTP status during rollback.

## 20. Reviewer Checklist

- [ ] Four canonical states are used consistently.
- [ ] `default` is distinct from effective enabled/disabled.
- [ ] Exact OS build gates default resolution.
- [ ] Completeness is per evidence class.
- [ ] Access denied is distinct from absent.
- [ ] V1 omission becomes unknown.
- [ ] Explicit unsafe v1 evidence still finds.
- [ ] Existing CLI/API entry points remain valid.
- [ ] External evidence does not overwrite registry state.
- [ ] Coverage language is scanner-scoped.
- [ ] IIS FTP is still uncovered, applicable, and in the denominator.
- [ ] No FTP implementation work is included.
