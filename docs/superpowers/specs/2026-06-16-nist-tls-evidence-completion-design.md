# NIST TLS Evidence Completion Design

## Goal

Raise the NIST SP 800-52 Rev. 2 TLS evidence rows from bounded `partial`
coverage to `full` only where the existing `external.tls_inventory` control
can prove complete declared endpoint/SNI evidence.

This design covers the first stacked PR after the final follow-up 14
reconciliation. It intentionally does not implement the later Nginx policy or
ASVS web-surface PRs.

## Scope

The PR updates the following NIST counted items:

- `nist-3.3.1-recommended-cipher-posture`
- `nist-3.3.2-server-cipher-preference`
- `nist-4.2-ocsp-must-staple`
- `nist-4.3-revocation-evidence`

The implementation may update:

- `src/webconf_audit/data/control_source_coverage.yml`
- `src/webconf_audit/coverage_ledger.py`
- generated coverage documents
- coverage ledger tests
- release-check and CLI coverage tests only if their expected reconciliation
  output changes

## Evidence Model

The only new `full` basis is a declared complete TLS inventory:

- the policy contains `external.tls_inventory`;
- the inventory is `declared_complete: true`;
- each endpoint/SNI entry is part of the declared inventory;
- mandatory evidence is evaluated through `ControlAssessment`;
- incomplete, unavailable, contradictory, or failed evidence remains
  `indeterminate` or `fail` in target assessment and cannot be counted as
  ledger `full`.

The ledger status does not mean every possible internet endpoint is secure. It
means the project has a complete scanner-evidence path for an operator-declared
endpoint inventory.

## Required Facets

`nist-3.3.1-recommended-cipher-posture` requires:

- `external.tls_inventory` control evidence;
- `negotiated_cipher`;
- `safe-probe`;
- weak-cipher findings remain bound as defect evidence.

`nist-3.3.2-server-cipher-preference` requires:

- `external.tls_inventory` control evidence;
- `negotiated_cipher`;
- bounded server cipher preference metadata;
- explicit limitation to applicable TLS 1.2 preference observations.

`nist-4.2-ocsp-must-staple` requires:

- `external.tls_inventory` control evidence;
- `ocsp_stapling`;
- `external.tls_must_staple_not_observed` remains defect evidence.

`nist-4.3-revocation-evidence` requires:

- `external.tls_inventory` control evidence;
- `ocsp_stapling`;
- `external.ocsp_stapling_not_observed` remains defect evidence.

## Guardrails

The PR must add regression tests that reject a `full` NIST TLS ledger claim if
the item lacks:

- an `external.tls_inventory` assessment-control binding;
- `control-pass` absence semantics;
- the required assessed facets;
- a `safe-probe` evidence-kind or subclaim binding.

The existing follow-up 14 reconciliation still applies:

- no compliance or certification language;
- no implication that a single handshake proves deployment-wide posture;
- generated docs must match the ledger;
- `coverage reconcile --check` must remain clean.

## Out of Scope

This PR does not:

- add ASVS cookie/CORS/CSP web-surface policy;
- update Nginx logging or reverse-proxy policy coverage;
- implement IIS FTP;
- claim NIST compliance;
- change runtime scanner behavior unless a test shows the current TLS inventory
  assessment cannot express the required facets.

## Acceptance Criteria

- NIST SP 800-52 Rev. 2 summary becomes 10 applicable, 10 full, 0 partial.
- The four NIST TLS items above include explicit TLS inventory subclaims.
- The guardrail tests fail before ledger updates and pass after the proper
  bindings are present.
- `webconf-audit coverage validate` passes.
- `webconf-audit coverage reconcile --check` passes.
- `ruff`, targeted tests, the repository's fast CI pytest command, Docker
  integration tests, and release-related coverage checks pass before PR.
