# ASVS TLS Evidence Completion Implementation Plan

## Task 1: Add Guardrail Tests

Add regression tests proving that the packaged ASVS TLS full rows require
`external.tls_inventory` control-pass evidence, required facets, safe-probe
evidence, and mandatory subclaim and rule bindings.

## Task 2: Generalize TLS Inventory Ledger Validation

Refactor the NIST-only TLS inventory invariant into a shared TLS inventory full
claim invariant that covers both NIST and ASVS source rows while keeping
source-specific issue codes.

## Task 3: Promote ASVS TLS Rows

Update `src/webconf_audit/data/control_source_coverage.yml` so
`asvs-12.1.2-cipher-posture` and `asvs-12.1.4-ocsp-must-staple` are `full`
only through declared complete `external.tls_inventory` evidence plus the
required ASVS TLS defect rule bindings.

## Task 4: Reconcile Documentation

Regenerate coverage tracker, benchmark snapshot, and roadmap artifacts using
`webconf-audit coverage reconcile --write`.

## Task 5: Verify

Run focused ledger, CLI, and TLS inventory tests, then run lint and the project
fast test suite. Docker or heavier integration suites may be run separately if
available before merge.
