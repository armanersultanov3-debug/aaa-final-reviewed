# ASVS TLS Evidence Completion Design

## Goal

Promote the ASVS v5.0.0 TLS cipher and OCSP / must-staple coverage rows from
bounded `partial` evidence to `full` only when backed by the existing
`external.tls_inventory` control assessment.

The change reuses the declared-complete TLS inventory model added for NIST TLS
coverage. It does not claim ASVS verification or certification.

## Scope

The PR updates these counted ASVS items:

- `asvs-12.1.2-cipher-posture`
- `asvs-12.1.4-ocsp-must-staple`

The new full basis is valid only when the ledger item includes:

- `external.tls_inventory` in `evidence.assessment_controls`;
- `strength: direct`;
- `origin: declared`;
- `absence_semantics: control-pass`;
- the required assessed facet:
  - `negotiated_cipher`, `forward_secrecy`, and
    `server_cipher_preference` for `asvs-12.1.2-cipher-posture`;
  - `ocsp_stapling` for `asvs-12.1.4-ocsp-must-staple`;
- mandatory subclaims bound to `external.tls_inventory`;
- rule bindings for the ASVS TLS defects that remain observable as findings:
  - `external.tls_aead_cipher_not_negotiated`,
    `external.tls_forward_secrecy_not_observed`, and
    `external.tls_server_cipher_preference_not_observed` for
    `asvs-12.1.2-cipher-posture`;
  - `external.ocsp_stapling_not_observed` and
    `external.tls_must_staple_not_observed` for
    `asvs-12.1.4-ocsp-must-staple`;
- `safe-probe` evidence.

## Non-Goals

This PR does not:

- add cookie or CORS full coverage;
- add a web-surface route inventory model;
- modify runtime TLS probing behavior;
- change rule identifiers or baseline fingerprints;
- claim ASVS compliance or certification.

## Guardrail

`validate_coverage_ledger` rejects a full ASVS TLS claim when the declared TLS
inventory control evidence, required facets, safe-probe evidence, or mandatory
subclaim and rule bindings are missing.

## Expected Count Change

OWASP ASVS v5.0.0 changes from:

- 22 applicable, 14 full, 8 partial, 63.6%;

to:

- 22 applicable, 16 full, 6 partial, 72.7%.

The improvement is scanner-evidence coverage within the documented scope, not
ASVS verification.
