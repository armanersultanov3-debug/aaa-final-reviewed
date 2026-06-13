# Standards Mapping And Coverage Claims

The project keeps rule metadata and coverage accounting related but separate.
This distinction prevents a standards citation from being mistaken for proof
that a complete requirement or a particular deployed system complies.

## Rule registry references

Each `RuleMeta` can contain primary `standards` and secondary
`standards_secondary` references. A reference records:

- the source and exact requirement identifier;
- mapping strength: `direct`, `partial`, or `related`;
- mapping origin: `declared` or `derived`;
- optional bounded-evidence notes.

A declared reference was reviewed directly against the named edition. A
derived reference is an edition alignment produced from an earlier reviewed
mapping. Derived references carry their source provenance and use the
secondary tier. They can support discussion of partial alignment, but cannot
independently support a `full` coverage item.

## Coverage ledger statuses

The package ledger
`src/webconf_audit/data/control_source_coverage.yml` describes the selected
items used in the published coverage snapshot. Its statuses are:

- `full`: the complete counted item has declared direct evidence within the
  documented scanner scope;
- `partial`: implemented evidence covers a narrower signal and states its
  limitation;
- `policy-review`: an opt-in rule exposes facts that require operator
  judgment;
- `uncovered`: the item is applicable but has no adequate evidence path;
- `excluded`: the item is outside the denominator for an explicit boundary.

The applicable denominator is `full + partial + policy-review + uncovered`.
Only `full` enters the numerator. Grouped references remain one counted item
and list their underlying requirements explicitly.

## What validation proves

`webconf-audit coverage validate` checks schema integrity, stable IDs, source
metadata, status invariants, exact rule existence, exact registry-reference
matches, evidence sufficiency, and expected totals. Release checks also detect
drift in the generated tracker and headline benchmark summary.

Validation proves that the project's own coverage claims are internally
consistent with the shipped rule registry. It does not fetch standards,
evaluate an organization's policy, assess every control in a source, certify
the product, or determine compliance of an analyzed target.
