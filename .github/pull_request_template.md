## Summary

-

## Scope

- [ ] Behavior change
- [ ] Rule metadata / standards mapping
- [ ] Documentation only
- [ ] Packaging / release

## Testing

- [ ] `uv run --locked ruff check .`
- [ ] `uv run --locked pytest -q`
- [ ] `uv run --locked python scripts/release_check.py` when packaging or release metadata changed
- [ ] Docker-backed integration tests, if relevant and Docker is available

## Safety Notes

- [ ] No real secrets, production configs, or private target details are included.
- [ ] External probing remains safe and non-mutating.
- [ ] Coverage or standards claims are backed by ledger/test updates.

## Notes
