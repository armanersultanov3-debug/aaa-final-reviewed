# Contributing

Thanks for taking an interest in `webconf-audit`.

The project is a security-focused CLI, so changes should stay conservative:
prefer clear evidence, reproducible tests, and explicit scope boundaries over
broad claims.

## Development Setup

Install the development dependency group:

```bash
uv sync --group dev --locked
```

Run the fast local checks:

```bash
uv run --locked ruff check .
uv run --locked python -m compileall -q src
uv run --locked pytest tests --ignore=tests/integration_external --ignore=tests/integration_local --ignore=tests/integration_rule_coverage --ignore=tests/integration_real_world_cross_mode -q
uv run --locked webconf-audit list-rules
uv run --locked interrogate -c pyproject.toml
```

Run Docker-backed integration tests when Docker Engine is available:

```bash
uv run --locked pytest tests/integration_external tests/integration_local tests/integration_rule_coverage tests/integration_real_world_cross_mode -q
```

Run the release smoke check before release-oriented changes:

```bash
uv run --locked python scripts/release_check.py
```

## Pull Request Guidelines

- Keep each pull request focused on one behavior, rule set, documentation
  surface, or release task.
- Add or update tests before changing analyzer behavior.
- Keep rule identifiers, baseline fingerprints, JSON schema fields, and CLI
  contracts stable unless the pull request explicitly documents a versioned
  change.
- Do not claim compliance, certification, or full benchmark coverage unless the
  coverage ledger and tests prove the exact scoped claim.
- Safe external probes must remain non-mutating.
- Update the relevant documentation when changing public behavior, report
  fields, rule metadata, or source coverage.

## Security-Sensitive Changes

For parser, XML, TLS, path traversal, or external probing changes, include a
brief note in the pull request explaining the trust boundary and the test that
covers it.

Do not include real secrets, production configuration files, customer data, or
live target details in fixtures, issues, pull requests, or logs.
