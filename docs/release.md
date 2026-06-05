# Release Checks

This document describes the repeatable pre-release package check. It does not
publish anything to PyPI or TestPyPI.

## Local Release Check

Run the release check from the repository root:

```bash
uv run --locked python scripts/release_check.py
```

The script builds a fresh wheel and source distribution into
`.tmp/release-check/dist`, installs the built wheel into an isolated virtual
environment under `.tmp/release-check/venv`, and verifies the installed package
rather than the editable working tree.

The smoke checks are intentionally small and release-oriented:

- build exactly one wheel and one source distribution;
- install the built wheel into a clean virtual environment;
- verify the installed package metadata version matches `pyproject.toml`;
- run `pip check` in the release-test environment;
- run the installed `webconf-audit list-rules --format json` console command;
- run an installed-package IIS analysis smoke test with `--no-tls-registry`.

Preview the command sequence without building artifacts:

```bash
uv run --locked python scripts/release_check.py --dry-run
```

## GitHub Workflow

The manual `Release Check` workflow runs the same script on GitHub Actions. Use
it before creating a public release tag or publishing package artifacts.

The workflow is manual on purpose: normal pull requests already run linting,
compilation, tests, rule-catalog loading, and docstring coverage. Release checks
exercise packaging and installed-package behavior and are most useful when a
maintainer is preparing an actual release candidate.

## Publishing Boundary

Publishing remains a separate explicit decision. Before publishing, confirm at
least the following:

- the release-check script passes locally or in the manual GitHub workflow;
- the target commit is the commit intended for the release;
- the version in `pyproject.toml` is the version intended for the release;
- the current project scope and known limitations are reflected in the docs.

After a release tag exists, downstream CI examples can install from the tag as
documented in [ci-integration.md](ci-integration.md).
