# Release Checks

This document describes the repeatable release preparation flow. It does not
publish anything to PyPI or TestPyPI.

## Version And Changelog Policy

The project is still pre-1.0. Use SemVer-like `X.Y.Z` versions in
`pyproject.toml` and `vX.Y.Z` Git tags for public release points.

Use the version number to communicate the practical risk of an update:

- increment the patch version for compatible bug fixes, documentation updates
  that describe existing behavior, release-process fixes, and false-positive
  reductions that do not remove a documented rule;
- increment the minor version for new rules, new analyzer coverage, new CLI
  options, new output fields, new safe probes, or larger report improvements;
- reserve major-version changes for the future 1.0+ line; until then, any
  breaking CLI or JSON-contract change must be called out explicitly in
  [CHANGELOG.md](../CHANGELOG.md).

Every release candidate must have a matching `CHANGELOG.md` section for the
current `pyproject.toml` version. The release-check script refuses to continue
when that section is missing or empty.

Keep `## [Unreleased]` for work that has landed after the last release. When
preparing a release, move user-visible entries from `Unreleased` into
`## [X.Y.Z] - YYYY-MM-DD`, then update `pyproject.toml` to the same version.

## Release Candidate Checklist

Before tagging a release candidate:

1. Confirm that the target commit is the commit intended for release.
2. Update `pyproject.toml` with the intended version.
3. Add or update the matching section in `CHANGELOG.md`.
4. Run the fast local checks from `README.md`.
5. Run the release check locally or through the manual GitHub workflow.
6. Create a signed or annotated tag named `vX.Y.Z` only after the checks pass.

Recommended tag command:

```bash
git tag -a v0.1.0 -m "webconf-audit 0.1.0"
git push origin v0.1.0
```

If a tag was created from the wrong commit, do not move it silently. Delete and
replace a public tag only with a clear maintainer note in the release thread.

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

- verify that `CHANGELOG.md` has a non-empty section for the current package
  version;
- reconcile the temporary counted-coverage tracker and benchmark summary with
  canonical registry evidence before building artifacts;
- build exactly one wheel and one source distribution;
- install the built wheel into a clean virtual environment;
- verify the installed package metadata version matches `pyproject.toml`;
- run `pip check` in the release-test environment;
- validate the installed registry crosswalk using the packaged canonical
  catalog;
- run the installed `webconf-audit list-rules --format json` console command;
- verify that every serialized standard reference includes stable `origin` and
  `derived_from` provenance fields;
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

Publishing remains a separate explicit decision. The repository is now prepared
for repeatable release artifacts, but uploading to a package index is not part
of the default workflow.

Before publishing, confirm at least the following:

- the release-check script passes locally or in the manual GitHub workflow;
- the target commit is the commit intended for the release;
- the version in `pyproject.toml` is the version intended for the release;
- `CHANGELOG.md` has a matching, reviewed section for that version;
- the current project scope and known limitations are reflected in the docs.

After a release tag exists, downstream CI examples can install from the tag as
documented in [ci-integration.md](ci-integration.md).
