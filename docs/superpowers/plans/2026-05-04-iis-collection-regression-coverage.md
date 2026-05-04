# IIS Collection Regression Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Archive the resolved precision-finding list and add regression coverage proving IIS cross-file collection merges work beyond `customHeaders`.

**Architecture:** Keep production IIS effective-merge code unchanged unless a new regression exposes a real bug. Add focused tests around `merge_effective_configs()` for `handlers`, `modules`, and `requestFiltering` child collections, using the same `build_effective_config(parse_iis_config(...))` pattern already present in `tests/test_iis_discovery.py`.

**Tech Stack:** Python 3, pytest, existing IIS parser/effective-config model.

---

## Task 1: Archive Resolved Findings

**Files:**
- Move: `needfix.md` -> `docs/resolved-precision-findings.md`
- Modify: `docs/resolved-precision-findings.md`

- [x] Step 1: Move the root-level `needfix.md` file into `docs/resolved-precision-findings.md`.
- [x] Step 2: Change the title from `# Needfix` to `# Resolved Precision Findings`.
- [x] Step 3: Remove the "Remaining backlog" paragraph from the archive because `docs/roadmap.md` already tracks report grouping under "Severity calibration and report grouping".
- [x] Step 4: Verify `git status -sb` shows the root `needfix.md` removed and the docs archive added.

## Task 2: Add IIS Collection Regression Tests

**Files:**
- Modify: `tests/test_iis_discovery.py`

- [x] Step 1: Add small helper functions that return ordered child attributes for any effective section:
  - `_section_child_attr_values(config, suffix, attr_name)`
  - `_handler_names(config)`
  - `_module_names(config)`
  - `_request_filtering_file_extensions(config)`
- [x] Step 2: Add a `handlers` test where `machine.config` defines two handlers and `web.config` removes one by key while adding another.
- [x] Step 3: Add a `modules` test where `machine.config`, `applicationHost.config`, and `web.config` all contribute module entries and order is preserved.
- [x] Step 4: Add a `requestFiltering/fileExtensions` test where inherited denied extensions are preserved, one inherited extension is removed, and a local extension is added.
- [x] Step 5: Run `pytest -q tests/test_iis_discovery.py` and keep production code unchanged if the tests pass.

## Task 3: Verification And PR

**Files:**
- Modify: `docs/superpowers/plans/2026-05-04-iis-collection-regression-coverage.md`

- [x] Step 1: Run `ruff check .`.
- [x] Step 2: Run the broader fast suite with integration directories ignored.
- [ ] Step 3: Commit the archive and test coverage changes.
- [ ] Step 4: Push `codex/iis-regression-collections` and open a ready PR for CodeRabbit.
