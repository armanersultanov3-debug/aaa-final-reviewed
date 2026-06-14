# Follow-up 08 Nginx Rate-Limit Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a policy-backed Nginx rate-limit evaluation layer that can assess route-specific request and connection limiting evidence without changing default analyzer behavior when no `nginx.rate_limits` policy is supplied.

**Architecture:** Reuse the existing audit-policy, scope-graph, and location-matcher foundations. Introduce a dedicated Nginx rate-limit semantics module that resolves legal zone definitions, exact limit-list inheritance, and scalar companion directives, then evaluate that evidence against a bounded `nginx.rate_limits` schema inside the existing `control_assessments` pipeline.

**Tech Stack:** Python 3.10+, Pydantic v2, existing `webconf_audit` policy and Nginx analyzer architecture.

---

## File Map

- Create: `src/webconf_audit/local/nginx/rate_limit_semantics.py`
  Exact request/connection zone parsing, inheritance, and effective route evidence.
- Create: `src/webconf_audit/local/nginx/assessments/rate_limits.py`
  Policy-backed control assessment evaluator for Nginx rate-limit profiles.
- Modify: `src/webconf_audit/policy_models.py`
  Add `nginx.rate_limits` models, numeric ranges, zone inventory, route profiles, and validation.
- Modify: `src/webconf_audit/local/nginx/__init__.py`
  Integrate the new evaluator while preserving no-policy behavior.
- Modify: `src/webconf_audit/local/nginx/assessments/__init__.py`
  Export the new evaluator.
- Modify: `src/webconf_audit/local/nginx/rules/_limit_utils.py`
  Reuse or upgrade parsing helpers only if no-policy parity is preserved.
- Modify: `docs/audit-policy.md`
- Modify: `docs/architecture.md`
- Modify: `docs/benchmarks-covering.md`
- Modify: `docs/rule-coverage.md`
  Document schema, semantics, and conservative coverage boundaries.
- Create: `tests/test_nginx_rate_limit_semantics.py`
- Create: `tests/test_nginx_rate_limit_policy.py`
- Create: `tests/fixtures/webserver-configs/nginx/policy/rate_limits/`
  Unit, regression, and policy tests for the new semantics.

### Task 1: Extend the Policy Schema

**Files:**
- Modify: `src/webconf_audit/policy_models.py`
- Test: `tests/test_nginx_rate_limit_policy.py`

- [ ] **Step 1: Write failing policy-model tests**

Add tests that prove:
- `nginx.rate_limits` accepts request/connection zone inventory and route profiles;
- rates and size units are strictly parsed;
- `accepted_zones` must reference declared inventory;
- `min <= max` rules are enforced for rates, burst, delay, and connections;
- route profiles may explicitly exempt request and/or connection limits;
- overlapping non-equivalent profiles are rejected;
- unsupported combinations such as simultaneous delayed-only and `nodelay` requirements are rejected.

- [ ] **Step 2: Run the focused model tests to confirm failure**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py -q`
Expected: FAIL because the policy schema does not exist yet.

- [ ] **Step 3: Implement the bounded schema**

Add strict models for:
- normalized request-rate expressions and numeric ranges;
- request and connection zone inventory entries;
- request and connection route requirements;
- route profile selectors reusing server names, declared locations, and sample URIs;
- top-level `NginxRateLimitPolicy`.

- [ ] **Step 4: Re-run model tests**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py -q`
Expected: PASS for the schema-only cases.

### Task 2: Build Exact Nginx Rate-Limit Semantics

**Files:**
- Create: `src/webconf_audit/local/nginx/rate_limit_semantics.py`
- Modify: `src/webconf_audit/local/nginx/rules/_limit_utils.py`
- Test: `tests/test_nginx_rate_limit_semantics.py`

- [ ] **Step 1: Write failing semantics tests**

Add tests that prove:
- `limit_req_zone` and `limit_conn_zone` are collected only from legal `http` context;
- duplicate incompatible zone definitions become unsupported/indeterminate evidence;
- `60r/m` and `1r/s` compare exactly;
- request and connection limit lists inherit by complete nearest-list replacement, not merge;
- multiple same-level `limit_req` / `limit_conn` directives remain active together;
- scalar companions (`*_dry_run`, `*_status`, `*_log_level`) use nearest-value inheritance and documented defaults;
- `if in location` directives do not affect effective results;
- includes preserve source and completeness boundaries;
- malformed zone/usage options are preserved as unsupported evidence.

- [ ] **Step 2: Run semantics tests to confirm failure**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_semantics.py -q`
Expected: FAIL because the semantics layer does not exist yet.

- [ ] **Step 3: Implement the semantics module**

Implement:
- exact request-rate normalization with rational comparison;
- legal-context zone collection and duplicate-definition handling;
- effective request/connection limit usage resolution per scope;
- scalar companion resolution;
- completeness and unsupported-evidence propagation.

- [ ] **Step 4: Re-run semantics tests**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_semantics.py -q`
Expected: PASS.

### Task 3: Add Policy-Backed Rate-Limit Assessments

**Files:**
- Create: `src/webconf_audit/local/nginx/assessments/rate_limits.py`
- Modify: `src/webconf_audit/local/nginx/__init__.py`
- Modify: `src/webconf_audit/local/nginx/assessments/__init__.py`
- Test: `tests/test_nginx_rate_limit_policy.py`

- [ ] **Step 1: Write failing assessment tests**

Add tests that prove:
- no `nginx.rate_limits` section produces no new assessments and preserves findings;
- matched request and connection requirements produce separate assessments;
- missing required effective limits fail;
- unknown/malformed/duplicate zone definitions become `indeterminate`;
- key mismatch, weak/strict numeric mismatches, wrong dry-run, wrong status, and disallowed log level fail as assessments;
- route selection via server, declared location, and sample URI works through follow-up 07 matcher;
- unsupported or unresolved route evidence becomes `indeterminate`;
- existing `policy-review` findings remain unless explicitly covered by policy scope.

- [ ] **Step 2: Run assessment tests to confirm failure**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py -q`
Expected: FAIL because the evaluator is not integrated.

- [ ] **Step 3: Implement the evaluator and analyzer integration**

Implement:
- route profile matching;
- request and connection requirement evaluation;
- deterministic evidence payloads with source spans, effective scopes, zone definitions, scalar companions, and indeterminate reasons;
- integration into `analyze_nginx_config()` using the existing `control_assessments` mechanism.

- [ ] **Step 4: Re-run assessment tests**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py -q`
Expected: PASS.

### Task 4: Preserve No-Policy Parity and Review-Finding Boundaries

**Files:**
- Modify: `src/webconf_audit/local/nginx/__init__.py`
- Modify: `src/webconf_audit/local/nginx/rules/_limit_utils.py`
- Test: `tests/test_nginx_rate_limit_policy.py`
- Test: `tests/test_policy_review_rules.py`

- [ ] **Step 1: Add regression tests for no-policy parity**

Add tests that prove:
- the existing Nginx rule output remains stable when no policy is supplied;
- illegal `if`-scoped rate-limit directives do not create a false pass;
- `policy-review` findings are suppressed only for explicitly assessed policy subjects, not globally.

- [ ] **Step 2: Run focused regression tests to confirm boundaries**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py tests/test_policy_review_rules.py -q`
Expected: FAIL until parity and suppression behavior are correct.

- [ ] **Step 3: Fix parity/suppression integration**

Keep findings and assessments separate, preserve rule IDs and baseline behavior, and scope any suppression to the exact policy-covered subject.

- [ ] **Step 4: Re-run regression tests**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_policy.py tests/test_policy_review_rules.py -q`
Expected: PASS.

### Task 5: Documentation and Final Verification

**Files:**
- Modify: `docs/audit-policy.md`
- Modify: `docs/architecture.md`
- Modify: `docs/benchmarks-covering.md`
- Modify: `docs/rule-coverage.md`
- Test: `tests/test_nginx_rate_limit_semantics.py`
- Test: `tests/test_nginx_rate_limit_policy.py`

- [ ] **Step 1: Update the docs**

Document:
- the `nginx.rate_limits` schema;
- exact inheritance and legal-context boundaries;
- conservative coverage notes for CIS 5.2.4 / 5.2.5 and companion ASVS / OWASP mappings;
- explicit no-policy behavior.

- [ ] **Step 2: Run focused verification**

Run: `uv run --locked pytest tests/test_nginx_rate_limit_semantics.py tests/test_nginx_rate_limit_policy.py -q`
Expected: PASS with docs and terminology aligned.

- [ ] **Step 3: Run full verification**

Run:
- `uv run --locked ruff check .`
- `uv run --locked pytest -q`
- project integration / Docker slices if Docker is available

Expected: non-Docker checks pass; Docker-backed checks pass when available, otherwise document why they were skipped.
