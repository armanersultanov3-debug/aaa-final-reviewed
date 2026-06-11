# Policy-Review Coverage Reclassification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in Nginx HTTP/3 and `Alt-Svc` review rule and reclassify the existing CIS NGINX and CIS Apache evidence without changing conservative full-coverage percentages.

**Architecture:** The executable rule remains a normal local Nginx registry entry tagged `policy-review`, so the existing analyzer and CLI opt-in path controls it. The rule walks parsed Nginx server blocks, selects `listen ... quic` scopes, resolves effective `http3` and `add_header` directives using existing inheritance helpers, and emits one informational review finding per server block. Documentation treats `policy-review` as an evidence status separate from registry category, severity, and standard-reference strength.

**Tech Stack:** Python 3.10+, Pydantic AST models, project rule registry, pytest, Ruff, Markdown documentation, uv.

---

## File Structure

- Create `src/webconf_audit/local/nginx/rules/http3_alt_svc_review.py`
  - Owns only HTTP/3/`Alt-Svc` policy-review detection and finding construction.
- Modify `tests/test_policy_review_rules.py`
  - Pins the tenth opt-in rule and covers default-off, inheritance, effective
    state, deduplication, and source locations.
- Modify `docs/control-source-coverage-tracker.md`
  - Becomes the item-level source of truth for `full`, `partial`,
    `policy-review`, `uncovered`, and `excluded`.
- Modify `docs/benchmarks-covering.md`
  - Publishes the reconciled summary columns and unchanged full percentages.
- Modify `docs/rule-coverage.md`
  - Adds the rule inventory row, CIS mapping, rule count, severity count, and
    the updated Nginx/Apache/IIS gap decisions.
- Modify `docs/standards-roadmap.md`
  - Records the implemented HTTP/3 review signal and updated inventory count.
- Modify `docs/architecture.md`
  - Updates the Nginx and total counts and expands the opt-in examples.
- Modify `README.md`
  - Updates generated/repeated rule inventory counts required by consistency
    tests.
- Modify other count-bearing documentation only if
  `tests/test_rule_coverage_doc.py` identifies an existing enforced counter.

### Task 1: Pin the HTTP/3 Review Contract with Failing Tests

**Files:**
- Modify: `tests/test_policy_review_rules.py`

- [ ] **Step 1: Add the rule ID to the exact opt-in inventory**

Change the module description from nine to ten rules and add:

```python
POLICY_REVIEW_RULE_IDS = {
    "nginx.access_log_uses_default_format",
    "nginx.limit_req_zone_rate_review",
    "nginx.limit_conn_zone_review",
    "nginx.csp_value_review",
    "nginx.http3_alt_svc_review",
    "apache.custom_log_uses_default_format",
    "apache.csp_value_review",
    "apache.limit_request_body_value_review",
    "lighttpd.access_log_format_review",
    "iis.logging_fields_review",
}
```

- [ ] **Step 2: Add focused Nginx behavior tests**

Add tests equivalent to:

```python
def test_nginx_http3_alt_svc_review_missing_header(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic reuseport;\n"
        "    access_log off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing" in findings[0].description.lower()
    assert findings[0].location.line == 2


def test_nginx_http3_alt_svc_review_reports_configured_value(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic reuseport;\n"
        "    access_log off;\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=86400' always;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert 'h3=":443"' in findings[0].description
    assert "ma=86400" in findings[0].description


def test_nginx_http3_alt_svc_review_reports_effective_http3_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    http3 off;\n"
        "    server { listen 443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "http3 off" in findings[0].description.lower()


def test_nginx_http3_alt_svc_review_uses_inherited_alt_svc(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600' always;\n"
        "    server { listen 443 quic; access_log off; }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "ma=3600" in findings[0].description


def test_nginx_http3_alt_svc_review_respects_add_header_replacement(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "http {\n"
        "    add_header Alt-Svc 'h3=\":443\"; ma=3600' always;\n"
        "    server {\n"
        "        listen 443 quic;\n"
        "        access_log off;\n"
        "        add_header X-Content-Type-Options nosniff;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    findings = _findings_for(result, "nginx.http3_alt_svc_review")

    assert len(findings) == 1
    assert "missing" in findings[0].description.lower()


def test_nginx_http3_alt_svc_review_ignores_regular_tls_listener(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 443 ssl; access_log off; }\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert _findings_for(result, "nginx.http3_alt_svc_review") == []


def test_nginx_http3_alt_svc_review_is_default_off(tmp_path: Path) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server { listen 443 quic; access_log off; }\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path))
    assert _findings_for(result, "nginx.http3_alt_svc_review") == []


def test_nginx_http3_alt_svc_review_deduplicates_server_block(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "nginx.conf"
    config_path.write_text(
        "server {\n"
        "    listen 443 quic;\n"
        "    listen [::]:443 quic;\n"
        "    access_log off;\n"
        "}\n",
        encoding="utf-8",
    )

    result = analyze_nginx_config(str(config_path), enable_policy_review=True)
    assert len(_findings_for(result, "nginx.http3_alt_svc_review")) == 1
```

- [ ] **Step 3: Run the focused tests and confirm the intended failure**

Run:

```powershell
uv run --locked pytest tests/test_policy_review_rules.py -q
```

Expected: failure because `nginx.http3_alt_svc_review` is listed by the test
but is not registered or executable yet.

- [ ] **Step 4: Commit the failing contract tests**

```powershell
git add tests/test_policy_review_rules.py
git commit -m "Test Nginx HTTP3 policy review contract"
```

### Task 2: Implement the Nginx Policy-Review Rule

**Files:**
- Create: `src/webconf_audit/local/nginx/rules/http3_alt_svc_review.py`
- Test: `tests/test_policy_review_rules.py`

- [ ] **Step 1: Implement the minimal rule**

Create a module with this structure:

```python
"""nginx.http3_alt_svc_review -- opt-in HTTP/3 advertisement review."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    DirectiveNode,
    find_child_directives,
)
from webconf_audit.local.nginx.rules._value_utils import (
    effective_child_directives,
    iter_server_blocks_with_http_directives,
)
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import cis_nginx_v3_0_0

RULE_ID = "nginx.http3_alt_svc_review"


@rule(
    rule_id=RULE_ID,
    title="HTTP/3 and Alt-Svc configuration needs operator review",
    severity="info",
    description=(
        "A QUIC listener is configured. Static analysis can report the "
        "effective HTTP/3 and Alt-Svc settings but cannot prove deployed "
        "QUIC reachability or client discovery."
    ),
    recommendation=(
        "Verify the HTTP/3 module, UDP reachability, effective http3 setting, "
        "and Alt-Svc protocol, port, and lifetime against deployment intent."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "http3", "headers", "tls"),
    standards=(
        cis_nginx_v3_0_0(
            "4.1.12",
            coverage="partial",
            note=(
                "Surfaces QUIC listener, effective http3 state, and Alt-Svc "
                "advertisement for operator review; runtime HTTP/3 is not proven."
            ),
        ),
    ),
    order=284,
)
def find_http3_alt_svc_review(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for server_block, inherited in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header", "http3"},
    ):
        quic_listeners = [
            directive
            for directive in find_child_directives(server_block, "listen")
            if any(arg.lower() == "quic" for arg in directive.args)
        ]
        if not quic_listeners:
            continue

        http3_state = _effective_http3_state(server_block, inherited)
        alt_svc = _effective_alt_svc(server_block, inherited)
        findings.append(
            _build_finding(
                listener=quic_listeners[0],
                http3_state=http3_state,
                alt_svc=alt_svc,
            )
        )
    return findings
```

Implement helpers in the same module:

```python
def _effective_http3_state(
    server_block: BlockNode,
    inherited: dict[str, list[DirectiveNode]],
) -> str:
    directives = effective_child_directives(server_block, "http3", inherited)
    if not directives or not directives[-1].args:
        return "on (default)"
    return " ".join(directives[-1].args)


def _effective_alt_svc(
    server_block: BlockNode,
    inherited: dict[str, list[DirectiveNode]],
) -> str | None:
    for directive in find_server_add_headers(server_block, inherited):
        if directive.args and directive.args[0].lower() == "alt-svc":
            value_args = directive.args[1:]
            if value_args and value_args[-1].lower() == "always":
                value_args = value_args[:-1]
            return _strip_matching_quotes(" ".join(value_args).strip())
    return None


def _strip_matching_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1].strip()
    return value


def _build_finding(
    *,
    listener: DirectiveNode,
    http3_state: str,
    alt_svc: str | None,
) -> Finding:
    alt_svc_text = (
        f"effective Alt-Svc value: {alt_svc}"
        if alt_svc is not None
        else "effective Alt-Svc header is missing"
    )
    return Finding(
        rule_id=RULE_ID,
        title="HTTP/3 and Alt-Svc configuration needs operator review",
        severity="info",
        description=(
            f"QUIC listener found; effective http3 state: {http3_state}; "
            f"{alt_svc_text}. Static analysis does not prove runtime HTTP/3."
        ),
        recommendation=(
            "Verify the HTTP/3 module, UDP reachability, effective http3 "
            "setting, and Alt-Svc protocol, port, and lifetime against "
            "deployment intent."
        ),
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=listener.source.file_path,
            line=listener.source.line,
        ),
    )


__all__ = ["find_http3_alt_svc_review"]
```

- [ ] **Step 2: Run focused tests**

Run:

```powershell
uv run --locked pytest tests/test_policy_review_rules.py -q
```

Expected: all tests in the module pass.

- [ ] **Step 3: Run lint for the changed Python files**

Run:

```powershell
uv run --locked ruff check src/webconf_audit/local/nginx/rules/http3_alt_svc_review.py tests/test_policy_review_rules.py
```

Expected: no Ruff errors.

- [ ] **Step 4: Commit the implementation**

```powershell
git add src/webconf_audit/local/nginx/rules/http3_alt_svc_review.py
git commit -m "Add Nginx HTTP3 policy review rule"
```

### Task 3: Reconcile Coverage Documentation and Inventory Counts

**Files:**
- Modify: `docs/control-source-coverage-tracker.md`
- Modify: `docs/benchmarks-covering.md`
- Modify: `docs/rule-coverage.md`
- Modify: `docs/standards-roadmap.md`
- Modify: `docs/architecture.md`
- Modify: `README.md`

- [ ] **Step 1: Replace the tracker status vocabulary**

Define:

```markdown
| `full` | Complete evidence within the documented boundary. |
| `partial` | A narrower real signal exists, but the complete requirement is not proven. |
| `policy-review` | An opt-in informational rule surfaces evidence requiring operator judgment. |
| `uncovered` | The item is applicable but has no implemented project evidence. |
| `excluded` | The item is outside the denominator under the documented scope. |
```

State the invariant:

```text
Applicable = Full + Partial + Policy review + Uncovered
```

- [ ] **Step 2: Update item-level statuses**

In `docs/control-source-coverage-tracker.md`:

- change Nginx sections 2.5.4, 3.1, 3.3, 4.1.2, 5.1.1,
  5.2.4/5.2.5, and 5.3.2/5.3.3 to `partial`;
- change Nginx section 4.1.12 to `policy-review` and name
  `nginx.http3_alt_svc_review`;
- change Apache sections 2.1-2.9 and 4.1-4.2 to `partial`;
- change IIS sections 6.1/6.2 to `uncovered`;
- keep SChannel `partial`.

Add or update ledgers:

```markdown
| Source | Applicable | Full | Partial | Policy review | Uncovered | Full coverage |
| CIS NGINX Benchmark v3.0.0 | 15 | 7 | 7 | 1 | 0 | 46.7% |
| CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | 19 | 17 | 2 | 0 | 0 | 89.5% |
| CIS Microsoft IIS 10 Benchmark v1.2.1 | 10 | 8 | 1 | 0 | 1 | 80.0% |
```

- [ ] **Step 3: Update the public coverage snapshot**

In `docs/benchmarks-covering.md`, replace the broad `Not fully covered`
column with `Partial`, `Policy review`, and `Uncovered`. Preserve all existing
applicable and full counts and percentages. The relevant rows become:

```markdown
| CIS NGINX Benchmark v3.0.0 | 15 | 7 | 7 | 1 | 0 | 46.7% |
| CIS Apache HTTP Server 2.4 Benchmark v2.3.0 | 19 | 17 | 2 | 0 | 0 | 89.5% |
| CIS Microsoft IIS 10 Benchmark v1.2.1 | 10 | 8 | 1 | 0 | 1 | 80.0% |
| OWASP Top 10:2025 | 8 | 2 | 6 | 0 | 0 | 25.0% |
| OWASP ASVS v5.0.0 | 22 | 15 | 7 | 0 | 0 | 68.2% |
| NIST SP 800-52 Rev. 2 | 10 | 10 | 0 | 0 | 0 | 100.0% |
| PCI DSS v4.0.1 | 11 | 11 | 0 | 0 | 0 | 100.0% |
| ISO/IEC 27002:2022 | 10 | 8 | 2 | 0 | 0 | 80.0% |
```

- [ ] **Step 4: Update rule inventory and gap narratives**

In `docs/rule-coverage.md`:

- add `nginx.http3_alt_svc_review` with severity `info`, input `ast`, tags
  `policy-review, http3, headers, tls`, and CIS NGINX v3.0.0 section 4.1.12
  marked partial;
- change section 4.1.12 from closed/not pursued to implemented opt-in review;
- rewrite the seven Nginx and two Apache gap rows to say `partial`;
- rewrite IIS FTP as `uncovered`, not `out-of-scope`;
- increment Nginx, local, total, and info counters from registry-derived
  values.

In `docs/standards-roadmap.md`, replace the deferred HTTP/3 candidate text
with the implemented opt-in rule and retain runtime HTTP/3 as unproven.

In `docs/architecture.md`, include HTTP/3/`Alt-Svc` among policy-review
examples and update repeated counts.

In `README.md`, update repeated registry counts.

The post-rule count values are:

```text
Total: 472
Local: 286
Nginx: 96
Apache: 87
Lighttpd: 50
IIS: 53
Universal: 14
External: 172
Severity: high 57, medium 236, low 154, info 25
```

Apply the same total and per-family values in the count-bearing prose of
`docs/benchmarks-covering.md`. Also remove its documentation-only fence for
this change and state that this revision includes the dedicated Nginx
policy-review rule plus mapping updates.

- [ ] **Step 5: Run documentation consistency tests**

Run:

```powershell
uv run --locked pytest tests/test_rule_coverage_doc.py -q
```

Expected: all tests pass. If an enforced count-bearing document is reported,
verify the value against the registry, update the matching repeated counter,
and rerun this exact test command.

- [ ] **Step 6: Check documentation formatting**

Run:

```powershell
git diff --check
rg -n "not-full|closed \(not pursued|HTTP/3 directive signals stay a deferred" docs/control-source-coverage-tracker.md docs/benchmarks-covering.md docs/rule-coverage.md docs/standards-roadmap.md
```

Expected: no stale status remains for the reclassified rows and no whitespace
errors are reported.

- [ ] **Step 7: Commit the documentation**

```powershell
git add README.md docs/architecture.md docs/benchmarks-covering.md docs/control-source-coverage-tracker.md docs/rule-coverage.md docs/standards-roadmap.md
git commit -m "Reclassify control source coverage evidence"
```

### Task 4: Full Verification and PR Preparation

**Files:**
- Verify all changed files.

- [ ] **Step 1: Run Ruff**

```powershell
uv run --locked ruff check .
```

Expected: no errors.

- [ ] **Step 2: Run the complete test suite**

```powershell
uv run --locked pytest tests
```

Expected: all tests pass with no unexpected skips or failures.

- [ ] **Step 3: Run docstring coverage**

```powershell
uv run --locked interrogate -c pyproject.toml src
```

Expected: coverage is at or above the configured 40% threshold.

- [ ] **Step 4: Inspect the final diff**

```powershell
git diff master...HEAD --check
git diff master...HEAD --stat
git status --short --branch
```

Expected: no whitespace errors, no unstaged changes, and only PR2-scoped
files are present.

- [ ] **Step 5: Push and open a ready PR**

```powershell
git push -u origin codex/policy-review-coverage-reclassification
gh pr create --repo armanersultanov3-debug/aaa-final-reviewed --base master --head codex/policy-review-coverage-reclassification --title "Add HTTP3 policy review and reconcile source coverage" --body "## Summary
- add a default-off Nginx HTTP/3 and Alt-Svc policy-review rule
- reclassify seven CIS NGINX and two CIS Apache items as partial evidence
- keep IIS FTP applicable and uncovered while preserving full-coverage percentages

## Verification
- uv run --locked ruff check .
- uv run --locked pytest tests
- uv run --locked interrogate -c pyproject.toml src"
```

The PR body must summarize:

- the new default-off Nginx review rule;
- the seven Nginx and two Apache partial reclassifications;
- IIS FTP remaining uncovered;
- unchanged full-coverage percentages;
- exact verification commands and results.
