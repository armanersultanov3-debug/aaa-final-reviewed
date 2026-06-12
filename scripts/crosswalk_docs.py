"""Temporary Markdown adapter for follow-up 01 crosswalk validation.

Follow-up 02 replaces this adapter with a machine-readable coverage ledger.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Iterable

from webconf_audit.crosswalk_integrity import (
    CountedCoverageClaim,
    CoverageClaimStatus,
    CrosswalkIssue,
    validate_registry_crosswalk,
)
from webconf_audit.rule_registry import RuleMeta

_TRACKER_PATH = Path("docs") / "control-source-coverage-tracker.md"
_SUMMARY_PATH = Path("docs") / "benchmarks-covering.md"

_SOURCE_CONFIG = {
    "owasp-top10-2025": {
        "heading": "## OWASP Top 10:2025",
        "label": "OWASP Top 10:2025",
        "standard": "OWASP Top 10",
    },
    "owasp-asvs-5.0.0": {
        "heading": "## OWASP ASVS v5.0.0",
        "label": "OWASP ASVS v5.0.0",
        "standard": "OWASP ASVS",
    },
    "pci-dss-4.0.1": {
        "heading": "## PCI DSS v4.0.1",
        "label": "PCI DSS v4.0.1",
        "standard": "PCI DSS v4.0.1",
    },
}

_EXPECTED_STATUS_COUNTS = {
    "owasp-top10-2025": {
        "full": 0,
        "partial": 8,
        "policy-review": 0,
        "uncovered": 0,
        "excluded": 0,
    },
    "owasp-asvs-5.0.0": {
        "full": 14,
        "partial": 8,
        "policy-review": 0,
        "uncovered": 0,
        "excluded": 0,
    },
    "pci-dss-4.0.1": {
        "full": 0,
        "partial": 9,
        "policy-review": 0,
        "uncovered": 2,
        "excluded": 0,
    },
}

_STATUSES: tuple[CoverageClaimStatus, ...] = (
    "full",
    "partial",
    "policy-review",
    "uncovered",
    "excluded",
)


def load_tracker_claims(repo_root: Path) -> tuple[CountedCoverageClaim, ...]:
    """Parse the three strict-source sections from the temporary tracker."""
    text = (repo_root / _TRACKER_PATH).read_text(encoding="utf-8")
    claims: list[CountedCoverageClaim] = []
    for source_id, config in _SOURCE_CONFIG.items():
        section = _markdown_section(text, str(config["heading"]))
        for raw_line in section.splitlines():
            cells = _table_cells(raw_line)
            if len(cells) < 3 or cells[1] not in _STATUSES:
                continue
            item_id = cells[0]
            references = _references_for_item(
                source_id,
                item_id,
                standard=str(config["standard"]),
            )
            claims.append(
                CountedCoverageClaim(
                    source_id=source_id,  # type: ignore[arg-type]
                    item_id=item_id,
                    status=cells[1],  # type: ignore[arg-type]
                    references=references,
                )
            )
    return tuple(
        sorted(
            claims,
            key=lambda claim: (claim.source_id, claim.item_id),
        )
    )


def count_claim_statuses(
    claims: Iterable[CountedCoverageClaim],
) -> dict[str, int]:
    counts = Counter(claim.status for claim in claims)
    return {status: counts[status] for status in _STATUSES}


def validate_coverage_documents(
    repo_root: Path,
    rules: Iterable[RuleMeta],
) -> tuple[CrosswalkIssue, ...]:
    """Validate strict tracker rows, summaries, and registry evidence."""
    claims = load_tracker_claims(repo_root)
    issues = list(
        validate_registry_crosswalk(
            rules,
            coverage_claims=claims,
        )
    )
    claims_by_source: dict[str, list[CountedCoverageClaim]] = {}
    for claim in claims:
        claims_by_source.setdefault(claim.source_id, []).append(claim)

    tracker_summary = _read_summary_table(repo_root / _TRACKER_PATH)
    benchmark_summary = _read_summary_table(repo_root / _SUMMARY_PATH)
    for source_id, expected_counts in _EXPECTED_STATUS_COUNTS.items():
        actual_counts = count_claim_statuses(claims_by_source.get(source_id, ()))
        if actual_counts != expected_counts:
            issues.append(
                _document_issue(
                    source_id,
                    "Tracker row statuses do not match the follow-up 01 "
                    f"snapshot: expected {expected_counts}, got {actual_counts}.",
                )
            )
            continue

        expected_summary = _summary_tuple(actual_counts)
        source_label = str(_SOURCE_CONFIG[source_id]["label"])
        for document_name, summary in (
            (_TRACKER_PATH.as_posix(), tracker_summary),
            (_SUMMARY_PATH.as_posix(), benchmark_summary),
        ):
            if summary.get(source_label) != expected_summary:
                issues.append(
                    _document_issue(
                        source_id,
                        f"{document_name} summary for {source_label!r} does not "
                        f"match tracker rows: expected {expected_summary}, got "
                        f"{summary.get(source_label)!r}.",
                    )
                )

    return tuple(sorted(set(issues), key=_issue_sort_key))


def _references_for_item(
    source_id: str,
    item_id: str,
    *,
    standard: str,
) -> tuple[tuple[str, str], ...]:
    if source_id == "owasp-top10-2025":
        references = re.findall(r"\bA\d{2}:2025\b", item_id)
    elif source_id == "pci-dss-4.0.1":
        references = re.findall(
            r"\bReq\. \d+(?:\.\d+)*(?: / \d+(?:\.\d+)*)?",
            item_id,
        )
    else:
        references = []
        for token in re.findall(
            r"(?:v5\.0\.0-)?\d+\.\d+\.\d+",
            item_id,
        ):
            references.append(
                token if token.startswith("v5.0.0-") else f"v5.0.0-{token}"
            )
    if not references:
        raise ValueError(
            f"Could not parse a canonical reference from tracker item {item_id!r}."
        )
    return tuple((standard, reference) for reference in references)


def _markdown_section(text: str, heading: str) -> str:
    start = text.find(heading)
    if start < 0:
        raise ValueError(f"Missing tracker section {heading!r}.")
    end = text.find("\n## ", start + len(heading))
    return text[start:] if end < 0 else text[start:end]


def _table_cells(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    return [cell.strip() for cell in stripped.strip("|").split("|")]


def _read_summary_table(path: Path) -> dict[str, tuple[int, int, int, int, int, str]]:
    summary: dict[str, tuple[int, int, int, int, int, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        cells = _table_cells(line)
        if len(cells) != 7:
            continue
        try:
            values = tuple(int(value) for value in cells[1:6])
        except ValueError:
            continue
        summary[cells[0]] = (*values, cells[6])
    return summary


def _summary_tuple(
    counts: dict[str, int],
) -> tuple[int, int, int, int, int, str]:
    applicable = sum(
        counts[status]
        for status in ("full", "partial", "policy-review", "uncovered")
    )
    percentage = 0.0 if applicable == 0 else counts["full"] / applicable * 100
    return (
        applicable,
        counts["full"],
        counts["partial"],
        counts["policy-review"],
        counts["uncovered"],
        f"{percentage:.1f}%",
    )


def _document_issue(source_id: str, message: str) -> CrosswalkIssue:
    return CrosswalkIssue(
        code="coverage_tracker_registry_mismatch",
        rule_id=None,
        standard=str(_SOURCE_CONFIG[source_id]["standard"]),
        reference=None,
        message=message,
    )


def _issue_sort_key(issue: CrosswalkIssue) -> tuple[str, str, str, str, str]:
    return (
        issue.code,
        issue.rule_id or "",
        issue.standard or "",
        issue.reference or "",
        issue.message,
    )


__all__ = [
    "count_claim_statuses",
    "load_tracker_claims",
    "validate_coverage_documents",
]
