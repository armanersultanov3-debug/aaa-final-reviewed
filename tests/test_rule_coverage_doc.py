"""Verify that docs/rule-coverage.md stays in sync with the rule registry."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from webconf_audit.cli import _ensure_all_rules_loaded
from webconf_audit.rule_registry import registry

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DOC_PATH = _REPO_ROOT / "docs" / "rule-coverage.md"
_RULE_ID_PATTERN = re.compile(
    r"`((?:universal|nginx|apache|lighttpd|iis|external)\.[A-Za-z0-9_.]+)`"
)


def _document_text() -> str:
    return _DOC_PATH.read_text(encoding="utf-8")


def _markdown_section(text: str, heading: str) -> str:
    start = text.find(heading)
    assert start != -1, f"missing markdown section: {heading}"
    next_heading = text.find("\n## ", start + len(heading))
    if next_heading == -1:
        return text[start:]
    return text[start:next_heading]


def _documented_rule_ids() -> set[str]:
    return set(_RULE_ID_PATTERN.findall(_document_text()))


def _registered_rule_ids() -> set[str]:
    _ensure_all_rules_loaded()
    return {meta.rule_id for meta in registry.list_rules()}


def _registry_counter_values() -> dict[str, int]:
    _ensure_all_rules_loaded()
    rules = registry.list_rules()
    local_counts = Counter(
        meta.server_type
        for meta in rules
        if meta.category == "local"
    )
    category_counts = Counter(meta.category for meta in rules)
    return {
        "total": len(rules),
        "local": category_counts["local"],
        "universal": category_counts["universal"],
        "external": category_counts["external"],
        "nginx": local_counts["nginx"],
        "apache": local_counts["apache"],
        "lighttpd": local_counts["lighttpd"],
        "iis": local_counts["iis"],
    }


def _assert_doc_counter(
    *,
    doc_path: Path,
    label: str,
    pattern: str,
    expected: int,
) -> None:
    text = doc_path.read_text(encoding="utf-8")
    match = re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
    assert match is not None, f"{doc_path} is missing counter pattern for {label!r}"
    actual = int(match.group(1))
    assert actual == expected, (
        f"{doc_path} reports {label}={actual}, expected {expected} from registry"
    )


def test_every_registered_rule_appears_in_doc() -> None:
    missing = _registered_rule_ids() - _documented_rule_ids()
    assert not missing, (
        "Rules registered but missing from docs/rule-coverage.md: "
        + ", ".join(sorted(missing))
    )


def test_doc_does_not_reference_unknown_rules() -> None:
    unknown = _documented_rule_ids() - _registered_rule_ids()
    assert not unknown, (
        "docs/rule-coverage.md references rules that are not registered: "
        + ", ".join(sorted(unknown))
    )


def test_total_rules_summary_matches_registry() -> None:
    _ensure_all_rules_loaded()
    expected_total = len(registry.list_rules())
    match = re.search(r"Total rules: \*\*(\d+)\*\*", _document_text())
    assert match is not None, "Could not find 'Total rules: **N**' in docs/rule-coverage.md"
    assert int(match.group(1)) == expected_total


def test_summary_severity_counts_match_registry() -> None:
    _ensure_all_rules_loaded()
    rules = registry.list_rules()
    counts = Counter(meta.severity for meta in rules)
    match = re.search(
        r"\|\s*Severity\s*\|\s*high\s*\((\d+)\),\s*medium\s*\((\d+)\),\s*low\s*\((\d+)\),\s*info\s*\((\d+)\)\s*\|",
        _document_text(),
    )
    assert match is not None, "Could not find Severity summary row in docs/rule-coverage.md"
    assert tuple(int(group) for group in match.groups()) == (
        counts["high"],
        counts["medium"],
        counts["low"],
        counts["info"],
    )


def test_per_group_counts_match_registry() -> None:
    _ensure_all_rules_loaded()
    rules = registry.list_rules()

    counts_by_group: dict[str, int] = Counter()
    for meta in rules:
        if meta.category == "universal":
            counts_by_group["Universal Rules"] += 1
        elif meta.category == "external":
            counts_by_group["External (Probe-based)"] += 1
        elif meta.category == "local":
            label = {
                "nginx": "Nginx (Local)",
                "apache": "Apache (Local)",
                "lighttpd": "Lighttpd (Local)",
                "iis": "IIS (Local)",
            }.get(meta.server_type or "", None)
            assert label is not None, f"Unmapped local server_type: {meta.server_type}"
            counts_by_group[label] += 1
        else:
            raise AssertionError(f"Unknown category: {meta.category}")

    text = _document_text()
    for heading, expected in counts_by_group.items():
        # Match `### Heading` followed by `Count: N` on a later line.
        section_match = re.search(
            rf"### {re.escape(heading)}\s*\n+Count:\s*(\d+)",
            text,
        )
        assert section_match is not None, (
            f"Could not find 'Count: N' line under '### {heading}' heading"
        )
        actual = int(section_match.group(1))
        assert actual == expected, (
            f"docs/rule-coverage.md '{heading}' reports {actual} rules but "
            f"registry has {expected}"
        )


def test_repeated_document_counters_match_registry() -> None:
    counts = _registry_counter_values()
    targets = {
        _REPO_ROOT / "README.md": {
            "total": r"The catalog currently contains\s+(\d+)\s+rules",
            "nginx": r"\|\s*Local\s+[^|]*Nginx\s*\|\s*(\d+)\s*\|",
            "apache": r"\|\s*Local\s+[^|]*Apache\s*\|\s*(\d+)\s*\|",
            "lighttpd": r"\|\s*Local\s+[^|]*Lighttpd\s*\|\s*(\d+)\s*\|",
            "iis": r"\|\s*Local\s+[^|]*IIS\s*\|\s*(\d+)\s*\|",
            "universal": r"\|\s*Universal \(local\)\s*\|\s*(\d+)\s*\|",
            "external": r"\|\s*External\s*\|\s*(\d+)\s*\|",
        },
        _REPO_ROOT / "docs" / "architecture.md": {
            "total": r"Current catalog:\s+(\d+)\s+rules total",
            "nginx": r"\|\s*Local\s+[^|]*Nginx\s*\|\s*(\d+)\s*\|",
            "apache": r"\|\s*Local\s+[^|]*Apache\s*\|\s*(\d+)\s*\|",
            "lighttpd": r"\|\s*Local\s+[^|]*Lighttpd\s*\|\s*(\d+)\s*\|",
            "iis": r"\|\s*Local\s+[^|]*IIS\s*\|\s*(\d+)\s*\|",
            "universal": r"\|\s*Universal \(local\)\s*\|\s*(\d+)\s*\|",
            "external": r"\|\s*External\s*\|\s*(\d+)\s*\|",
        },
        _REPO_ROOT / "docs" / "standards-roadmap.md": {
            "total": r"current project inventory is\s+(\d+)\s+rules",
            "nginx": r"-\s+Nginx local:\s+(\d+)",
            "apache": r"-\s+Apache local:\s+(\d+)",
            "lighttpd": r"-\s+Lighttpd local:\s+(\d+)",
            "iis": r"-\s+IIS local:\s+(\d+)",
            "universal": r"-\s+Universal:\s+(\d+)",
            "external": r"-\s+External probes:\s+(\d+)",
        },
        _DOC_PATH: {
            "total": r"Total rules:\s+\*\*(\d+)\*\*",
            "local": r"Category\s*\|\s*local \((\d+)\)",
            "universal": r"Category\s*\|.*universal \((\d+)\)",
            "external": r"Category\s*\|.*external \((\d+)\)",
        },
        _REPO_ROOT / "docs" / "benchmarks-covering.md": {
            "total": r"existing\s+(\d+)-rule inventory",
            "nginx": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bNginx\s+(\d+)",
            "apache": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bApache\s+(\d+)",
            "lighttpd": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bLighttpd\s+(\d+)",
            "iis": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bIIS\s+(\d+)",
            "external": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bExternal\s+(\d+)",
            "universal": r"обновлён до\s+\d+\s+правил\s+\([^)]*\bUniversal\s+(\d+)",
        },
    }

    for doc_path, patterns in targets.items():
        for label, pattern in patterns.items():
            _assert_doc_counter(
                doc_path=doc_path,
                label=label,
                pattern=pattern,
                expected=counts[label],
            )


def test_removed_topic_grouped_mapping_blocks_are_gone() -> None:
    text = _document_text()
    for heading in (
        "## OWASP Cheat Sheet Series companions",
        "## PCI DSS v4.0.1 mapping",
        "## NIST SP 800-52 Rev. 2 mapping",
        "## ФСТЭК «Меры защиты информации в ГИС» mapping",
        "## Lighttpd vendor reference mapping",
        "## ISO/IEC 27002:2022 / ГОСТ Р ИСО/МЭК 27002-2021 mapping",
        "### MITRE ATT&CK Enterprise v15",
        "### ФСТЭК БДУ — Банк данных угроз",
    ):
        assert heading not in text


def test_inventory_tables_include_other_standards_column() -> None:
    headers = re.findall(r"^\| Rule ID \| Severity \| Input \| Tags \| .* \|$", _document_text(), re.MULTILINE)
    assert headers
    assert all("Standards (other)" in header for header in headers)


def test_standards_roadmap_records_mapping_health_snapshot() -> None:
    text = (_REPO_ROOT / "docs" / "standards-roadmap.md").read_text(encoding="utf-8")
    section = _markdown_section(text, "## Mapping Health Check (2026-06-05)")
    assert "`v0.1.0`" in section
    assert "`docs/rule-coverage.md`" in section
    assert "`docs/benchmarks-covering.md`" in section
    assert "`tests/test_rule_coverage_doc.py`" in section
    assert "`STD-GAP-015`" in section
    assert "documentation-only" in section.lower()


def test_roadmap_is_source_coverage_oriented() -> None:
    text = (_REPO_ROOT / "docs" / "roadmap.md").read_text(encoding="utf-8")
    section = _markdown_section(text, "## Source Coverage Direction")

    for source in (
        "OWASP Top 10:2025",
        "OWASP ASVS v5.0.0",
        "CIS NGINX Benchmark v3.0.0",
        "CIS Apache HTTP Server 2.4 Benchmark v2.3.0",
        "CIS Microsoft IIS 10 Benchmark v1.2.1",
        "NIST SP 800-52 Rev. 2",
        "PCI DSS v4.0.1",
        "ISO/IEC 27002:2022",
        "FSTEC",
        "OWASP Cheat Sheet Series",
        "Lighttpd vendor references",
        "HTTP Archive Web Almanac 2025",
        "CISA Proactive Threat Hunt",
        "CVE-2025-59775",
    ):
        assert source in section

    assert "source-first" in section.lower()
    assert "scanner signal" in section.lower()


def test_tls_source_coverage_explanation_is_recorded() -> None:
    text = (_REPO_ROOT / "docs" / "benchmarks-covering.md").read_text(
        encoding="utf-8",
    )
    section = _markdown_section(text, "## TLS Source Coverage Explanations")

    for source in (
        "NIST SP 800-52 Rev. 2",
        "PCI DSS v4.0.1",
        "ISO/IEC 27002:2022",
        "FSTEC",
    ):
        assert source in section

    for rule_id in (
        "universal.weak_tls_protocol",
        "external.tls_server_cipher_preference_not_observed",
        "external.ocsp_stapling_not_observed",
        "iis.schannel_tls12_not_enabled",
    ):
        assert f"`{rule_id}`" in section

    assert "scanner signal" in section.lower()
    assert "partial" in section.lower()
    assert "bounded" in section.lower()
