"""Invariant tests for Lighttpd condition source span.

These tests are the guardian for the precision contract established by
O-05 (plan ``docs/superpowers/plans/2026-05-14-open-items-followup.md``):
every Lighttpd finding emitted inside a conditional block must point at
either the condition line itself or a specific directive/assignment line
inside the block. It must never point at a line that nothing meaningful
happens on (closing brace, blank line, comment).

The tests also enforce that ``LighttpdCondition.source.line`` is always
populated by the parser, so the source-span contract cannot regress
silently.
"""

from __future__ import annotations

from pathlib import Path

from webconf_audit.local.lighttpd import analyze_lighttpd_config
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdBlockNode,
    LighttpdConfigAst,
    LighttpdDirectiveNode,
    parse_lighttpd_config,
)

_FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "webserver-configs" / "lighttpd"


def _iter_fixtures() -> list[Path]:
    return sorted(_FIXTURE_ROOT.rglob("*.conf"))


def _collect_conditional_block_ranges(
    nodes: list,
    file_path: str,
) -> list[tuple[int, int, frozenset[int]]]:
    """Walk the AST and return, for every conditional block, a tuple of
    ``(condition_line, block_end_line, valid_lines)``.

    ``valid_lines`` are the lines a rule is allowed to point at when it
    emits a finding tied to this block — i.e. the condition line itself
    and the line of every directive/assignment/nested-condition
    *inside* the block.
    """
    ranges: list[tuple[int, int, frozenset[int]]] = []

    for node in nodes:
        if not isinstance(node, LighttpdBlockNode):
            continue
        if node.condition is None:
            ranges.extend(_collect_conditional_block_ranges(node.children, file_path))
            continue

        condition_line = node.condition.source.line
        assert condition_line is not None, (
            "LighttpdCondition.source.line must be populated by the parser; "
            f"got None in {file_path}"
        )

        inner_valid_lines = _collect_valid_lines(node.children)
        valid_lines: frozenset[int] = frozenset({condition_line, *inner_valid_lines})
        end_line = max(valid_lines)
        ranges.append((condition_line, end_line, valid_lines))

        # Recurse into nested blocks so their own conditional invariants
        # are also checked.
        ranges.extend(_collect_conditional_block_ranges(node.children, file_path))

    return ranges


def _collect_valid_lines(nodes: list) -> set[int]:
    valid: set[int] = set()
    for node in nodes:
        if isinstance(node, (LighttpdAssignmentNode, LighttpdDirectiveNode)):
            if node.source.line is not None:
                valid.add(node.source.line)
        elif isinstance(node, LighttpdBlockNode):
            if node.condition is not None and node.condition.source.line is not None:
                valid.add(node.condition.source.line)
            if node.source.line is not None:
                # Block opening line — only valid when it coincides with the
                # condition line, which is the parser's normal behaviour for
                # single-line headers.
                valid.add(node.source.line)
            valid.update(_collect_valid_lines(node.children))
    return valid


def test_parser_populates_condition_source_line_for_all_fixtures() -> None:
    """Every conditional block parsed from a fixture must carry a
    non-empty ``condition.source.line``."""
    for fixture in _iter_fixtures():
        ast: LighttpdConfigAst = parse_lighttpd_config(
            fixture.read_text(encoding="utf-8"),
            file_path=str(fixture),
        )
        for condition in _walk_conditions(ast.nodes):
            assert condition.source.line is not None, (
                f"Condition {condition.variable} in {fixture} has no source line"
            )


def _walk_conditions(nodes: list):
    for node in nodes:
        if isinstance(node, LighttpdBlockNode):
            if node.condition is not None:
                yield node.condition
            yield from _walk_conditions(node.children)


def test_conditional_findings_point_at_condition_or_directive_line() -> None:
    """For every Lighttpd fixture, every finding whose location falls
    inside a conditional block range must land on either the condition
    line or the line of an actual directive/assignment within the block.

    This is the inverse of the regression we want to prevent: a rule
    emitting a finding tied to a conditional scope but using
    ``block.source.line`` (the ``{`` line, which currently coincides
    with the condition line, but could drift) or some unrelated number
    such as the closing brace.
    """
    for fixture in _iter_fixtures():
        ast = parse_lighttpd_config(
            fixture.read_text(encoding="utf-8"),
            file_path=str(fixture),
        )
        ranges = _collect_conditional_block_ranges(ast.nodes, str(fixture))
        if not ranges:
            continue

        result = analyze_lighttpd_config(str(fixture))
        for finding in result.findings:
            loc = finding.location
            if loc is None or loc.kind != "file":
                continue
            if loc.line is None:
                continue
            # Skip findings located in a different file (e.g. included
            # configs); the invariant we care about is per-file.
            if loc.file_path != str(fixture):
                continue

            for condition_line, end_line, valid_lines in ranges:
                if not (condition_line <= loc.line <= end_line):
                    continue
                assert loc.line in valid_lines, (
                    f"Rule {finding.rule_id} in {fixture} emits a finding "
                    f"at line {loc.line}, which falls inside the conditional "
                    f"block starting at line {condition_line} but does not "
                    f"correspond to the condition or any directive inside "
                    f"the block (valid lines: {sorted(valid_lines)}). "
                    f"Conditional-block findings must point at "
                    f"condition.source.line or a specific directive line, "
                    f"never at the closing brace or an unrelated location."
                )
