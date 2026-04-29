from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.models import Finding, SourceLocation

PER_IP_KEYS = {"$binary_remote_addr", "$remote_addr"}

_RATE_RE = re.compile(r"^(?P<value>[0-9]+)r/(?P<unit>s|m)$", re.IGNORECASE)


def iter_directives(config_ast: ConfigAst, directive_name: str) -> list[DirectiveNode]:
    return [
        node
        for node in iter_nodes(config_ast.nodes)
        if isinstance(node, DirectiveNode) and node.name == directive_name
    ]


def parse_zone_name(value: str) -> str | None:
    if not value.startswith("zone="):
        return None
    zone_name = value.removeprefix("zone=").split(":", 1)[0]
    return zone_name or None


def find_zone_name(args: list[str]) -> str | None:
    for arg in args:
        zone_name = parse_zone_name(arg)
        if zone_name is not None:
            return zone_name
    return None


def defined_zone_names(config_ast: ConfigAst, directive_name: str) -> set[str]:
    zones: set[str] = set()
    for directive in iter_directives(config_ast, directive_name):
        zone_name = find_zone_name(directive.args)
        if zone_name is not None:
            zones.add(zone_name)
    return zones


def is_per_ip_key(args: list[str]) -> bool:
    return bool(args) and args[0] in PER_IP_KEYS


def parse_positive_integer(value: str) -> int | None:
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed <= 0:
        return None
    return parsed


def is_positive_rate(value: str) -> bool:
    match = _RATE_RE.fullmatch(value)
    if match is None:
        return False
    return int(match.group("value"), 10) > 0


def make_finding(
    *,
    rule_id: str,
    title: str,
    description: str,
    recommendation: str,
    directive: DirectiveNode,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity="low",
        description=description,
        recommendation=recommendation,
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=directive.source.file_path,
            line=directive.source.line,
        ),
    )


__all__ = [
    "PER_IP_KEYS",
    "defined_zone_names",
    "find_zone_name",
    "is_per_ip_key",
    "is_positive_rate",
    "iter_directives",
    "make_finding",
    "parse_positive_integer",
    "parse_zone_name",
]
