from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterator

from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import (
    LighttpdAssignmentNode,
    LighttpdConfigAst,
    LighttpdSourceSpan,
)
from webconf_audit.local.lighttpd.rules.rule_utils import iter_all_nodes, unquote


@dataclass(frozen=True, slots=True)
class LighttpdHeaderValue:
    name: str
    value: str
    source: LighttpdSourceSpan


def iter_header_values(
    config_ast: LighttpdConfigAst,
    *,
    header_name: str,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> Iterator[LighttpdHeaderValue]:
    expected_name = header_name.lower()
    if merged_directives is not None and request_context is not None:
        yield from _values_from_directives(merged_directives, expected_name)
        return

    if effective_config is not None:
        yield from _values_from_directives(
            effective_config.global_directives,
            expected_name,
        )
        for scope in effective_config.conditional_scopes:
            yield from _values_from_directives(scope.directives, expected_name)
        return

    for node in iter_all_nodes(config_ast):
        if not isinstance(node, LighttpdAssignmentNode):
            continue
        if node.name != "setenv.add-response-header":
            continue
        yield from _values_from_tuple(node.value, node.source, expected_name)


def _values_from_directives(
    directives: dict[str, LighttpdEffectiveDirective],
    expected_name: str,
) -> Iterator[LighttpdHeaderValue]:
    directive = directives.get("setenv.add-response-header")
    if directive is None:
        return
    yield from _values_from_tuple(directive.value, directive.source, expected_name)


def _values_from_tuple(
    raw: str,
    source: LighttpdSourceSpan,
    expected_name: str,
) -> Iterator[LighttpdHeaderValue]:
    stripped = unquote(raw).strip()
    if stripped.startswith("(") and stripped.endswith(")"):
        stripped = stripped[1:-1]

    for pair in _split_tuple_items(stripped):
        key, separator, value = pair.partition("=>")
        if not separator:
            continue
        name = unquote(key.strip()).lower()
        if name != expected_name:
            continue
        yield LighttpdHeaderValue(name=name, value=unquote(value.strip()), source=source)


def _split_tuple_items(raw: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False

    for char in raw:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if quote is not None:
            current.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            current.append(char)
            quote = char
            continue
        if char == ",":
            items.append("".join(current))
            current = []
            continue
        current.append(char)

    if current or raw.endswith(","):
        items.append("".join(current))
    return items


__all__ = ["LighttpdHeaderValue", "iter_header_values"]
