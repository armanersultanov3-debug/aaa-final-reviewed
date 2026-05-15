"""Internal helpers for the variable taint utils rule family.

Location: ``src/webconf_audit/local/nginx/rules/_variable_taint_utils.py``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import re

from webconf_audit.local.nginx.parser.ast import AstNode, BlockNode, ConfigAst, DirectiveNode

_VARIABLE_RE = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*|\d+)")
_USER_CONTROLLED_PREFIXES = ("$arg_", "$http_", "$cookie_")
_USER_CONTROLLED_NAMES = frozenset(
    {
        "$args",
        "$query_string",
        "$request_body",
        "$request_filename",
        "$request_method",
        "$request_uri",
    }
)
_PROXY_PASS_HOST_USER_CONTROLLED_NAMES = frozenset({"$uri"})
_NON_USER_CONTROLLED_NAMES = frozenset({"$binary_remote_addr", "$realip_remote_addr"})


@dataclass(frozen=True)
class VariableDefinition:
    kind: str
    scope: BlockNode | None
    order: int
    line: int
    value: str | None = None
    input_var: str | None = None
    branch_values: tuple[str, ...] = ()


class TaintAnalyzer:
    def __init__(self, config_ast: ConfigAst) -> None:
        self._definitions_by_var: dict[str, list[VariableDefinition]] = defaultdict(list)
        self._definition_order = 0
        self._parent_by_block_id: dict[int, BlockNode | None] = {}
        self._scope_by_node_id: dict[int, BlockNode | None] = {}
        self._index_nodes(config_ast.nodes, parent_scope=None)

    def is_user_controlled(
        self,
        var_name: str,
        scope: BlockNode | None,
        *,
        in_proxy_pass_host: bool = False,
    ) -> bool:
        normalized_var = normalize_variable_name(var_name)
        return self._is_user_controlled(
            normalized_var,
            scope,
            in_proxy_pass_host=in_proxy_pass_host,
            visited=frozenset(),
        )

    def scope_for_node(self, node: AstNode) -> BlockNode | None:
        return self._scope_by_node_id.get(id(node))

    def value_contains_user_controlled(
        self,
        value: str,
        scope: BlockNode | None,
        *,
        in_proxy_pass_host: bool = False,
    ) -> bool:
        return self._value_contains_user_controlled(
            value,
            scope,
            in_proxy_pass_host=in_proxy_pass_host,
            visited=frozenset(),
        )

    def _next_definition_order(self) -> int:
        self._definition_order += 1
        return self._definition_order

    def _index_nodes(
        self,
        nodes: list[AstNode],
        *,
        parent_scope: BlockNode | None,
    ) -> None:
        for node in nodes:
            self._scope_by_node_id[id(node)] = parent_scope
            if isinstance(node, DirectiveNode):
                self._record_directive(node, scope=parent_scope)
                continue

            self._parent_by_block_id[id(node)] = parent_scope
            self._record_block(node, definition_scope=parent_scope)
            self._index_nodes(node.children, parent_scope=node)

    def _record_directive(
        self,
        directive: DirectiveNode,
        *,
        scope: BlockNode | None,
    ) -> None:
        if directive.name != "set" or len(directive.args) < 2:
            return
        target_var = normalize_variable_name(directive.args[0])
        self._definitions_by_var[target_var].append(
            VariableDefinition(
                kind="set",
                scope=scope,
                order=self._next_definition_order(),
                line=directive.source.line,
                value=" ".join(directive.args[1:]),
            )
        )

    def _record_block(
        self,
        block: BlockNode,
        *,
        definition_scope: BlockNode | None,
    ) -> None:
        if block.name == "map":
            self._record_map(block, scope=definition_scope)
            return
        if block.name == "geo" and block.args:
            self._record_non_user_controlled_output(block.args[0], scope=definition_scope, line=block.source.line)
            return
        if block.name == "split_clients" and len(block.args) >= 2:
            self._record_non_user_controlled_output(block.args[1], scope=definition_scope, line=block.source.line)

    def _record_map(self, block: BlockNode, *, scope: BlockNode | None) -> None:
        if len(block.args) < 2:
            return
        input_var = normalize_variable_name(block.args[0])
        output_var = normalize_variable_name(block.args[1])
        branch_values = tuple(
            " ".join(child.args[1:])
            for child in block.children
            if isinstance(child, DirectiveNode) and len(child.args) >= 2
        )
        self._definitions_by_var[output_var].append(
            VariableDefinition(
                kind="map",
                scope=scope,
                order=self._next_definition_order(),
                line=block.source.line,
                input_var=input_var,
                branch_values=branch_values,
            )
        )

    def _record_non_user_controlled_output(
        self,
        var_name: str,
        *,
        scope: BlockNode | None,
        line: int,
    ) -> None:
        normalized_var = normalize_variable_name(var_name)
        self._definitions_by_var[normalized_var].append(
            VariableDefinition(
                kind="non_user_controlled",
                scope=scope,
                order=self._next_definition_order(),
                line=line,
            )
        )

    def _is_user_controlled(
        self,
        var_name: str,
        scope: BlockNode | None,
        *,
        in_proxy_pass_host: bool,
        visited: frozenset[tuple[str, int | None, bool]],
    ) -> bool:
        if is_builtin_user_controlled(var_name, in_proxy_pass_host=in_proxy_pass_host):
            return True
        if var_name in _NON_USER_CONTROLLED_NAMES:
            return False

        visit_key = (var_name, id(scope) if scope is not None else None, in_proxy_pass_host)
        if visit_key in visited:
            return False

        definition = self._visible_definition(var_name, scope)
        if definition is None:
            return False
        if definition.kind == "non_user_controlled":
            return False

        next_visited = visited | {visit_key}
        definition_scope = definition.scope
        if definition.kind == "set" and definition.value is not None:
            return self._value_contains_user_controlled(
                definition.value,
                definition_scope,
                in_proxy_pass_host=in_proxy_pass_host,
                visited=next_visited,
            )
        if definition.kind == "map" and definition.input_var is not None:
            if self._is_user_controlled(
                definition.input_var,
                definition_scope,
                in_proxy_pass_host=in_proxy_pass_host,
                visited=next_visited,
            ):
                return True
            return any(
                self._value_contains_user_controlled(
                    branch_value,
                    definition_scope,
                    in_proxy_pass_host=in_proxy_pass_host,
                    visited=next_visited,
                )
                for branch_value in definition.branch_values
            )
        return False

    def _value_contains_user_controlled(
        self,
        value: str,
        scope: BlockNode | None,
        *,
        in_proxy_pass_host: bool,
        visited: frozenset[tuple[str, int | None, bool]],
    ) -> bool:
        return any(
            self._is_user_controlled(
                variable_name,
                scope,
                in_proxy_pass_host=in_proxy_pass_host,
                visited=visited,
            )
            for variable_name in extract_variables(value)
        )

    def _visible_definition(
        self,
        var_name: str,
        scope: BlockNode | None,
    ) -> VariableDefinition | None:
        definitions = self._definitions_by_var.get(var_name)
        if not definitions:
            return None
        for visible_scope in self._visible_scopes(scope):
            scoped_definitions = [
                definition
                for definition in definitions
                if definition.scope is visible_scope
            ]
            if scoped_definitions:
                return max(scoped_definitions, key=lambda definition: definition.order)
        return None

    def _visible_scopes(self, scope: BlockNode | None) -> list[BlockNode | None]:
        scopes: list[BlockNode | None] = []
        current = scope
        while current is not None:
            scopes.append(current)
            current = self._parent_by_block_id.get(id(current))
        scopes.append(None)
        return scopes


def extract_variables(value: str) -> tuple[str, ...]:
    seen: set[str] = set()
    variables: list[str] = []
    for match in _VARIABLE_RE.finditer(value):
        variable_name = match.group(0).lower()
        if variable_name in seen:
            continue
        seen.add(variable_name)
        variables.append(variable_name)
    return tuple(variables)


def is_builtin_user_controlled(
    var_name: str,
    *,
    in_proxy_pass_host: bool = False,
) -> bool:
    normalized_var = normalize_variable_name(var_name)
    if normalized_var in _USER_CONTROLLED_NAMES:
        return True
    if normalized_var.startswith(_USER_CONTROLLED_PREFIXES):
        return True
    if in_proxy_pass_host and normalized_var in _PROXY_PASS_HOST_USER_CONTROLLED_NAMES:
        return True
    return False


def normalize_variable_name(var_name: str) -> str:
    return var_name.strip().strip('"').strip("'").lower()


__all__ = [
    "TaintAnalyzer",
    "extract_variables",
    "is_builtin_user_controlled",
    "normalize_variable_name",
]
