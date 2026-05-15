"""Internal helpers for the modsecurity inventory utils rule family.

Location: ``src/webconf_audit/local/apache/rules/_modsecurity_inventory_utils.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from webconf_audit.local.apache.parser import ApacheBlockNode
from webconf_audit.local.apache.parser import ApacheDirectiveNode
from webconf_audit.local.apache.rules._policy_semantics_utils import (
    iter_enabled_scoped_directives,
    module_explicitly_loaded,
)

_INCLUDE_DIRECTIVES = frozenset({"include", "includeoptional"})
_MODSECURITY_DIRECTIVE_NAMES = frozenset(
    {
        "secaction",
        "secauditengine",
        "secauditlog",
        "secrule",
        "secruleengine",
        "secrequestbodyaccess",
        "secresponsebodyaccess",
    }
)
_MODSECURITY_INCLUDE_MARKERS = ("modsecurity", "security2", "mod_security")
_MODSECURITY_LOADMODULE_NAMES = frozenset({"security2_module"})
_MODSECURITY_LOADMODULE_PATH_MARKERS = ("mod_security2",)
_CRS_INCLUDE_MARKERS = (
    "owasp-crs",
    "owasp_crs",
    "coreruleset",
    "crs-setup.conf",
    "/crs/",
    "\\crs\\",
)


@dataclass(frozen=True, slots=True)
class InventorySource:
    file_path: str
    line: int | None


def find_modsecurity_inventory_source(
    nodes,
    modules: frozenset[str],
) -> InventorySource | None:
    for directive in iter_enabled_scoped_directives(nodes, modules):
        if _is_modsecurity_loadmodule(directive):
            return _inventory_source_from_directive(directive)
        if directive.name.lower() in _MODSECURITY_DIRECTIVE_NAMES:
            return _inventory_source_from_directive(directive)
        if _directive_args_contain_marker(
            directive,
            markers=_MODSECURITY_INCLUDE_MARKERS,
        ):
            return _inventory_source_from_directive(directive)
    return _find_raw_inventory_source(nodes, kind="modsecurity")


def has_modsecurity_inventory(
    nodes,
    modules: frozenset[str],
) -> bool:
    if module_explicitly_loaded(modules, "security2_module"):
        return True
    return find_modsecurity_inventory_source(nodes, modules) is not None


def find_crs_inventory_source(
    nodes,
    modules: frozenset[str],
) -> InventorySource | None:
    for directive in iter_enabled_scoped_directives(nodes, modules):
        if not _directive_args_contain_marker(
            directive,
            markers=_CRS_INCLUDE_MARKERS,
        ):
            continue
        return _inventory_source_from_directive(directive)
    return _find_raw_inventory_source(nodes, kind="crs")


def has_crs_inventory(
    nodes,
    modules: frozenset[str],
) -> bool:
    return find_crs_inventory_source(nodes, modules) is not None


def _is_modsecurity_loadmodule(
    directive: ApacheDirectiveNode,
) -> bool:
    if directive.name.lower() != "loadmodule":
        return False
    module_name, module_path = _loadmodule_parts(directive.args)
    return _is_modsecurity_loadmodule_target(
        module_name=module_name,
        module_path=module_path,
    )


def _directive_args_contain_marker(
    directive: ApacheDirectiveNode,
    *,
    markers: tuple[str, ...],
) -> bool:
    if directive.name.lower() not in _INCLUDE_DIRECTIVES:
        return False
    rendered_args = " ".join(arg.lower() for arg in directive.args)
    return any(marker in rendered_args for marker in markers)


def _inventory_source_from_directive(
    directive: ApacheDirectiveNode,
) -> InventorySource:
    return InventorySource(
        file_path=directive.source.file_path,
        line=directive.source.line,
    )


def _find_raw_inventory_source(
    nodes,
    *,
    kind: str,
):
    matcher = (
        _raw_line_has_modsecurity_inventory
        if kind == "modsecurity"
        else _raw_line_has_crs_inventory
    )
    for file_path in _source_file_paths(nodes):
        try:
            lines = Path(file_path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue

        for line_number, raw_line in enumerate(lines, start=1):
            if matcher(raw_line):
                return InventorySource(file_path=file_path, line=line_number)
    return None


def _source_file_paths(nodes) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()

    def walk(current_nodes) -> None:
        for node in current_nodes:
            source = getattr(node, "source", None)
            file_path = getattr(source, "file_path", None)
            if file_path and file_path not in seen:
                seen.add(file_path)
                paths.append(file_path)

            if isinstance(node, ApacheBlockNode):
                walk(node.children)

    walk(nodes)
    return paths


def _raw_line_has_modsecurity_inventory(raw_line: str) -> bool:
    directive_name, rendered_args = _directive_name_and_args(raw_line)
    if directive_name is None:
        return False

    if directive_name == "loadmodule":
        module_name, module_path = _loadmodule_parts(rendered_args.split())
        if _is_modsecurity_loadmodule_target(
            module_name=module_name,
            module_path=module_path,
        ):
            return True
    if directive_name in _MODSECURITY_DIRECTIVE_NAMES:
        return True
    if directive_name in _INCLUDE_DIRECTIVES:
        return any(marker in rendered_args for marker in _MODSECURITY_INCLUDE_MARKERS)
    return False


def _raw_line_has_crs_inventory(raw_line: str) -> bool:
    directive_name, rendered_args = _directive_name_and_args(raw_line)
    if directive_name is None or directive_name not in _INCLUDE_DIRECTIVES:
        return False
    return any(marker in rendered_args for marker in _CRS_INCLUDE_MARKERS)


def _directive_name_and_args(raw_line: str) -> tuple[str | None, str]:
    line = raw_line.split("#", 1)[0].strip()
    if not line:
        return None, ""

    parts = line.split(None, 1)
    directive_name = parts[0].lower()
    rendered_args = parts[1].lower() if len(parts) > 1 else ""
    return directive_name, rendered_args


def _loadmodule_parts(args: list[str]) -> tuple[str, str]:
    if not args:
        return "", ""
    module_name = args[0].strip().strip('"').strip("'").lower()
    module_path = " ".join(
        arg.strip().strip('"').strip("'").lower()
        for arg in args[1:]
    )
    return module_name, module_path


def _is_modsecurity_loadmodule_target(
    *,
    module_name: str,
    module_path: str,
) -> bool:
    return (
        module_name in _MODSECURITY_LOADMODULE_NAMES
        or any(marker in module_path for marker in _MODSECURITY_LOADMODULE_PATH_MARKERS)
    )


__all__ = [
    "InventorySource",
    "find_crs_inventory_source",
    "find_modsecurity_inventory_source",
    "has_crs_inventory",
    "has_modsecurity_inventory",
]
