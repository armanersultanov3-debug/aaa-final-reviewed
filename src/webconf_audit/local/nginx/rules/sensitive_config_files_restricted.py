from __future__ import annotations

import re

from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode, iter_nodes
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.sensitive_artifact_policy import CONFIG_DATA_EXTENSIONS
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "nginx.sensitive_config_files_not_restricted"
TARGET_EXTENSIONS = CONFIG_DATA_EXTENSIONS + ("orig", "save", "tmp")
TARGET_EXTENSION_LIST = ", ".join(f"'.{extension}'" for extension in TARGET_EXTENSIONS)


@rule(
    rule_id=RULE_ID,
    title="Sensitive config/data file extensions not restricted",
    severity="low",
    description=(
        "Nginx config does not deny a baseline set of sensitive config, data, and "
        "temporary file extensions."
    ),
    recommendation=(
        "Add a regex location for sensitive extensions such as "
        f"{TARGET_EXTENSION_LIST} and block it with 'deny all;' or 'return 403;'."
    ),
    category="local",
    server_type="nginx",
    standards=(
        cwe(538),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "13.4.7",
            coverage="partial",
            note="Sensitive config/data extension deny-list coverage only.",
        ),
    ),
    order=218,
)
def find_sensitive_config_files_restricted(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if skips_content_response_checks(node):
            continue
        if not _server_has_root_location(node):
            continue

        missing_extensions = _missing_extensions(node)
        if not missing_extensions:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Sensitive config/data file extensions not restricted",
                severity="low",
                description=(
                    "Nginx config does not deny these sensitive extensions: "
                    + ", ".join(f".{extension}" for extension in missing_extensions)
                ),
                recommendation=(
                    "Add a regex location for the missing extensions with "
                    "'deny all;' or 'return 403;'."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=node.source.file_path,
                    line=node.source.line,
                ),
            )
        )

    return findings


def _missing_extensions(server_block: BlockNode) -> tuple[str, ...]:
    covered_extensions = _covered_extensions(server_block)
    return tuple(
        extension
        for extension in TARGET_EXTENSIONS
        if extension not in covered_extensions
    )


def _covered_extensions(server_block: BlockNode) -> set[str]:
    covered: set[str] = set()

    for node in server_block.children:
        if not isinstance(node, BlockNode) or node.name != "location":
            continue
        if not _looks_like_extension_location(node):
            continue
        if not _location_blocks_sensitive_files(node):
            continue

        pattern = " ".join(node.args[1:]).lower()
        for extension in TARGET_EXTENSIONS:
            if _pattern_mentions_extension(pattern, extension):
                covered.add(extension)

    return covered


def _server_has_root_location(server_block: BlockNode) -> bool:
    return any(
        isinstance(node, BlockNode)
        and node.name == "location"
        and _is_root_location(node)
        for node in server_block.children
    )


def _looks_like_extension_location(location_block: BlockNode) -> bool:
    return bool(location_block.args) and location_block.args[0] in {"~", "~*"}


def _location_blocks_sensitive_files(location_block: BlockNode) -> bool:
    return any(
        isinstance(child, DirectiveNode) and child.name == "deny" and child.args == ["all"]
        for child in location_block.children
    ) or any(
        isinstance(child, DirectiveNode)
        and child.name == "return"
        and child.args
        and child.args[0] == "403"
        for child in location_block.children
    )


def _pattern_mentions_extension(pattern: str, extension: str) -> bool:
    candidate_path = f"/probe.{extension}"
    try:
        return re.search(pattern, candidate_path) is not None
    except re.error:
        return False


def _is_root_location(location_block: BlockNode) -> bool:
    return " ".join(location_block.args) in {"/", "^~ /"}


__all__ = ["find_sensitive_config_files_restricted"]
