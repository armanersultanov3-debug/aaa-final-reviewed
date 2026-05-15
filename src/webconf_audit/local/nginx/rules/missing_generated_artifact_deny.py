"""nginx.missing_generated_artifact_deny -- Generated artifacts not denied."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import (
    BlockNode,
    ConfigAst,
    find_child_directives,
    iter_nodes,
)
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.sensitive_artifact_policy import (
    GENERATED_ARTIFACT_LABELS,
    missing_marker_labels,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_generated_artifact_deny"


@rule(
    rule_id=RULE_ID,
    title="Generated artifacts not denied",
    severity="low",
    description=(
        "Server block does not deny common generated or dependency metadata "
        "artifacts such as Thumbs.db, composer manifests, and package-lock.json."
    ),
    recommendation=(
        "Add a deny/403 location for common generated artifacts. Existing "
        "hidden-file deny locations cover dotfile artifacts such as .DS_Store, "
        ".npmrc, .yarnrc, .idea, and .vscode."
    ),
    category="local",
    server_type="nginx",
    order=217,
)
def find_missing_generated_artifact_deny(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    for node in iter_nodes(config_ast.nodes):
        if not isinstance(node, BlockNode) or node.name != "server":
            continue
        if skips_content_response_checks(node):
            continue

        missing = _missing_generated_artifact_labels(node)
        if not missing:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="Generated artifacts not denied",
                severity="low",
                description=(
                    "Server block does not deny these generated artifacts: "
                    + ", ".join(missing)
                ),
                recommendation=(
                    "Add regex locations with 'deny all;' or 'return 403;' "
                    "for the missing generated artifacts."
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


def _missing_generated_artifact_labels(server_block: BlockNode) -> list[str]:
    covered_text_parts: list[str] = []
    if _server_has_hidden_files_deny(server_block):
        covered_text_parts.extend(
            marker
            for label, markers in GENERATED_ARTIFACT_LABELS.items()
            if label.startswith(".")
            for marker in markers
        )

    for location in _blocking_locations(server_block):
        covered_text_parts.append(" ".join(location.args[1:]))

    return missing_marker_labels(
        " ".join(covered_text_parts),
        GENERATED_ARTIFACT_LABELS,
    )


def _blocking_locations(server_block: BlockNode) -> list[BlockNode]:
    return [
        node
        for node in server_block.children
        if isinstance(node, BlockNode)
        and node.name == "location"
        and _is_regex_location(node)
        and _location_blocks_artifacts(node)
        and _location_mentions_generated_artifact(node)
    ]


def _server_has_hidden_files_deny(server_block: BlockNode) -> bool:
    return any(
        isinstance(node, BlockNode)
        and node.name == "location"
        and _is_regex_location(node)
        and _looks_like_hidden_files_location(node)
        and _location_blocks_artifacts(node)
        for node in server_block.children
    )


def _is_regex_location(location_block: BlockNode) -> bool:
    return bool(location_block.args) and location_block.args[0] in {"~", "~*"}


def _looks_like_hidden_files_location(location_block: BlockNode) -> bool:
    pattern = " ".join(location_block.args[1:])
    return any(marker in pattern for marker in ("/\\.", "^/\\.", "/.", "^/."))


def _location_mentions_generated_artifact(location_block: BlockNode) -> bool:
    pattern = " ".join(location_block.args[1:]).lower()
    return any(
        marker.lower() in pattern
        for markers in GENERATED_ARTIFACT_LABELS.values()
        for marker in markers
    )


def _location_blocks_artifacts(location_block: BlockNode) -> bool:
    return any(
        directive.args == ["all"] for directive in find_child_directives(location_block, "deny")
    ) or any(
        directive.args and directive.args[0] == "403"
        for directive in find_child_directives(location_block, "return")
    )


__all__ = ["find_missing_generated_artifact_deny"]
