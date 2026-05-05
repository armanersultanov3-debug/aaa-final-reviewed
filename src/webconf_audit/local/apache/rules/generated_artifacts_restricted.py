from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    block_denies_all,
    block_pattern_text,
    default_location,
    iter_blocks,
)
from webconf_audit.local.sensitive_artifact_policy import (
    GENERATED_ARTIFACT_LABELS,
    missing_marker_labels,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.generated_artifacts_not_restricted"
_RESTRICTION_BLOCKS = frozenset({"directory", "directorymatch", "files", "filesmatch"})


@rule(
    rule_id=RULE_ID,
    title="Generated artifacts not restricted",
    severity="low",
    description=(
        "Apache config does not deny a curated set of generated, dependency, "
        "and editor metadata artifacts."
    ),
    recommendation=(
        "Add FilesMatch/DirectoryMatch denials for artifacts such as .DS_Store, "
        "Thumbs.db, composer manifests, package-lock.json, .npmrc, .yarnrc, "
        ".idea, and .vscode."
    ),
    category="local",
    server_type="apache",
    order=344,
)
def find_generated_artifacts_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    covered_text = " ".join(
        block_pattern_text(block)
        for block in iter_blocks(config_ast.nodes, _RESTRICTION_BLOCKS)
        if block_denies_all(block)
    )
    missing = missing_marker_labels(covered_text, GENERATED_ARTIFACT_LABELS)
    if not missing:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Generated artifacts not restricted",
            severity="low",
            description=(
                "Apache config does not deny these generated artifacts: "
                + ", ".join(missing)
            ),
            recommendation=(
                "Add FilesMatch/DirectoryMatch rules for the missing artifacts "
                "with 'Require all denied'."
            ),
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_generated_artifacts_restricted"]
