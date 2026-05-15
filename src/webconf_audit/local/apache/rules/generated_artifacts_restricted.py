"""apache.generated_artifacts_not_restricted -- Generated artifacts not restricted."""

from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    denied_pattern_text,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.local.apache.rules.server_directive_utils import virtualhost_label
from webconf_audit.local.sensitive_artifact_policy import (
    GENERATED_ARTIFACT_LABELS,
    missing_marker_labels,
)
from webconf_audit.models import Finding, SourceLocation
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
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            _build_finding(config_ast, missing, virtualhost_context=context)
            for context in virtualhosts
            if not is_redirect_only_virtualhost(context)
            for missing in (_missing_artifacts(config_ast, context),)
            if missing
        ]

    missing = _missing_artifacts(config_ast)
    if not missing:
        return []

    return [_build_finding(config_ast, missing)]


def _missing_artifacts(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> list[str]:
    covered_text = denied_pattern_text(
        config_ast,
        block_names=_RESTRICTION_BLOCKS,
        virtualhost_context=virtualhost_context,
    )
    return missing_marker_labels(covered_text, GENERATED_ARTIFACT_LABELS)


def _build_finding(
    config_ast: ApacheConfigAst,
    missing: list[str],
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> Finding:
    metadata = {}
    if virtualhost_context is not None:
        metadata = {
            "scope_name": virtualhost_label(virtualhost_context),
            "missing_extensions": list(missing),
        }

    return Finding(
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
        location=_finding_location(
            config_ast,
            virtualhost_context=virtualhost_context,
        ),
        metadata=metadata,
    )


def _finding_location(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> SourceLocation | None:
    if virtualhost_context is not None:
        source = virtualhost_context.node.source
        return SourceLocation(
            mode="local",
            kind="file",
            file_path=source.file_path,
            line=source.line,
        )

    return default_location(config_ast)


__all__ = ["find_generated_artifacts_restricted"]
