from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    denied_extensions,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.local.apache.rules.server_directive_utils import virtualhost_label
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.vcs_metadata_not_restricted"
_VCS_EXTENSIONS = ("git", "svn")
_RESTRICTION_BLOCKS = frozenset({"directorymatch", "filesmatch", "locationmatch"})


@rule(
    rule_id=RULE_ID,
    title="Version-control metadata not restricted",
    severity="medium",
    description=(
        "Apache config does not contain a denial for exposed .git or .svn "
        "metadata paths."
    ),
    recommendation=(
        "Add DirectoryMatch/FilesMatch restrictions for .git and .svn paths "
        "with 'Require all denied'."
    ),
    category="local",
    server_type="apache",
    order=344,
)
def find_vcs_metadata_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            _build_finding(
                config_ast,
                missing_extensions,
                virtualhost_context=context,
            )
            for context in virtualhosts
            if not is_redirect_only_virtualhost(context)
            for missing_extensions in (_missing_extensions(config_ast, context),)
            if missing_extensions
        ]

    missing_extensions = _missing_extensions(config_ast)
    if not missing_extensions:
        return []

    return [_build_finding(config_ast, missing_extensions)]


def _missing_extensions(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> tuple[str, ...]:
    covered = denied_extensions(
        config_ast,
        extensions=_VCS_EXTENSIONS,
        block_names=_RESTRICTION_BLOCKS,
        virtualhost_context=virtualhost_context,
    )
    return tuple(extension for extension in _VCS_EXTENSIONS if extension not in covered)


def _build_finding(
    config_ast: ApacheConfigAst,
    missing_extensions: tuple[str, ...],
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> Finding:
    metadata = {}
    if virtualhost_context is not None:
        metadata = {
            "scope_name": virtualhost_label(virtualhost_context),
            "missing_extensions": list(missing_extensions),
        }

    return Finding(
        rule_id=RULE_ID,
        title="Version-control metadata not restricted",
        severity="medium",
        description=(
            "Apache config does not deny direct access to .git or .svn "
            "metadata paths."
        ),
        recommendation=(
            "Deny .git and .svn paths with a DirectoryMatch or FilesMatch "
            "rule and 'Require all denied'."
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


__all__ = ["find_vcs_metadata_restricted"]
