from __future__ import annotations

from webconf_audit.local.apache.effective import (
    ApacheVirtualHostContext,
    extract_virtualhost_contexts,
)
from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    has_denied_pattern,
)
from webconf_audit.local.apache.rules._redirect_scope_utils import (
    is_redirect_only_virtualhost,
)
from webconf_audit.local.apache.rules.server_directive_utils import virtualhost_label
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ht_files_not_restricted"
_HT_FILE_MARKERS = ("\\.ht", ".ht")
_RESTRICTION_BLOCKS = frozenset({"files", "filesmatch"})


@rule(
    rule_id=RULE_ID,
    title=".ht* files not restricted",
    severity="medium",
    description=(
        "Apache config does not contain a Files/FilesMatch denial for .ht* "
        "metadata files such as .htaccess and .htpasswd."
    ),
    recommendation=(
        "Add a '<FilesMatch \"^\\.ht\"> Require all denied </FilesMatch>' "
        "or equivalent rule."
    ),
    category="local",
    server_type="apache",
    order=342,
)
def find_ht_files_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    virtualhosts = extract_virtualhost_contexts(config_ast)
    if virtualhosts:
        return [
            _build_finding(config_ast, virtualhost_context=context)
            for context in virtualhosts
            if not is_redirect_only_virtualhost(context)
            and not _has_ht_file_denial(config_ast, context)
        ]

    if _has_ht_file_denial(config_ast):
        return []

    return [_build_finding(config_ast)]


def _has_ht_file_denial(
    config_ast: ApacheConfigAst,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> bool:
    return has_denied_pattern(
        config_ast,
        markers=_HT_FILE_MARKERS,
        block_names=_RESTRICTION_BLOCKS,
        virtualhost_context=virtualhost_context,
    )


def _build_finding(
    config_ast: ApacheConfigAst,
    *,
    virtualhost_context: ApacheVirtualHostContext | None = None,
) -> Finding:
    metadata = {}
    if virtualhost_context is not None:
        metadata = {
            "scope_name": virtualhost_label(virtualhost_context),
            "missing_extensions": [".ht*"],
        }

    return Finding(
        rule_id=RULE_ID,
        title=".ht* files not restricted",
        severity="medium",
        description=(
            "Apache config does not deny direct requests for .ht* files. "
            "These files often contain override policy or credentials."
        ),
        recommendation=(
            "Deny .ht* files with a FilesMatch rule and 'Require all denied'."
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


__all__ = ["find_ht_files_restricted"]
