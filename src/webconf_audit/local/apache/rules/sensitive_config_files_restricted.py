"""apache.sensitive_config_files_not_restricted -- Sensitive config/data file extensions not restricted."""

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
from webconf_audit.local.sensitive_artifact_policy import CONFIG_DATA_EXTENSIONS
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule
from webconf_audit.standards import asvs_5, cwe, owasp_top10_2021

RULE_ID = "apache.sensitive_config_files_not_restricted"
TARGET_EXTENSIONS = CONFIG_DATA_EXTENSIONS + ("orig", "save", "tmp")
_RESTRICTION_BLOCKS = frozenset({"files", "filesmatch"})


@rule(
    rule_id=RULE_ID,
    title="Sensitive config/data file extensions not restricted",
    severity="low",
    description=(
        "Apache config does not deny a baseline set of sensitive config, "
        "data, and temporary file extensions."
    ),
    recommendation=(
        "Add a FilesMatch denial for sensitive extensions such as .conf, "
        ".env, .ini, .log, .sql, .tmp, .orig, and .save."
    ),
    category="local",
    server_type="apache",
    standards=(
        cwe(538),
        owasp_top10_2021("A05:2021"),
        asvs_5(
            "13.4.7",
            coverage="partial",
            note="Sensitive config/data extension deny-list coverage only.",
        ),
    ),
    order=343,
)
def find_sensitive_config_files_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
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
    covered_extensions = denied_extensions(
        config_ast,
        extensions=TARGET_EXTENSIONS,
        block_names=_RESTRICTION_BLOCKS,
        virtualhost_context=virtualhost_context,
    )
    return tuple(
        extension
        for extension in TARGET_EXTENSIONS
        if extension not in covered_extensions
    )


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
        title="Sensitive config/data file extensions not restricted",
        severity="low",
        description=(
            "Apache config does not deny these sensitive extensions: "
            + ", ".join(f".{extension}" for extension in missing_extensions)
        ),
        recommendation=(
            "Add a FilesMatch rule for the missing extensions with "
            "'Require all denied'."
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


__all__ = ["find_sensitive_config_files_restricted"]
