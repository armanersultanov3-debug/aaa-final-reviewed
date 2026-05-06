from __future__ import annotations

from collections.abc import Callable, Iterable

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.local.lighttpd.rules.rule_utils import default_location
from webconf_audit.local.lighttpd.rules.url_access_deny_missing import (
    url_access_deny_texts,
)
from webconf_audit.local.sensitive_artifact_policy import (
    BACKUP_TEMP_EXTENSIONS,
    CONFIG_DATA_EXTENSIONS,
    GENERATED_ARTIFACT_LABELS,
    missing_marker_labels,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

_VCS_MARKERS = (".git", ".svn")


@rule(
    rule_id="lighttpd.backup_temp_files_access_not_denied",
    title="Backup and temporary files are not denied",
    severity="medium",
    description="url.access-deny does not cover common backup and temporary file extensions.",
    recommendation="Add backup and temporary extensions such as .bak, .old, .swp, and .tmp to url.access-deny.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=439,
)
def find_backup_temp_files_access_not_denied(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    markers = tuple(f".{extension}" for extension in BACKUP_TEMP_EXTENSIONS)
    return _find_missing_markers(
        config_ast,
        markers,
        find_backup_temp_files_access_not_denied,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.config_data_files_access_not_denied",
    title="Configuration and data files are not denied",
    severity="medium",
    description="url.access-deny does not cover common configuration and data file extensions.",
    recommendation="Add .conf, .env, .ini, .log, and .sql to url.access-deny.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=440,
)
def find_config_data_files_access_not_denied(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    markers = tuple(f".{extension}" for extension in CONFIG_DATA_EXTENSIONS)
    return _find_missing_markers(
        config_ast,
        markers,
        find_config_data_files_access_not_denied,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.generated_artifacts_access_not_denied",
    title="Generated artifacts are not denied",
    severity="medium",
    description="url.access-deny does not cover common generated artifacts and local metadata.",
    recommendation="Add generated artifact names such as .DS_Store, Thumbs.db, package manifests, and editor metadata to url.access-deny.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=441,
)
def find_generated_artifacts_access_not_denied(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    texts = _texts(
        config_ast,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )
    missing = _unique(
        label
        for text in texts
        for label in missing_marker_labels(text or "", GENERATED_ARTIFACT_LABELS)
    )
    return _finding(config_ast, find_generated_artifacts_access_not_denied, missing)


@rule(
    rule_id="lighttpd.vcs_metadata_access_not_denied",
    title="VCS metadata is not denied",
    severity="medium",
    description="url.access-deny does not cover common version-control metadata paths.",
    recommendation="Add .git and .svn markers to url.access-deny.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=442,
)
def find_vcs_metadata_access_not_denied(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_missing_markers(
        config_ast,
        _VCS_MARKERS,
        find_vcs_metadata_access_not_denied,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


def _find_missing_markers(
    config_ast: LighttpdConfigAst,
    markers: tuple[str, ...],
    rule_fn: Callable[..., list[Finding]],
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    missing = _unique(
        marker
        for text in _texts(
            config_ast,
            effective_config=effective_config,
            merged_directives=merged_directives,
            request_context=request_context,
        )
        for marker in _missing_markers_from_text(text, markers)
    )
    return _finding(config_ast, rule_fn, missing)


def _texts(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[str | None]:
    return url_access_deny_texts(
        config_ast,
        effective_config=effective_config,
        merged_directives=merged_directives,
        use_request_scoped_directives=request_context is not None,
    )


def _missing_markers_from_text(
    text: str | None,
    markers: tuple[str, ...],
) -> list[str]:
    if not text:
        return list(markers)
    lowered = text.lower()
    return [marker for marker in markers if marker.lower() not in lowered]


def _finding(
    config_ast: LighttpdConfigAst,
    rule_fn: Callable[..., list[Finding]],
    missing_markers: list[str],
) -> list[Finding]:
    if is_redirect_only_config(config_ast) or not missing_markers:
        return []
    return [
        finding_from_rule(
            rule_fn,
            location=default_location(config_ast),
            description=(
                f"{rule_fn._rule_meta.description} Missing markers: "
                + ", ".join(missing_markers)
            ),
            metadata={"missing_markers": missing_markers},
        )
    ]


def _unique(markers: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(markers))


__all__ = [
    "find_backup_temp_files_access_not_denied",
    "find_config_data_files_access_not_denied",
    "find_generated_artifacts_access_not_denied",
    "find_vcs_metadata_access_not_denied",
]
