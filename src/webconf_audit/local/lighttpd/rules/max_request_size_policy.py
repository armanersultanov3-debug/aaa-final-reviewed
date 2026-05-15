"""lighttpd.max_request_size_unlimited -- Maximum request size is unlimited."""

from __future__ import annotations

from webconf_audit.finding_factory import finding_from_rule
from webconf_audit.local.lighttpd.conditions import LighttpdRequestContext
from webconf_audit.local.lighttpd.effective import (
    LighttpdEffectiveConfig,
    LighttpdEffectiveDirective,
)
from webconf_audit.local.lighttpd.parser import LighttpdConfigAst
from webconf_audit.local.lighttpd.rules.directive_value_utils import (
    directive_location,
    iter_effective_assignments,
    parse_int_value,
)
from webconf_audit.local.lighttpd.rules.redirect_scope_utils import (
    is_redirect_only_config,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

_MAX_REQUEST_SIZE_KB = 102400
_MAX_REQUEST_FIELD_SIZE_BYTES = 65535


@rule(
    rule_id="lighttpd.max_request_size_unlimited",
    title="Maximum request size is unlimited",
    severity="low",
    description="server.max-request-size allows unlimited request bodies.",
    recommendation=(
        "Set server.max-request-size to a bounded value appropriate for the "
        "application upload profile."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=424,
)
def find_max_request_size_unlimited(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for directive in iter_effective_assignments(
        config_ast,
        "server.max-request-size",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        value = parse_int_value(directive)
        if value is not None and value <= 0:
            findings.append(
                finding_from_rule(
                    find_max_request_size_unlimited,
                    location=directive_location(directive),
                    metadata={"configured_value": value},
                )
            )
    return findings


@rule(
    rule_id="lighttpd.max_request_size_too_large",
    title="Maximum request size is very large",
    severity="low",
    description="server.max-request-size is configured above a conservative static-analysis threshold.",
    recommendation=(
        "Lower server.max-request-size or document why this virtual host needs "
        "large request bodies."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=425,
)
def find_max_request_size_too_large(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for directive in iter_effective_assignments(
        config_ast,
        "server.max-request-size",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        value = parse_int_value(directive)
        if value is not None and value > _MAX_REQUEST_SIZE_KB:
            findings.append(
                finding_from_rule(
                    find_max_request_size_too_large,
                    location=directive_location(directive),
                    metadata={
                        "configured_value_kb": value,
                        "threshold_kb": _MAX_REQUEST_SIZE_KB,
                    },
                )
            )
    return findings


@rule(
    rule_id="lighttpd.max_request_field_size_too_large",
    title="Maximum request header field size is very large",
    severity="low",
    description="server.max-request-field-size allows unusually large request header fields.",
    recommendation=(
        "Keep server.max-request-field-size near the Lighttpd default unless "
        "large request headers are intentionally required."
    ),
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=426,
)
def find_max_request_field_size_too_large(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for directive in iter_effective_assignments(
        config_ast,
        "server.max-request-field-size",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        value = parse_int_value(directive)
        if value is not None and value > _MAX_REQUEST_FIELD_SIZE_BYTES:
            findings.append(
                finding_from_rule(
                    find_max_request_field_size_too_large,
                    location=directive_location(directive),
                    metadata={
                        "configured_value_bytes": value,
                        "threshold_bytes": _MAX_REQUEST_FIELD_SIZE_BYTES,
                    },
                )
            )
    return findings


__all__ = [
    "find_max_request_field_size_too_large",
    "find_max_request_size_too_large",
    "find_max_request_size_unlimited",
]
