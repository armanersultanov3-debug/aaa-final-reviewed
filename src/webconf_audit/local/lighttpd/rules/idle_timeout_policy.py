from __future__ import annotations

from collections.abc import Callable

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

_MAX_KEEP_ALIVE_IDLE_SECONDS = 15
_MAX_READ_IDLE_SECONDS = 60
_MAX_WRITE_IDLE_SECONDS = 360


@rule(
    rule_id="lighttpd.max_keep_alive_idle_too_high",
    title="Keep-alive idle timeout is high",
    severity="low",
    description="server.max-keep-alive-idle is higher than the conservative policy threshold.",
    recommendation="Keep server.max-keep-alive-idle low to limit idle connection retention.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=427,
)
def find_max_keep_alive_idle_too_high(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_threshold_exceeded(
        config_ast,
        "server.max-keep-alive-idle",
        _MAX_KEEP_ALIVE_IDLE_SECONDS,
        find_max_keep_alive_idle_too_high,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.max_read_idle_too_high",
    title="Read idle timeout is high",
    severity="low",
    description="server.max-read-idle is higher than the conservative policy threshold.",
    recommendation="Keep server.max-read-idle bounded to reduce slow request resource retention.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=428,
)
def find_max_read_idle_too_high(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_threshold_exceeded(
        config_ast,
        "server.max-read-idle",
        _MAX_READ_IDLE_SECONDS,
        find_max_read_idle_too_high,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.max_write_idle_too_high",
    title="Write idle timeout is high",
    severity="low",
    description="server.max-write-idle is higher than the conservative policy threshold.",
    recommendation="Keep server.max-write-idle bounded to reduce stalled response retention.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=429,
)
def find_max_write_idle_too_high(
    config_ast: LighttpdConfigAst,
    *,
    effective_config: LighttpdEffectiveConfig | None = None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None = None,
    request_context: LighttpdRequestContext | None = None,
) -> list[Finding]:
    return _find_threshold_exceeded(
        config_ast,
        "server.max-write-idle",
        _MAX_WRITE_IDLE_SECONDS,
        find_max_write_idle_too_high,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    )


@rule(
    rule_id="lighttpd.max_keep_alive_requests_unlimited",
    title="Keep-alive request count is unlimited",
    severity="low",
    description="server.max-keep-alive-requests disables the per-connection keep-alive request cap.",
    recommendation="Set server.max-keep-alive-requests to a bounded positive value.",
    category="local",
    server_type="lighttpd",
    input_kind="effective",
    order=430,
)
def find_max_keep_alive_requests_unlimited(
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
        "server.max-keep-alive-requests",
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        value = parse_int_value(directive)
        if value is not None and value <= 0:
            findings.append(
                finding_from_rule(
                    find_max_keep_alive_requests_unlimited,
                    location=directive_location(directive),
                    metadata={"configured_value": value},
                )
            )
    return findings


def _find_threshold_exceeded(
    config_ast: LighttpdConfigAst,
    directive_name: str,
    threshold: int,
    rule_fn: Callable[..., list[Finding]],
    *,
    effective_config: LighttpdEffectiveConfig | None,
    merged_directives: dict[str, LighttpdEffectiveDirective] | None,
    request_context: LighttpdRequestContext | None,
) -> list[Finding]:
    if is_redirect_only_config(config_ast):
        return []

    findings: list[Finding] = []
    for directive in iter_effective_assignments(
        config_ast,
        directive_name,
        effective_config=effective_config,
        merged_directives=merged_directives,
        request_context=request_context,
    ):
        value = parse_int_value(directive)
        if value is not None and value > threshold:
            findings.append(
                finding_from_rule(
                    rule_fn,
                    location=directive_location(directive),
                    metadata={
                        "configured_value_seconds": value,
                        "threshold_seconds": threshold,
                    },
                )
            )
    return findings


__all__ = [
    "find_max_keep_alive_idle_too_high",
    "find_max_keep_alive_requests_unlimited",
    "find_max_read_idle_too_high",
    "find_max_write_idle_too_high",
]
