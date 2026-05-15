"""nginx.keepalive_timeout_too_high -- keepalive_timeout is too high."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_direct_child_directives,
    parse_duration_seconds,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.keepalive_timeout_too_high"
MAX_TIMEOUT_SECONDS = 10.0


@rule(
    rule_id=RULE_ID,
    title="keepalive_timeout is too high",
    severity="low",
    description="Nginx sets 'keepalive_timeout' above the recommended limit or disables it with 0.",
    recommendation="Set 'keepalive_timeout' to a non-zero value of 10 seconds or less.",
    category="local",
    server_type="nginx",
    order=243,
)
def find_keepalive_timeout_too_high(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_direct_child_directives(
        config_ast,
        "keepalive_timeout",
        block_names={"http", "server", "location"},
    ):
        if not directive.args:
            continue
        duration = parse_duration_seconds(directive.args[0])
        if duration is None or 0 < duration <= MAX_TIMEOUT_SECONDS:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="keepalive_timeout is too high",
                severity="low",
                description=(
                    "Nginx sets 'keepalive_timeout "
                    f"{directive.args[0]};', which is zero or above 10 seconds."
                ),
                recommendation="Set 'keepalive_timeout' to a non-zero value of 10 seconds or less.",
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_keepalive_timeout_too_high"]
