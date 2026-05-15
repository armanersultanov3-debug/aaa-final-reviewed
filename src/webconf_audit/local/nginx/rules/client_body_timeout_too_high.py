"""nginx.client_body_timeout_too_high -- client_body_timeout is too high."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_direct_child_directives,
    parse_duration_seconds,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.client_body_timeout_too_high"
MAX_TIMEOUT_SECONDS = 20.0


@rule(
    rule_id=RULE_ID,
    title="client_body_timeout is too high",
    severity="low",
    description="Nginx sets 'client_body_timeout' above the recommended low global value.",
    recommendation=(
        "Set 'client_body_timeout' to a non-zero value of 20 seconds or less in the "
        "http or server context; use a scoped location override only where uploads require it."
    ),
    category="local",
    server_type="nginx",
    order=241,
)
def find_client_body_timeout_too_high(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_direct_child_directives(
        config_ast,
        "client_body_timeout",
        block_names={"http", "server"},
    ):
        if not directive.args:
            continue
        duration = parse_duration_seconds(directive.args[0])
        if duration is None or 0 < duration <= MAX_TIMEOUT_SECONDS:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="client_body_timeout is too high",
                severity="low",
                description=(
                    "Nginx sets 'client_body_timeout "
                    f"{directive.args[0]};', which is zero or above 20 seconds."
                ),
                recommendation=(
                    "Set 'client_body_timeout' to a non-zero value of 20 seconds or less in the "
                    "http or server context; use a scoped location override only where uploads require it."
                ),
                location=SourceLocation(
                    mode="local",
                    kind="file",
                    file_path=directive.source.file_path,
                    line=directive.source.line,
                ),
            )
        )

    return findings


__all__ = ["find_client_body_timeout_too_high"]
