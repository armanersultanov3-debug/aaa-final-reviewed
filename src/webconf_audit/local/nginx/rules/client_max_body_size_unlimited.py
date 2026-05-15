"""nginx.client_max_body_size_unlimited -- client_max_body_size disables request body limits."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_last_direct_child_directives,
    parse_size_bytes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.client_max_body_size_unlimited"


@rule(
    rule_id=RULE_ID,
    title="client_max_body_size disables request body limits",
    severity="low",
    description="Nginx sets 'client_max_body_size' to 0, which disables request body size checks.",
    recommendation=(
        "Set 'client_max_body_size' to an explicit non-zero limit, and use scoped overrides "
        "only for endpoints that require larger uploads."
    ),
    category="local",
    server_type="nginx",
    order=245,
)
def find_client_max_body_size_unlimited(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_last_direct_child_directives(
        config_ast,
        "client_max_body_size",
        block_names={"http", "server", "location"},
    ):
        if not directive.args:
            continue
        size = parse_size_bytes(directive.args[0])
        if size != 0:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="client_max_body_size disables request body limits",
                severity="low",
                description=(
                    "Nginx sets 'client_max_body_size "
                    f"{directive.args[0]};', which disables request body size checks."
                ),
                recommendation=(
                    "Set 'client_max_body_size' to an explicit non-zero limit, and use scoped "
                    "overrides only for endpoints that require larger uploads."
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


__all__ = ["find_client_max_body_size_unlimited"]
