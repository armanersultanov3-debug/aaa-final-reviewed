from __future__ import annotations

from webconf_audit.header_policy import permissions_policy_is_safe
from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.permissions_policy_unsafe"
TITLE = "Permissions-Policy header is overly broad"
DESCRIPTION = "Nginx sets Permissions-Policy to an empty or overly broad value."
RECOMMENDATION = (
    "Use a least-privilege Permissions-Policy allowlist and avoid wildcard "
    "feature grants."
)


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="low",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=264,
)
def find_permissions_policy_unsafe(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        for directive in find_server_add_headers(server_block, inherited_directives):
            if len(directive.args) < 2 or directive.args[0].lower() != "permissions-policy":
                continue
            if permissions_policy_is_safe(directive.args[1]):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title=TITLE,
                    severity="low",
                    description=(
                        f"{DESCRIPTION} Configured value: "
                        f"{directive.args[1] or '<missing value>'}."
                    ),
                    recommendation=RECOMMENDATION,
                    location=SourceLocation(
                        mode="local",
                        kind="file",
                        file_path=directive.source.file_path,
                        line=directive.source.line,
                    ),
                )
            )

    return findings


__all__ = ["find_permissions_policy_unsafe"]
