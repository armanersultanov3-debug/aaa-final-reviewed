from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.referrer_policy_unsafe"

_ALLOWED_POLICIES = {"no-referrer", "strict-origin-when-cross-origin"}


@rule(
    rule_id=RULE_ID,
    title="Referrer-Policy is weak",
    severity="low",
    description="Referrer-Policy is present but uses a weak value or lacks the always parameter.",
    recommendation=(
        "Use 'add_header Referrer-Policy strict-origin-when-cross-origin always;' "
        "or 'no-referrer always;'."
    ),
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=260,
)
def find_referrer_policy_unsafe(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        for directive in find_server_add_headers(server_block, inherited_directives):
            if not directive.args or directive.args[0].lower() != "referrer-policy":
                continue
            if _is_safe_referrer_policy(directive.args):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Referrer-Policy is weak",
                    severity="low",
                    description=(
                        "Referrer-Policy should use no-referrer or "
                        "strict-origin-when-cross-origin and apply with always."
                    ),
                    recommendation=(
                        "Use 'add_header Referrer-Policy strict-origin-when-cross-origin always;'."
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


def _is_safe_referrer_policy(args: list[str]) -> bool:
    if len(args) < 3:
        return False
    policy = args[1].strip('"').strip("'").lower()
    return policy in _ALLOWED_POLICIES and any(arg.lower() == "always" for arg in args[2:])


__all__ = ["find_referrer_policy_unsafe"]
