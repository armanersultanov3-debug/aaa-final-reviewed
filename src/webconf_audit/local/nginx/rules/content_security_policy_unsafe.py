"""nginx.content_security_policy_unsafe -- Content-Security-Policy is weak."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.content_security_policy_unsafe"

_UNSAFE_SCRIPT_TOKENS = {"'unsafe-inline'", "'unsafe-eval'", "unsafe-inline", "unsafe-eval"}


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy is weak",
    severity="low",
    description="Content-Security-Policy is present but lacks baseline protections.",
    recommendation=(
        "Include at least a restrictive default-src directive and avoid "
        "'unsafe-inline' / 'unsafe-eval' in script-src."
    ),
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=254,
)
def find_content_security_policy_unsafe(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        for directive in find_server_add_headers(server_block, inherited_directives):
            if not directive.args or directive.args[0].lower() != "content-security-policy":
                continue
            policy = _header_value(directive.args)
            if _policy_is_baseline_safe(policy):
                continue
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Content-Security-Policy is weak",
                    severity="low",
                    description=(
                        "Content-Security-Policy is present but lacks a restrictive "
                        "default-src or safe script-src posture."
                    ),
                    recommendation=(
                        "Use a baseline such as default-src 'self'; form-action "
                        "'self'; and remove unsafe script tokens."
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


def _header_value(args: list[str]) -> str:
    value_args = args[1:]
    if value_args and value_args[-1].lower() == "always":
        value_args = value_args[:-1]
    value = " ".join(value_args).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value.lower()


def _policy_is_baseline_safe(policy: str) -> bool:
    default_src = _directive_value(policy, "default-src")
    if default_src is None:
        return False
    default_tokens = set(default_src.split())
    if not default_tokens or "*" in default_tokens:
        return False
    script_src = _directive_value(policy, "script-src")
    if script_src is None:
        return not any(token in default_tokens for token in _UNSAFE_SCRIPT_TOKENS)
    return not any(token in script_src.split() for token in _UNSAFE_SCRIPT_TOKENS)


def _directive_value(policy: str, directive_name: str) -> str | None:
    for directive in policy.split(";"):
        stripped = directive.strip()
        if not stripped:
            continue
        parts = stripped.split(maxsplit=1)
        if parts[0] == directive_name:
            return parts[1] if len(parts) == 2 else ""
    return None


__all__ = ["find_content_security_policy_unsafe"]
