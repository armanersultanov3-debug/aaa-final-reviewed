"""Implements rule ``nginx.missing_x_frame_options``.

Location: ``src/webconf_audit/local/nginx/rules/missing_x_frame_options.py``.
"""

from __future__ import annotations

from webconf_audit.header_policy import (
    content_security_policy_has_frame_ancestors,
    x_frame_options_is_safe,
)
from webconf_audit.local.nginx.parser.ast import BlockNode, ConfigAst, DirectiveNode
from webconf_audit.local.nginx.rules._scope_utils import skips_content_response_checks
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import (
    build_missing_header_finding,
    find_server_add_headers,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.missing_x_frame_options"

# Rule metadata used both in the registry decorator (for ``list-rules``
# / registry introspection) and in the per-finding message emitted by
# ``build_missing_header_finding`` below.  Keeping them in module-level
# constants guarantees the two copies stay in sync — the previous code
# repeated each string literal in both places, which made a harmless
# wording tweak silently produce a finding whose user-visible text
# disagreed with the registry metadata.
_TITLE = "Missing X-Frame-Options header"
_DESCRIPTION = "Server block does not define a valid X-Frame-Options header."
_RECOMMENDATION = (
    "Add 'add_header X-Frame-Options DENY;' or "
    "'add_header X-Frame-Options SAMEORIGIN;' to this server block."
)


@rule(
    rule_id=RULE_ID,
    title=_TITLE,
    severity="low",
    description=_DESCRIPTION,
    recommendation=_RECOMMENDATION,
    category="local",
    server_type="nginx",
    tags=("headers",),
    order=235,
)
def find_missing_x_frame_options(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        finding = _find_missing_x_frame_options_in_server(server_block, inherited_directives)
        if finding is not None:
            findings.append(finding)

    return findings


def _find_missing_x_frame_options_in_server(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> Finding | None:
    if skips_content_response_checks(server_block):
        return None

    if _server_has_clickjacking_control(server_block, inherited_directives):
        return None

    return build_missing_header_finding(
        server_block,
        rule_id=RULE_ID,
        title=_TITLE,
        description=_DESCRIPTION,
        recommendation=_RECOMMENDATION,
    )


def _server_has_clickjacking_control(
    server_block: BlockNode,
    inherited_directives: dict[str, list[DirectiveNode]],
) -> bool:
    for directive in find_server_add_headers(server_block, inherited_directives):
        if len(directive.args) < 2:
            continue
        header_name = directive.args[0].lower()
        header_value = directive.args[1]
        if header_name == "x-frame-options" and x_frame_options_is_safe(header_value):
            return True
        if (
            header_name == "content-security-policy"
            and content_security_policy_has_frame_ancestors(header_value)
        ):
            return True
    return False


__all__ = ["find_missing_x_frame_options"]
