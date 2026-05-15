"""nginx.csp_value_review -- policy-review rule.

Surfaces every observed Content-Security-Policy value so an operator can
audit it against application-specific semantics (allowed CDN origins,
nonce vs. hash strategy, inline-script policy). The scanner already
flags obvious problems (unsafe-inline, missing default-src, etc.) via
the standard rules; this rule complements them by listing the full
configured policy for human review.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import iter_server_blocks_with_http_directives
from webconf_audit.local.nginx.rules.header_utils import find_server_add_headers
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.csp_value_review"

_MAX_REPORTED_POLICY_LEN = 240


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy value needs operator review",
    severity="info",
    description=(
        "A Content-Security-Policy header is configured. The full policy "
        "needs human review to decide whether it matches the application's "
        "trusted-source posture (allowed CDNs, inline-script strategy, "
        "reporting endpoint completeness)."
    ),
    recommendation=(
        "Audit the configured policy against the application's actual "
        "third-party origins and inline-script approach. Document the "
        "decision or tighten the policy where possible."
    ),
    category="local",
    server_type="nginx",
    tags=("policy-review", "headers"),
    order=283,
)
def find_csp_value_review(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    seen_at_location: set[tuple[str | None, int | None]] = set()

    for server_block, inherited_directives in iter_server_blocks_with_http_directives(
        config_ast,
        {"add_header"},
    ):
        for directive in find_server_add_headers(server_block, inherited_directives):
            if not directive.args or directive.args[0].lower() != "content-security-policy":
                continue
            location_key = (
                directive.source.file_path,
                directive.source.line,
            )
            if location_key in seen_at_location:
                continue
            seen_at_location.add(location_key)

            policy = _header_value(directive.args)
            displayed = (
                policy[:_MAX_REPORTED_POLICY_LEN] + "..."
                if len(policy) > _MAX_REPORTED_POLICY_LEN
                else policy
            )
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    title="Content-Security-Policy value needs operator review",
                    severity="info",
                    description=(
                        f"Configured CSP: {displayed}. Review whether the "
                        "allowed sources and inline-script strategy match "
                        "the application's actual posture."
                    ),
                    recommendation=(
                        "Audit the configured policy against actual third-party "
                        "origins; document the decision or tighten where possible."
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
    return value


__all__ = ["find_csp_value_review"]
