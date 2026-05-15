"""apache.csp_value_review -- policy-review rule.

Surfaces every observed ``Header set Content-Security-Policy ...``
directive so an operator can audit the policy against
application-specific semantics (allowed CDN origins, nonce vs. hash
strategy, inline-script policy). Existing rules already flag obvious
defects (unsafe-inline, missing default-src, missing report-to /
report-uri); this rule complements them by listing the full configured
policy for human review.

Opt-in: only runs when ``--enable-policy-review`` is set on the CLI.
"""

from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst, ApacheDirectiveNode
from webconf_audit.local.apache.rules._block_policy_utils import iter_directives
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "apache.csp_value_review"

_MAX_REPORTED_POLICY_LEN = 240
_HEADER_VALUE_TRAILERS = frozenset({"early", "always"})


@rule(
    rule_id=RULE_ID,
    title="Content-Security-Policy value needs operator review",
    severity="info",
    description=(
        "A Content-Security-Policy Header directive is configured. The "
        "full policy needs human review to decide whether it matches "
        "the application's trusted-source posture (allowed CDNs, "
        "inline-script strategy, reporting endpoint completeness)."
    ),
    recommendation=(
        "Audit the configured policy against the application's actual "
        "third-party origins and inline-script approach. Document the "
        "decision or tighten the policy where possible."
    ),
    category="local",
    server_type="apache",
    tags=("policy-review", "headers"),
    order=379,
)
def find_csp_value_review(config_ast: ApacheConfigAst) -> list[Finding]:
    findings: list[Finding] = []
    seen_at_location: set[tuple[str | None, int | None]] = set()

    for directive in iter_directives(config_ast.nodes, "Header"):
        policy = _csp_header_value(directive)
        if policy is None:
            continue
        location_key = (directive.source.file_path, directive.source.line)
        if location_key in seen_at_location:
            continue
        seen_at_location.add(location_key)

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


def _csp_header_value(directive: ApacheDirectiveNode) -> str | None:
    """Return the CSP value for ``Header set Content-Security-Policy ...``.

    Returns ``None`` when the directive does not set CSP (different
    header name, ``unset`` action, no value).
    """
    args = list(directive.args)
    if not args:
        return None

    # Optional leading 'always' / 'onsuccess' / 'early' condition keyword.
    if args[0].lower() in {"always", "onsuccess", "early"}:
        args = args[1:]
    if not args:
        return None

    action = args[0].lower()
    if action not in {"set", "setifempty", "add", "append", "merge"}:
        return None

    if len(args) < 3:
        return None

    header_name = args[1].lower()
    if header_name != "content-security-policy":
        return None

    value_args = args[2:]
    # Strip trailing condition keyword ('early' / 'always') and any
    # 'env=...' / 'expr=...' modifiers from the value.
    while value_args and (
        value_args[-1].lower() in _HEADER_VALUE_TRAILERS
        or value_args[-1].startswith("env=")
        or value_args[-1].startswith("expr=")
    ):
        value_args = value_args[:-1]
    if not value_args:
        return None

    value = " ".join(value_args).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1].strip()
    return value


__all__ = ["find_csp_value_review"]
