from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules.security_header_utils import (
    unsafe_header_findings,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.x_frame_options_unsafe"
_SAFE_X_FRAME_OPTIONS = frozenset({"deny", "sameorigin"})


@rule(
    rule_id=RULE_ID,
    title="X-Frame-Options header is weak",
    severity="low",
    description="Apache sets X-Frame-Options to a weak or unsupported value.",
    recommendation=(
        "Use 'Header set X-Frame-Options SAMEORIGIN' or "
        "'Header set X-Frame-Options DENY'."
    ),
    category="local",
    server_type="apache",
    tags=("headers",),
    order=335,
)
def find_x_frame_options_unsafe(config_ast: ApacheConfigAst) -> list[Finding]:
    return unsafe_header_findings(
        config_ast,
        header_name="X-Frame-Options",
        is_safe_value=_is_safe_x_frame_options,
        rule_id=RULE_ID,
        title="X-Frame-Options header is weak",
        description="Apache sets X-Frame-Options to a weak or unsupported value.",
        recommendation=(
            "Use 'Header set X-Frame-Options SAMEORIGIN' or "
            "'Header set X-Frame-Options DENY'."
        ),
    )


def _is_safe_x_frame_options(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().strip('"').strip("'").lower() in _SAFE_X_FRAME_OPTIONS


__all__ = ["find_x_frame_options_unsafe"]
