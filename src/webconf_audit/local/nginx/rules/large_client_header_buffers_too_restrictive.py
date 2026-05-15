"""nginx.large_client_header_buffers_too_restrictive -- large_client_header_buffers is too restrictive."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_direct_child_directives,
    parse_size_bytes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.large_client_header_buffers_too_restrictive"
MIN_BUFFER_COUNT = 4
MIN_BUFFER_SIZE_BYTES = 8 * 1024


@rule(
    rule_id=RULE_ID,
    title="large_client_header_buffers is too restrictive",
    severity="low",
    description=(
        "Nginx sets 'large_client_header_buffers' below the default 4 buffers of 8k each, "
        "which can reject legitimate large request URIs or headers."
    ),
    recommendation=(
        "Remove the restrictive 'large_client_header_buffers' override or set it to at "
        "least '4 8k' unless the lower value is intentionally documented."
    ),
    category="local",
    server_type="nginx",
    order=247,
)
def find_large_client_header_buffers_too_restrictive(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_direct_child_directives(
        config_ast,
        "large_client_header_buffers",
        block_names={"http", "server"},
    ):
        if len(directive.args) < 2:
            continue
        try:
            buffer_count = int(directive.args[0])
        except ValueError:
            continue
        buffer_size = parse_size_bytes(directive.args[1])
        if buffer_size is None:
            continue
        if buffer_count >= MIN_BUFFER_COUNT and buffer_size >= MIN_BUFFER_SIZE_BYTES:
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="large_client_header_buffers is too restrictive",
                severity="low",
                description=(
                    "Nginx sets 'large_client_header_buffers "
                    f"{' '.join(directive.args[:2])};', which is below the default 4 8k."
                ),
                recommendation=(
                    "Remove the restrictive 'large_client_header_buffers' override or set it to at "
                    "least '4 8k' unless the lower value is intentionally documented."
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


__all__ = ["find_large_client_header_buffers_too_restrictive"]
