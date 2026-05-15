"""nginx.large_client_header_buffers_too_large -- large_client_header_buffers is unusually large."""

from __future__ import annotations

from webconf_audit.local.nginx.parser.ast import ConfigAst
from webconf_audit.local.nginx.rules._value_utils import (
    iter_last_direct_child_directives,
    parse_size_bytes,
)
from webconf_audit.models import Finding, SourceLocation
from webconf_audit.rule_registry import rule

RULE_ID = "nginx.large_client_header_buffers_too_large"
MAX_BUFFER_COUNT = 8
MAX_BUFFER_SIZE_BYTES = 64 * 1024
MAX_TOTAL_BUFFER_BYTES = 512 * 1024


@rule(
    rule_id=RULE_ID,
    title="large_client_header_buffers is unusually large",
    severity="low",
    description=(
        "Nginx sets 'large_client_header_buffers' above conservative request-header "
        "allocation thresholds."
    ),
    recommendation=(
        "Keep 'large_client_header_buffers' close to the default 4 8k unless larger "
        "headers are required and rate limiting protects the endpoint."
    ),
    category="local",
    server_type="nginx",
    order=247,
)
def find_large_client_header_buffers_too_large(config_ast: ConfigAst) -> list[Finding]:
    findings: list[Finding] = []

    for directive, _parent in iter_last_direct_child_directives(
        config_ast,
        "large_client_header_buffers",
        block_names={"http", "server"},
    ):
        if len(directive.args) < 2:
            continue
        try:
            buffer_count = int(directive.args[0], 10)
        except ValueError:
            continue
        if buffer_count <= 0:
            continue
        buffer_size = parse_size_bytes(directive.args[1])
        if buffer_size is None:
            continue
        total_size = buffer_count * buffer_size
        if (
            buffer_count <= MAX_BUFFER_COUNT
            and buffer_size <= MAX_BUFFER_SIZE_BYTES
            and total_size <= MAX_TOTAL_BUFFER_BYTES
        ):
            continue

        findings.append(
            Finding(
                rule_id=RULE_ID,
                title="large_client_header_buffers is unusually large",
                severity="low",
                description=(
                    "Nginx sets 'large_client_header_buffers "
                    f"{' '.join(directive.args[:2])};', which can allocate large "
                    "per-request buffers for oversized request headers."
                ),
                recommendation=(
                    "Keep 'large_client_header_buffers' close to the default 4 8k "
                    "unless larger headers are required and rate limiting protects "
                    "the endpoint."
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


__all__ = ["find_large_client_header_buffers_too_large"]
