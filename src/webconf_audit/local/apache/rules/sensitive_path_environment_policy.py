from __future__ import annotations

import re

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    block_denies_all,
    block_pattern_text,
    default_location,
    iter_blocks,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.sensitive_path_environment_policy"
TITLE = "Sensitive environment-specific paths are not denied"
DESCRIPTION = (
    "Apache exposes environment-specific path names such as private, backup, "
    "staging, or secret directories without a deny-all policy."
)
RECOMMENDATION = (
    "Add direct deny-all Directory, DirectoryMatch, Location, or LocationMatch "
    "rules for sensitive environment-specific paths."
)
_TARGET_BLOCKS = frozenset({"directory", "directorymatch", "location", "locationmatch"})
_SENSITIVE_PATH_MARKERS = (
    "private",
    "secret",
    "secrets",
    "backup",
    "backups",
    "staging",
    "tmp",
    "cache",
    "sample",
    "samples",
    "demo",
)
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")


@rule(
    rule_id=RULE_ID,
    title=TITLE,
    severity="medium",
    description=DESCRIPTION,
    recommendation=RECOMMENDATION,
    category="local",
    server_type="apache",
    order=377,
)
def find_sensitive_path_environment_policy(
    config_ast: ApacheConfigAst,
) -> list[Finding]:
    candidate_blocks = [
        block
        for block in iter_blocks(config_ast.nodes, _TARGET_BLOCKS)
        if _block_mentions_sensitive_path(block) and not block_denies_all(block)
    ]
    if not candidate_blocks:
        return []

    markers = sorted(
        {
            marker
            for block in candidate_blocks
            for marker in _matching_markers(block_pattern_text(block))
        }
    )
    return [
        Finding(
            rule_id=RULE_ID,
            title=TITLE,
            severity="medium",
            description=(
                "Apache config does not deny these sensitive path patterns: "
                + ", ".join(markers)
            ),
            recommendation=RECOMMENDATION,
            location=default_location(config_ast, candidate_blocks),
        )
    ]


def _block_mentions_sensitive_path(block) -> bool:
    return bool(_matching_markers(block_pattern_text(block)))


def _matching_markers(pattern: str) -> set[str]:
    lowered = pattern.lower()
    tokens = {token for token in _TOKEN_SPLIT_RE.split(lowered) if token}
    return {
        marker
        for marker in _SENSITIVE_PATH_MARKERS
        if marker in tokens
    }


__all__ = ["find_sensitive_path_environment_policy"]
