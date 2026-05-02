from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    has_denied_pattern,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.ht_files_not_restricted"
_HT_FILE_MARKERS = ("\\.ht", ".ht")
_RESTRICTION_BLOCKS = frozenset({"files", "filesmatch"})


@rule(
    rule_id=RULE_ID,
    title=".ht* files not restricted",
    severity="medium",
    description=(
        "Apache config does not contain a Files/FilesMatch denial for .ht* "
        "metadata files such as .htaccess and .htpasswd."
    ),
    recommendation=(
        "Add a '<FilesMatch \"^\\.ht\"> Require all denied </FilesMatch>' "
        "or equivalent rule."
    ),
    category="local",
    server_type="apache",
    order=342,
)
def find_ht_files_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    if has_denied_pattern(
        config_ast,
        markers=_HT_FILE_MARKERS,
        block_names=_RESTRICTION_BLOCKS,
    ):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title=".ht* files not restricted",
            severity="medium",
            description=(
                "Apache config does not deny direct requests for .ht* files. "
                "These files often contain override policy or credentials."
            ),
            recommendation=(
                "Deny .ht* files with a FilesMatch rule and 'Require all denied'."
            ),
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_ht_files_restricted"]
