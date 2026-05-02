from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    denied_extensions,
)
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.vcs_metadata_not_restricted"
_VCS_EXTENSIONS = ("git", "svn")
_RESTRICTION_BLOCKS = frozenset({"directorymatch", "filesmatch", "locationmatch"})


@rule(
    rule_id=RULE_ID,
    title="Version-control metadata not restricted",
    severity="medium",
    description=(
        "Apache config does not contain a denial for exposed .git or .svn "
        "metadata paths."
    ),
    recommendation=(
        "Add DirectoryMatch/FilesMatch restrictions for .git and .svn paths "
        "with 'Require all denied'."
    ),
    category="local",
    server_type="apache",
    order=344,
)
def find_vcs_metadata_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    covered = denied_extensions(
        config_ast,
        extensions=_VCS_EXTENSIONS,
        block_names=_RESTRICTION_BLOCKS,
    )
    if set(_VCS_EXTENSIONS).issubset(covered):
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Version-control metadata not restricted",
            severity="medium",
            description=(
                "Apache config does not deny direct access to .git or .svn "
                "metadata paths."
            ),
            recommendation=(
                "Deny .git and .svn paths with a DirectoryMatch or FilesMatch "
                "rule and 'Require all denied'."
            ),
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_vcs_metadata_restricted"]
