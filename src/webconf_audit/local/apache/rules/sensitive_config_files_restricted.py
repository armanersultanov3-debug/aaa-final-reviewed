from __future__ import annotations

from webconf_audit.local.apache.parser import ApacheConfigAst
from webconf_audit.local.apache.rules._block_policy_utils import (
    default_location,
    denied_extensions,
)
from webconf_audit.local.sensitive_artifact_policy import CONFIG_DATA_EXTENSIONS
from webconf_audit.models import Finding
from webconf_audit.rule_registry import rule

RULE_ID = "apache.sensitive_config_files_not_restricted"
TARGET_EXTENSIONS = CONFIG_DATA_EXTENSIONS + ("orig", "save", "tmp")
_RESTRICTION_BLOCKS = frozenset({"files", "filesmatch"})


@rule(
    rule_id=RULE_ID,
    title="Sensitive config/data file extensions not restricted",
    severity="low",
    description=(
        "Apache config does not deny a baseline set of sensitive config, "
        "data, and temporary file extensions."
    ),
    recommendation=(
        "Add a FilesMatch denial for sensitive extensions such as .conf, "
        ".env, .ini, .log, .sql, .tmp, .orig, and .save."
    ),
    category="local",
    server_type="apache",
    order=343,
)
def find_sensitive_config_files_restricted(config_ast: ApacheConfigAst) -> list[Finding]:
    covered_extensions = denied_extensions(
        config_ast,
        extensions=TARGET_EXTENSIONS,
        block_names=_RESTRICTION_BLOCKS,
    )
    missing_extensions = tuple(
        extension
        for extension in TARGET_EXTENSIONS
        if extension not in covered_extensions
    )
    if not missing_extensions:
        return []

    return [
        Finding(
            rule_id=RULE_ID,
            title="Sensitive config/data file extensions not restricted",
            severity="low",
            description=(
                "Apache config does not deny these sensitive extensions: "
                + ", ".join(f".{extension}" for extension in missing_extensions)
            ),
            recommendation=(
                "Add a FilesMatch rule for the missing extensions with "
                "'Require all denied'."
            ),
            location=default_location(config_ast),
        )
    ]


__all__ = ["find_sensitive_config_files_restricted"]
