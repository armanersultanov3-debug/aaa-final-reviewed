"""Shared catalogue of sensitive file extensions and metadata paths.

Centralises the deny-list constants (backup/temp extensions, dotfile
artefacts, package-manager metadata) consumed by the per-server
``sensitive_config_files_not_restricted`` and ``backup_temp_files_*``
rules, plus the matching external-probe expectations.
"""

from __future__ import annotations

BACKUP_TEMP_EXTENSIONS = ("bak", "old", "backup", "orig", "save", "swp", "tmp")
CONFIG_DATA_EXTENSIONS = ("conf", "env", "ini", "log", "sql")

GENERATED_ARTIFACT_LABELS = {
    ".DS_Store": (".ds_store", "\\.ds_store"),
    "Thumbs.db": ("thumbs.db", "thumbs\\.db"),
    "composer manifests": ("composer.", "composer\\.", "composer.json", "composer.lock"),
    "package-lock.json": ("package-lock.json", "package-lock\\.json"),
    ".npmrc": (".npmrc", "\\.npmrc"),
    ".yarnrc": (".yarnrc", "\\.yarnrc"),
    ".idea": (".idea", "\\.idea", "(idea", "|idea", "idea|", "idea)"),
    ".vscode": (".vscode", "\\.vscode", "(vscode", "|vscode", "vscode|", "vscode)"),
}

LIGHTTPD_URL_ACCESS_DENY_MARKERS = (
    ".inc",
    ".bak",
    ".old",
    ".backup",
    ".orig",
    ".save",
    ".swp",
    ".tmp",
    ".sql",
    ".conf",
    ".log",
    ".env",
    ".DS_Store",
    "Thumbs.db",
    "composer.json",
    "composer.lock",
    "package-lock.json",
    ".npmrc",
    ".yarnrc",
    ".idea",
    ".vscode",
)

def missing_marker_labels(
    text: str,
    labels_to_markers: dict[str, tuple[str, ...]],
) -> list[str]:
    normalized = text.lower()
    return [
        label
        for label, markers in labels_to_markers.items()
        if not any(marker.lower() in normalized for marker in markers)
    ]


__all__ = [
    "BACKUP_TEMP_EXTENSIONS",
    "CONFIG_DATA_EXTENSIONS",
    "GENERATED_ARTIFACT_LABELS",
    "LIGHTTPD_URL_ACCESS_DENY_MARKERS",
    "missing_marker_labels",
]
