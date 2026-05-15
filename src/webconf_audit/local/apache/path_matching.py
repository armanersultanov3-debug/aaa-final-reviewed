"""Apache path-matching helpers for ``Directory`` / ``DocumentRoot``
covering.

Decides whether a discovered ``.htaccess`` directory falls under a
parent ``Directory`` block or matches a VirtualHost's effective
DocumentRoot, normalising case and separators for cross-platform
parity.
"""

from __future__ import annotations

from pathlib import Path


def normalize_path_for_match(
    path: Path,
    *,
    resolve: bool = False,
    case_sensitive: bool | None = None,
) -> str:
    """Return a stable string key for Apache filesystem-scope matching."""
    match_path = path.resolve() if resolve else path
    normalized = str(match_path).replace("\\", "/").rstrip("/")
    if case_sensitive is None:
        case_sensitive = not bool(match_path.drive)
    return normalized if case_sensitive else normalized.lower()


def directory_path_covers(
    target_path: Path,
    directory_path: Path,
    *,
    resolve: bool = False,
    case_sensitive: bool | None = None,
) -> bool:
    target = normalize_path_for_match(
        target_path,
        resolve=resolve,
        case_sensitive=case_sensitive,
    )
    directory = normalize_path_for_match(
        directory_path,
        resolve=resolve,
        case_sensitive=case_sensitive,
    )
    return target == directory or target.startswith(directory + "/")


def path_match_specificity(
    path: Path,
    *,
    resolve: bool = False,
    case_sensitive: bool | None = None,
) -> int:
    return len(
        normalize_path_for_match(
            path,
            resolve=resolve,
            case_sensitive=case_sensitive,
        )
    )


__all__ = [
    "directory_path_covers",
    "normalize_path_for_match",
    "path_match_specificity",
]
