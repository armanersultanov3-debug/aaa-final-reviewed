"""Embedded IIS XML schema resources."""

from __future__ import annotations

from importlib.resources import files

try:
    from importlib.resources.abc import Traversable
except ImportError:  # pragma: no cover - Python 3.10 compatibility
    from importlib.abc import Traversable

_SCHEMA_FILE_NAMES = (
    "IIS_schema.xml",
    "ASPNET_schema.xml",
    "FX_schema.xml",
)


def schema_file_names() -> tuple[str, ...]:
    """Return the embedded IIS schema filenames."""
    return _SCHEMA_FILE_NAMES


def schema_resource(name: str) -> Traversable:
    """Return a Traversable for one embedded schema file."""
    if name not in _SCHEMA_FILE_NAMES:
        raise FileNotFoundError(name)
    return files(__name__).joinpath(name)


def schema_resources() -> tuple[Traversable, ...]:
    """Return Traversables for all embedded schema files."""
    root = files(__name__)
    return tuple(root.joinpath(name) for name in _SCHEMA_FILE_NAMES)


__all__ = [
    "schema_file_names",
    "schema_resource",
    "schema_resources",
]
