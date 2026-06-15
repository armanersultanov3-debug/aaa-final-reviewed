from __future__ import annotations

from pathlib import Path


def module_aliases(raw_value: str) -> frozenset[str]:
    value = raw_value.strip().strip('"').strip("'").lower()
    if not value:
        return frozenset()

    file_name = Path(value).name.lower()
    aliases = {value, file_name}
    aliases.update(_normalized_module_aliases(value))
    if file_name != value:
        aliases.update(_normalized_module_aliases(file_name))
    return frozenset(sorted(alias for alias in aliases if alias))


def normalized_module_identifier(raw_value: str) -> str:
    aliases = module_aliases(raw_value)
    if not aliases:
        return ""
    explicit_identifier = next(
        (alias for alias in aliases if alias.endswith("_module")),
        None,
    )
    if explicit_identifier is not None:
        return explicit_identifier
    bare_identifier = next(
        (
            alias
            for alias in aliases
            if "." not in alias and "/" not in alias and "\\" not in alias
        ),
        None,
    )
    if bare_identifier is not None:
        return bare_identifier
    return next(iter(aliases))


def _normalized_module_aliases(value: str) -> set[str]:
    normalized = value.removeprefix("!")
    aliases = {normalized}

    if normalized.endswith("_module"):
        bare = normalized.removesuffix("_module")
        aliases.update({bare, f"mod_{bare}.c"})
    elif normalized.startswith("mod_") and normalized.endswith(".c"):
        bare = normalized.removeprefix("mod_").removesuffix(".c")
        aliases.update({bare, f"{bare}_module"})
    elif normalized.startswith("mod_") and normalized.endswith(".so"):
        bare = normalized.removeprefix("mod_").removesuffix(".so")
        aliases.update({bare, f"{bare}_module", f"mod_{bare}.c"})
    elif normalized.endswith(".so"):
        bare = normalized.removesuffix(".so")
        aliases.add(bare)

    return aliases


__all__ = ["module_aliases", "normalized_module_identifier"]
