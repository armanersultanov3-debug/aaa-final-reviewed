"""Embedded IIS schema defaults."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from defusedxml import ElementTree as ET

from webconf_audit.local.iis._iis_schema import schema_resources


@dataclass(frozen=True, slots=True)
class IISDefaults:
    _section_attribute_defaults: dict[tuple[str, str], str]
    _section_defaults_by_path: dict[str, dict[str, str]]
    _element_defaults: dict[str, dict[str, str]]

    def get_section_attribute_default(
        self,
        section_path: str,
        attribute_name: str,
    ) -> str | None:
        """Return the default for a section attribute."""
        return self._section_attribute_defaults.get(
            (_normalize_path(section_path), _normalize_attribute_name(attribute_name)),
        )

    def get_element_default(
        self,
        element_path: str,
    ) -> dict[str, str]:
        """Return defaults for a nested schema element."""
        return dict(self._element_defaults.get(_normalize_path(element_path), {}))

    def get_section_defaults(
        self,
        section_path: str,
    ) -> dict[str, str]:
        """Return all defaults for a section schema."""
        return dict(self._section_defaults_by_path.get(_normalize_path(section_path), {}))


def _load_schema_defaults() -> IISDefaults:
    section_attribute_defaults: dict[tuple[str, str], str] = {}
    section_defaults_by_path: dict[str, dict[str, str]] = {}
    element_defaults: dict[str, dict[str, str]] = {}

    for resource in schema_resources():
        with resource.open("rb") as handle:
            root = ET.parse(handle).getroot()

        for section_schema in root.findall(".//sectionSchema"):
            section_path = section_schema.attrib.get("name")
            if not section_path:
                continue

            section_key = _normalize_path(section_path)
            section_defaults: dict[str, str] = {}
            for child in section_schema:
                if child.tag != "attribute":
                    continue
                name = child.attrib.get("name")
                default_value = _attribute_default_value(child)
                if not name or default_value is None:
                    continue
                section_defaults[name] = default_value
                section_attribute_defaults[
                    (section_key, _normalize_attribute_name(name))
                ] = default_value

            if section_defaults:
                section_defaults_by_path[section_key] = section_defaults

            _collect_nested_element_defaults(
                section_schema,
                base_path=section_path,
                element_defaults=element_defaults,
            )

    return IISDefaults(
        _section_attribute_defaults=section_attribute_defaults,
        _section_defaults_by_path=section_defaults_by_path,
        _element_defaults=element_defaults,
    )


def _collect_nested_element_defaults(
    node: ET.Element,
    *,
    base_path: str,
    element_defaults: dict[str, dict[str, str]],
) -> None:
    for child in node:
        if child.tag == "element":
            element_name = child.attrib.get("name")
            if not element_name:
                _collect_nested_element_defaults(
                    child,
                    base_path=base_path,
                    element_defaults=element_defaults,
                )
                continue

            element_path = f"{base_path}/{element_name}"
            defaults = _attribute_defaults(child)
            if defaults:
                element_defaults[_normalize_path(element_path)] = defaults
            _collect_nested_element_defaults(
                child,
                base_path=element_path,
                element_defaults=element_defaults,
            )
            continue

        if child.tag == "collection":
            _collect_nested_element_defaults(
                child,
                base_path=base_path,
                element_defaults=element_defaults,
            )


def _attribute_defaults(node: ET.Element) -> dict[str, str]:
    defaults: dict[str, str] = {}
    for child in node:
        if child.tag != "attribute":
            continue
        name = child.attrib.get("name")
        default_value = _attribute_default_value(child)
        if not name or default_value is None:
            continue
        defaults[name] = default_value
    return defaults


def _attribute_default_value(attribute: ET.Element) -> str | None:
    if "defaultValue" not in attribute.attrib:
        return None
    default_value = attribute.attrib["defaultValue"]
    attr_type = attribute.attrib.get("type", "").casefold()
    if attr_type == "bool":
        return default_value.casefold()
    return default_value


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").strip("/").casefold()


def _normalize_attribute_name(name: str) -> str:
    return name.strip().casefold()


_DEFAULTS = _load_schema_defaults()


@lru_cache(maxsize=1)
def load_defaults() -> IISDefaults:
    """Return the cached IIS schema defaults."""
    return _DEFAULTS


__all__ = [
    "IISDefaults",
    "load_defaults",
]
