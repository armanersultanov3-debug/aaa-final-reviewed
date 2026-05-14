"""IIS effective configuration reconstruction for a single file scope.

Merges global sections with location-scoped overrides and applies
child-element collection semantics (clear / remove / add).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from webconf_audit.local.iis.iis_defaults import load_defaults
from webconf_audit.local.iis.parser import (
    IISChildElement,
    IISConfigDocument,
    IISSection,
    IISSourceRef,
)

_REMOVE_KEY_COMBINATIONS: tuple[tuple[str, ...], ...] = (
    ("statusCode",),
    ("ipAddress", "subnetMask"),
    ("ipAddress",),
    ("name", "path", "verb"),
    ("name",),
    ("path", "verb"),
    ("path",),
)


@dataclass(frozen=True, slots=True)
class IISEffectiveSection:
    """A section after global and location merge."""

    tag: str
    section_path_suffix: str
    attributes: dict[str, str]
    children: list[IISChildElement]
    location_path: str | None
    origin_chain: list[IISSourceRef]
    child_operations: list[IISChildElement] = field(default_factory=list)
    section_path: str | None = None
    materialized_from_defaults: bool = False
    # When the section was contributed by a parent ``<location>`` block
    # with ``inheritInChildApplications="false"`` (default ``True``).
    # Used by ``merge_effective_configs`` to gate cross-file inheritance
    # into deeper-nested child applications.
    inherit_in_child_applications: bool = True

    @property
    def source(self) -> IISSourceRef:
        """Source of the most specific contributing section."""
        return self.origin_chain[-1]


@dataclass(frozen=True, slots=True)
class IISEffectiveConfig:
    """Effective configuration for one IIS config file."""

    global_sections: dict[str, IISEffectiveSection] = field(default_factory=dict)
    location_sections: dict[str, dict[str, IISEffectiveSection]] = field(
        default_factory=dict,
    )

    def get_effective_section(
        self,
        suffix: str,
        location_path: str | None = None,
    ) -> IISEffectiveSection | None:
        """Return the effective section for a suffix and optional location."""
        if location_path is not None:
            loc = self.location_sections.get(location_path, {})
            return loc.get(suffix)
        return self.global_sections.get(suffix)

    def get_effective_section_by_path(
        self,
        section_path: str,
        location_path: str | None = None,
    ) -> IISEffectiveSection | None:
        """Return the effective section for a canonical IIS section path."""
        target = _normalize_section_path(section_path)
        sections = (
            _effective_sections_for_location(self, location_path)
            if location_path is not None
            else self.global_sections
        )
        for section in sections.values():
            if _normalize_section_path(
                section.section_path or section.source.xml_path or "",
            ) == target:
                return section
        return None

    def get_effective_or_default_section(
        self,
        section_path: str,
        *,
        location_path: str | None = None,
        anchor_paths: tuple[str, ...] = (),
    ) -> IISEffectiveSection | None:
        """Return the effective section, or a schema-default materialization."""
        defaults = _default_attributes_for_section_path(section_path)
        section = self.get_effective_section_by_path(
            section_path,
            location_path=location_path,
        )
        if section is not None:
            if not defaults:
                return section
            merged_attributes = dict(defaults)
            merged_attributes.update(section.attributes)
            if merged_attributes == section.attributes:
                return section
            return IISEffectiveSection(
                tag=section.tag,
                section_path_suffix=section.section_path_suffix,
                attributes=merged_attributes,
                children=list(section.children),
                location_path=section.location_path,
                origin_chain=list(section.origin_chain),
                child_operations=list(section.child_operations),
                section_path=section.section_path,
                materialized_from_defaults=True,
                inherit_in_child_applications=section.inherit_in_child_applications,
            )

        if not defaults:
            return None

        anchor = _default_anchor(
            self,
            location_path=location_path,
            anchor_paths=anchor_paths,
        )
        if anchor is None:
            return None

        tag = section_path.strip("/").split("/")[-1]
        return IISEffectiveSection(
            tag=tag,
            section_path_suffix=f"/{tag}",
            attributes=defaults,
            children=[],
            location_path=location_path,
            origin_chain=list(anchor.origin_chain),
            child_operations=[],
            section_path=section_path,
            materialized_from_defaults=True,
        )

    @property
    def all_sections(self) -> list[IISEffectiveSection]:
        """Return all effective sections across global and locations."""
        result = list(self.global_sections.values())
        for loc_dict in self.location_sections.values():
            result.extend(loc_dict.values())
        return result


def build_effective_config(doc: IISConfigDocument) -> IISEffectiveConfig:
    """Build effective config from a parsed IIS config document."""
    global_raw, location_raw = _group_raw_sections(doc.sections)
    global_effective = _merge_global_sections(global_raw)
    location_effective = _merge_location_sections(location_raw, global_effective)
    return IISEffectiveConfig(
        global_sections=global_effective,
        location_sections=location_effective,
    )


def _group_raw_sections(
    sections: list[IISSection],
) -> tuple[
    dict[str, list[IISSection]],
    dict[str, dict[str, list[IISSection]]],
]:
    global_raw: dict[str, list[IISSection]] = {}
    location_raw: dict[str, dict[str, list[IISSection]]] = {}
    for section in sections:
        suffix = _section_suffix(section.xml_path)
        if section.location_path is None:
            global_raw.setdefault(suffix, []).append(section)
            continue

        loc_dict = location_raw.setdefault(section.location_path, {})
        loc_dict.setdefault(suffix, []).append(section)
    return global_raw, location_raw


def _merge_global_sections(
    global_raw: dict[str, list[IISSection]],
) -> dict[str, IISEffectiveSection]:
    global_effective: dict[str, IISEffectiveSection] = {}
    for suffix, sections in global_raw.items():
        global_effective[suffix] = _merge_sections(sections, location_path=None)
    return global_effective


def _merge_location_sections(
    location_raw: dict[str, dict[str, list[IISSection]]],
    global_effective: dict[str, IISEffectiveSection],
) -> dict[str, dict[str, IISEffectiveSection]]:
    location_effective: dict[str, dict[str, IISEffectiveSection]] = {}
    for location_path in sorted(
        location_raw,
        key=lambda path: (path.count("/"), path),
    ):
        parent_effective = _find_parent_effective(
            location_path,
            location_effective,
            global_effective,
        )
        location_effective[location_path] = _merge_location_section_dict(
            location_path,
            parent_effective,
            location_raw[location_path],
        )
    return location_effective


def _merge_location_section_dict(
    location_path: str,
    parent_effective: dict[str, IISEffectiveSection],
    raw_sections: dict[str, list[IISSection]],
) -> dict[str, IISEffectiveSection]:
    merged: dict[str, IISEffectiveSection] = {}
    for suffix in set(parent_effective) | set(raw_sections):
        base = parent_effective.get(suffix)
        overrides = raw_sections.get(suffix, [])
        if not overrides:
            if base is not None:
                merged[suffix] = _clone_effective_section(
                    base,
                    location_path=location_path,
                )
            continue

        merged[suffix] = _merge_location_section_overrides(
            overrides,
            base,
            location_path,
        )
    return merged


def _merge_location_section_overrides(
    overrides: list[IISSection],
    base: IISEffectiveSection | None,
    location_path: str,
) -> IISEffectiveSection:
    base_attrs = dict(base.attributes) if base else {}
    base_children = list(base.children) if base else []
    base_child_operations = list(base.child_operations) if base else []
    base_origin = list(base.origin_chain) if base else []
    base_inherit = base.inherit_in_child_applications if base else True
    return _merge_sections(
        overrides,
        location_path=location_path,
        base_attrs=base_attrs,
        base_children=base_children,
        base_child_operations=base_child_operations,
        base_origin=base_origin,
        base_inherit_in_child_applications=base_inherit,
    )


def _find_parent_effective(
    loc_path: str,
    location_effective: dict[str, dict[str, IISEffectiveSection]],
    global_effective: dict[str, IISEffectiveSection],
) -> dict[str, IISEffectiveSection]:
    """Find the nearest parent location's effective sections for *loc_path*."""
    parts = loc_path.replace("\\", "/").split("/")
    for depth in range(len(parts) - 1, 0, -1):
        candidate = "/".join(parts[:depth])
        if candidate in location_effective:
            return location_effective[candidate]
    return global_effective


def _merge_sections(
    sections: list[IISSection],
    *,
    location_path: str | None,
    base_attrs: dict[str, str] | None = None,
    base_children: list[IISChildElement] | None = None,
    base_child_operations: list[IISChildElement] | None = None,
    base_origin: list[IISSourceRef] | None = None,
    base_inherit_in_child_applications: bool = True,
) -> IISEffectiveSection:
    """Merge multiple raw sections into one effective section."""
    attrs = dict(base_attrs) if base_attrs else {}
    children = list(base_children) if base_children else []
    child_operations = list(base_child_operations) if base_child_operations else []
    origin = list(base_origin) if base_origin else []
    tag = sections[-1].tag
    inherit_in_child_applications = base_inherit_in_child_applications

    for section in sections:
        attrs.update(section.attributes)
        origin.append(section.source)
        child_operations.extend(section.children)
        children = _merge_children(children, section.children)
        # AND-fold: a single ``inheritInChildApplications="false"`` on any
        # contributing source blocks the cascade into child applications.
        # This is the conservative interpretation when multiple ``<location>``
        # blocks for the same path contradict each other.
        inherit_in_child_applications = (
            inherit_in_child_applications
            and section.location_inherit_in_child_applications
        )

    suffix = _section_suffix(sections[-1].xml_path)
    return IISEffectiveSection(
        tag=tag,
        section_path_suffix=suffix,
        attributes=attrs,
        children=children,
        location_path=location_path,
        origin_chain=origin,
        child_operations=child_operations,
        section_path=_strip_configuration_path(sections[-1].xml_path),
        inherit_in_child_applications=inherit_in_child_applications,
    )


def _merge_children(
    base: list[IISChildElement],
    incoming: list[IISChildElement],
) -> list[IISChildElement]:
    """Apply IIS collection semantics to child elements."""
    result = list(base)
    for child in incoming:
        tag_lower = child.tag.lower()
        if tag_lower == "clear":
            result.clear()
            continue
        if tag_lower == "remove":
            if child.attributes:
                result = [
                    candidate
                    for candidate in result
                    if not _matches_remove_attributes(candidate, child)
                ]
            continue
        result.append(child)
    return result


def _matches_remove_attributes(
    candidate: IISChildElement,
    remove_child: IISChildElement,
) -> bool:
    """Return True when *candidate* matches every selected remove attribute."""
    match_attributes = _remove_match_attributes(remove_child)
    return all(
        candidate.attributes.get(name) == value
        for name, value in match_attributes.items()
    )


def _remove_match_attributes(remove_child: IISChildElement) -> dict[str, str]:
    attrs = remove_child.attributes
    for key_names in _REMOVE_KEY_COMBINATIONS:
        matched = _matching_remove_keys(attrs, key_names)
        if matched:
            return matched
    return attrs


def _matching_remove_keys(
    attrs: dict[str, str],
    key_names: tuple[str, ...],
) -> dict[str, str]:
    # IIS treats a ``<remove>`` element's key group as atomic: the whole
    # combination must be present on the element for it to be considered
    # a match.  Returning a partial dict when only some of the keys are
    # present (e.g. only ``ipAddress`` from the ``ipAddress``+``subnetMask``
    # pair used by ``ipSecurity``) causes the caller to match the wrong
    # entry and drop a different element from the collection.  Require
    # every key to be present before reporting a hit.
    if not all(name in attrs for name in key_names):
        return {}
    return {name: attrs[name] for name in key_names}


def _section_suffix(xml_path: str) -> str:
    """Extract the section-identifying suffix from an xml_path."""
    last_slash = xml_path.rfind("/")
    if last_slash >= 0:
        return xml_path[last_slash:]
    return f"/{xml_path}"


def merge_effective_configs(
    base: IISEffectiveConfig,
    override: IISEffectiveConfig,
    *,
    child_application_path: str | None = None,
) -> IISEffectiveConfig:
    """Merge two effective configs such as applicationHost.config and web.config.

    When ``child_application_path`` is given, the merge represents inheriting
    the ``base`` (parent) configuration into a deeper-nested child application
    rooted at that path.  Sections from the ``base`` that are scoped to an
    ancestor ``<location>`` with ``inheritInChildApplications="false"`` are
    dropped from the inherited view to honour IIS's cascade-blocking semantic.
    """
    filtered_base = (
        _filter_for_child_application(base, child_application_path)
        if child_application_path is not None
        else base
    )

    merged_global = _merge_section_dicts(
        filtered_base.global_sections,
        override.global_sections,
        location_path=None,
    )

    merged_locations: dict[str, dict[str, IISEffectiveSection]] = {}
    all_location_paths = (
        set(filtered_base.location_sections) | set(override.location_sections)
    )
    for location_path in sorted(all_location_paths, key=lambda path: (path.count("/"), path)):
        base_loc = _effective_sections_for_location(filtered_base, location_path)
        override_loc = _effective_sections_for_location(override, location_path)
        merged_locations[location_path] = _merge_section_dicts(
            base_loc,
            override_loc,
            location_path=location_path,
        )

    return IISEffectiveConfig(
        global_sections=merged_global,
        location_sections=merged_locations,
    )


def _filter_for_child_application(
    base: IISEffectiveConfig,
    child_application_path: str,
) -> IISEffectiveConfig:
    """Drop base sections that should not cascade into a child application.

    A section is dropped when:

    * It is scoped to a ``<location path=...>`` whose path is an *ancestor*
      (or equal) of ``child_application_path`` AND that location declared
      ``inheritInChildApplications="false"``.

    A section scoped to the same path as the child application itself is
    also dropped on the same grounds — IIS treats the gating block as
    not extending into child applications, which includes the child
    application's own root scope.
    """
    normalized_child = _normalize_location_path(child_application_path)

    filtered_globals: dict[str, IISEffectiveSection] = {
        suffix: section
        for suffix, section in base.global_sections.items()
        if section.inherit_in_child_applications
    }
    filtered_locations: dict[str, dict[str, IISEffectiveSection]] = {}
    for loc_path, sections in base.location_sections.items():
        if _is_ancestor_or_equal_location(loc_path, normalized_child):
            kept = {
                suffix: section
                for suffix, section in sections.items()
                if section.inherit_in_child_applications
            }
            if kept:
                filtered_locations[loc_path] = kept
        else:
            filtered_locations[loc_path] = dict(sections)

    return IISEffectiveConfig(
        global_sections=filtered_globals,
        location_sections=filtered_locations,
    )


def _is_ancestor_or_equal_location(
    candidate: str | None,
    descendant: str | None,
) -> bool:
    """Return True when ``candidate`` is the same as ``descendant`` or an ancestor."""
    norm_candidate = _normalize_location_path(candidate or "")
    norm_descendant = _normalize_location_path(descendant or "")
    if not norm_candidate or not norm_descendant:
        return False
    if norm_candidate == norm_descendant:
        return True
    return norm_descendant.startswith(norm_candidate + "/")


def _normalize_location_path(path: str | None) -> str:
    if path is None:
        return ""
    return path.replace("\\", "/").strip("/")


def _merge_section_dicts(
    base: dict[str, IISEffectiveSection],
    override: dict[str, IISEffectiveSection],
    *,
    location_path: str | None,
) -> dict[str, IISEffectiveSection]:
    """Merge two suffix-to-section mappings using IIS merge semantics."""
    merged: dict[str, IISEffectiveSection] = {}
    for suffix in set(base) | set(override):
        base_sec = base.get(suffix)
        override_sec = override.get(suffix)
        if base_sec is None and override_sec is not None:
            merged[suffix] = _clone_effective_section(
                override_sec,
                location_path=location_path,
            )
            continue
        if override_sec is None and base_sec is not None:
            merged[suffix] = _clone_effective_section(
                base_sec,
                location_path=location_path,
            )
            continue
        if base_sec is not None and override_sec is not None:
            merged[suffix] = _merge_effective_section_pair(
                base_sec,
                override_sec,
                location_path=location_path,
            )
    return merged


def _merge_effective_section_pair(
    base: IISEffectiveSection,
    override: IISEffectiveSection,
    *,
    location_path: str | None,
) -> IISEffectiveSection:
    """Merge two effective sections where override children already won locally."""
    attrs = dict(base.attributes)
    attrs.update(override.attributes)
    child_operations = (
        override.child_operations
        if override.child_operations
        else override.children
    )
    children = _merge_children(base.children, child_operations)
    origin = list(base.origin_chain) + list(override.origin_chain)
    return IISEffectiveSection(
        tag=override.tag,
        section_path_suffix=override.section_path_suffix,
        attributes=attrs,
        children=children,
        location_path=location_path if location_path is not None else override.location_path,
        origin_chain=origin,
        child_operations=list(base.child_operations) + list(child_operations),
        section_path=override.section_path,
        materialized_from_defaults=(
            base.materialized_from_defaults and override.materialized_from_defaults
        ),
        # Most-restrictive AND-fold: if either contributor blocks cascade,
        # the merged effective section blocks it as well.
        inherit_in_child_applications=(
            base.inherit_in_child_applications
            and override.inherit_in_child_applications
        ),
    )


def _effective_sections_for_location(
    config: IISEffectiveConfig,
    location_path: str,
) -> dict[str, IISEffectiveSection]:
    if location_path in config.location_sections:
        return config.location_sections[location_path]
    return _find_parent_effective(
        location_path,
        config.location_sections,
        config.global_sections,
    )


def _clone_effective_section(
    section: IISEffectiveSection,
    *,
    location_path: str | None,
) -> IISEffectiveSection:
    return IISEffectiveSection(
        tag=section.tag,
        section_path_suffix=section.section_path_suffix,
        attributes=dict(section.attributes),
        children=list(section.children),
        location_path=location_path if location_path is not None else section.location_path,
        origin_chain=list(section.origin_chain),
        child_operations=list(section.child_operations),
        section_path=section.section_path,
        materialized_from_defaults=section.materialized_from_defaults,
        inherit_in_child_applications=section.inherit_in_child_applications,
    )


def _default_attributes_for_section_path(section_path: str) -> dict[str, str]:
    defaults = load_defaults()
    section_defaults = defaults.get_section_defaults(section_path)
    if section_defaults:
        return section_defaults
    return defaults.get_element_default(section_path)


def _default_anchor(
    config: IISEffectiveConfig,
    *,
    location_path: str | None,
    anchor_paths: tuple[str, ...],
) -> IISEffectiveSection | None:
    for index, anchor_path in enumerate(anchor_paths):
        anchor = config.get_effective_section_by_path(
            anchor_path,
            location_path=location_path,
        )
        if anchor is not None:
            return anchor

    for index, anchor_path in enumerate(anchor_paths):
        anchor = config.get_effective_or_default_section(
            anchor_path,
            location_path=location_path,
            anchor_paths=anchor_paths[index + 1 :],
        )
        if anchor is not None:
            return anchor
    return None


def _strip_configuration_path(xml_path: str) -> str:
    parts = [part for part in xml_path.replace("\\", "/").split("/") if part]
    if parts and parts[0].casefold() == "configuration":
        parts = parts[1:]
    parts = [part for part in parts if not part.casefold().startswith("location[@path=")]
    return "/".join(parts)


def _normalize_section_path(path: str) -> str:
    if path.casefold().startswith("configuration/"):
        path = _strip_configuration_path(path)
    return path.replace("\\", "/").strip("/").casefold()


__all__ = [
    "IISEffectiveConfig",
    "IISEffectiveSection",
    "build_effective_config",
    "merge_effective_configs",
]
