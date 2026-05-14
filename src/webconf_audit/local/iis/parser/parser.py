from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
# ``defusedxml.ElementTree`` hardens parsing against XXE / external-entity
# attacks but intentionally does not re-export the ``Element`` class:
# types still have to come from the stdlib ``xml.etree.ElementTree``
# module, so import them separately and keep ``ET`` for parser calls.
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import Element as _XmlElement


IISConfigKind = Literal["applicationHost", "web", "machine", "unknown"]


class IISParseError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        file_path: str | None = None,
        line: int | None = None,
    ) -> None:
        self.file_path = file_path
        self.line = line
        super().__init__(message)


@dataclass(slots=True)
class IISSourceRef:
    file_path: str | None = None
    xml_path: str | None = None
    line: int | None = None


@dataclass(slots=True)
class IISChildElement:
    tag: str
    attributes: dict[str, str] = field(default_factory=dict)
    source: IISSourceRef = field(default_factory=IISSourceRef)
    children: list[IISChildElement] = field(default_factory=list)


@dataclass(slots=True)
class IISSection:
    tag: str
    xml_path: str
    attributes: dict[str, str] = field(default_factory=dict)
    children: list[IISChildElement] = field(default_factory=list)
    location_path: str | None = None
    source: IISSourceRef = field(default_factory=IISSourceRef)
    # ``inheritInChildApplications`` lives on the ``<location>`` block in
    # ``applicationHost.config`` / parent ``web.config``.  When ``False``,
    # settings inside the location apply to the path itself but do NOT
    # cascade into deeper-nested child applications.  Default ``True``
    # mirrors IIS's documented behaviour for an absent attribute.
    location_inherit_in_child_applications: bool = True


@dataclass(slots=True)
class IISConfigDocument:
    root_tag: str
    config_kind: IISConfigKind
    sections: list[IISSection]
    file_path: str | None = None


def classify_config_kind(
    root_tag: str,
    file_path: str | None,
    *,
    root: _XmlElement | None = None,
) -> IISConfigKind:
    if file_path is not None:
        lower_path = file_path.lower().replace("\\", "/")
        if lower_path.endswith("applicationhost.config"):
            return "applicationHost"
        if lower_path.endswith("machine.config"):
            return "machine"
        if lower_path.endswith("web.config"):
            return "web"

    if root_tag == "configuration":
        if root is not None:
            child_tags = {child.tag for child in root}
            if "system.applicationHost" in child_tags:
                return "applicationHost"
            if _looks_like_machine_config(child_tags):
                return "machine"
        return "unknown"

    return "unknown"


def parse_iis_config(
    text: str,
    *,
    file_path: str | None = None,
) -> IISConfigDocument:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        line = exc.position[0] if exc.position else None
        raise IISParseError(
            f"XML parse error: {exc}",
            file_path=file_path,
            line=line,
        ) from exc
    except DefusedXmlException as exc:
        raise IISParseError(
            f"XML parse error: {exc}",
            file_path=file_path,
        ) from exc

    config_kind = classify_config_kind(root.tag, file_path, root=root)
    sections = _extract_sections(root, file_path=file_path)

    return IISConfigDocument(
        root_tag=root.tag,
        config_kind=config_kind,
        sections=sections,
        file_path=file_path,
    )


def _extract_sections(
    root: _XmlElement,
    *,
    file_path: str | None = None,
) -> list[IISSection]:
    sections: list[IISSection] = []

    for child in root:
        if child.tag == "location":
            loc_path = child.attrib.get("path", "")
            loc_prefix = f"{root.tag}/location[@path='{loc_path}']"
            inherit_in_child = _parse_inherit_in_child_applications(
                child.attrib.get("inheritInChildApplications"),
            )
            for grandchild in child:
                _append_section_tree(
                    grandchild,
                    parent_path=loc_prefix,
                    sections=sections,
                    file_path=file_path,
                    location_path=loc_path or None,
                    location_inherit_in_child_applications=inherit_in_child,
                )
        else:
            _append_section_tree(
                child,
                parent_path=root.tag,
                sections=sections,
                file_path=file_path,
                location_path=None,
                location_inherit_in_child_applications=True,
            )

    return sections


def _parse_inherit_in_child_applications(value: str | None) -> bool:
    """Parse the ``inheritInChildApplications`` attribute value.

    IIS treats anything other than a literal ``false`` (case-insensitive,
    stripped) as the default ``true``.  This matches the schema-typed
    boolean attribute semantics used elsewhere in IIS XML.
    """
    if value is None:
        return True
    return value.strip().casefold() != "false"


def _looks_like_machine_config(child_tags: set[str]) -> bool:
    return "configSections" in child_tags and bool(
        child_tags & {"system.web", "runtime", "mscorlib"}
    )


_CHILD_DIRECTIVE_TAGS = frozenset({
    "add", "remove", "clear", "error", "binding",
    "deny", "allow", "rule", "filter", "limit",
})


def _is_child_directive(element: _XmlElement) -> bool:
    """Return True if the element should be stored as a child of its parent section."""
    return element.tag.lower() in _CHILD_DIRECTIVE_TAGS


def _append_section_tree(
    element: _XmlElement,
    *,
    parent_path: str,
    sections: list[IISSection],
    file_path: str | None,
    location_path: str | None = None,
    location_inherit_in_child_applications: bool = True,
) -> None:
    xml_path = f"{parent_path}/{element.tag}"
    child_elements: list[IISChildElement] = []
    sub_elements: list[_XmlElement] = []

    for child in element:
        if _is_child_directive(child):
            child_elements.append(
                _build_child_element(
                    child,
                    file_path=file_path,
                    xml_path=f"{xml_path}/{child.tag}",
                )
            )
        else:
            sub_elements.append(child)

    sections.append(
        IISSection(
            tag=element.tag,
            xml_path=xml_path,
            attributes=dict(element.attrib),
            children=child_elements,
            location_path=location_path,
            source=IISSourceRef(
                file_path=file_path,
                xml_path=xml_path,
            ),
            location_inherit_in_child_applications=(
                location_inherit_in_child_applications
            ),
        )
    )

    for sub in sub_elements:
        _append_section_tree(
            sub,
            parent_path=xml_path,
            sections=sections,
            file_path=file_path,
            location_path=location_path,
            location_inherit_in_child_applications=(
                location_inherit_in_child_applications
            ),
        )


def _build_child_element(
    element: _XmlElement,
    *,
    file_path: str | None,
    xml_path: str,
) -> IISChildElement:
    return IISChildElement(
        tag=element.tag,
        attributes=dict(element.attrib),
        source=IISSourceRef(
            file_path=file_path,
            xml_path=xml_path,
        ),
        children=[
            _build_child_element(
                child,
                file_path=file_path,
                xml_path=f"{xml_path}/{child.tag}",
            )
            for child in element
        ],
    )


__all__ = [
    "IISChildElement",
    "IISConfigDocument",
    "IISConfigKind",
    "IISParseError",
    "IISSection",
    "IISSourceRef",
    "classify_config_kind",
    "parse_iis_config",
]
