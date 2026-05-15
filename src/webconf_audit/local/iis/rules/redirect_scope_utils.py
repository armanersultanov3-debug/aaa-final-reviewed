"""Rule module: redirect scope utils.

Location: ``src/webconf_audit/local/iis/rules/redirect_scope_utils.py``.
"""

from __future__ import annotations

from webconf_audit.local.iis.effective import IISEffectiveConfig, IISEffectiveSection

_HTTP_REDIRECT_SUFFIX = "/httpRedirect"


def is_global_http_redirect_only(effective_config: IISEffectiveConfig) -> bool:
    section = effective_config.global_sections.get(_HTTP_REDIRECT_SUFFIX)
    if section is None or not _section_redirects_all_requests(section):
        return False

    for location_sections in effective_config.location_sections.values():
        location_redirect = location_sections.get(_HTTP_REDIRECT_SUFFIX)
        if location_redirect is not None and not _section_redirects_all_requests(
            location_redirect
        ):
            return False

    return True


def _section_redirects_all_requests(section: IISEffectiveSection) -> bool:
    attrs = {key.lower(): value.strip().lower() for key, value in section.attributes.items()}
    if attrs.get("enabled") != "true":
        return False
    if attrs.get("childonly") == "true":
        return False
    return bool(attrs.get("destination"))


__all__ = ["is_global_http_redirect_only"]
