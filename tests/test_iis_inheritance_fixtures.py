from __future__ import annotations

from pathlib import Path

from webconf_audit.local.iis.effective import build_effective_config, merge_effective_configs
from webconf_audit.local.iis.parser import parse_iis_config
from webconf_audit.local.iis.rules_runner import run_iis_rules

_FIXTURE_ROOT = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "webserver-configs"
    / "iis"
    / "inheritance-edge-cases"
)
_HANDLER_RULE_IDS = frozenset(
    {
        "iis.cgi_handler_enabled",
        "iis.handler_write_script_execute_enabled",
    }
)
_MODULE_RULE_IDS = frozenset({"iis.webdav_module_enabled"})
_REQUEST_FILTERING_RULE_IDS = frozenset(
    {
        "iis.file_extensions_allow_unlisted",
        "iis.request_filtering_max_query_string_missing",
        "iis.request_filtering_max_query_string_too_high",
        "iis.request_filtering_max_url_missing",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_remove_server_header_disabled",
    }
)


def _parse_config(path: Path):
    return parse_iis_config(path.read_text(encoding="utf-8"), file_path=str(path))


def _load_fixture(
    name: str,
    *,
    base_name: str,
):
    fixture_root = _FIXTURE_ROOT / name
    base_doc = _parse_config(fixture_root / base_name)
    web_doc = _parse_config(fixture_root / "web.config")
    merged = merge_effective_configs(
        build_effective_config(base_doc),
        build_effective_config(web_doc),
    )
    return base_doc, web_doc, merged


def _rule_ids(doc, effective_config) -> set[str]:
    return {finding.rule_id for finding in run_iis_rules(doc, effective_config=effective_config)}


def test_handlers_machine_vs_web_fixture_merges_and_suppresses_handler_findings() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "handlers-machine-vs-web.config",
        base_name="machine.config",
    )

    handlers = merged.get_effective_section("/handlers")
    assert handlers is not None
    assert handlers.attributes["accessPolicy"] == "Read, Script"
    assert [child.attributes.get("name") for child in handlers.children] == [
        "StaticFile",
        "ApiHandler",
    ]
    assert [Path(origin.file_path).name for origin in handlers.origin_chain] == [
        "machine.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert _HANDLER_RULE_IDS <= base_rule_ids
    assert _HANDLER_RULE_IDS.isdisjoint(merged_rule_ids)


def test_modules_clear_then_add_fixture_resets_inherited_modules() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "modules-clear-then-add.config",
        base_name="applicationHost.config",
    )

    modules = merged.get_effective_section("/modules")
    assert modules is not None
    assert [child.attributes.get("name") for child in modules.children] == [
        "StaticFileModule",
        "RequestFilteringModule",
    ]
    assert [Path(origin.file_path).name for origin in modules.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert "iis.webdav_module_enabled" in base_rule_ids
    assert _MODULE_RULE_IDS.isdisjoint(merged_rule_ids)


def test_request_filtering_inherited_fixture_merges_children_and_rule_inputs() -> None:
    base_doc, web_doc, merged = _load_fixture(
        "requestFiltering-inherited.config",
        base_name="applicationHost.config",
    )

    request_filtering = merged.get_effective_section("/requestFiltering")
    request_limits = merged.get_effective_section("/requestLimits")
    file_extensions = merged.get_effective_section("/fileExtensions")

    assert request_filtering is not None
    assert request_limits is not None
    assert file_extensions is not None

    assert request_filtering.attributes == {"removeServerHeader": "true"}
    assert request_limits.attributes == {
        "maxAllowedContentLength": "4194304",
        "maxQueryString": "1024",
        "maxUrl": "2048",
    }
    assert file_extensions.attributes == {"allowUnlisted": "false"}
    assert [child.attributes.get("fileExtension") for child in file_extensions.children] == [
        ".config",
        ".json",
    ]
    assert [
        Path(origin.file_path).name for origin in request_filtering.origin_chain
    ] == [
        "applicationHost.config",
        "web.config",
    ]
    assert [Path(origin.file_path).name for origin in request_limits.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]
    assert [Path(origin.file_path).name for origin in file_extensions.origin_chain] == [
        "applicationHost.config",
        "web.config",
    ]

    base_rule_ids = _rule_ids(base_doc, build_effective_config(base_doc))
    merged_rule_ids = _rule_ids(web_doc, merged)

    assert {
        "iis.file_extensions_allow_unlisted",
        "iis.request_filtering_max_url_too_high",
        "iis.request_filtering_remove_server_header_disabled",
    } <= base_rule_ids
    assert _REQUEST_FILTERING_RULE_IDS.isdisjoint(merged_rule_ids)
