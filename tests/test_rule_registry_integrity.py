"""Integrity tests for the rule registry.

Verify that all rule packages load the expected number of rules into
the catalog and executable stores, with no duplicate IDs and correct
ordering.
"""

from __future__ import annotations

import importlib
import pkgutil

import pytest

import webconf_audit.local.iis.rules as iis_rules_package
import webconf_audit.external.rules._runner as external_runner
from webconf_audit.external.rules._runner import register_external_rule_metas
from webconf_audit.rule_registry import RuleRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_registry() -> RuleRegistry:
    """Return a registry loaded with all known rule packages."""
    reg = RuleRegistry()
    # Executable rules (decorator-based)
    reg.ensure_loaded("webconf_audit.local.rules.universal")
    reg.ensure_loaded("webconf_audit.local.nginx.rules")
    reg.ensure_loaded("webconf_audit.local.apache.rules")
    reg.ensure_loaded("webconf_audit.local.lighttpd.rules")
    reg.ensure_loaded("webconf_audit.local.iis.rules")
    reg.ensure_loaded("webconf_audit.external.rules")
    register_external_rule_metas(reg)
    return reg


def test_iis_rule_modules_import_individually() -> None:
    module_names = [
        module_info.name
        for module_info in pkgutil.iter_modules(iis_rules_package.__path__)
        if not module_info.ispkg
    ]

    assert module_names

    for module_name in module_names:
        importlib.import_module(f"{iis_rules_package.__name__}.{module_name}")


@pytest.fixture
def full_reg() -> RuleRegistry:
    return _fresh_registry()


# ---------------------------------------------------------------------------
# Total counts
# ---------------------------------------------------------------------------

class TestTotalCounts:
    def test_catalog_total(self, full_reg: RuleRegistry) -> None:
        assert len(full_reg._catalog) == 370

    def test_executable_total(self, full_reg: RuleRegistry) -> None:
        assert len(full_reg._executable) == 284


# ---------------------------------------------------------------------------
# Per-category / per-server counts
# ---------------------------------------------------------------------------

class TestCategoryCounts:
    def test_universal(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="universal")
        assert len(rules) == 13

    def test_nginx(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="nginx")
        assert len(rules) == 83

    def test_apache(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="apache")
        assert len(rules) == 84

    def test_lighttpd(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="lighttpd")
        assert len(rules) == 49

    def test_iis(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="local", server_type="iis")
        assert len(rules) == 52

    def test_external(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="external")
        assert len(rules) == 89

    def test_external_meta_registration_is_idempotent_after_clear(self) -> None:
        reg = RuleRegistry()
        register_external_rule_metas(reg)
        first_size = reg.catalog_size

        register_external_rule_metas(reg)
        assert reg.catalog_size == first_size == 86

        reg.clear()
        register_external_rule_metas(reg)

        assert reg.catalog_size == 86
        assert reg.get_meta("external.https_not_available") is not None

    def test_external_meta_registration_rejects_duplicate_seed_ids(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first_meta = external_runner._EXTERNAL_RULE_METAS[0]
        monkeypatch.setattr(
            external_runner,
            "_EXTERNAL_RULE_METAS",
            [first_meta, first_meta],
        )

        with pytest.raises(ValueError, match="Duplicate external rule_id"):
            register_external_rule_metas(RuleRegistry())


# ---------------------------------------------------------------------------
# Standards metadata
# ---------------------------------------------------------------------------

class TestStandardsMetadata:
    def test_apache_default_tls_vhost_rule_has_standards(self, full_reg: RuleRegistry) -> None:
        meta = full_reg.get_meta("apache.default_tls_vhost_not_rejecting_unknown_hosts")
        assert meta is not None

        references = {(ref.standard, ref.reference) for ref in meta.standards}
        assert ("OWASP Top 10", "A05:2021") in references
        assert any(
            ref.standard == "CIS"
            and ref.reference.startswith("Apache HTTP Server 2.4 v2.3.0 ")
            for ref in meta.standards
        )

    def test_apache_allowoverride_rules_have_expected_standards(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        expectations = {
            "apache.allowoverride_not_none": {
                ("CWE", "CWE-732"),
                ("OWASP Top 10", "A05:2021"),
                ("CIS", "Apache HTTP Server 2.4 v2.3.0 §4.3/§4.4"),
            },
            "apache.directory_without_allowoverride": {
                ("OWASP Top 10", "A05:2021"),
                ("CIS", "Apache HTTP Server 2.4 v2.3.0 §4.4"),
            },
        }

        for rule_id, expected_refs in expectations.items():
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert expected_refs.issubset(references)

    def test_followup_rules_have_expected_standards(self, full_reg: RuleRegistry) -> None:
        expectations = {
            "nginx.auth_basic_over_http": {
                ("CWE", "CWE-319"),
                ("OWASP Top 10", "A02:2021"),
                ("OWASP ASVS", "v5.0.0-12.2.1"),
                ("NIST SP 800-53 Rev. 5", "IA-2"),
                ("PCI DSS v4.0.1", "Req. 8.3.1"),
                ("BSI IT-Grundschutz", "APP.3.2.A5"),
                ('ФСТЭК "Меры защиты информации в ГИС"', "ИАФ.1"),
            },
            "external.cookie_prefix_contract_violated": {
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-3.3.1"),
            },
            "external.content_security_policy_nonce_reused": {
                ("CWE", "CWE-693"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-3.4.3"),
            },
        }

        for rule_id, expected_refs in expectations.items():
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert expected_refs.issubset(references)

    def test_new_mapping_rules_have_expected_standards(self, full_reg: RuleRegistry) -> None:
        expectations = {
            "nginx.log_format_missing_fields": {
                ("CWE", "CWE-778"),
                ("OWASP Top 10", "A09:2021"),
            },
            "apache.log_format_missing_fields": {
                ("CWE", "CWE-778"),
                ("OWASP Top 10", "A09:2021"),
            },
            "nginx.sensitive_config_files_not_restricted": {
                ("CWE", "CWE-538"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-13.4.7"),
            },
            "apache.sensitive_config_files_not_restricted": {
                ("CWE", "CWE-538"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-13.4.7"),
            },
            "nginx.sitewide_http_method_policy_missing": {
                ("CWE", "CWE-650"),
                ("OWASP Top 10", "A05:2021"),
                ("CIS", "NGINX v3.0.0 §5.1.2"),
            },
            "external.backup_file_exposed": {
                ("CWE", "CWE-538"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-13.4.7"),
            },
            "nginx.default_tls_server_not_rejecting_unknown_hosts": {
                ("OWASP Top 10", "A05:2021"),
                ("CIS", "NGINX v3.0.0 §2.4.2"),
            },
        }

        for rule_id, expected_refs in expectations.items():
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert expected_refs.issubset(references)

    def test_nginx_ocsp_stapling_rules_have_expected_standards(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        expectations = {
            "nginx.ssl_stapling_disabled": {
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-12.1.4"),
                ("CIS", "NGINX v3.0.0 §4.1.7"),
            },
            "nginx.ssl_stapling_missing_resolver": {
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-12.1.4"),
                ("CIS", "NGINX v3.0.0 §4.1.7"),
            },
            "nginx.ssl_stapling_without_verify": {
                ("CWE", "CWE-295"),
                ("OWASP Top 10", "A02:2021"),
                ("OWASP ASVS", "v5.0.0-12.1.4"),
                ("CIS", "NGINX v3.0.0 §4.1.7"),
            },
        }

        for rule_id, expected_refs in expectations.items():
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert expected_refs.issubset(references)

            asvs_refs = [
                ref
                for ref in meta.standards
                if ref.standard == "OWASP ASVS" and ref.reference == "v5.0.0-12.1.4"
            ]
            assert len(asvs_refs) == 1
            assert asvs_refs[0].coverage == "partial"

    def test_cookie_prefix_contract_mapping_is_partial(self, full_reg: RuleRegistry) -> None:
        meta = full_reg.get_meta("external.cookie_prefix_contract_violated")
        assert meta is not None

        asvs_refs = [
            ref
            for ref in meta.standards
            if ref.standard == "OWASP ASVS" and ref.reference == "v5.0.0-3.3.1"
        ]
        assert len(asvs_refs) == 1
        assert asvs_refs[0].coverage == "partial"

    def test_csp_frame_ancestors_local_rules_have_expected_standards(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        for rule_id in (
            "nginx.content_security_policy_missing_frame_ancestors",
            "apache.content_security_policy_missing_frame_ancestors",
            "lighttpd.content_security_policy_missing_frame_ancestors",
            "iis.content_security_policy_missing_frame_ancestors",
        ):
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert {
                ("CWE", "CWE-1021"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-3.4.6"),
            }.issubset(references)

    def test_tls_legacy_direct_rules_have_rfc_8996_mapping(self, full_reg: RuleRegistry) -> None:
        for rule_id in (
            "nginx.weak_ssl_protocols",
            "apache.tls_legacy_versions_explicitly_enabled",
            "lighttpd.tls_legacy_versions_explicitly_enabled",
            "iis.schannel_weak_protocol_enabled",
        ):
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert {
                ("CWE", "CWE-327"),
                ("OWASP Top 10", "A02:2021"),
                ("OWASP ASVS", "v5.0.0-12.1.1"),
                ("IETF RFC", "RFC 8996"),
            }.issubset(references)

            rfc_refs = [
                ref
                for ref in meta.standards
                if ref.standard == "IETF RFC" and ref.reference == "RFC 8996"
            ]
            assert len(rfc_refs) == 1
            assert rfc_refs[0].coverage == "partial"

    def test_local_hsts_policy_rules_have_expected_standards(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        for rule_id in (
            "nginx.hsts_header_unsafe",
            "apache.hsts_header_unsafe",
            "lighttpd.strict_transport_security_unsafe",
            "iis.hsts_header_unsafe",
        ):
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            references = {(ref.standard, ref.reference) for ref in meta.standards}
            assert {
                ("CWE", "CWE-319"),
                ("OWASP Top 10", "A05:2021"),
                ("OWASP ASVS", "v5.0.0-3.4.1"),
            }.issubset(references)

            asvs_refs = [
                ref
                for ref in meta.standards
                if ref.standard == "OWASP ASVS" and ref.reference == "v5.0.0-3.4.1"
            ]
            assert len(asvs_refs) == 1
            assert asvs_refs[0].coverage == "partial"

    def test_doc_migrated_rules_expose_primary_and_secondary_standards(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        expectations = {
            "external.https_not_available": {
                "primary": {
                    ("PCI DSS v4.0.1", "Req. 4.2.1"),
                    ("NIST SP 800-52 Rev. 2", "NO PLAINTEXT FALLBACK"),
                    ('ФСТЭК "Меры защиты информации в ГИС"', "УПД.13"),
                    ("ISO/IEC 27002:2022", "8.21"),
                },
                "secondary": {
                    ("MITRE ATT&CK Enterprise v15", "T1040"),
                    ("ФСТЭК БДУ", "УБИ.044"),
                },
            },
            "lighttpd.missing_http_method_restrictions": {
                "primary": {
                    ("Vendor", "DevSec lighttpd-baseline lighttpd-05"),
                },
                "secondary": set(),
            },
            "nginx.missing_content_security_policy": {
                "primary": {
                    ("PCI DSS v4.0.1", "Req. 6.4.3"),
                    ("OWASP Cheat Sheet Series", "Content Security Policy"),
                },
                "secondary": set(),
            },
        }

        for rule_id, expected in expectations.items():
            meta = full_reg.get_meta(rule_id)
            assert meta is not None

            primary_refs = {(ref.standard, ref.reference) for ref in meta.standards}
            secondary_refs = {
                (ref.standard, ref.reference)
                for ref in meta.standards_secondary
            }
            assert expected["primary"].issubset(primary_refs)
            assert expected["secondary"].issubset(secondary_refs)

    def test_no_rule_duplicates_same_reference_across_primary_and_secondary(
        self,
        full_reg: RuleRegistry,
    ) -> None:
        for meta in full_reg.list_rules():
            primary = {(ref.standard, ref.reference) for ref in meta.standards}
            secondary = {
                (ref.standard, ref.reference)
                for ref in meta.standards_secondary
            }
            assert not primary & secondary, meta.rule_id


# ---------------------------------------------------------------------------
# No duplicate rule IDs
# ---------------------------------------------------------------------------

class TestNoDuplicates:
    def test_no_duplicate_ids_in_catalog(self, full_reg: RuleRegistry) -> None:
        # _catalog is a dict so duplicates would silently overwrite.
        # Check that the count matches expectations (covered above),
        # and also verify all IDs are unique across the meta lists.
        import webconf_audit.external.rules._runner

        all_ids = [entry.meta.rule_id for entry in full_reg._executable.values()]
        all_ids += [
            meta.rule_id for meta in webconf_audit.external.rules._runner._EXTERNAL_RULE_METAS
        ]

        assert len(all_ids) == len(set(all_ids)), (
            f"Duplicate rule IDs found: "
            f"{[x for x in all_ids if all_ids.count(x) > 1]}"
        )


# ---------------------------------------------------------------------------
# Ordering invariants
# ---------------------------------------------------------------------------

class TestOrdering:
    def test_universal_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="universal"):
            assert 100 <= m.order <= 199, f"{m.rule_id} order={m.order}"

    def test_nginx_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="nginx"):
            assert 200 <= m.order <= 299, f"{m.rule_id} order={m.order}"

    def test_apache_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="apache"):
            assert 300 <= m.order <= 399, f"{m.rule_id} order={m.order}"

    def test_lighttpd_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="lighttpd"):
            assert 400 <= m.order <= 499, f"{m.rule_id} order={m.order}"

    def test_iis_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="iis"):
            assert 500 <= m.order <= 599, f"{m.rule_id} order={m.order}"

    def test_external_order_range(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="external"):
            assert 600 <= m.order <= 799, f"{m.rule_id} order={m.order}"

    def test_external_rule_orders_are_unique(self, full_reg: RuleRegistry) -> None:
        rules = full_reg.list_rules(category="external")
        order_to_ids: dict[int, list[str]] = {}
        for meta in rules:
            order_to_ids.setdefault(meta.order, []).append(meta.rule_id)

        duplicates = {
            order: rule_ids
            for order, rule_ids in order_to_ids.items()
            if len(rule_ids) > 1
        }

        assert duplicates == {}

    def test_list_rules_sorted(self, full_reg: RuleRegistry) -> None:
        all_rules = full_reg.list_rules()
        keys = [(m.order, m.rule_id) for m in all_rules]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# Executable store only has callable entries
# ---------------------------------------------------------------------------

class TestExecutableCallable:
    def test_all_executable_have_fn(self, full_reg: RuleRegistry) -> None:
        for entry in full_reg._executable.values():
            assert callable(entry.fn), f"{entry.meta.rule_id} has non-callable fn"


# ---------------------------------------------------------------------------
# Prefix conventions
# ---------------------------------------------------------------------------

class TestPrefixConventions:
    def test_nginx_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="nginx"):
            assert m.rule_id.startswith("nginx."), m.rule_id

    def test_apache_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="apache"):
            assert m.rule_id.startswith("apache."), m.rule_id

    def test_lighttpd_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="lighttpd"):
            assert m.rule_id.startswith("lighttpd."), m.rule_id

    def test_iis_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="local", server_type="iis"):
            assert m.rule_id.startswith("iis."), m.rule_id

    def test_external_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="external"):
            assert m.rule_id.startswith("external."), m.rule_id

    def test_universal_prefix(self, full_reg: RuleRegistry) -> None:
        for m in full_reg.list_rules(category="universal"):
            assert m.rule_id.startswith("universal."), m.rule_id
