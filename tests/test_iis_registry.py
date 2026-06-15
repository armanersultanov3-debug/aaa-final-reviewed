from __future__ import annotations

import json
from pathlib import Path

import pytest

from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.iis import registry as registry_module
from webconf_audit.local.iis.registry import (
    SchannelEvidenceLoadError,
    load_registry_export,
    load_schannel_export,
    read_live_registry,
    read_live_schannel,
)
from webconf_audit.local.iis.schannel_models import IISSchannelEvidence
from webconf_audit.models import AnalysisIssue


class FakeRegistryReader:
    def __init__(
        self,
        values: dict[tuple[str, str], object] | None = None,
        subkeys: dict[str, object] | None = None,
    ) -> None:
        self.values = values or {}
        self.subkeys = subkeys or {}

    def open_subkeys(self, parent: str) -> object:
        return self.subkeys.get(parent, registry_module._ReadResult("absent"))

    def query_value(self, parent: str, value_name: str) -> object:
        return self.values.get((parent, value_name), registry_module._ReadResult("absent"))


def _write_json(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _write_iis_config(path: Path) -> Path:
    path.write_text(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <security>
      <access sslFlags="Ssl" />
    </security>
  </system.webServer>
</configuration>
""",
        encoding="utf-8",
    )
    return path


def _v1_export(
    *,
    protocols: dict[str, dict[str, int]] | None = None,
    ciphers: dict[str, dict[str, int]] | None = None,
    cipher_suite_order: object | None = None,
) -> dict[str, object]:
    schannel: dict[str, object] = {}
    if protocols is not None:
        schannel["protocols"] = protocols
    if ciphers is not None:
        schannel["ciphers"] = ciphers
    if cipher_suite_order is not None:
        schannel["cipher_suite_order"] = cipher_suite_order
    return {"schannel": schannel}


def _v2_protocol_entry(*, enabled: int | None = None, disabled_by_default: int | None = None) -> dict[str, object]:
    def _value(raw: int | None) -> dict[str, object]:
        if raw is None:
            return {"present": False}
        return {"present": True, "value": raw}

    return {
        "server": {
            "enabled": _value(enabled),
            "disabled_by_default": _value(disabled_by_default),
        }
    }


def _v2_cipher_entry(*, enabled: int | None = None) -> dict[str, object]:
    if enabled is None:
        return {"enabled": {"present": False}}
    return {"enabled": {"present": True, "value": enabled}}


def _v2_suite_order(*, present: bool, value: list[str] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {"present": present}
    if present:
        payload["value"] = value or []
    return payload


def _v2_export(
    *,
    protocols: dict[str, object] | None = None,
    ciphers: dict[str, object] | None = None,
    cipher_suite_order: dict[str, object] | None = None,
    build: int | None = 20348,
    completeness: dict[str, str] | None = None,
    collection_issues: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "kind": "iis-schannel-evidence",
        "host": "iis-prod-01",
        "captured_at": "2026-06-12T08:00:00Z",
        "os": {
            "product_name": "Windows Server 2022 Datacenter",
            "version": "10.0",
            "build": build,
            "ubr": 2527,
            "architecture": "x64",
        },
        "completeness": completeness
        or {
            "os_build": "complete",
            "protocols": "complete",
            "ciphers": "complete",
            "cipher_suite_order": "complete",
        },
        "schannel": {
            "protocols": protocols or {},
            "ciphers": ciphers or {},
            "cipher_suite_order": cipher_suite_order or {"present": False},
        },
        "collection_issues": collection_issues or [],
    }


def _preferred_cipher_suite_order() -> list[str]:
    return [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    ]


def test_load_registry_export_maps_enabled_protocols_and_ciphers(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel.json",
        _v1_export(
            protocols={
                "TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0},
                "TLS 1.1": {"server_enabled": 1, "server_disabled_by_default": 1},
                "TLS 1.2": {"server_enabled": 4294967295, "server_disabled_by_default": 0},
            },
            ciphers={
                "RC4 40/128": {"enabled": 4294967295},
                "AES 128/128": {"enabled": 0},
            },
            cipher_suite_order={"Functions": "TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256"},
        ),
    )

    snapshot, issues = load_registry_export(str(export))

    assert snapshot is not None
    assert len(issues) == 1
    assert issues[0].code == "iis_tls_registry_v1_adapter_warning"
    assert "adapted to canonical v2 evidence" in issues[0].message
    assert snapshot.protocols_enabled == ["TLSv1.0", "TLSv1.2"]
    assert snapshot.ciphers_enabled == ["RC4 40/128"]
    assert snapshot.cipher_suite_order == [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
    ]
    assert snapshot.source_kind == "export"


def test_load_schannel_export_v2_resolves_supported_build_defaults(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel-v2.json",
        _v2_export(
            protocols={
                "TLS 1.0": _v2_protocol_entry(enabled=1, disabled_by_default=0),
            },
            ciphers={
                "AES 128/128": _v2_cipher_entry(enabled=0),
            },
            cipher_suite_order=_v2_suite_order(present=False),
        ),
    )

    evidence = load_schannel_export(export)

    assert evidence.protocol("TLSv1.2").state == "default"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.2").effective_state == "enabled"  # type: ignore[union-attr]
    assert evidence.cipher("AES 256/256").state == "default"  # type: ignore[union-attr]
    assert evidence.cipher("AES 256/256").effective_state == "enabled"  # type: ignore[union-attr]
    assert evidence.schannel.cipher_suite_order.order_source == "default"
    assert evidence.schannel.cipher_suite_order.effective_order[:2] == (
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
    )


def test_load_schannel_export_unsupported_build_keeps_defaults_unknown(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel-v2.json",
        _v2_export(
            build=99999,
            protocols={},
            ciphers={},
            cipher_suite_order=_v2_suite_order(present=False),
        ),
    )

    evidence = load_schannel_export(export)

    assert evidence.protocol("TLSv1.2").state == "default"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.2").effective_state == "unknown"  # type: ignore[union-attr]
    assert evidence.cipher("AES 256/256").effective_state == "unknown"  # type: ignore[union-attr]
    assert evidence.schannel.cipher_suite_order.order_source == "unknown"


def test_load_schannel_export_v1_adapts_omissions_to_unknown(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel-v1.json",
        _v1_export(
            protocols={"TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0}},
            ciphers={"AES 128/128": {"enabled": 4294967295}},
            cipher_suite_order=["TLS_RSA_WITH_AES_128_CBC_SHA"],
        ),
    )

    evidence = load_schannel_export(export)

    assert evidence.input_schema_version == 1
    assert evidence.adapted_to_v2 is True
    assert evidence.protocol("TLSv1.0").effective_state == "enabled"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.2").state == "unknown"  # type: ignore[union-attr]
    assert evidence.cipher("AES 128/128").effective_state == "enabled"  # type: ignore[union-attr]
    assert evidence.cipher("AES 256/256").state == "unknown"  # type: ignore[union-attr]
    assert evidence.schannel.cipher_suite_order.order_source == "explicit"
    assert evidence.collection_issues[0].code == "iis_tls_registry_v1_adapter_warning"


def test_load_schannel_export_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel.json",
        {"schema_version": 3, "kind": "iis-schannel-evidence"},
    )

    with pytest.raises(SchannelEvidenceLoadError, match="Unsupported TLS registry export schema_version"):
        load_schannel_export(export)


def test_read_live_schannel_distinguishes_access_denied_from_absent(monkeypatch) -> None:
    base = registry_module._SCHANNEL_BASE
    reader = FakeRegistryReader(
        values={
            (registry_module._WINDOWS_VERSION_PATH, "ProductName"): "Windows Server 2022 Datacenter",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentVersion"): "10.0",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentBuildNumber"): "20348",
            (registry_module._WINDOWS_VERSION_PATH, "UBR"): 2527,
            (
                f"{base}\\Protocols\\TLS 1.1\\Server",
                "Enabled",
            ): registry_module._ReadResult("access-denied"),
        },
        subkeys={f"{base}\\Ciphers": registry_module._ReadResult("present", value=[])},
    )
    monkeypatch.setattr(registry_module.socket, "gethostname", lambda: "iis-prod-1")

    evidence, issues = read_live_schannel(reader)

    assert evidence is not None
    assert evidence.host == "iis-prod-1"
    assert evidence.completeness.protocols == "partial"
    assert evidence.protocol("TLSv1.2").state == "unknown"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.2").effective_state == "unknown"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.1").state == "unknown"  # type: ignore[union-attr]
    assert any(issue.code == "iis_tls_registry_collection_issue" for issue in issues)


def test_read_live_schannel_late_protocol_issue_downgrades_earlier_absences(monkeypatch) -> None:
    base = registry_module._SCHANNEL_BASE
    reader = FakeRegistryReader(
        values={
            (registry_module._WINDOWS_VERSION_PATH, "ProductName"): "Windows Server 2022 Datacenter",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentVersion"): "10.0",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentBuildNumber"): "20348",
            (registry_module._WINDOWS_VERSION_PATH, "UBR"): 2527,
            (
                f"{base}\\Protocols\\TLS 1.3\\Server",
                "Enabled",
            ): registry_module._ReadResult("access-denied"),
        },
        subkeys={f"{base}\\Ciphers": registry_module._ReadResult("present", value=[])},
    )
    monkeypatch.setattr(registry_module.socket, "gethostname", lambda: "iis-prod-1")

    evidence, _issues = read_live_schannel(reader)

    assert evidence is not None
    assert evidence.completeness.protocols == "partial"
    assert evidence.protocol("TLSv1.1").state == "unknown"  # type: ignore[union-attr]
    assert evidence.protocol("TLSv1.2").state == "unknown"  # type: ignore[union-attr]


def test_read_live_schannel_late_cipher_issue_downgrades_earlier_absences(monkeypatch) -> None:
    base = registry_module._SCHANNEL_BASE
    reader = FakeRegistryReader(
        values={
            (registry_module._WINDOWS_VERSION_PATH, "ProductName"): "Windows Server 2022 Datacenter",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentVersion"): "10.0",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentBuildNumber"): "20348",
            (registry_module._WINDOWS_VERSION_PATH, "UBR"): 2527,
            (
                f"{base}\\Ciphers\\AES 128/128",
                "Enabled",
            ): registry_module._ReadResult("access-denied"),
        },
        subkeys={
            f"{base}\\Ciphers": registry_module._ReadResult(
                "present",
                value=["AES 128/128"],
            )
        },
    )
    monkeypatch.setattr(registry_module.socket, "gethostname", lambda: "iis-prod-1")

    evidence, _issues = read_live_schannel(reader)

    assert evidence is not None
    assert evidence.completeness.ciphers == "partial"
    assert evidence.cipher("AES 256/256").state == "unknown"  # type: ignore[union-attr]


def test_read_live_registry_compatibility_wrapper_uses_injected_reader(monkeypatch) -> None:
    base = registry_module._SCHANNEL_BASE
    reader = FakeRegistryReader(
        values={
            (registry_module._WINDOWS_VERSION_PATH, "ProductName"): "Windows Server 2022 Datacenter",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentVersion"): "10.0",
            (registry_module._WINDOWS_VERSION_PATH, "CurrentBuildNumber"): "20348",
            (registry_module._WINDOWS_VERSION_PATH, "UBR"): 2527,
            (f"{base}\\Protocols\\TLS 1.0\\Server", "Enabled"): 1,
            (f"{base}\\Protocols\\TLS 1.0\\Server", "DisabledByDefault"): 0,
            (f"{base}\\Protocols\\TLS 1.2\\Server", "Enabled"): 1,
            (f"{base}\\Protocols\\TLS 1.2\\Server", "DisabledByDefault"): 0,
            (f"{base}\\Ciphers\\RC4 40/128", "Enabled"): 4294967295,
            (f"{base}\\Ciphers\\AES 128/128", "Enabled"): 0,
            (registry_module._CIPHER_SUITE_ORDER_PATH, "Functions"): [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
            ],
        },
        subkeys={f"{base}\\Ciphers": registry_module._ReadResult("present", value=["RC4 40/128", "AES 128/128"])},
    )
    monkeypatch.setattr(registry_module.socket, "gethostname", lambda: "iis-prod-1")

    snapshot, issues = read_live_registry(reader)

    assert issues == []
    assert snapshot is not None
    assert snapshot.protocols_enabled == ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    assert snapshot.ciphers_enabled == ["RC4 40/128", "AES 256/256"]
    assert snapshot.cipher_suite_order == [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
    ]
    assert snapshot.host == "iis-prod-1"


def test_analyze_iis_config_v1_export_removes_omission_based_findings(tmp_path: Path) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel-v1.json",
        _v1_export(
            protocols={"TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0}},
            ciphers={"AES 128/128": {"enabled": 4294967295}},
            cipher_suite_order=["TLS_RSA_WITH_AES_128_CBC_SHA"],
        ),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "iis.schannel_weak_protocol_enabled" in rule_ids
    assert "iis.schannel_aes128_enabled" in rule_ids
    assert "iis.schannel_cipher_suite_order_not_preferred" in rule_ids
    assert "iis.schannel_tls12_not_enabled" not in rule_ids
    assert "iis.schannel_aes256_not_enabled" not in rule_ids
    assert any(issue.code == "iis_tls_registry_v1_adapter_warning" for issue in result.issues)


def test_analyze_iis_config_v2_complete_export_can_fire_all_schannel_rules(
    tmp_path: Path,
) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel-v2.json",
        _v2_export(
            protocols={
                "TLS 1.0": _v2_protocol_entry(enabled=1, disabled_by_default=0),
                "TLS 1.2": _v2_protocol_entry(enabled=0, disabled_by_default=1),
            },
            ciphers={
                "AES 128/128": _v2_cipher_entry(enabled=4294967295),
                "AES 256/256": _v2_cipher_entry(enabled=0),
            },
            cipher_suite_order=_v2_suite_order(
                present=True,
                value=["TLS_RSA_WITH_AES_128_CBC_SHA"],
            ),
        ),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "iis.schannel_tls12_not_enabled" in rule_ids
    assert "iis.schannel_weak_protocol_enabled" in rule_ids
    assert "iis.schannel_aes128_enabled" in rule_ids
    assert "iis.schannel_aes256_not_enabled" in rule_ids
    assert "iis.schannel_cipher_suite_order_not_preferred" in rule_ids


def test_analyze_iis_config_v2_metadata_exposes_canonical_details(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    evidence = load_schannel_export(
        _write_json(
            tmp_path / "schannel-v2.json",
            _v2_export(
                protocols={"TLS 1.2": _v2_protocol_entry(enabled=1, disabled_by_default=0)},
                ciphers={"AES 256/256": _v2_cipher_entry(enabled=4294967295)},
                cipher_suite_order=_v2_suite_order(
                    present=True,
                    value=_preferred_cipher_suite_order(),
                ),
            ),
        )
    )

    def fake_resolve(
        registry_source: str | None = None,
        *,
        use_live_registry: bool = True,
    ) -> tuple[IISSchannelEvidence | None, list[AnalysisIssue]]:
        assert registry_source is None
        assert use_live_registry is True
        return evidence, []

    monkeypatch.setattr("webconf_audit.local.iis.resolve_schannel_evidence", fake_resolve)

    result = analyze_iis_config(str(config))

    metadata = result.metadata["tls_registry_source"]
    assert metadata["schema_version"] == 2
    assert metadata["input_schema_version"] == 2
    assert metadata["adapted_to_v2"] is False
    assert metadata["os"]["build"] == 20348
    assert metadata["completeness"]["protocols"] == "complete"
    assert any(entry["name"] == "TLSv1.2" for entry in metadata["protocols"])
    assert metadata["cipher_suite_order"]["order_source"] == "explicit"
