from __future__ import annotations

import json
from pathlib import Path

from webconf_audit.local.iis import analyze_iis_config
from webconf_audit.local.iis import registry as registry_module
from webconf_audit.local.iis.registry import (
    IISRegistryTLS,
    load_registry_export,
    read_live_registry,
)
from webconf_audit.models import AnalysisIssue


class FakeRegistryReader:
    def __init__(
        self,
        values: dict[tuple[str, str], int] | None = None,
        subkeys: dict[str, list[str] | None] | None = None,
    ) -> None:
        self.values = values or {}
        self.subkeys = subkeys or {}

    def open_subkeys(self, parent: str) -> list[str] | None:
        return self.subkeys.get(parent)

    def query_value(self, parent: str, value_name: str) -> object | None:
        return self.values.get((parent, value_name))

    def query_dword(self, parent: str, value_name: str) -> int | None:
        value = self.query_value(parent, value_name)
        if isinstance(value, int):
            return value
        return None


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


def _registry_export(
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


def _preferred_cipher_suite_order() -> list[str]:
    return [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    ]


def test_load_registry_export_maps_enabled_protocols_and_ciphers(tmp_path: Path) -> None:
    export = _write_json(
        tmp_path / "schannel.json",
        _registry_export(
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

    assert issues == []
    assert snapshot is not None
    assert snapshot.protocols_enabled == ["TLSv1.0", "TLSv1.2"]
    assert snapshot.ciphers_enabled == ["RC4 40/128"]
    assert snapshot.cipher_suite_order == [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
    ]
    assert snapshot.source_kind == "export"


def test_load_registry_export_reports_invalid_json(tmp_path: Path) -> None:
    export = tmp_path / "schannel.json"
    export.write_text("{broken", encoding="utf-8")

    snapshot, issues = load_registry_export(str(export))

    assert snapshot is None
    assert len(issues) == 1
    assert issues[0].code == "iis_tls_registry_export_error"
    assert issues[0].level == "warning"


def test_load_registry_export_requires_tls_data(tmp_path: Path) -> None:
    export = _write_json(tmp_path / "schannel.json", {"schannel": {}})

    snapshot, issues = load_registry_export(str(export))

    assert snapshot is None
    assert len(issues) == 1
    assert "does not contain" in issues[0].message


def test_read_live_registry_uses_injected_reader(monkeypatch) -> None:
    base = registry_module._SCHANNEL_BASE
    cipher_order_path = registry_module._CIPHER_SUITE_ORDER_PATH
    reader = FakeRegistryReader(
        values={
            (f"{base}\\Protocols\\TLS 1.0\\Server", "Enabled"): 1,
            (f"{base}\\Protocols\\TLS 1.0\\Server", "DisabledByDefault"): 0,
            (f"{base}\\Protocols\\TLS 1.1\\Server", "Enabled"): 1,
            (f"{base}\\Protocols\\TLS 1.1\\Server", "DisabledByDefault"): 1,
            (f"{base}\\Protocols\\TLS 1.2\\Server", "Enabled"): 1,
            (f"{base}\\Protocols\\TLS 1.2\\Server", "DisabledByDefault"): 0,
            (f"{base}\\Ciphers\\RC4 40/128", "Enabled"): 4294967295,
            (f"{base}\\Ciphers\\AES 128/128", "Enabled"): 0,
            (cipher_order_path, "Functions"): [
                "TLS_AES_256_GCM_SHA384",
                "TLS_AES_128_GCM_SHA256",
            ],
        },
        subkeys={f"{base}\\Ciphers": ["RC4 40/128", "AES 128/128"]},
    )
    monkeypatch.setattr(registry_module.socket, "gethostname", lambda: "iis-prod-1")

    snapshot, issues = read_live_registry(reader)

    assert issues == []
    assert snapshot is not None
    assert snapshot.protocols_enabled == ["TLSv1.0", "TLSv1.2"]
    assert snapshot.ciphers_enabled == ["RC4 40/128"]
    assert snapshot.cipher_suite_order == [
        "TLS_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
    ]
    assert snapshot.host == "iis-prod-1"
    assert "iis-prod-1" in snapshot.source_file_path


def test_read_live_registry_returns_none_when_no_schannel_data() -> None:
    snapshot, issues = read_live_registry(FakeRegistryReader())

    assert snapshot is None
    assert issues == []


def test_analyze_iis_config_export_fires_weak_tls_protocol(tmp_path: Path) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel.json",
        _registry_export(
            protocols={
                "TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0},
                "TLS 1.2": {"server_enabled": 1, "server_disabled_by_default": 0},
            }
        ),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    weak = [f for f in result.findings if f.rule_id == "universal.weak_tls_protocol"]
    assert len(weak) == 1
    assert weak[0].location is not None
    assert str(export) in (weak[0].location.details or "")
    assert "iis_tls_registry_source" in {issue.code for issue in result.issues}


def test_analyze_iis_config_export_fires_weak_tls_ciphers(tmp_path: Path) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel.json",
        _registry_export(ciphers={"RC4 40/128": {"enabled": 4294967295}}),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    assert "universal.weak_tls_ciphers" in {finding.rule_id for finding in result.findings}


def test_analyze_iis_config_export_fires_schannel_tls_policy_rules(
    tmp_path: Path,
) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel.json",
        _registry_export(
            protocols={"TLS 1.0": {"server_enabled": 1, "server_disabled_by_default": 0}},
            ciphers={"AES 128/128": {"enabled": 4294967295}},
            cipher_suite_order=["TLS_RSA_WITH_AES_128_CBC_SHA"],
        ),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    rule_ids = {finding.rule_id for finding in result.findings}
    assert "iis.schannel_tls12_not_enabled" in rule_ids
    assert "iis.schannel_weak_protocol_enabled" in rule_ids
    assert "iis.schannel_aes128_enabled" in rule_ids
    assert "iis.schannel_aes256_not_enabled" in rule_ids
    assert "iis.schannel_cipher_suite_order_not_preferred" in rule_ids


def test_analyze_iis_config_clean_export_has_no_schannel_tls_findings(
    tmp_path: Path,
) -> None:
    config = _write_iis_config(tmp_path / "web.config")
    export = _write_json(
        tmp_path / "schannel.json",
        _registry_export(
            protocols={"TLS 1.2": {"server_enabled": 1, "server_disabled_by_default": 0}},
            ciphers={
                "AES 128/128": {"enabled": 0},
                "AES 256/256": {"enabled": 4294967295},
            },
            cipher_suite_order=_preferred_cipher_suite_order(),
        ),
    )

    result = analyze_iis_config(str(config), tls_registry_path=str(export))

    tls_ids = {
        "universal.weak_tls_protocol",
        "universal.weak_tls_ciphers",
        "iis.schannel_tls12_not_enabled",
        "iis.schannel_weak_protocol_enabled",
        "iis.schannel_aes128_enabled",
        "iis.schannel_aes256_not_enabled",
        "iis.schannel_cipher_suite_order_not_preferred",
    }
    assert not (tls_ids & {finding.rule_id for finding in result.findings})


def test_analyze_iis_config_live_registry_source_labels_host(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = _write_iis_config(tmp_path / "web.config")

    def fake_resolve_registry_tls(
        registry_source: str | None = None,
        *,
        use_live_registry: bool = True,
    ) -> tuple[IISRegistryTLS | None, list[AnalysisIssue]]:
        assert registry_source is None
        assert use_live_registry is True
        return (
            IISRegistryTLS(
                protocols_enabled=["TLSv1.0"],
                source_kind="live",
                host="prod-iis",
            ),
            [],
        )

    monkeypatch.setattr(
        "webconf_audit.local.iis.resolve_registry_tls",
        fake_resolve_registry_tls,
    )

    result = analyze_iis_config(str(config))

    weak = [f for f in result.findings if f.rule_id == "universal.weak_tls_protocol"]
    assert len(weak) == 1
    assert weak[0].location is not None
    assert "prod-iis" in (weak[0].location.details or "")
    assert result.metadata["tls_registry_source"]["host"] == "prod-iis"
    assert any(
        issue.code == "iis_tls_registry_source" and issue.level == "info"
        for issue in result.issues
    )
