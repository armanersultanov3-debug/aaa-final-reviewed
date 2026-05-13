from tests.iis_helpers import build_effective_config, parse_iis_config


def _build(xml: str):
    doc = parse_iis_config(xml, file_path="web.config")
    return build_effective_config(doc)


def test_effective_authentication_uses_schema_default_when_absent() -> None:
    effective = _build(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <compilation debug="false" />
    </system.web>
</configuration>
""",
    )

    auth = effective.get_effective_or_default_section(
        "system.web/authentication",
        anchor_paths=("system.web",),
    )

    assert auth is not None
    assert auth.attributes["mode"] == "Windows"
    assert auth.materialized_from_defaults is True


def test_effective_authentication_override_wins_over_default() -> None:
    effective = _build(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication mode="Forms" />
    </system.web>
</configuration>
""",
    )

    auth = effective.get_effective_or_default_section(
        "system.web/authentication",
        anchor_paths=("system.web",),
    )

    assert auth is not None
    assert auth.attributes["mode"] == "Forms"


def test_effective_forms_override_wins_over_default_require_ssl() -> None:
    effective = _build(
        """\
<?xml version="1.0" encoding="utf-8"?>
<configuration>
    <system.web>
        <authentication mode="Forms">
            <forms requireSSL="true" />
        </authentication>
    </system.web>
</configuration>
""",
    )

    forms = effective.get_effective_or_default_section(
        "system.web/authentication/forms",
        anchor_paths=("system.web/authentication", "system.web"),
    )

    assert forms is not None
    assert forms.attributes["requireSSL"] == "true"
