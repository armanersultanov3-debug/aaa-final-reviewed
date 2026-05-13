from webconf_audit.local.iis.iis_defaults import load_defaults


def test_section_attribute_default_returns_authentication_mode() -> None:
    defaults = load_defaults()

    assert (
        defaults.get_section_attribute_default(
            "system.web/authentication",
            "mode",
        )
        == "Windows"
    )


def test_element_default_returns_forms_defaults() -> None:
    defaults = load_defaults()

    forms_defaults = defaults.get_element_default("system.web/authentication/forms")

    assert forms_defaults["cookieless"] == "UseDeviceProfile"
    assert forms_defaults["requireSSL"] == "false"


def test_element_default_returns_app_pool_process_model_defaults() -> None:
    defaults = load_defaults()

    process_model_defaults = defaults.get_element_default(
        "system.applicationHost/applicationPools/applicationPoolDefaults/processModel",
    )

    assert process_model_defaults["identityType"] == "ApplicationPoolIdentity"


def test_unknown_section_attribute_default_returns_none() -> None:
    defaults = load_defaults()

    assert (
        defaults.get_section_attribute_default(
            "system.web/doesNotExist",
            "enabled",
        )
        is None
    )
