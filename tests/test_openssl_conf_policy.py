from webconf_audit.openssl_conf_policy import ssl_conf_option_state


def test_ssl_conf_option_state_handles_quoted_comma_options() -> None:
    value = '"Compression,UnsafeLegacyRenegotiation"'

    assert ssl_conf_option_state(value, "Compression") is True
    assert ssl_conf_option_state(value, "UnsafeLegacyRenegotiation") is True


def test_ssl_conf_option_state_keeps_last_state_for_quoted_tokens() -> None:
    value = '"Compression,-Compression"'

    assert ssl_conf_option_state(value, "Compression") is False
