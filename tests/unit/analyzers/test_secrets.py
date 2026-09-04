from fwtriage.analyzers.secrets import Secrets, der_is_well_formed

from .helpers import filesystem, rules, run


def test_pem_header_without_a_body_is_not_a_finding() -> None:
    fs = filesystem({"/usr/lib/libparse.so": b"\0-----BEGIN RSA PRIVATE KEY-----\0-----END RSA PRIVATE KEY-----\0"})
    assert rules(run(Secrets(), fs)) == []


def test_key_option_holding_a_file_path_is_not_a_passphrase() -> None:
    fs = filesystem({"/etc/config/wireless": b"config wifi-iface\n\toption key '/etc/wifi.key'\n"})
    assert rules(run(Secrets(), fs)) == []


def test_passphrase_syntax_outside_wifi_configuration_is_ignored() -> None:
    fs = filesystem({"/usr/share/doc/example.txt": b"wpa_passphrase=documentation-example\n"})
    assert rules(run(Secrets(), fs)) == []


def test_der_check_rejects_garbage() -> None:
    assert not der_is_well_formed(b"not base64 at all!")
    assert not der_is_well_formed(b"AAAA")
