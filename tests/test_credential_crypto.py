import pytest

from credential_crypto import (
    KEY_ENV_VAR,
    decrypt_value,
    encrypt_value,
    generate_key,
    is_encrypted,
)


def test_generate_key_produces_usable_fernet_key():
    key = generate_key()
    token = encrypt_value("hello", key)
    assert is_encrypted(token)


def test_encrypt_decrypt_roundtrip(monkeypatch):
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key)

    token = encrypt_value("hunter2", key)
    assert decrypt_value(token) == "hunter2"


def test_decrypt_value_passes_through_plaintext(monkeypatch):
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    assert decrypt_value("plaintext-password") == "plaintext-password"


def test_decrypt_value_raises_without_key(monkeypatch):
    key = generate_key()
    token = encrypt_value("hunter2", key)
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)

    with pytest.raises(RuntimeError, match=KEY_ENV_VAR):
        decrypt_value(token)


def test_decrypt_value_raises_on_wrong_key(monkeypatch):
    token = encrypt_value("hunter2", generate_key())
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())

    with pytest.raises(RuntimeError, match="failed to decrypt"):
        decrypt_value(token)


def test_is_encrypted_false_for_plain_string():
    assert is_encrypted("plaintext") is False
