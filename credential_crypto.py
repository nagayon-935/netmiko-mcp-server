"""Encryption for credential fields (password/secret) in the device inventory TOML.

Encrypted values are stored in the TOML file as `enc:<fernet-token>` strings.
The decryption key is read only from the NETMIKO_MCP_SERVER_INVENTORY_KEY
environment variable, never from the TOML file itself, so a leaked inventory
file alone does not expose device credentials.
"""

import os

from cryptography.fernet import Fernet, InvalidToken

ENC_PREFIX = "enc:"
KEY_ENV_VAR = "NETMIKO_MCP_SERVER_INVENTORY_KEY"


def generate_key() -> str:
    """Generate a new Fernet key, suitable for NETMIKO_MCP_SERVER_INVENTORY_KEY."""
    return Fernet.generate_key().decode("utf-8")


def is_encrypted(value: str) -> bool:
    return value.startswith(ENC_PREFIX)


def encrypt_value(value: str, key: str) -> str:
    """Encrypt value with key, returning a string ready to paste into the TOML file."""
    fernet = Fernet(key.encode("utf-8"))
    token = fernet.encrypt(value.encode("utf-8")).decode("utf-8")
    return ENC_PREFIX + token


def decrypt_value(value: str) -> str:
    """Decrypt an `enc:`-prefixed value using the key from the environment.

    Returns the value unchanged if it is not encrypted. Raises RuntimeError if
    the value is encrypted but the key is missing or does not decrypt it.
    """
    if not is_encrypted(value):
        return value

    key = os.environ.get(KEY_ENV_VAR, "").strip()
    if not key:
        raise RuntimeError(
            f"Startup Error: the inventory contains an encrypted value but "
            f"{KEY_ENV_VAR} is not set in the environment."
        )

    token = value[len(ENC_PREFIX) :]
    try:
        fernet = Fernet(key.encode("utf-8"))
        return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            f"Startup Error: failed to decrypt an inventory value: invalid "
            f"{KEY_ENV_VAR} or corrupted token."
        ) from exc
