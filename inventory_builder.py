"""Pure helpers for building and merging the device inventory TOML.

Interactive I/O lives in import_inventory.py; everything here takes plain
values and returns validated values or tomlkit structures, so it can be unit
tested without faking user input. Validation error messages are user-facing
(Japanese) because the interactive layer shows them verbatim.
"""

import ipaddress
import os
import re
import shutil
import tempfile
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import tomlkit
from netmiko.ssh_dispatcher import platforms, telnet_platforms
from tomlkit import TOMLDocument
from tomlkit.items import Array, Table

from credential_crypto import encrypt_value

VALID_DEVICE_TYPES: tuple[str, ...] = tuple(platforms) + tuple(telnet_platforms)

NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
MAX_HOSTNAME_LEN = 253
MIN_PORT = 1
MAX_PORT = 65535

# Top-level TOML keys that are not device tables (see inventory._RESERVED_KEYS).
RESERVED_TOML_KEYS = frozenset({"default", "groups"})
# 'q' is additionally reserved because the interactive UI uses it to quit.
RESERVED_DEVICE_NAMES = RESERVED_TOML_KEYS | {"q"}

SUGGESTION_LIMIT = 15


@dataclass(frozen=True)
class EnteredDevice:
    """One validated device entered interactively, before TOML serialization."""

    name: str
    hostname: str
    device_type: str
    username: str
    password: str | None
    use_keys: bool
    key_file: str | None
    secret: str | None
    port: int | None
    groups: tuple[str, ...]


def validate_device_name(raw: str, existing: Collection[str]) -> str:
    name = raw.strip()
    if not name:
        raise ValueError("デバイス名を入力してください。")
    if not NAME_RE.match(name):
        raise ValueError(
            "デバイス名には英数字、ハイフン、アンダースコアのみ使用できます。"
        )
    if name in RESERVED_DEVICE_NAMES:
        raise ValueError(f"'{name}' は予約されている名前のため使用できません。")
    if name in existing:
        raise ValueError(f"デバイス名 '{name}' は既に存在します。")
    return name


def validate_hostname(raw: str) -> str:
    host = raw.strip()
    if not host:
        raise ValueError("ホスト名またはIPアドレスを入力してください。")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    is_valid_fqdn = len(host) <= MAX_HOSTNAME_LEN and all(
        HOSTNAME_LABEL_RE.match(label) for label in labels
    )
    if not is_valid_fqdn:
        raise ValueError("ホスト名またはIPアドレスの形式が不正です。")
    return host


def validate_username(raw: str) -> str:
    username = raw.strip()
    if not username:
        raise ValueError("ユーザー名を入力してください。")
    return username


def validate_device_type(raw: str) -> str:
    device_type = raw.strip()
    if device_type not in VALID_DEVICE_TYPES:
        raise ValueError(f"'{device_type}' は有効な device_type ではありません。")
    return device_type


def suggest_device_types(raw: str, limit: int = SUGGESTION_LIMIT) -> list[str]:
    """Return platform names containing the typed string, for typo recovery."""
    needle = raw.strip().lower()
    if not needle:
        return []
    return sorted(t for t in VALID_DEVICE_TYPES if needle in t.lower())[:limit]


def validate_port(raw: str) -> int | None:
    text = raw.strip()
    if not text:
        return None
    try:
        port = int(text)
    except ValueError:
        raise ValueError("ポート番号は数値で入力してください。") from None
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(
            f"ポート番号は {MIN_PORT}〜{MAX_PORT} の範囲で入力してください。"
        )
    return port


def validate_group_names(raw: str) -> tuple[str, ...]:
    text = raw.strip()
    if not text:
        return ()
    names: list[str] = []
    for part in text.split(","):
        name = part.strip()
        if not name or not NAME_RE.match(name):
            raise ValueError(
                "グループ名には英数字、ハイフン、アンダースコアのみ使用できます"
                "（カンマ区切り）。"
            )
        if name not in names:
            names.append(name)
    return tuple(names)


def collect_existing_names(doc: TOMLDocument) -> frozenset[str]:
    """Device names already defined in the document (reserved tables excluded)."""
    return frozenset(str(k) for k in doc.keys() if str(k) not in RESERVED_TOML_KEYS)


def count_devices_and_groups(doc: TOMLDocument) -> tuple[int, int]:
    groups = doc.get("groups", {})
    return len(collect_existing_names(doc)), len(groups)


def _maybe_encrypt(value: str, key: str | None) -> str:
    return encrypt_value(value, key) if key else value


def device_to_table(dev: EnteredDevice, key: str | None) -> Table:
    """Serialize one device to a tomlkit table, encrypting credentials if key."""
    table = tomlkit.table()
    table["hostname"] = dev.hostname
    table["device_type"] = dev.device_type
    table["username"] = dev.username
    if dev.use_keys:
        table["use_keys"] = True
        if dev.key_file is not None:
            table["key_file"] = dev.key_file
    elif dev.password is not None:
        table["password"] = _maybe_encrypt(dev.password, key)
    if dev.secret is not None:
        table["secret"] = _maybe_encrypt(dev.secret, key)
    if dev.port is not None:
        table["port"] = dev.port
    return table


def merge_devices(
    doc: TOMLDocument, devices: Sequence[EnteredDevice], key: str | None
) -> None:
    """Append device tables (and their group memberships) to the document.

    Existing content — comments, key order, already-encrypted values — is left
    untouched; only new tables and group members are added.
    """
    for dev in devices:
        if dev.name in doc:
            raise ValueError(f"デバイス '{dev.name}' は既にファイル内に存在します。")
        if tomlkit.dumps(doc).strip():
            doc.add(tomlkit.nl())
        doc[dev.name] = device_to_table(dev, key)
    merge_groups(doc, devices)


def merge_groups(doc: TOMLDocument, devices: Sequence[EnteredDevice]) -> None:
    memberships = [(group, dev.name) for dev in devices for group in dev.groups]
    if not memberships:
        return
    if "groups" not in doc:
        doc["groups"] = tomlkit.table()
    groups = cast(Table, doc["groups"])
    for group_name, device_name in memberships:
        if group_name not in groups:
            groups[group_name] = tomlkit.array()
        members = cast(Array, groups[group_name])
        if device_name not in members:
            members.append(device_name)


def backup_file(path: Path) -> Path:
    """Copy path to path.bak (overwriting any previous backup) and return it."""
    backup = path.with_name(path.name + ".bak")
    shutil.copy2(path, backup)
    return backup


def atomic_write(path: Path, content: str) -> None:
    """Write content to path atomically with owner-only (0600) permissions."""
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
