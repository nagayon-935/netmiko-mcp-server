"""Pure helpers for building and merging the device inventory TOML.

Interactive I/O lives in import_inventory.py; everything here takes plain
values and returns validated values or tomlkit structures, so it can be unit
tested without faking user input. Validation error messages are user-facing
(Japanese) because the interactive layer shows them verbatim.
"""

import ipaddress
import os
import re
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
from inventory import RESERVED_KEYS as RESERVED_TOML_KEYS

VALID_DEVICE_TYPES: tuple[str, ...] = tuple(platforms) + tuple(telnet_platforms)

NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
MAX_HOSTNAME_LEN = 253
MIN_PORT = 1
MAX_PORT = 65535

# RESERVED_TOML_KEYS (the non-device top-level keys) is imported from inventory
# so the builder and the loader cannot disagree about what counts as a device.
# 'q' is additionally reserved because the interactive UI uses it to quit.
RESERVED_DEVICE_NAMES = RESERVED_TOML_KEYS | {"q"}

SUGGESTION_LIMIT = 15

# inventory.get_device_names() resolves device names before group names, so a
# group sharing a device's name can never be selected. Reject the collision
# from whichever side creates it.
NAME_COLLIDES_WITH_GROUP = (
    "'{name}' は同名のグループが存在するため使用できません"
    "（同名だとグループを参照できなくなります）。"
)
GROUP_COLLIDES_WITH_DEVICE = (
    "グループ名 '{name}' は同名のデバイスが存在するため使用できません"
    "（同名だとグループを参照できなくなります）。"
)
# Mirrors the shape check in inventory.load_groups().
GROUPS_NOT_A_TABLE = (
    "'groups' はグループ名 = [デバイス名] のテーブルである必要があります。"
)


class InventoryDataError(ValueError):
    """The inventory document itself is unusable (bad shape or a name clash).

    A ValueError subclass so the prompt loops keep re-prompting on it, but a
    distinct type so main() can report it as user-facing without also
    swallowing unrelated ValueErrors raised by a genuine bug.
    """


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


def validate_device_name(
    raw: str, existing: Collection[str], group_names: Collection[str] = ()
) -> str:
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
    if name in group_names:
        raise ValueError(NAME_COLLIDES_WITH_GROUP.format(name=name))
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


def validate_group_names(
    raw: str, device_names: Collection[str] = ()
) -> tuple[str, ...]:
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
        if name in device_names:
            raise ValueError(GROUP_COLLIDES_WITH_DEVICE.format(name=name))
        if name not in names:
            names.append(name)
    return tuple(names)


def collect_existing_names(doc: TOMLDocument) -> frozenset[str]:
    """Device names already defined in the document (reserved tables excluded)."""
    return frozenset(str(k) for k in doc.keys() if str(k) not in RESERVED_TOML_KEYS)


def _require_group_table(groups: object) -> Table:
    """Reject a `groups` value that is not a table, as inventory.load_groups does."""
    if not isinstance(groups, dict):
        raise InventoryDataError(GROUPS_NOT_A_TABLE)
    return cast(Table, groups)


def collect_existing_group_names(doc: TOMLDocument) -> frozenset[str]:
    """Group names already defined in the document's `[groups]` table."""
    groups = doc.get("groups")
    if groups is None:
        return frozenset()
    return frozenset(str(k) for k in _require_group_table(groups))


def count_devices_and_groups(doc: TOMLDocument) -> tuple[int, int]:
    groups = doc.get("groups")
    n_groups = 0 if groups is None else len(_require_group_table(groups))
    return len(collect_existing_names(doc)), n_groups


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
            raise InventoryDataError(
                f"デバイス '{dev.name}' は既にファイル内に存在します。"
            )
        if doc.body:
            doc.add(tomlkit.nl())
        doc[dev.name] = device_to_table(dev, key)
    merge_groups(doc, devices)


def merge_groups(doc: TOMLDocument, devices: Sequence[EnteredDevice]) -> None:
    memberships = [(group, dev.name) for dev in devices for group in dev.groups]
    if not memberships:
        return
    device_names = collect_existing_names(doc)
    for group_name, _device_name in memberships:
        if group_name in device_names:
            raise InventoryDataError(GROUP_COLLIDES_WITH_DEVICE.format(name=group_name))
    if "groups" not in doc:
        doc["groups"] = tomlkit.table()
    groups = _require_group_table(doc["groups"])
    for group_name, device_name in memberships:
        if group_name not in groups:
            groups[group_name] = tomlkit.array()
        members = cast(Array, groups[group_name])
        if device_name not in members:
            members.append(device_name)


def backup_file(path: Path) -> Path:
    """Copy path to path.bak (overwriting any previous backup) and return it.

    The backup is owner-only, like atomic_write(): shutil.copy2 would preserve
    the source mode, so backing up a hand-written 0644 inventory would leave
    its credentials world-readable. O_CREAT applies the mode only to a file it
    creates, hence the explicit chmod for a pre-existing backup.
    """
    backup = path.with_name(path.name + ".bak")
    fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as dst:
        dst.write(path.read_bytes())
    os.chmod(backup, 0o600)
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
