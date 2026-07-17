"""Tests for inventory_builder: validators and TOML building/writing helpers."""

import stat
from pathlib import Path
from typing import Any

import pytest
import tomlkit

from credential_crypto import KEY_ENV_VAR, decrypt_value, generate_key
from inventory_builder import (
    EnteredDevice,
    atomic_write,
    backup_file,
    collect_existing_names,
    count_devices_and_groups,
    device_to_table,
    merge_devices,
    merge_groups,
    suggest_device_types,
    validate_device_name,
    validate_device_type,
    validate_group_names,
    validate_hostname,
    validate_port,
    validate_username,
)


def make_device(**overrides: Any) -> EnteredDevice:
    fields: dict[str, Any] = {
        "name": "r1",
        "hostname": "192.0.2.1",
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "pw123",
        "use_keys": False,
        "key_file": None,
        "secret": None,
        "port": None,
        "groups": (),
    }
    fields.update(overrides)
    return EnteredDevice(**fields)


# ---------------------------------------------------------------------------
# validate_device_name
# ---------------------------------------------------------------------------


def test_validate_device_name_accepts_valid_charset() -> None:
    assert validate_device_name(" core-sw_01 ", set()) == "core-sw_01"


def test_validate_device_name_rejects_empty() -> None:
    with pytest.raises(ValueError, match="デバイス名"):
        validate_device_name("   ", set())


def test_validate_device_name_rejects_invalid_chars() -> None:
    with pytest.raises(ValueError, match="英数字"):
        validate_device_name("core sw 01", set())


def test_validate_device_name_rejects_duplicate_existing() -> None:
    with pytest.raises(ValueError, match="既に存在"):
        validate_device_name("r1", {"r1", "r2"})


@pytest.mark.parametrize("reserved", ["default", "groups", "q"])
def test_validate_device_name_rejects_reserved_names(reserved: str) -> None:
    with pytest.raises(ValueError, match="予約"):
        validate_device_name(reserved, set())


# ---------------------------------------------------------------------------
# validate_hostname
# ---------------------------------------------------------------------------


def test_validate_hostname_accepts_ipv4() -> None:
    assert validate_hostname("192.0.2.1") == "192.0.2.1"


def test_validate_hostname_accepts_ipv6() -> None:
    assert validate_hostname("2001:db8::1") == "2001:db8::1"


def test_validate_hostname_accepts_fqdn() -> None:
    assert validate_hostname("sw01.example.com") == "sw01.example.com"


def test_validate_hostname_rejects_empty() -> None:
    with pytest.raises(ValueError, match="ホスト名"):
        validate_hostname("")


def test_validate_hostname_rejects_leading_hyphen_label() -> None:
    with pytest.raises(ValueError, match="形式が不正"):
        validate_hostname("-bad.example.com")


def test_validate_hostname_rejects_overlong() -> None:
    with pytest.raises(ValueError, match="形式が不正"):
        validate_hostname("a" * 254)


def test_validate_hostname_rejects_embedded_space() -> None:
    with pytest.raises(ValueError, match="形式が不正"):
        validate_hostname("192.0.2.1 bad")


# ---------------------------------------------------------------------------
# validate_username
# ---------------------------------------------------------------------------


def test_validate_username_accepts_and_strips() -> None:
    assert validate_username(" admin ") == "admin"


def test_validate_username_rejects_empty() -> None:
    with pytest.raises(ValueError, match="ユーザー名"):
        validate_username("   ")


# ---------------------------------------------------------------------------
# validate_device_type / suggest_device_types
# ---------------------------------------------------------------------------


def test_validate_device_type_accepts_cisco_ios() -> None:
    assert validate_device_type(" cisco_ios ") == "cisco_ios"


def test_validate_device_type_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="device_type"):
        validate_device_type("cisco_iso")


def test_suggest_device_types_substring_match() -> None:
    suggestions = suggest_device_types("cisco")
    assert "cisco_ios" in suggestions
    assert all("cisco" in s for s in suggestions)


def test_suggest_device_types_empty_for_no_match() -> None:
    assert suggest_device_types("no_such_platform_xyz") == []


def test_suggest_device_types_respects_limit() -> None:
    assert len(suggest_device_types("cisco", limit=3)) == 3


# ---------------------------------------------------------------------------
# validate_port
# ---------------------------------------------------------------------------


def test_validate_port_empty_returns_none() -> None:
    assert validate_port("  ") is None


def test_validate_port_parses_valid() -> None:
    assert validate_port("2222") == 2222


@pytest.mark.parametrize("raw", ["0", "65536", "-1"])
def test_validate_port_rejects_out_of_range(raw: str) -> None:
    with pytest.raises(ValueError, match="65535"):
        validate_port(raw)


def test_validate_port_rejects_non_numeric() -> None:
    with pytest.raises(ValueError, match="数値"):
        validate_port("twenty-two")


# ---------------------------------------------------------------------------
# validate_group_names
# ---------------------------------------------------------------------------


def test_validate_group_names_parses_and_dedupes() -> None:
    assert validate_group_names("core, edge ,core") == ("core", "edge")


def test_validate_group_names_rejects_bad_charset() -> None:
    with pytest.raises(ValueError, match="グループ名"):
        validate_group_names("core switches")


def test_validate_group_names_empty_returns_empty_tuple() -> None:
    assert validate_group_names("  ") == ()


# ---------------------------------------------------------------------------
# device_to_table
# ---------------------------------------------------------------------------


def test_device_to_table_encrypts_password_and_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key)
    dev = make_device(password="pw123", secret="enable123")

    table = device_to_table(dev, key)

    assert str(table["password"]).startswith("enc:")
    assert str(table["secret"]).startswith("enc:")
    assert decrypt_value(str(table["password"])) == "pw123"
    assert decrypt_value(str(table["secret"])) == "enable123"


def test_device_to_table_plaintext_when_key_none() -> None:
    table = device_to_table(make_device(password="pw123"), None)

    assert table["password"] == "pw123"


def test_device_to_table_key_auth_writes_use_keys_and_key_file() -> None:
    dev = make_device(password=None, use_keys=True, key_file="~/.ssh/id_ed25519")

    table = device_to_table(dev, None)

    assert table["use_keys"] is True
    assert table["key_file"] == "~/.ssh/id_ed25519"
    assert "password" not in table


def test_device_to_table_omits_port_when_none() -> None:
    assert "port" not in device_to_table(make_device(port=None), None)
    assert device_to_table(make_device(port=2222), None)["port"] == 2222


# ---------------------------------------------------------------------------
# merge_devices / merge_groups
# ---------------------------------------------------------------------------

EXISTING_TOML = """\
# inventory managed by hand
[default]
username = "admin"

[r1]  # first router
hostname = "192.0.2.1"
device_type = "cisco_ios"
password = "enc:AAAA-existing-token"

[groups]
core = ["r1"]
"""


def test_merge_devices_preserves_comments_and_enc_values() -> None:
    doc = tomlkit.parse(EXISTING_TOML)
    dev = make_device(name="r2", hostname="192.0.2.2")

    merge_devices(doc, [dev], None)
    dumped = tomlkit.dumps(doc)

    assert "# inventory managed by hand" in dumped
    assert "# first router" in dumped
    assert "enc:AAAA-existing-token" in dumped
    assert "[r2]" in dumped


def test_merge_devices_rejects_duplicate_name() -> None:
    doc = tomlkit.parse(EXISTING_TOML)

    with pytest.raises(ValueError, match="r1"):
        merge_devices(doc, [make_device(name="r1")], None)


def test_merge_groups_creates_table() -> None:
    doc = tomlkit.document()

    merge_groups(doc, [make_device(name="r9", groups=("edge",))])

    assert doc["groups"]["edge"] == ["r9"]


def test_merge_groups_appends_to_existing_array() -> None:
    doc = tomlkit.parse(EXISTING_TOML)

    merge_groups(doc, [make_device(name="r2", groups=("core",))])

    assert list(doc["groups"]["core"]) == ["r1", "r2"]


def test_merge_groups_skips_existing_member() -> None:
    doc = tomlkit.parse(EXISTING_TOML)

    merge_groups(doc, [make_device(name="r1", groups=("core",))])

    assert list(doc["groups"]["core"]) == ["r1"]


# ---------------------------------------------------------------------------
# collect_existing_names / count_devices_and_groups
# ---------------------------------------------------------------------------


def test_collect_existing_names_skips_reserved_tables() -> None:
    doc = tomlkit.parse(EXISTING_TOML)

    assert collect_existing_names(doc) == frozenset({"r1"})


def test_count_devices_and_groups_counts_tables() -> None:
    doc = tomlkit.parse(EXISTING_TOML)

    assert count_devices_and_groups(doc) == (1, 1)


# ---------------------------------------------------------------------------
# atomic_write / backup_file
# ---------------------------------------------------------------------------


def test_atomic_write_sets_0600_permissions(tmp_path: Path) -> None:
    target = tmp_path / "devices.toml"

    atomic_write(target, "x = 1\n")

    assert target.read_text() == "x = 1\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_atomic_write_replaces_existing_content(tmp_path: Path) -> None:
    target = tmp_path / "devices.toml"
    target.write_text("old = true\n")

    atomic_write(target, "new = true\n")

    assert target.read_text() == "new = true\n"
    assert list(tmp_path.iterdir()) == [target]


def test_backup_file_copies_content(tmp_path: Path) -> None:
    target = tmp_path / "devices.toml"
    target.write_text("x = 1\n")

    backup = backup_file(target)

    assert backup == tmp_path / "devices.toml.bak"
    assert backup.read_text() == "x = 1\n"
    assert target.read_text() == "x = 1\n"
