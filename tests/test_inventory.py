import pytest

import inventory
from credential_crypto import KEY_ENV_VAR, encrypt_value, generate_key
from inventory import Device, get_device_names, load_config_toml, load_groups


def test_device_rejects_invalid_device_type():
    with pytest.raises(ValueError, match="invalid device_type"):
        Device(name="r1", hostname="192.0.2.1", device_type="not_a_real_platform")


def test_device_defaults_ssh_port_22():
    device = Device(name="r1", hostname="192.0.2.1", device_type="cisco_ios")
    assert device.port == 22


def test_device_defaults_telnet_port_23():
    device = Device(name="r1", hostname="192.0.2.1", device_type="cisco_ios_telnet")
    assert device.port == 23


def test_device_json_excludes_credentials():
    device = Device(
        name="r1",
        hostname="192.0.2.1",
        device_type="cisco_ios",
        username="admin",
        password="hunter2",
        secret="enablepass",
    )
    data = device.json()
    assert "password" not in data
    assert "username" not in data
    assert "secret" not in data
    assert data == {
        "name": "r1",
        "hostname": "192.0.2.1",
        "device_type": "cisco_ios",
        "port": 22,
    }


def test_connect_kwargs_omits_unset_optional_fields():
    device = Device(name="r1", hostname="192.0.2.1", device_type="cisco_ios")
    kwargs = device.connect_kwargs
    assert "username" not in kwargs
    assert "password" not in kwargs
    assert "secret" not in kwargs
    assert kwargs["host"] == "192.0.2.1"


def test_load_config_toml_raises_when_tomlpath_unset(monkeypatch):
    monkeypatch.setattr(inventory, "tomlpath", None)
    with pytest.raises(RuntimeError, match="config toml is not specified"):
        load_config_toml()


def test_load_config_toml_applies_defaults(tmp_path, monkeypatch):
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        """
        [default]
        username = "netops"
        password = "password"

        [router1]
        hostname = "192.0.2.10"
        device_type = "cisco_ios"

        [router2]
        hostname = "192.0.2.11"
        device_type = "cisco_ios"
        username = "override"
        """
    )
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    devs = load_config_toml()

    assert devs["router1"].username == "netops"
    assert devs["router1"].password == "password"
    assert devs["router2"].username == "override"
    assert devs["router2"].password == "password"


def test_load_config_toml_rejects_non_table_entries(tmp_path, monkeypatch):
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text('bad_entry = "not a table"\n')
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    with pytest.raises(ValueError, match="unexpected value in toml"):
        load_config_toml()


def _write_devices_with_groups(tmp_path):
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        """
        [router1]
        hostname = "192.0.2.10"
        device_type = "cisco_ios"

        [router2]
        hostname = "192.0.2.11"
        device_type = "cisco_ios"

        [groups]
        core = ["router1", "router2"]
        """
    )
    return toml_file


def test_load_config_toml_skips_groups_table(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    devs = load_config_toml()

    assert set(devs.keys()) == {"router1", "router2"}


def test_load_groups_returns_group_table(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    assert load_groups() == {"core": ["router1", "router2"]}


def test_get_device_names_resolves_single_device(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    assert get_device_names("router1") == ["router1"]


def test_get_device_names_resolves_group(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    assert set(get_device_names("core")) == {"router1", "router2"}


def test_get_device_names_resolves_all(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    assert set(get_device_names("all")) == {"router1", "router2"}


def test_get_device_names_raises_for_unknown_name(tmp_path, monkeypatch):
    toml_file = _write_devices_with_groups(tmp_path)
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    with pytest.raises(ValueError, match="no device or group named"):
        get_device_names("nonexistent")


def test_get_device_names_raises_for_group_with_unknown_member(tmp_path, monkeypatch):
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        """
        [router1]
        hostname = "192.0.2.10"
        device_type = "cisco_ios"

        [groups]
        core = ["router1", "ghost"]
        """
    )
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    with pytest.raises(ValueError, match="unknown device"):
        get_device_names("core")


def test_load_config_toml_decrypts_encrypted_password(tmp_path, monkeypatch):
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key)
    encrypted = encrypt_value("hunter2", key)

    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        f"""
        [router1]
        hostname = "192.0.2.10"
        device_type = "cisco_ios"
        password = "{encrypted}"
        """
    )
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    devs = load_config_toml()

    assert devs["router1"].password == "hunter2"


def test_load_config_toml_raises_when_key_missing_for_encrypted_value(
    tmp_path, monkeypatch
):
    key = generate_key()
    encrypted = encrypt_value("hunter2", key)
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)

    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        f"""
        [router1]
        hostname = "192.0.2.10"
        device_type = "cisco_ios"
        password = "{encrypted}"
        """
    )
    monkeypatch.setattr(inventory, "tomlpath", str(toml_file))

    with pytest.raises(RuntimeError, match=KEY_ENV_VAR):
        load_config_toml()
