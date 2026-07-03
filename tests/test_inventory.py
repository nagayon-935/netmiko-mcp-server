import pytest

import inventory
from inventory import Device, load_config_toml


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
