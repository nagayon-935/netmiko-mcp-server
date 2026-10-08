import asyncio
import json

import pytest

import inventory
import server
from inventory import Device, load_inventory


@pytest.fixture
def registered_inventory(tmp_path, monkeypatch):
    path = tmp_path / "devices.toml"
    path.write_text("""
[default]
device_type = "cisco_ios"
username = "DO_NOT_EXPOSE_USER"
password = "DO_NOT_EXPOSE_PASSWORD"
secret = "DO_NOT_EXPOSE_SECRET"
[r1]
hostname = "192.0.2.1"
site = "Tokyo"
role = "core-switch"
environment = "production"
description = "東京の基幹スイッチ"
tags = ["bgp", "critical"]
[r2]
hostname = "192.0.2.2"
site = "Tokyo"
role = "edge-router"
environment = "lab"
tags = ["bgp"]
[r3]
hostname = "192.0.2.3"
site = "Osaka"
role = "core-switch"
environment = "production"
[groups]
core = ["r1", "r3", "r1"]
""")
    monkeypatch.setattr(inventory, "tomlpath", str(path))

    def unexpected(**kwargs):
        raise AssertionError("Discovery must not open device connections")

    monkeypatch.setattr(inventory, "ConnectHandler", unexpected)
    return path


def names(result):
    return [device["name"] for device in result["matches"]]


@pytest.mark.parametrize(
    "filters, expected",
    [
        ({"query": "TOKYO"}, ["r1", "r2"]),
        ({"query": "基幹"}, ["r1"]),
        ({"site": "Tokyo", "environment": "PRODUCTION"}, ["r1"]),
        ({"role": "core-switch"}, ["r1", "r3"]),
        ({"tag": "BGP", "environment": "lab"}, ["r2"]),
        ({"group": "CORE"}, ["r1", "r3"]),
        ({"query": "192.0.2.3"}, ["r3"]),
        ({"query": "unknown"}, []),
    ],
)
def test_search_by_public_metadata(registered_inventory, filters, expected):
    result = server.find_network_devices(**filters)
    assert names(result) == expected
    assert result["total"] == len(expected)
    assert result["executed"] is False


def test_ambiguity_is_based_on_all_candidates_before_truncation(registered_inventory):
    result = server.find_network_devices(site="Tokyo", limit=1)
    assert len(result["matches"]) == 1
    assert result["total"] == 2
    assert result["requires_selection"] is True
    assert result["truncated"] is True
    with pytest.raises(ValueError, match="no device or group named"):
        inventory.get_device_names("Tokyo")


def test_discovery_never_exposes_credentials_or_key_paths(registered_inventory):
    listing = json.loads(server.get_network_device_list())
    assert listing[0]["groups"] == ["core"]
    assert listing[0]["site"] == "Tokyo"
    serialized = json.dumps(listing) + json.dumps(server.find_network_devices())
    assert "DO_NOT_EXPOSE" not in serialized
    for device in listing:
        assert (
            not {"username", "password", "secret", "key_file", "pre_commands"}
            & device.keys()
        )


def test_group_discovery_deduplicates_members(registered_inventory):
    assert server.get_network_group_list() == {"core": ["r1", "r3"]}


def test_inventory_changes_are_visible_on_next_search(registered_inventory):
    assert server.find_network_devices(site="Kyoto")["total"] == 0
    registered_inventory.write_text(
        registered_inventory.read_text().replace('site = "Osaka"', 'site = "Kyoto"')
    )
    assert names(server.find_network_devices(site="Kyoto")) == ["r3"]


@pytest.mark.parametrize(
    "field, value",
    [
        ("site", 42),
        ("role", []),
        ("environment", True),
        ("description", {}),
        ("tags", "bgp"),
        ("tags", ["bgp", 42]),
        ("tags", [""]),
    ],
)
def test_metadata_is_validated_before_search(field, value):
    with pytest.raises(ValueError, match=field):
        Device(name="r1", device_type="cisco_ios", **{field: value})


def test_metadata_is_not_forwarded_to_netmiko():
    device = Device(
        name="r1",
        hostname="192.0.2.1",
        device_type="cisco_ios",
        site="Tokyo",
        role="core",
        environment="production",
        description="core switch",
        tags=["bgp"],
    )
    assert (
        not {"site", "role", "environment", "description", "tags"}
        & device.connect_kwargs.keys()
    )
    data = device.json()
    data["tags"].append("changed")
    assert device.tags == ["bgp"]


@pytest.mark.parametrize("group", ["all", "r1"])
def test_unreachable_group_names_are_reported(registered_inventory, group):
    registered_inventory.write_text(
        registered_inventory.read_text().replace("core =", f"{group} =")
    )
    with pytest.raises(ValueError, match="conflicts"):
        load_inventory().describe_devices()


def test_reserved_all_device_name_is_rejected():
    with pytest.raises(ValueError, match="reserved"):
        Device(name="all", device_type="cisco_ios")


def test_registered_name_cannot_be_replaced_by_another_name(registered_inventory):
    registered_inventory.write_text(
        registered_inventory.read_text().replace("[r1]", '[r1]\nname = "r2"')
    )
    with pytest.raises(ValueError, match="registered name"):
        load_inventory()


@pytest.mark.parametrize("limit", [0, -1, 101])
def test_search_limits_are_validated(registered_inventory, limit):
    assert "error" in server.find_network_devices(limit=limit)


def test_discovery_tools_have_mcp_argument_schemas(registered_inventory):
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    schema = tools["find_network_devices"].inputSchema
    assert {"query", "site", "role", "environment", "group", "tag", "limit"} <= schema[
        "properties"
    ].keys()
    assert "get_network_group_list" in tools
