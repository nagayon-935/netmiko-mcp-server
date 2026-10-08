import asyncio

import pytest

import server
from security import CommandPolicy, validate_command, validate_config_command


@pytest.fixture(autouse=True)
def configured_server(monkeypatch):
    monkeypatch.setattr(server, "enable_config", False)
    monkeypatch.setattr(
        server,
        "command_policy",
        CommandPolicy(("show version", "show ip route *"), ("show running-config*",)),
    )
    monkeypatch.setattr(
        server, "config_command_policy", CommandPolicy(("description *", "shutdown"))
    )


def test_discovery_reports_effective_rules_and_default_deny():
    result = server.get_server_capabilities()
    assert result["default_deny"] is True
    assert result["configuration_enabled"] is False
    assert "shutdown*" in result["configuration_commands"]["denied_commands"]
    assert result["show_commands"]["allowed_commands"] == [
        "show version",
        "show ip route *",
    ]


@pytest.mark.parametrize(
    "command",
    [
        "SHOW   version",
        "show ip route",
        "show ip route vrf blue",
        "reload",
        "show\nversion",
    ],
)
def test_permission_preview_agrees_with_execution_validation(command):
    preview = server.check_command_permission(command)
    decision = validate_command(command, server.command_policy)
    assert preview["allowed"] == decision.allowed
    assert preview["reason"] == decision.reason
    assert preview["executed"] is False


def test_config_preview_denies_when_disabled():
    result = server.check_command_permission("description uplink", configuration=True)
    assert result["allowed"] is False
    assert result["reason"] == "CONFIG_MODE_DISABLED"


@pytest.mark.parametrize(
    "command", ["description uplink", "shutdown", "clear counters"]
)
def test_config_preview_enforces_baseline_deny(monkeypatch, command):
    monkeypatch.setattr(server, "enable_config", True)
    decision = validate_config_command(command, server.config_command_policy)
    preview = server.check_command_permission(command, configuration=True)
    assert preview["allowed"] == decision.allowed
    assert preview["reason"] == decision.reason


def test_discovery_and_preview_never_load_inventory_or_connect(monkeypatch):
    def unexpected():
        raise AssertionError("Discovery must work without device access")

    monkeypatch.setattr(server, "load_config_toml", unexpected)
    monkeypatch.setattr(server, "load_inventory", unexpected)
    server.get_server_capabilities()
    server.check_command_permission("show version")


def test_capabilities_do_not_expose_mutable_policy_state():
    result = server.get_server_capabilities()
    result["show_commands"]["allowed_commands"].append("reload")
    assert server.check_command_permission("reload")["allowed"] is False


def test_new_tools_are_registered_with_mcp():
    names = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert {"get_server_capabilities", "check_command_permission"} <= names
