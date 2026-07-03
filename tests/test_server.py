import json

import pytest
from netmiko import exceptions

import server
from inventory import Device
from security import CommandPolicy


class _StubDevice:
    """Stand-in for inventory.Device that never opens a real connection."""

    def __init__(
        self, name: str, *, output: str = "ok", raise_exc: Exception | None = None
    ):
        self.name = name
        self._output = output
        self._raise_exc = raise_exc
        self.last_command: str | None = None
        self.last_config_commands: list[str] | None = None

    def json(self):
        return {"name": self.name}

    def send_command(self, cmd: str) -> str:
        self.last_command = cmd
        if self._raise_exc:
            raise self._raise_exc
        return self._output

    def send_config_set_and_commit_and_save(self, cmds: list[str]) -> str:
        self.last_config_commands = cmds
        if self._raise_exc:
            raise self._raise_exc
        return self._output


@pytest.fixture(autouse=True)
def _reset_server_globals():
    original_enable_config = server.enable_config
    original_policy = server.command_policy
    yield
    server.enable_config = original_enable_config
    server.command_policy = original_policy


@pytest.fixture(autouse=True)
def _configure_audit_log(tmp_path):
    from audit import configure_audit_logger

    configure_audit_logger(str(tmp_path / "audit.log"))


def test_get_network_device_list_returns_sanitized_json(monkeypatch):
    device = Device(
        name="r1", hostname="192.0.2.1", device_type="cisco_ios", password="secret"
    )
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": device})

    result = json.loads(server.get_network_device_list())

    assert result == [
        {"name": "r1", "hostname": "192.0.2.1", "device_type": "cisco_ios", "port": 22}
    ]


def test_send_command_denied_by_default_policy(monkeypatch):
    server.command_policy = CommandPolicy()
    stub = _StubDevice("r1")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version")

    assert "Security Error" in result
    assert stub.last_command is None


def test_send_command_allowed_reaches_device(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    stub = _StubDevice("r1", output="Cisco IOS")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version")

    assert result == "Cisco IOS"
    assert stub.last_command == "show version"


def test_send_command_unknown_device_returns_error(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    monkeypatch.setattr(server, "load_config_toml", lambda: {})

    result = server.send_command_and_get_output("missing", "show version")

    assert "no device named" in result


def test_send_command_connection_exception_is_caught(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    stub = _StubDevice("r1", raise_exc=exceptions.ConnectionException("boom"))
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version")

    assert "Connection Error" in result


def test_set_config_denied_by_default(monkeypatch):
    server.enable_config = False
    stub = _StubDevice("r1")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.set_config_commands_and_commit_or_save("r1", ["no shutdown"])

    assert "disabled by default" in result
    assert stub.last_config_commands is None


def test_set_config_allowed_when_enabled(monkeypatch):
    server.enable_config = True
    stub = _StubDevice("r1", output="applied")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.set_config_commands_and_commit_or_save("r1", ["no shutdown"])

    assert result == "applied"
    assert stub.last_config_commands == ["no shutdown"]
