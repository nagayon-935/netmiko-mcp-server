import json

import pytest
from netmiko import exceptions

import output_store
import server
from inventory import Device
from security import CommandPolicy


class _StubDevice:
    """Stand-in for inventory.Device that never opens a real connection."""

    def __init__(
        self, name: str, *, output: object = "ok", raise_exc: Exception | None = None
    ):
        self.name = name
        self._output = output
        self._raise_exc = raise_exc
        self.last_command: str | None = None
        self.last_use_textfsm: bool | None = None
        self.last_config_commands: list[str] | None = None

    def json(self):
        return {"name": self.name}

    def send_command(self, cmd: str, use_textfsm: bool = False) -> object:
        self.last_command = cmd
        self.last_use_textfsm = use_textfsm
        if self._raise_exc:
            raise self._raise_exc
        return self._output

    def send_config_set_and_commit_and_save(self, cmds: list[str]) -> str:
        self.last_config_commands = cmds
        if self._raise_exc:
            raise self._raise_exc
        return str(self._output)


@pytest.fixture(autouse=True)
def _reset_server_globals():
    original_enable_config = server.enable_config
    original_policy = server.command_policy
    original_threshold = server.output_save_threshold
    original_max_workers = server.max_workers
    yield
    server.enable_config = original_enable_config
    server.command_policy = original_policy
    server.output_save_threshold = original_threshold
    server.max_workers = original_max_workers


@pytest.fixture(autouse=True)
def _configure_audit_log(tmp_path):
    from audit import configure_audit_logger

    configure_audit_logger(str(tmp_path / "audit.log"))


@pytest.fixture(autouse=True)
def _configure_output_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(output_store, "output_dir", str(tmp_path / "outputs"))


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
    assert stub.last_use_textfsm is False


def test_send_command_forwards_use_textfsm(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    stub = _StubDevice("r1", output={"parsed": True})
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version", use_textfsm=True)

    assert result == {"parsed": True}
    assert stub.last_use_textfsm is True


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


def test_send_command_save_output_true_writes_file(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    stub = _StubDevice("r1", output="line1\nline2")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version", save_output=True)

    assert "Output saved as" in result
    assert output_store.list_outputs("r1") != []


def test_send_command_auto_saves_when_over_threshold(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    server.output_save_threshold = 3
    stub = _StubDevice("r1", output="\n".join(f"line{i}" for i in range(10)))
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})

    result = server.send_command_and_get_output("r1", "show version")

    assert "too large" in result
    assert output_store.list_outputs("r1") != []


def test_send_command_to_group_runs_on_each_device(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    stub1 = _StubDevice("r1", output="out1")
    stub2 = _StubDevice("r2", output="out2")
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub1, "r2": stub2})
    monkeypatch.setattr(server, "get_device_names", lambda group: ["r1", "r2"])

    result = server.send_command_to_group("mygroup", "show version")

    assert result == {"r1": "out1", "r2": "out2"}


def test_send_command_to_group_denied_by_policy(monkeypatch):
    server.command_policy = CommandPolicy()

    result = server.send_command_to_group("mygroup", "show version")

    assert "error" in result
    assert "Security Error" in result["error"]


def test_send_command_to_group_unknown_group_returns_error(monkeypatch):
    server.command_policy = CommandPolicy(allowed_commands=("show version",))
    monkeypatch.setattr(
        server,
        "get_device_names",
        lambda g: (_ for _ in ()).throw(ValueError(f"no device or group named '{g}'")),
    )

    result = server.send_command_to_group("missing", "show version")

    assert "error" in result
    assert "Inventory Error" in result["error"]


def test_list_and_read_device_outputs_roundtrip(monkeypatch):
    monkeypatch.setattr(server, "get_device_names", lambda name: [name])
    output_store.save_output("r1", "show version", "hello\nworld")

    listing = json.loads(server.list_device_outputs("r1"))
    assert list(listing.keys()) == ["r1"]
    filename = listing["r1"][0]

    content = server.read_device_output("r1", filename)
    assert "hello" in content
    assert "world" in content


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
