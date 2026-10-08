import asyncio
import json

import pytest
from mcp.types import CallToolResult
from netmiko import exceptions

import output_store
import server
from audit import AuditWriteError, configure_audit_logger
from inventory import Inventory
from security import CommandPolicy


class StubDevice:
    def __init__(self, output="ok", error=None):
        self.output = output
        self.error = error
        self.calls = 0

    def json(self):
        return {"name": "r1", "hostname": "192.0.2.1"}

    def send_command(self, cmd, use_textfsm=False):
        self.calls += 1
        if self.error:
            raise self.error
        return self.output

    def send_config_set_and_commit_and_save(self, cmds):
        return self.send_command("configuration")


@pytest.fixture
def device(tmp_path, monkeypatch):
    configure_audit_logger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "command_policy", CommandPolicy(("show version",)))
    monkeypatch.setattr(
        server, "config_command_policy", CommandPolicy(("description *",))
    )
    monkeypatch.setattr(server, "enable_config", True)
    monkeypatch.setattr(output_store, "output_dir", str(tmp_path / "outputs"))
    stub = StubDevice()
    monkeypatch.setattr(server, "load_config_toml", lambda: {"r1": stub})
    monkeypatch.setattr(server, "load_inventory", lambda: Inventory({"r1": stub}, {}))
    return stub


def call(tool_name, **arguments):
    result = asyncio.run(server.mcp.call_tool(tool_name, arguments))
    assert isinstance(result, CallToolResult)
    payload = result.structuredContent
    assert payload is not None
    assert json.loads(result.content[0].text) == payload
    assert result.isError is (not payload["ok"])
    return payload


@pytest.mark.parametrize(
    "output",
    [
        "ok",
        "Error: a device's ordinary output",
        {"error": "ordinary parsed data"},
        [{"interface": "Gi0/1"}],
    ],
)
def test_successful_output_is_not_misclassified_as_an_error(device, output):
    device.output = output
    payload = call("send_command_and_get_output", name="r1", command="show version")
    assert payload == {"ok": True, "data": output}


def test_policy_denial_is_structured_and_does_not_execute(device):
    payload = call("send_command_and_get_output", name="r1", command="reload")
    assert payload["error"]["code"] == "NO_ALLOW_MATCH"
    assert payload["error"]["execution_state"] == "not_started"
    assert payload["error"]["next_action"]
    assert device.calls == 0


@pytest.mark.parametrize(
    "exc, code",
    [
        (
            exceptions.NetmikoAuthenticationException("DO_NOT_EXPOSE"),
            "AUTHENTICATION_FAILED",
        ),
        (exceptions.NetmikoTimeoutException("DO_NOT_EXPOSE"), "CONNECTION_TIMEOUT"),
        (exceptions.ReadTimeout("DO_NOT_EXPOSE"), "CONNECTION_TIMEOUT"),
        (OSError("DO_NOT_EXPOSE"), "CONNECTION_FAILED"),
    ],
)
def test_connection_failures_have_distinct_codes_without_raw_details(device, exc, code):
    device.error = exc
    payload = call("send_command_and_get_output", name="r1", command="show version")
    assert payload["error"]["code"] == code
    assert "DO_NOT_EXPOSE" not in json.dumps(payload)


def test_failed_config_requires_state_inspection_before_retry(device):
    device.error = exceptions.ReadTimeout("timeout after some commands")
    payload = call(
        "set_config_commands_and_commit_or_save",
        name="r1",
        commands=["description uplink"],
    )
    assert payload["error"]["execution_state"] == "unknown"
    assert payload["error"]["retryable"] is False
    assert "Inspect the device configuration" in payload["error"]["next_action"]
    assert device.calls == 1


@pytest.mark.parametrize(
    "stage, calls, state", [("attempt", 0, "not_started"), ("outcome", 1, "unknown")]
)
def test_audit_failure_stops_operation_and_reports_execution_state(
    device, monkeypatch, stage, calls, state
):
    def fail(**kwargs):
        raise AuditWriteError(state)

    monkeypatch.setattr(
        server,
        "log_command_attempt" if stage == "attempt" else "log_connection_outcome",
        fail,
    )
    payload = call("send_command_and_get_output", name="r1", command="show version")
    assert payload["error"]["code"] == "AUDIT_WRITE_FAILED"
    assert payload["error"]["execution_state"] == state
    assert payload["error"]["retryable"] is False
    assert device.calls == calls


def test_output_save_failure_does_not_suggest_command_failed(device, monkeypatch):
    def fail(*args):
        raise OSError("DO_NOT_EXPOSE")

    monkeypatch.setattr(output_store, "save_output", fail)
    payload = call(
        "send_command_and_get_output",
        name="r1",
        command="show version",
        save_output=True,
    )
    assert payload["error"]["code"] == "OUTPUT_SAVE_FAILED"
    assert payload["error"]["execution_state"] == "completed"
    assert "DO_NOT_EXPOSE" not in json.dumps(payload)
    assert device.calls == 1


def test_group_result_preserves_successful_and_failed_devices(device, monkeypatch):
    bad = StubDevice(error=exceptions.NetmikoAuthenticationException("wrong password"))
    monkeypatch.setattr(
        server,
        "load_inventory",
        lambda: Inventory({"r1": device, "r2": bad}, {"core": ["r1", "r2"]}),
    )
    payload = call(
        "send_command_to_group", device_or_group="core", command="show version"
    )
    assert payload["ok"] is False
    assert payload["summary"] == {"total": 2, "succeeded": 1, "failed": 1}
    assert payload["data"]["r1"] == {"ok": True, "data": "ok"}
    assert payload["data"]["r2"]["error"]["code"] == "AUTHENTICATION_FAILED"


def test_inventory_errors_are_structured_without_secret_details(device, monkeypatch):
    def fail():
        raise ValueError("DO_NOT_EXPOSE")

    monkeypatch.setattr(server, "load_config_toml", fail)
    payload = call("get_network_device_list")
    assert payload["error"]["code"] == "INVENTORY_UNAVAILABLE"
    assert "DO_NOT_EXPOSE" not in json.dumps(payload)


def test_lists_are_returned_as_structured_data(device, monkeypatch):
    assert call("get_network_device_list")["data"] == [device.json()]
    monkeypatch.setattr(server, "get_device_names", lambda target: ["r1"])
    assert call("list_device_outputs", device_or_group="r1")["data"] == {"r1": []}


@pytest.mark.parametrize(
    "arguments, code",
    [
        ({"filename": "missing.txt"}, "OUTPUT_NOT_FOUND"),
        ({"filename": "../private.txt"}, "UNSAFE_OUTPUT_PATH"),
        ({"filename": "missing.txt", "offset": -1}, "INVALID_PAGINATION"),
    ],
)
def test_output_read_errors_use_the_same_contract(device, arguments, code):
    payload = call("read_device_output", device_name="r1", **arguments)
    assert payload["error"]["code"] == code


def test_registration_preserves_original_tool_argument_schema():
    tools = {tool.name: tool for tool in asyncio.run(server.mcp.list_tools())}
    schema = tools["send_command_and_get_output"].inputSchema
    assert set(schema["required"]) == {"name", "command"}
    assert {"use_textfsm", "save_output"} <= set(schema["properties"])
