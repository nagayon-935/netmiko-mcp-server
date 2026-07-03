"""MCP tool definitions for the netmiko MCP server."""

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from mcp.server.fastmcp import FastMCP
from netmiko import exceptions
from paramiko.ssh_exception import SSHException

import output_store
from audit import (
    OUTCOME_CONNECTION_ERROR,
    OUTCOME_SUCCESS,
    log_command_attempt,
    log_connection_outcome,
)
from inventory import Device, get_device_names, load_config_toml
from security import CommandPolicy, validate_command, validate_config_command

logger = logging.getLogger("netmiko-mcp-server")

# netmiko's exception hierarchy is inconsistent: most of its exceptions derive
# from NetmikoBaseException, but NetmikoTimeoutException and
# NetmikoAuthenticationException derive from paramiko's SSHException instead
# (kept that way for backwards compatibility with paramiko-based code). Catch
# both hierarchies together so device-unreachable and bad-credential errors
# surface as a clean "Connection Error" response instead of an unhandled
# exception.
CONNECTION_ERRORS = (exceptions.NetmikoBaseException, SSHException)

# Set by main() at startup from CLI arguments.
enable_config: bool = False
command_policy: CommandPolicy = CommandPolicy()
config_command_policy: CommandPolicy = CommandPolicy()
output_save_threshold: int = 1000
max_workers: int = 10

mcp = FastMCP("netmiko server", dependencies=["netmiko"])


@mcp.tool()
def get_network_device_list() -> str:
    """
    List all network devices that are controllable through this netmiko MCP server.
    """
    logger.info("device list requested")
    devs = load_config_toml()
    return json.dumps([dev.json() for dev in devs.values()])


def _maybe_save_output(
    device_name: str, command: str, output: Any, save_output: bool
) -> Any:
    """Persist output to disk when explicitly requested or when it exceeds
    output_save_threshold lines, returning a short pointer message instead of
    the raw output in either case. Otherwise returns output unchanged.
    """
    if save_output:
        saved_name = output_store.save_output(device_name, command, output)
        return f"Output saved as '{saved_name}'."

    as_str = (
        json.dumps(output, indent=2)
        if isinstance(output, (list, dict))
        else str(output)
    )
    line_count = len(as_str.splitlines())
    if line_count > output_save_threshold:
        saved_name = output_store.save_output(device_name, command, output)
        return (
            f"Output too large to return inline ({line_count:,} lines, exceeds "
            f"output_save_threshold of {output_save_threshold:,}). Automatically "
            f"saved as '{saved_name}'. Use read_device_output to retrieve it."
        )
    return output


def _execute_show_command(
    tool: str,
    device_name: str,
    device: Device,
    normalized_command: str,
    original_command: str,
    use_textfsm: bool,
    save_output: bool,
) -> Any:
    """Run normalized_command on device and return its (possibly saved) output.

    Shared by send_command_and_get_output and send_command_to_group so both
    tools apply the same connection-error handling, audit logging, and
    output-size policy.
    """
    try:
        output = device.send_command(normalized_command, use_textfsm=use_textfsm)
        log_connection_outcome(
            tool=tool,
            device=device_name,
            command=original_command,
            outcome=OUTCOME_SUCCESS,
        )
    except CONNECTION_ERRORS as exc:
        log_connection_outcome(
            tool=tool,
            device=device_name,
            command=original_command,
            outcome=OUTCOME_CONNECTION_ERROR,
            detail=str(exc),
        )
        return f"Connection Error: {exc}"

    return _maybe_save_output(device_name, original_command, output, save_output)


@mcp.tool()
def send_command_and_get_output(
    name: str, command: str, use_textfsm: bool = False, save_output: bool = False
) -> Any:
    """
    Connect to a network device and execute a single command.

    Args:
        name: The exact device name from the inventory.
        command: The CLI command to execute.
        use_textfsm: If True, attempt to parse the output into structured JSON
            data using ntc-templates. Falls back to raw text if no template matches.
        save_output: If True, always save output to disk and return the filename
            instead of the raw output.

    If save_output is False and the output exceeds output_save_threshold lines
    (default 1000), it is automatically saved to disk instead. Use
    list_device_outputs and read_device_output to retrieve saved content.
    """
    result = validate_command(command, command_policy)
    log_command_attempt(
        tool="send_command_and_get_output",
        device=name,
        command=command,
        verdict="ALLOWED" if result.allowed else "DENIED",
        reason=result.reason,
    )
    if not result.allowed:
        logger.warning("blocked command for %s: %s (%s)", name, command, result.reason)
        return (
            f"Security Error: command '{command}' is not permitted ({result.reason})."
        )

    devs = load_config_toml()
    if name not in devs:
        ret = f"Error: no device named '{name}'"
        logger.warning("get_output: %s", ret)
        return ret

    return _execute_show_command(
        tool="send_command_and_get_output",
        device_name=name,
        device=devs[name],
        normalized_command=result.normalized_command,
        original_command=command,
        use_textfsm=use_textfsm,
        save_output=save_output,
    )


@mcp.tool()
def send_command_to_group(
    device_or_group: str,
    command: str,
    use_textfsm: bool = False,
    save_output: bool = False,
) -> dict[str, Any]:
    """
    Execute a command concurrently across a group of devices.

    Args:
        device_or_group: A device name, a group name defined in the inventory's
            [groups] table, or 'all' for every device in the inventory.
        command: The CLI command to execute on each device.
        use_textfsm: If True, attempt to return parsed structured JSON data.
        save_output: If True, save per-device output to files instead of
            returning raw output.

    Returns:
        A dict mapping each device name to its output (or an error string).
    """
    result = validate_command(command, command_policy)
    log_command_attempt(
        tool="send_command_to_group",
        device=f"GROUP:{device_or_group}",
        command=command,
        verdict="ALLOWED" if result.allowed else "DENIED",
        reason=result.reason,
    )
    if not result.allowed:
        return {
            "error": f"Security Error: command '{command}' is not permitted ({result.reason})."
        }

    try:
        device_names = get_device_names(device_or_group)
    except ValueError as e:
        return {"error": f"Inventory Error: {e}"}

    devs = load_config_toml()
    results: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {
            executor.submit(
                _execute_show_command,
                "send_command_to_group",
                device_name,
                devs[device_name],
                result.normalized_command,
                command,
                use_textfsm,
                save_output,
            ): device_name
            for device_name in device_names
        }
        for future in as_completed(future_to_name):
            device_name = future_to_name[future]
            results[device_name] = future.result()

    return results


@mcp.tool()
def list_device_outputs(device_or_group: str) -> str:
    """
    List saved output files for a device, group, or 'all'.

    Returns a JSON object mapping each device name to a list of saved
    filenames (newest first).
    """
    try:
        device_names = get_device_names(device_or_group)
    except ValueError as e:
        return json.dumps({"error": f"Inventory Error: {e}"})
    return json.dumps({name: output_store.list_outputs(name) for name in device_names})


@mcp.tool()
def read_device_output(
    device_name: str, filename: str, offset: int = 0, limit: int = 500
) -> str:
    """
    Read a previously saved output file for a device, with pagination.

    Args:
        device_name: The device name whose output directory to read from.
        filename: The exact filename as returned by list_device_outputs.
        offset: Line number to start reading from (0-indexed). Defaults to 0.
        limit: Maximum number of lines to return. Defaults to 500.
    """
    return output_store.read_output(device_name, filename, offset, limit)


@mcp.tool()
def set_config_commands_and_commit_or_save(name: str, commands: list[str]) -> str:
    """
    Send configuration commands to a network device specified by the name.

    Disabled by default; start the server with --enable-config to allow this
    tool. Each command is validated against config_allowed_commands /
    config_denied_commands (from --commands-file) before anything is sent to
    the device; if any single command is denied, none of them are sent.
    Certain state-changing commands (interface shutdown/no shutdown, clear)
    are always denied regardless of configuration.
    """
    joined_commands = "; ".join(commands)

    if not enable_config:
        log_command_attempt(
            tool="set_config_commands_and_commit_or_save",
            device=name,
            command=joined_commands,
            verdict="DENIED",
            reason="CONFIG_MODE_DISABLED",
        )
        return (
            "Error: configuration changes are disabled by default. "
            "Start the server with --enable-config to allow this tool."
        )

    normalized_commands: list[str] = []
    for cmd in commands:
        result = validate_config_command(cmd, config_command_policy)
        log_command_attempt(
            tool="set_config_commands_and_commit_or_save",
            device=name,
            command=cmd,
            verdict="ALLOWED" if result.allowed else "DENIED",
            reason=result.reason,
        )
        if not result.allowed:
            logger.warning(
                "blocked config command for %s: %s (%s)", name, cmd, result.reason
            )
            return f"Security Error: config command '{cmd}' is not permitted ({result.reason})."
        normalized_commands.append(result.normalized_command)

    devs = load_config_toml()
    if name not in devs:
        ret = f"Error: no device named '{name}'"
        logger.warning("set_config: %s", ret)
        return ret

    try:
        ret = devs[name].send_config_set_and_commit_and_save(normalized_commands)
        log_connection_outcome(
            tool="set_config_commands_and_commit_or_save",
            device=name,
            command=joined_commands,
            outcome=OUTCOME_SUCCESS,
        )
    except CONNECTION_ERRORS as exc:
        ret = f"Connection Error: {exc}"
        log_connection_outcome(
            tool="set_config_commands_and_commit_or_save",
            device=name,
            command=joined_commands,
            outcome=OUTCOME_CONNECTION_ERROR,
            detail=str(exc),
        )

    logger.info("set: name=%s commands=%s", name, commands)

    return ret
