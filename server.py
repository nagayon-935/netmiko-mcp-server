"""MCP tool definitions for the netmiko MCP server."""

import json
import logging

from mcp.server.fastmcp import FastMCP
from netmiko import exceptions

from audit import (
    OUTCOME_CONNECTION_ERROR,
    OUTCOME_SUCCESS,
    log_command_attempt,
    log_connection_outcome,
)
from inventory import load_config_toml
from security import CommandPolicy, validate_command

logger = logging.getLogger("netmiko-mcp-server")

# Set by main() at startup from CLI arguments.
enable_config: bool = False
command_policy: CommandPolicy = CommandPolicy()

mcp = FastMCP("netmiko server", dependencies=["netmiko"])


@mcp.tool()
def get_network_device_list() -> str:
    """
    List all network devices that are controllable through this netmiko MCP server.
    """
    logger.info("device list requested")
    devs = load_config_toml()
    return json.dumps([dev.json() for dev in devs.values()])


@mcp.tool()
def send_command_and_get_output(name: str, command: str) -> str:
    """
    Send a command to a network device specified by the name and return its output.
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

    try:
        ret = devs[name].send_command(result.normalized_command)
        log_connection_outcome(
            tool="send_command_and_get_output",
            device=name,
            command=command,
            outcome=OUTCOME_SUCCESS,
        )
    except exceptions.ConnectionException as exc:
        ret = f"Connection Error: {exc}"
        log_connection_outcome(
            tool="send_command_and_get_output",
            device=name,
            command=command,
            outcome=OUTCOME_CONNECTION_ERROR,
            detail=str(exc),
        )

    logger.info("get: name=%s command='%s'", name, command)

    return ret


@mcp.tool()
def set_config_commands_and_commit_or_save(name: str, commands: list[str]) -> str:
    """
    Send configuration commands to a network device specified by the name.
    Disabled by default; start the server with --enable-config to allow this tool.
    """
    joined_commands = "; ".join(commands)
    log_command_attempt(
        tool="set_config_commands_and_commit_or_save",
        device=name,
        command=joined_commands,
        verdict="ALLOWED" if enable_config else "DENIED",
        reason="ALLOWED" if enable_config else "CONFIG_MODE_DISABLED",
    )
    if not enable_config:
        return (
            "Error: configuration changes are disabled by default. "
            "Start the server with --enable-config to allow this tool."
        )

    devs = load_config_toml()
    if name not in devs:
        ret = f"Error: no device named '{name}'"
        logger.warning("set_config: %s", ret)
        return ret

    try:
        ret = devs[name].send_config_set_and_commit_and_save(commands)
        log_connection_outcome(
            tool="set_config_commands_and_commit_or_save",
            device=name,
            command=joined_commands,
            outcome=OUTCOME_SUCCESS,
        )
    except exceptions.ConnectionException as exc:
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
