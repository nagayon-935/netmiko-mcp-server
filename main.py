import argparse
import json
import logging
import os
import tomllib
from dataclasses import dataclass
import ipaddress
from typing import Any

from netmiko import ConnectHandler
from netmiko import exceptions
from netmiko.ssh_dispatcher import platforms, telnet_platforms

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.responses import PlainTextResponse

from audit import (
    OUTCOME_CONNECTION_ERROR,
    OUTCOME_SUCCESS,
    configure_audit_logger,
    log_command_attempt,
    log_connection_outcome,
)
from http_auth import BearerTokenMiddleware
from security import CommandPolicy, load_command_policy, validate_command, validate_command_lists

logger = logging.getLogger("netmiko-mcp-server")
logging.basicConfig(level=logging.INFO)


BEARER_TOKEN_ENV_VAR = "NETMIKO_MCP_SERVER_BEARER_TOKEN"

tomlpath: str | None = None
enable_config: bool = False
command_policy: CommandPolicy = CommandPolicy()


mcp = FastMCP("netmiko server", dependencies=["netmiko"])


@dataclass
class Device:
    name: str
    hostname: str
    device_type: str
    username: str | None
    password: str | None
    port: int
    secret: str | None
    use_keys: bool
    key_file: str | None
    pre_commands: list[str]
    ansi_escape_codes: bool
    conn_timeout: int
    read_timeout_override: int

    def __init__(
        self,
        name: str = "",
        hostname: str = "",
        device_type: str = "",
        username: str | None = None,
        password: str | None = None,
        port: int | None = None,
        secret: str | None = None,
        use_keys: bool = False,
        key_file: str | None = None,
        pre_commands: list[str] | None = None,
        ansi_escape_codes: bool = False,
        conn_timeout: int = 5,
        read_timeout_override: int = 20,
    ) -> None:
        if device_type not in platforms + telnet_platforms:
            raise ValueError(f"name:{name}, invalid device_type: '{device_type}'")

        if port is None:
            port = 23 if device_type in telnet_platforms else 22

        self.name = name
        self.hostname = hostname
        self.device_type = device_type
        self.username = username
        self.password = password
        self.port = port
        self.secret = secret
        self.use_keys = use_keys
        self.key_file = key_file
        self.pre_commands = pre_commands or []
        self.ansi_escape_codes = ansi_escape_codes
        self.conn_timeout = conn_timeout
        self.read_timeout_override = read_timeout_override

    def json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "hostname": self.hostname,
            "device_type": self.device_type,
            "port": self.port,
        }

    @property
    def connect_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "host": self.hostname,
            "device_type": self.device_type,
            "port": self.port,
            "conn_timeout": self.conn_timeout,
            "read_timeout_override": self.read_timeout_override,
        }
        if self.username is not None:
            kwargs["username"] = self.username
        if self.password is not None:
            kwargs["password"] = self.password
        if self.secret is not None:
            kwargs["secret"] = self.secret
        if self.use_keys:
            kwargs["use_keys"] = True
        if self.key_file:
            kwargs["key_file"] = self.key_file
        return kwargs

    def _maybe_enable(self, conn: Any) -> None:
        if self.secret:
            try:
                conn.enable()
            except Exception as exc:  # pragma: no cover - vendor/device-specific
                logger.warning("enable() failed for %s: %s", self.name, exc)

    def _apply_session_options(self, conn: Any) -> None:
        if self.ansi_escape_codes:
            conn.ansi_escape_codes = True

    def _run_pre_commands(self, conn: Any) -> None:
        for cmd in self.pre_commands:
            try:
                conn.send_command(cmd, expect_string=r"#")
            except Exception as exc:
                logger.warning("pre_command failed for %s (%s): %s", self.name, cmd, exc)

    def send_command(self, cmd: str) -> str:
        with ConnectHandler(**self.connect_kwargs) as conn:
            self._apply_session_options(conn)
            self._maybe_enable(conn)
            self._run_pre_commands(conn)
            output = conn.send_command(cmd)
        return str(output)

    def send_config_set_and_commit_and_save(self, cmds: list[str]) -> str:
        with ConnectHandler(**self.connect_kwargs) as conn:
            self._apply_session_options(conn)
            self._maybe_enable(conn)
            self._run_pre_commands(conn)
            output = conn.send_config_set(cmds)
            try:
                output += conn.commit()
            except AttributeError:
                pass

            try:
                output += conn.save_config()
            except NotImplementedError:
                pass

        return output



def load_config_toml() -> dict[str, Device]:
    devs: dict[str, Device] = {}

    if not tomlpath:
        raise RuntimeError("config toml is not specified")

    with open(tomlpath, "rb") as f:
        data = tomllib.load(f)

        default_args = {}
        if "default" in data:
            default_args = data["default"]

        for name, v in data.items():
            if name == "default":
                continue
            if not isinstance(v, dict):
                raise ValueError(f"unexpected value in toml: {v}")

            for default_k, default_v in default_args.items():
                v.setdefault(default_k, default_v)
            v.setdefault("name", name)

            devs[name] = Device(**v)

    return devs


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
        return f"Security Error: command '{command}' is not permitted ({result.reason})."

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



def main() -> None:
    desc = "netmiko-mcp-server"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        "--enable-config",
        action="store_true",
        help="allow the set_config_commands_and_commit_or_save tool (disabled by default)",
    )
    parser.add_argument(
        "--commands-file",
        type=str,
        default=None,
        help=(
            "path to a TOML file with allowed_commands/denied_commands. "
            "Without this, ALL commands are denied by default."
        ),
    )
    parser.add_argument(
        "--audit-log-file",
        type=str,
        default="~/.netmiko_mcp_server_audit.log",
        help="path to the JSON audit log file",
    )
    parser.add_argument(
        "--sse", action="store_true", help="run as an SSE server (default stdio)"
    )
    parser.add_argument(
        "--port", type=int, default=10000, help="port number for SSE server"
    )
    parser.add_argument(
        "--bind",
        type=str,
        default="0.0.0.0",
        help="bind address for SSE server",
    )
    parser.add_argument(
        "--allowed-subnet",
        type=str,
        default="0.0.0.0/0",
        help=(
            "allow client and bind addresses only from these subnets (SSE only). "
            "comma-separated, e.g. 10.70.72.0/24,127.0.0.1/32"
        ),
    )
    parser.add_argument(
        "--no-http-auth",
        action="store_true",
        help=(
            "disable bearer token authentication for the SSE server (INSECURE, "
            f"SSE only). Without this flag, {BEARER_TOKEN_ENV_VAR} must be set "
            "in the environment."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable starlette debug mode for SSE server",
    )

    parser.add_argument("tomlpath", help="path to config toml file")

    args = parser.parse_args()

    global tomlpath
    tomlpath = args.tomlpath

    global enable_config
    enable_config = args.enable_config

    global command_policy
    command_policy = load_command_policy(args.commands_file)
    policy_errors = validate_command_lists(command_policy)
    if policy_errors:
        raise SystemExit("Startup Error: " + " ".join(policy_errors))
    if args.commands_file is None:
        logger.warning(
            "no --commands-file specified: ALL commands will be denied by default"
        )

    configure_audit_logger(args.audit_log_file)

    load_config_toml()

    if args.sse:
        allowed_subnets = [
            ipaddress.ip_network(item.strip(), strict=False)
            for item in args.allowed_subnet.split(",")
            if item.strip()
        ]
        bind_ip = ipaddress.ip_address(args.bind)
        if not any(bind_ip in net for net in allowed_subnets):
            raise SystemExit(
                f"--bind {args.bind} is not inside --allowed-subnet {args.allowed_subnet}"
            )

        sse_app = mcp.sse_app()

        @sse_app.middleware("http")
        async def restrict_subnet(request, call_next):
            client_host = request.client.host if request.client else ""
            try:
                client_ip = ipaddress.ip_address(client_host)
            except ValueError:
                return PlainTextResponse("Forbidden", status_code=403)
            if not any(client_ip in net for net in allowed_subnets):
                return PlainTextResponse("Forbidden", status_code=403)
            return await call_next(request)

        app: Any = Starlette(debug=args.debug, routes=[Mount("/", app=sse_app)])

        if not args.no_http_auth:
            token = os.environ.get(BEARER_TOKEN_ENV_VAR, "").strip()
            if not token:
                raise SystemExit(
                    f"Startup Error: {BEARER_TOKEN_ENV_VAR} must be set in the "
                    "environment when running --sse. Use --no-http-auth to run "
                    "without authentication (not recommended)."
                )
            app = BearerTokenMiddleware(app, token)

        import uvicorn

        uvicorn.run(app, host=args.bind, port=args.port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
