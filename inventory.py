"""Device inventory: the Device model and TOML-based inventory loading."""

import logging
import tomllib
from dataclasses import dataclass
from typing import Any

from netmiko import ConnectHandler
from netmiko.ssh_dispatcher import platforms, telnet_platforms

logger = logging.getLogger("netmiko-mcp-server")

# Set by main() from the CLI's positional tomlpath argument before the first
# tool call. load_config_toml() re-reads this file on every call so config
# changes take effect without a server restart.
tomlpath: str | None = None


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
                logger.warning(
                    "pre_command failed for %s (%s): %s", self.name, cmd, exc
                )

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
