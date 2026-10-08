"""Offline startup diagnostics. Never connect, execute commands, or write files."""

import ipaddress
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet

from credential_crypto import KEY_ENV_VAR
from inventory import Inventory, _parse_devices, _parse_groups
from security import load_command_policies, validate_command_lists

BEARER_TOKEN_ENV_VAR = "NETMIKO_MCP_SERVER_BEARER_TOKEN"


@dataclass(frozen=True)
class DiagnosticSettings:
    inventory_path: str
    commands_path: str | None
    audit_log_file: str
    output_dir: str
    sse: bool = False
    bind: str = "0.0.0.0"
    allowed_subnet: str = "0.0.0.0/0"
    port: int = 10000
    max_workers: int = 10
    output_save_threshold: int = 1000
    no_http_auth: bool = False
    enable_config: bool = False


def _check(
    name: str, status: str, message: str, next_action: str = ""
) -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "message": message,
        "next_action": next_action,
    }


def _inventory_checks(path: str) -> list[dict[str, str]]:
    try:
        with Path(path).open("rb") as f:
            data = tomllib.load(f)
    except OSError:
        return [
            _check(
                "inventory",
                "error",
                "Inventory file cannot be read.",
                "Check the inventory path and file permissions.",
            )
        ]
    except (ValueError, UnicodeError):
        return [
            _check(
                "inventory",
                "error",
                "Inventory TOML cannot be parsed.",
                "Correct the TOML syntax in the inventory file.",
            )
        ]
    try:
        snapshot = Inventory(_parse_devices(data), _parse_groups(data))
        for device in snapshot.devices.values():
            if device.key_file is not None and not isinstance(device.key_file, str):
                raise TypeError("key_file must be a path string")
        for group in snapshot.groups:
            # Device/group name collisions would bypass group resolution.
            if group == "all" or group in snapshot.devices:
                raise ValueError("Unreachable group")
            snapshot.get_device_names(group)
    except RuntimeError:
        return [
            _check(
                "inventory",
                "error",
                "Encrypted credentials cannot be decrypted.",
                f"Check {KEY_ENV_VAR} and the encrypted credential values.",
            )
        ]
    except (ValueError, TypeError, AttributeError):
        return [
            _check(
                "inventory",
                "error",
                "Inventory contains invalid devices, defaults, or groups.",
                "Check device_type and field names; groups must contain existing device names and use unique names other than 'all'.",
            )
        ]
    checks = [
        _check(
            "inventory",
            "ok",
            f"Loaded {len(snapshot.devices)} device(s) and {len(snapshot.groups)} group(s).",
        )
    ]
    for device in snapshot.devices.values():
        if device.key_file:
            key_file = Path(device.key_file).expanduser()
            if not key_file.is_file() or not os.access(key_file, os.R_OK):
                checks.append(
                    _check(
                        "ssh_key",
                        "error",
                        "An inventory SSH key file is missing or unreadable.",
                        "Check key_file paths and permissions; paths are resolved on the server host.",
                    )
                )
    if not snapshot.devices:
        checks.append(
            _check(
                "devices",
                "warning",
                "No devices are registered.",
                "Add devices with import_inventory.py.",
            )
        )
    return checks


def _path_check(name: str, raw_path: str, *, directory: bool) -> dict[str, str]:
    try:
        return _inspect_storage_path(name, raw_path, directory=directory)
    except (OSError, RuntimeError):
        return _check(
            name,
            "error",
            "Storage path cannot be inspected.",
            "Check path permissions and symlinks.",
        )


def _inspect_storage_path(
    name: str, raw_path: str, *, directory: bool
) -> dict[str, str]:
    path = Path(raw_path).expanduser()
    if path.exists():
        if (directory and not path.is_dir()) or (not directory and not path.is_file()):
            return _check(
                name,
                "error",
                "Storage path has the wrong file type.",
                "Use a directory for output and a file for the audit log.",
            )
        target = path
    else:
        target = path.parent
        while not target.exists() and target != target.parent:
            target = target.parent
        if not target.is_dir():
            return _check(
                name,
                "error",
                "A parent of the storage path is not a directory.",
                "Correct the storage path.",
            )
    if not os.access(target, os.W_OK | (os.X_OK if target.is_dir() else 0)):
        return _check(
            name,
            "error",
            "Storage path is not writable.",
            "Grant the server account write access or choose another path.",
        )
    return _check(
        name, "ok", "Storage path is accessible (no files were created or written)."
    )


def run_diagnostics(settings: DiagnosticSettings) -> dict[str, Any]:
    """Return checks and remedies without exposing credential or token values."""
    checks: list[dict[str, str]] = []
    key = os.environ.get(KEY_ENV_VAR, "").strip()
    if key:
        try:
            Fernet(key.encode("utf-8"))
        except (ValueError, TypeError):
            checks.append(
                _check(
                    "inventory_key",
                    "error",
                    "Inventory encryption key is malformed.",
                    f"Generate a valid key and supply it through {KEY_ENV_VAR}; do not replace a key without re-encrypting its inventory.",
                )
            )
        else:
            checks.append(
                _check(
                    "inventory_key",
                    "ok",
                    "Inventory encryption key has a valid format.",
                )
            )
    checks.extend(_inventory_checks(settings.inventory_path))
    try:
        show, config = load_command_policies(settings.commands_path)
        errors = validate_command_lists(show) + validate_command_lists(config)
        if errors:
            checks.append(
                _check(
                    "command_policy",
                    "error",
                    "Command policy contains unsupported glob patterns.",
                    "Use only a single trailing '*' and no bare '*' entries.",
                )
            )
        elif not show.allowed_commands:
            checks.append(
                _check(
                    "command_policy",
                    "warning",
                    "All show commands are denied.",
                    "Supply --commands-file with explicit allowed_commands to enable queries.",
                )
            )
        else:
            checks.append(
                _check("command_policy", "ok", "Command policy parsed successfully.")
            )
        if settings.enable_config and not config.allowed_commands:
            checks.append(
                _check(
                    "configuration",
                    "warning",
                    "Configuration is enabled but all configuration commands are denied.",
                    "Add explicit config_allowed_commands if configuration changes are intended.",
                )
            )
    except OSError:
        checks.append(
            _check(
                "command_policy",
                "error",
                "Commands file cannot be read.",
                "Check --commands-file and its permissions.",
            )
        )
    except (ValueError, UnicodeError):
        checks.append(
            _check(
                "command_policy",
                "error",
                "Commands file has invalid syntax or command lists.",
                "Use valid TOML with arrays of non-empty command strings.",
            )
        )
    checks.append(_path_check("audit_log", settings.audit_log_file, directory=False))
    checks.append(_path_check("output_dir", settings.output_dir, directory=True))
    if settings.max_workers < 1 or settings.output_save_threshold < 0:
        checks.append(
            _check(
                "limits",
                "error",
                "Concurrency or output threshold is invalid.",
                "Set --max-workers to at least 1 and --output-save-threshold to at least 0.",
            )
        )
    if settings.sse:
        try:
            networks = [
                ipaddress.ip_network(item.strip(), strict=False)
                for item in settings.allowed_subnet.split(",")
                if item.strip()
            ]
            bind = ipaddress.ip_address(settings.bind)
            if (
                not any(bind in net for net in networks)
                or not 1 <= settings.port <= 65535
            ):
                raise ValueError("Invalid SSE binding")
        except ValueError:
            checks.append(
                _check(
                    "sse_binding",
                    "error",
                    "SSE bind, subnet, or port is invalid.",
                    "Use an IP bind inside --allowed-subnet and a port between 1 and 65535.",
                )
            )
        else:
            checks.append(
                _check(
                    "sse_binding",
                    "ok",
                    "SSE binding configuration is valid; the port was not opened.",
                )
            )
        if settings.no_http_auth:
            checks.append(
                _check(
                    "http_auth",
                    "warning",
                    "HTTP authentication is disabled.",
                    "Enable bearer authentication for remote access.",
                )
            )
        elif not os.environ.get(BEARER_TOKEN_ENV_VAR, "").strip():
            checks.append(
                _check(
                    "http_auth",
                    "error",
                    "SSE bearer token is missing.",
                    f"Set {BEARER_TOKEN_ENV_VAR} in the server environment.",
                )
            )
        else:
            checks.append(_check("http_auth", "ok", "SSE bearer token is present."))
    failed = any(check["status"] == "error" for check in checks)
    return {"ok": not failed, "device_connections_attempted": False, "checks": checks}


def format_diagnostics(report: dict[str, Any]) -> str:
    lines = ["Offline diagnostics (no device connections or file writes):"]
    for check in report["checks"]:
        lines.append(f"[{check['status'].upper()}] {check['name']}: {check['message']}")
        if check["next_action"]:
            lines.append(f"  Next: {check['next_action']}")
    lines.append(
        "Result: "
        + (
            "ready (review any warnings)"
            if report["ok"]
            else "configuration needs attention"
        )
    )
    return "\n".join(lines)
