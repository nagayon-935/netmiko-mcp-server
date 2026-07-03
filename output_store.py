"""Saved command output storage with pagination.

Large command output is written to a per-device file on disk instead of being
returned inline, so a single command (e.g. a full BGP table) cannot overwhelm
an LLM's context window. list_outputs() and read_output() let a client
discover and page through what was saved.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_OUTPUT_DIR = "~/.netmiko_mcp_server_outputs"

# Set by main() from the CLI's --output-dir argument before the first tool call.
output_dir: str = DEFAULT_OUTPUT_DIR

# Sequences rejected as substrings within a device name or filename, including
# Unicode slash/backslash lookalikes that could otherwise defeat a plain "/"
# check and reach outside the per-device output directory.
_UNSAFE_PATH_SUBSTRINGS: list[str] = [
    "/",
    "\\",
    "..",
    "\x00",
    "∕",
    "／",
    "⁄",
    "⧸",
    "＼",
    "⧵",
    "∖",
    "⧹",
]
_UNSAFE_PATH_VALUES: frozenset[str] = frozenset({"", "."})


def _validate_path_component(value: str, label: str) -> None:
    if value in _UNSAFE_PATH_VALUES:
        raise ValueError(f"Security Error: unsafe path value ({label}: {value!r})")
    if any(unsafe in value for unsafe in _UNSAFE_PATH_SUBSTRINGS):
        raise ValueError(
            f"Security Error: unsafe characters in path ({label}: {value})"
        )


def _sanitize_command_for_filename(command: str) -> str:
    normalized = "_".join(command.split())
    safe = "".join(c if c.isalnum() or c == "_" else "_" for c in normalized)
    return safe[:50]


def save_output(device_name: str, command: str, output: Any) -> str:
    """Save output for device_name to a new file and return its filename."""
    _validate_path_component(device_name, "device name")

    base_dir = Path(output_dir).expanduser()
    base_dir.mkdir(parents=True, exist_ok=True)
    base_dir.chmod(0o700)

    device_dir = base_dir / device_name
    device_dir.mkdir(exist_ok=True)
    device_dir.chmod(0o700)

    cmd_part = _sanitize_command_for_filename(command)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    file_path = device_dir / f"{cmd_part}_{timestamp}.txt"

    content = (
        json.dumps(output, indent=2)
        if isinstance(output, (list, dict))
        else str(output)
    )
    file_path.write_text(content, encoding="utf-8")
    file_path.chmod(0o600)
    return file_path.name


def list_outputs(device_name: str) -> list[str]:
    """List saved output filenames for device_name, newest first."""
    _validate_path_component(device_name, "device name")

    device_dir = Path(output_dir).expanduser() / device_name
    if not device_dir.is_dir():
        return []
    return sorted((f.name for f in device_dir.glob("*.txt")), reverse=True)


def read_output(
    device_name: str, filename: str, offset: int = 0, limit: int = 500
) -> str:
    """Return a paginated slice of a previously saved output file."""
    try:
        _validate_path_component(device_name, "device name")
        _validate_path_component(filename, "filename")
    except ValueError as e:
        return str(e)

    base_dir = Path(output_dir).expanduser()
    device_dir = base_dir / device_name
    file_path = device_dir / filename

    # Resolve and confirm the final path is still inside base_dir. This catches
    # bypasses that survive the substring checks above, such as a symlink
    # planted inside device_dir that points outside the output directory.
    try:
        if not file_path.resolve().is_relative_to(base_dir.resolve()):
            return (
                f"Security Error: path resolves outside restricted directory "
                f"(device: {device_name}, file: {filename})"
            )
    except OSError:
        return (
            f"Security Error: path resolves outside restricted directory "
            f"(device: {device_name}, file: {filename})"
        )

    if not file_path.is_file():
        return f"Error: file '{filename}' not found for device '{device_name}'."

    lines = file_path.read_text(encoding="utf-8").splitlines()
    total = len(lines)
    if total == 0:
        return "Lines 0-0 of 0.\n"
    if offset >= total:
        return f"Error: offset {offset} is beyond end of file ({total} line(s))."

    end = min(offset + limit, total)
    page = lines[offset:end]
    continuation = (
        f" Call read_device_output with offset={end} to continue."
        if end < total
        else ""
    )
    header = f"Lines {offset + 1}-{end} of {total}.{continuation}"
    return header + "\n" + "\n".join(page)
