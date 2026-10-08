"""Saved command output storage with pagination.

Large command output is written to a per-device file on disk instead of being
returned inline, so a single command (e.g. a full BGP table) cannot overwhelm
an LLM's context window. list_outputs() and read_output() let a client
discover and page through what was saved.
"""

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tool_results import ToolFailure

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


def _restricted_path(base_dir: Path, path: Path) -> Path:
    """Resolve every storage path before reading, writing, or changing its mode."""
    try:
        resolved = path.resolve()
        if resolved.is_relative_to(base_dir.resolve()):
            return resolved
    except (OSError, RuntimeError):
        pass
    raise ValueError("Security Error: path resolves outside restricted directory")


def _device_directory(device_name: str) -> Path:
    _validate_path_component(device_name, "device name")
    base_dir = Path(output_dir).expanduser()
    return _restricted_path(base_dir, base_dir / device_name)


def save_output(device_name: str, command: str, output: Any) -> str:
    """Save output for device_name to a new file and return its filename."""
    device_dir = _device_directory(device_name)

    base_dir = Path(output_dir).expanduser()
    base_dir.mkdir(parents=True, exist_ok=True)
    base_dir.chmod(0o700)

    device_dir.mkdir(exist_ok=True)
    device_dir.chmod(0o700)

    cmd_part = _sanitize_command_for_filename(command)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    content = (
        json.dumps(output, indent=2)
        if isinstance(output, (list, dict))
        else str(output)
    )
    # mkstemp creates a unique file with mode 0600 from the first write, so
    # concurrent results cannot overwrite each other or expose output briefly.
    fd, filename = tempfile.mkstemp(
        dir=device_dir, prefix=f"{cmd_part}_{timestamp}_", suffix=".txt"
    )
    file_path = Path(filename)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
    except BaseException:
        file_path.unlink(missing_ok=True)
        raise
    return file_path.name


def list_outputs(device_name: str) -> list[str]:
    """List saved output filenames for device_name, newest first."""
    device_dir = _device_directory(device_name)
    if not device_dir.is_dir():
        return []
    base_dir = Path(output_dir).expanduser()
    return sorted(
        (
            f.name
            for f in device_dir.glob("*.txt")
            if _restricted_path(base_dir, f).is_file()
        ),
        reverse=True,
    )


def read_output(
    device_name: str, filename: str, offset: int = 0, limit: int = 500
) -> str:
    """Return a paginated slice of a previously saved output file."""
    if offset < 0:
        return ToolFailure(
            "Error: offset must be non-negative.",
            code="INVALID_PAGINATION",
            next_action="Use an offset of at least 0 and a positive limit.",
        )
    if limit <= 0:
        return ToolFailure(
            "Error: limit must be positive.",
            code="INVALID_PAGINATION",
            next_action="Use an offset of at least 0 and a positive limit.",
        )
    try:
        _validate_path_component(device_name, "device name")
        _validate_path_component(filename, "filename")
    except ValueError as e:
        return ToolFailure(
            str(e),
            code="UNSAFE_OUTPUT_PATH",
            next_action="Use exact device and file names from list_device_outputs.",
        )

    base_dir = Path(output_dir).expanduser()
    try:
        file_path = _restricted_path(base_dir, base_dir / device_name / filename)
    except ValueError as exc:
        return ToolFailure(
            str(exc),
            code="UNSAFE_OUTPUT_PATH",
            next_action="Use a saved output path inside the configured output directory.",
        )

    if not file_path.is_file():
        return ToolFailure(
            f"Error: file '{filename}' not found for device '{device_name}'.",
            code="OUTPUT_NOT_FOUND",
            next_action="Use list_device_outputs to select an existing saved file.",
        )

    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ToolFailure(
            "Error: saved output cannot be read.",
            code="OUTPUT_READ_FAILED",
            next_action="Check the file permissions and UTF-8 encoding.",
        )
    total = len(lines)
    if total == 0:
        return "Lines 0-0 of 0.\n"
    if offset >= total:
        return ToolFailure(
            f"Error: offset {offset} is beyond end of file ({total} line(s)).",
            code="INVALID_PAGINATION",
            next_action=f"Use an offset between 0 and {total - 1}.",
        )

    end = min(offset + limit, total)
    page = lines[offset:end]
    continuation = (
        f" Call read_device_output with offset={end} to continue."
        if end < total
        else ""
    )
    header = f"Lines {offset + 1}-{end} of {total}.{continuation}"
    return header + "\n" + "\n".join(page)
