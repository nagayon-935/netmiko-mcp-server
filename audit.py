"""Audit logging for the netmiko MCP server.

Every command sent to a device produces two JSON log lines: one at validation
time (allowed/denied + reason) and one after the connection attempt completes
(success/error). Emitted via a dedicated logger isolated from the general
application logger so audit records cannot be mixed with debug output or
accidentally suppressed by changing the root log level.

The file handler is fail-closed: if a write fails, the exception propagates
to the caller instead of being swallowed, so a broken audit log cannot allow
unlogged commands to continue executing silently.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

OUTCOME_SUCCESS = "SUCCESS"
OUTCOME_CONNECTION_ERROR = "CONNECTION_ERROR"

_audit_logger = logging.getLogger("netmiko-mcp-server.audit")
_audit_logger.addHandler(logging.NullHandler())

_LOGRECORD_BUILTIN_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class _AuditJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
        }
        for key, value in record.__dict__.items():
            if key not in _LOGRECORD_BUILTIN_ATTRS:
                data[key] = value
        return json.dumps(data, default=str)


class _FailClosedFileHandler(logging.FileHandler):
    """Re-raises write errors instead of routing them to stderr.

    The stdlib default swallows emit() exceptions via handleError(). For an
    audit trail that must never silently go dark, a failed write should
    propagate so the caller (and thus the tool invocation) fails instead.
    """

    def handleError(self, record: logging.LogRecord) -> None:
        _, exc_value, _ = sys.exc_info()
        raise RuntimeError(f"Audit log write failed: {exc_value}") from exc_value


def configure_audit_logger(log_file: str) -> None:
    """Attach a fail-closed file handler to the audit logger. Call once at
    server startup before any tool invocations.
    """
    log_path = Path(log_file).expanduser()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = _FailClosedFileHandler(filename=str(log_path), mode="a", encoding="utf-8")
    handler.setFormatter(_AuditJsonFormatter())

    _audit_logger.setLevel(logging.INFO)
    _audit_logger.propagate = False
    _audit_logger.handlers.clear()
    _audit_logger.addHandler(handler)

    log_path.chmod(0o600)


def log_command_attempt(
    *, tool: str, device: str, command: str, verdict: str, reason: str
) -> None:
    """Record a command validation decision (allowed or denied + reason)."""
    _audit_logger.info(
        "audit",
        extra={
            "event": "command_attempt",
            "tool": tool,
            "device": device,
            "command": command,
            "verdict": verdict,
            "reason": reason,
        },
    )


def log_connection_outcome(
    *, tool: str, device: str, command: str, outcome: str, detail: str | None = None
) -> None:
    """Record the result of the connection/command-execution attempt."""
    fields: dict[str, Any] = {
        "event": "connection_outcome",
        "tool": tool,
        "device": device,
        "command": command,
        "outcome": outcome,
    }
    if detail is not None:
        fields["detail"] = detail
    _audit_logger.info("audit", extra=fields)
