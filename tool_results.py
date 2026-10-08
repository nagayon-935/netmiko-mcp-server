"""Structured MCP results while preserving the Python helpers' text interface."""

import inspect
import json
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, ParamSpec, TypeVar

from mcp.types import CallToolResult, TextContent

from audit import AuditWriteError

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP

P = ParamSpec("P")
R = TypeVar("R")


class ToolFailure(str):
    """A legacy-compatible message with machine-readable failure information."""

    error: dict[str, Any]

    def __new__(
        cls,
        message: str,
        *,
        code: str,
        next_action: str,
        retryable: bool = False,
        execution_state: str = "not_started",
    ) -> "ToolFailure":
        value = super().__new__(cls, message)
        value.error = {
            "code": code,
            "message": message,
            "next_action": next_action,
            "retryable": retryable,
            "execution_state": execution_state,
        }
        return value


def result_payload(value: Any) -> dict[str, Any]:
    if isinstance(value, ToolFailure):
        return {"ok": False, "error": value.error}
    return {"ok": True, "data": value}


def structured_tool(mcp: "FastMCP") -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Register a structured MCP adapter, retaining the original Python helper."""

    def register(func: Callable[P, R]) -> Callable[P, R]:
        @wraps(func)
        def adapter(*args: P.args, **kwargs: P.kwargs) -> CallToolResult:
            try:
                value: Any = func(*args, **kwargs)
            except AuditWriteError as exc:
                value = ToolFailure(
                    "Audit log write failed; the operation was stopped.",
                    code="AUDIT_WRITE_FAILED",
                    next_action="Restore audit logging. If execution_state is unknown, inspect device state before repeating the operation.",
                    execution_state=exc.execution_state,
                )
            if (
                func.__name__ in {"get_network_device_list", "list_device_outputs"}
                and isinstance(value, str)
                and not isinstance(value, ToolFailure)
            ):
                value = json.loads(value)
            if func.__name__ == "send_command_to_group" and isinstance(value, dict):
                if isinstance(value.get("error"), ToolFailure):
                    payload = result_payload(value["error"])
                else:
                    items = {
                        name: result_payload(output) for name, output in value.items()
                    }
                    succeeded = sum(item["ok"] for item in items.values())
                    payload = {
                        "ok": succeeded == len(items),
                        "data": items,
                        "summary": {
                            "total": len(items),
                            "succeeded": succeeded,
                            "failed": len(items) - succeeded,
                        },
                    }
            elif isinstance(value, dict) and isinstance(
                value.get("error"), ToolFailure
            ):
                payload = result_payload(value["error"])
            else:
                payload = result_payload(value)
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(payload))],
                structuredContent=payload,
                isError=not payload["ok"],
            )

        # FastMCP inspects the original arguments but must see the adapter's
        # CallToolResult return type rather than the legacy helper's annotation.
        signature = inspect.signature(func).replace(return_annotation=CallToolResult)
        setattr(adapter, "__signature__", signature)
        adapter.__doc__ = (
            (func.__doc__ or "")
            + "\nMCP results use an ok/data or ok/error envelope. Errors include code, next_action, retryable, and execution_state. Configuration failures require inspecting device state before retrying."
        )
        mcp.tool()(adapter)
        return func

    return register
