import json
import logging

import pytest

import audit


@pytest.fixture(autouse=True)
def _reset_audit_logger():
    yield
    audit._audit_logger.handlers.clear()
    audit._audit_logger.addHandler(logging.NullHandler())


def test_configure_audit_logger_creates_file(tmp_path):
    log_file = tmp_path / "audit.log"
    audit.configure_audit_logger(str(log_file))

    assert log_file.exists()
    assert oct(log_file.stat().st_mode)[-3:] == "600"


def test_log_command_attempt_writes_json_line(tmp_path):
    log_file = tmp_path / "audit.log"
    audit.configure_audit_logger(str(log_file))

    audit.log_command_attempt(
        tool="send_command_and_get_output",
        device="router1",
        command="show version",
        verdict="ALLOWED",
        reason="ALLOWED",
    )

    line = log_file.read_text().strip()
    record = json.loads(line)
    assert record["event"] == "command_attempt"
    assert record["device"] == "router1"
    assert record["verdict"] == "ALLOWED"


def test_log_connection_outcome_includes_detail_when_present(tmp_path):
    log_file = tmp_path / "audit.log"
    audit.configure_audit_logger(str(log_file))

    audit.log_connection_outcome(
        tool="send_command_and_get_output",
        device="router1",
        command="show version",
        outcome=audit.OUTCOME_CONNECTION_ERROR,
        detail="timed out",
    )

    record = json.loads(log_file.read_text().strip())
    assert record["outcome"] == "CONNECTION_ERROR"
    assert record["detail"] == "timed out"


def test_fail_closed_handler_raises_on_write_error(tmp_path):
    log_file = tmp_path / "audit.log"
    audit.configure_audit_logger(str(log_file))
    handler = audit._audit_logger.handlers[0]
    handler.stream.close()

    with pytest.raises(RuntimeError, match="Audit log write failed"):
        audit.log_command_attempt(
            tool="t", device="d", command="c", verdict="ALLOWED", reason="ALLOWED"
        )
