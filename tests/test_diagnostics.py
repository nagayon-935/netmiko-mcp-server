import json
import sys
from dataclasses import replace

import pytest

import diagnostics
import inventory
import main
import server
from credential_crypto import KEY_ENV_VAR, encrypt_value, generate_key
from diagnostics import DiagnosticSettings, format_diagnostics, run_diagnostics


@pytest.fixture
def settings(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    monkeypatch.delenv(diagnostics.BEARER_TOKEN_ENV_VAR, raising=False)
    devices = tmp_path / "devices.toml"
    devices.write_text('[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n')
    commands = tmp_path / "commands.toml"
    commands.write_text('allowed_commands = ["show version"]\n')
    return DiagnosticSettings(
        str(devices),
        str(commands),
        str(tmp_path / "new" / "audit.log"),
        str(tmp_path / "outputs"),
    )


def errors(report):
    return [check for check in report["checks"] if check["status"] == "error"]


def test_valid_setup_is_checked_without_connecting_or_writing(
    settings, tmp_path, monkeypatch
):
    def unexpected(**kwargs):
        raise AssertionError("Doctor must never connect")

    monkeypatch.setattr(inventory, "ConnectHandler", unexpected)
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    report = run_diagnostics(settings)
    assert report["ok"] is True
    assert report["device_connections_attempted"] is False
    assert sorted(str(p) for p in tmp_path.rglob("*")) == before


@pytest.mark.parametrize(
    "content",
    [
        "not valid toml = [",
        '[r1]\npassword = "DO_NOT_EXPOSE"\ndevice_type = "wrong"',
        '[r1]\ndevice_type = "cisco_ios"\n[groups]\ncore = ["missing"]',
        '[r1]\ndevice_type = "cisco_ios"\n[groups]\nr1 = ["r1"]',
    ],
)
def test_inventory_failures_have_remedies_without_credentials(settings, content):
    from pathlib import Path

    Path(settings.inventory_path).write_text(content)
    report = run_diagnostics(settings)
    assert report["ok"] is False
    assert errors(report)[0]["next_action"]
    assert "DO_NOT_EXPOSE" not in json.dumps(report)


def test_missing_inventory_is_reported(settings):
    report = run_diagnostics(
        replace(settings, inventory_path="/no/such/inventory.toml")
    )
    assert errors(report)[0]["name"] == "inventory"


@pytest.mark.parametrize("with_key", [False, True])
def test_encrypted_inventory_checks_real_decryption(settings, monkeypatch, with_key):
    from pathlib import Path

    key = generate_key()
    encrypted = encrypt_value("DO_NOT_EXPOSE", key)
    Path(settings.inventory_path).write_text(
        f'[r1]\ndevice_type = "cisco_ios"\npassword = "{encrypted}"\n'
    )
    if with_key:
        monkeypatch.setenv(KEY_ENV_VAR, key)
    report = run_diagnostics(settings)
    assert report["ok"] is with_key
    serialized = json.dumps(report)
    assert "DO_NOT_EXPOSE" not in serialized
    assert encrypted not in serialized
    assert key not in serialized


def test_malformed_key_is_reported_without_echoing_value(settings, monkeypatch):
    monkeypatch.setenv(KEY_ENV_VAR, "DO_NOT_EXPOSE")
    report = run_diagnostics(settings)
    assert any(check["name"] == "inventory_key" for check in errors(report))
    assert "DO_NOT_EXPOSE" not in json.dumps(report)


@pytest.mark.parametrize(
    "commands", ['allowed_commands = "show version"', 'allowed_commands = ["*"]']
)
def test_invalid_policies_are_reported(settings, commands):
    from pathlib import Path

    Path(settings.commands_path).write_text(commands)
    report = run_diagnostics(settings)
    assert any(check["name"] == "command_policy" for check in errors(report))


def test_deny_all_is_a_warning(settings):
    report = run_diagnostics(replace(settings, commands_path=None))
    assert report["ok"] is True
    assert any(
        check["name"] == "command_policy" and check["status"] == "warning"
        for check in report["checks"]
    )


def test_missing_ssh_key_is_reported(settings):
    from pathlib import Path

    with Path(settings.inventory_path).open("a") as f:
        f.write('use_keys = true\nkey_file = "/no/such/key"\n')
    report = run_diagnostics(settings)
    assert any(check["name"] == "ssh_key" for check in errors(report))


def test_storage_type_and_permissions_are_checked(settings, tmp_path, monkeypatch):
    wrong = tmp_path / "file"
    wrong.write_text("x")
    report = run_diagnostics(replace(settings, output_dir=str(wrong)))
    assert any(check["name"] == "output_dir" for check in errors(report))
    monkeypatch.setattr(diagnostics.os, "access", lambda *args: False)
    report = run_diagnostics(settings)
    assert {"audit_log", "output_dir"} <= {check["name"] for check in errors(report)}


def test_sse_checks_token_and_binding_without_exposing_token(settings, monkeypatch):
    sse = replace(settings, sse=True, bind="127.0.0.1", allowed_subnet="127.0.0.0/8")
    assert any(check["name"] == "http_auth" for check in errors(run_diagnostics(sse)))
    monkeypatch.setenv(diagnostics.BEARER_TOKEN_ENV_VAR, "DO_NOT_EXPOSE")
    report = run_diagnostics(sse)
    assert report["ok"] is True
    assert "DO_NOT_EXPOSE" not in json.dumps(report)
    report = run_diagnostics(replace(sse, bind="192.0.2.1"))
    assert any(check["name"] == "sse_binding" for check in errors(report))


def test_numeric_limits_are_checked(settings):
    assert run_diagnostics(replace(settings, max_workers=0))["ok"] is False
    assert run_diagnostics(replace(settings, output_save_threshold=-1))["ok"] is False


@pytest.mark.parametrize("valid, expected_exit", [(True, 0), (False, 1)])
def test_doctor_cli_exits_without_starting_server(
    settings, monkeypatch, capsys, valid, expected_exit
):
    def unexpected(*args, **kwargs):
        raise AssertionError("Doctor must not start server or audit writes")

    monkeypatch.setattr(server.mcp, "run", unexpected)
    monkeypatch.setattr(main, "configure_audit_logger", unexpected)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            settings.inventory_path if valid else "/no/such/file",
            "--commands-file",
            settings.commands_path,
            "--doctor",
            "--doctor-json",
            "--audit-log-file",
            settings.audit_log_file,
            "--output-dir",
            settings.output_dir,
        ],
    )
    before = inventory.tomlpath
    with pytest.raises(SystemExit) as result:
        main.main()
    assert result.value.code == expected_exit
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] is valid
    assert inventory.tomlpath == before
    assert (
        "Next:" in format_diagnostics(report)
        if not valid
        else "Result: ready" in format_diagnostics(report)
    )
