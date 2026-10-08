"""Tests for import_inventory: interactive prompts and the main() flow."""

import stat
import tomllib
from pathlib import Path
from typing import Any

import pytest

import inventory
from credential_crypto import KEY_ENV_VAR, decrypt_value, generate_key
from import_inventory import (
    AbortRun,
    Prompter,
    ask_validated,
    choose_file_mode,
    main,
    prompt_auth,
    prompt_device_name,
    prompt_device_type,
    prompt_one_device,
    prompt_secret,
    render_summary,
    resolve_encryption_key,
    verify_written_file,
)
from inventory_builder import EnteredDevice, validate_hostname

CTRL_C = "<CTRL-C>"


def test_metadata_cli_round_trip(tmp_path, monkeypatch):
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    path = tmp_path / "devices.toml"
    inputs = [
        "1",
        "r1",
        "192.0.2.1",
        "admin",
        "1",
        "cisco_ios",
        "",
        "core",
        "Tokyo",
        "core-switch",
        "production",
        "東京のコア",
        "bgp,,critical",
        "bgp,critical,bgp",
        "q",
        "y",
    ]
    p, said = make_prompter(inputs, ["pw", "pw", ""])
    assert main(["-f", str(path), "--metadata"], p) == 0
    data = tomllib.loads(path.read_text())
    assert data["r1"]["site"] == "Tokyo"
    assert data["r1"]["role"] == "core-switch"
    assert data["r1"]["environment"] == "production"
    assert data["r1"]["description"] == "東京のコア"
    assert data["r1"]["tags"] == ["bgp", "critical"]
    assert any("空のタグ" in line for line in said)
    assert any("読み戻し検証 OK" in line for line in said)


def make_prompter(
    inputs: list[str], secrets: list[str] | None = None
) -> tuple[Prompter, list[str]]:
    """Build a Prompter fed by scripted answers; returns it and captured output."""
    said: list[str] = []
    input_iter = iter(inputs)
    secret_iter = iter(secrets or [])

    def fake_input(_prompt: str) -> str:
        value = next(input_iter)
        if value == CTRL_C:
            raise KeyboardInterrupt
        return value

    def fake_getpass(_prompt: str) -> str:
        value = next(secret_iter)
        if value == CTRL_C:
            raise KeyboardInterrupt
        return value

    prompter = Prompter(
        input_fn=fake_input,
        getpass_fn=fake_getpass,
        print_fn=said.append,
    )
    return prompter, said


def make_device(**overrides: Any) -> EnteredDevice:
    fields: dict[str, Any] = {
        "name": "r1",
        "hostname": "192.0.2.1",
        "device_type": "cisco_ios",
        "username": "admin",
        "password": "topsecret",
        "use_keys": False,
        "key_file": None,
        "secret": None,
        "port": None,
        "groups": (),
    }
    fields.update(overrides)
    return EnteredDevice(**fields)


# ---------------------------------------------------------------------------
# prompt helpers
# ---------------------------------------------------------------------------


def test_ask_validated_reprompts_until_valid() -> None:
    p, said = make_prompter(["bad host!!", "192.0.2.1"])

    assert ask_validated(p, "host: ", validate_hostname) == "192.0.2.1"
    assert any("[エラー]" in line for line in said)


def test_prompt_device_name_returns_none_on_q() -> None:
    p, _ = make_prompter(["q"])

    assert prompt_device_name(p, set()) is None


def test_prompt_auth_password_mismatch_reprompts() -> None:
    p, said = make_prompter(["1"], secrets=["first", "second", "pw123", "pw123"])

    assert prompt_auth(p) == ("pw123", False, None)
    assert any("一致しません" in line for line in said)


def test_prompt_secret_requires_confirmation() -> None:
    p, said = make_prompter([], secrets=["typo", "typoo", "enable123", "enable123"])

    assert prompt_secret(p) == "enable123"
    assert any("一致しません" in line for line in said)


def test_prompt_secret_empty_skips_confirmation() -> None:
    p, _ = make_prompter([], secrets=[""])

    assert prompt_secret(p) is None


def test_prompt_auth_key_file_existing_path_accepted(tmp_path: Path) -> None:
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("dummy")
    p, said = make_prompter(["2", str(key_file)])

    assert prompt_auth(p) == (None, True, str(key_file))
    assert not any("[警告]" in line for line in said)


def test_prompt_auth_key_file_missing_warns_and_accepts_yes() -> None:
    p, said = make_prompter(["2", "/no/such/key", "y"])

    assert prompt_auth(p) == (None, True, "/no/such/key")
    assert any("[警告]" in line for line in said)


def test_prompt_auth_key_file_missing_no_reprompts_path(tmp_path: Path) -> None:
    key_file = tmp_path / "id_ed25519"
    key_file.write_text("dummy")
    p, _ = make_prompter(["2", "/no/such/key", "n", str(key_file)])

    assert prompt_auth(p) == (None, True, str(key_file))


def test_prompt_device_type_shows_suggestions_on_invalid() -> None:
    p, said = make_prompter(["ios", "cisco_ios"])

    assert prompt_device_type(p) == "cisco_ios"
    assert any("cisco_ios" in line for line in said if "候補" in line)


def test_prompt_one_device_full_password_flow() -> None:
    inputs = ["r1", "192.0.2.1", "admin", "1", "cisco_ios", "2222", "core,edge"]
    p, _ = make_prompter(inputs, secrets=["pw123", "pw123", "enable123", "enable123"])

    dev = prompt_one_device(p, set(), 1)

    assert dev == EnteredDevice(
        name="r1",
        hostname="192.0.2.1",
        device_type="cisco_ios",
        username="admin",
        password="pw123",
        use_keys=False,
        key_file=None,
        secret="enable123",
        port=2222,
        groups=("core", "edge"),
    )


def test_render_summary_masks_credentials() -> None:
    summary = render_summary([make_device(password="topsecret", secret="alsohidden")])

    assert "topsecret" not in summary
    assert "alsohidden" not in summary
    assert "********" in summary
    assert "r1" in summary


# ---------------------------------------------------------------------------
# resolve_encryption_key
# ---------------------------------------------------------------------------


def test_resolve_encryption_key_returns_env_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key)
    p, _ = make_prompter([])

    assert resolve_encryption_key(p) == key


def test_resolve_encryption_key_rejects_invalid_env_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, "not-a-fernet-key")
    p, _ = make_prompter([])

    with pytest.raises(AbortRun, match="Fernet"):
        resolve_encryption_key(p)


def test_resolve_encryption_key_plaintext_choice_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    p, said = make_prompter(["1"])

    assert resolve_encryption_key(p) is None
    assert any("[警告]" in line for line in said)


def test_resolve_encryption_key_abort_raises_abort_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    p, _ = make_prompter(["2"])

    with pytest.raises(AbortRun, match="generate-key"):
        resolve_encryption_key(p)


def test_main_aborts_on_unset_key_before_prompting_devices(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The key is resolved first, so aborting costs the user no typed input."""
    monkeypatch.delenv(KEY_ENV_VAR, raising=False)
    target = tmp_path / "devices.toml"
    p, said = make_prompter(["2"])

    assert main(["-f", str(target)], prompter=p) == 1
    assert not target.exists()
    assert any("generate-key" in line for line in said)


# ---------------------------------------------------------------------------
# choose_file_mode
# ---------------------------------------------------------------------------


def test_choose_file_mode_new_when_file_absent(tmp_path: Path) -> None:
    p, _ = make_prompter([])

    assert choose_file_mode(p, tmp_path / "none.toml") == "new"


@pytest.mark.parametrize(("answer", "expected"), [("a", "append"), ("o", "overwrite")])
def test_choose_file_mode_append_or_overwrite(
    tmp_path: Path, answer: str, expected: str
) -> None:
    target = tmp_path / "devices.toml"
    target.write_text("")
    p, _ = make_prompter(["x", answer])

    assert choose_file_mode(p, target) == expected


def test_choose_file_mode_abort_exits_cleanly(tmp_path: Path) -> None:
    target = tmp_path / "devices.toml"
    target.write_text("")
    p, _ = make_prompter(["q"])

    with pytest.raises(AbortRun) as exc_info:
        choose_file_mode(p, target)
    assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# verify_written_file
# ---------------------------------------------------------------------------


def test_verify_written_file_restores_tomlpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        """\
[r1]
hostname = "192.0.2.1"
device_type = "cisco_ios"
"""
    )
    monkeypatch.setattr(inventory, "tomlpath", "sentinel-path")

    status, _message = verify_written_file(toml_file)

    assert status == "ok"
    assert inventory.tomlpath == "sentinel-path"


def test_verify_written_file_reports_invalid_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        """\
[r1]
hostname = "192.0.2.1"
device_type = "not_a_real_platform"
"""
    )
    monkeypatch.setattr(inventory, "tomlpath", None)

    status, message = verify_written_file(toml_file)

    assert status == "error"
    assert "device_type" in message


# ---------------------------------------------------------------------------
# main() end-to-end
# ---------------------------------------------------------------------------

DEVICE_R1_INPUTS = ["r1", "192.0.2.1", "admin", "1", "cisco_ios", "", "core"]
DEVICE_R1_SECRETS = ["pw123", "pw123", "enable123", "enable123"]


def test_main_creates_new_file_encrypted_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    monkeypatch.setenv(KEY_ENV_VAR, key)
    target = tmp_path / "devices.toml"
    p, said = make_prompter([*DEVICE_R1_INPUTS, "q", "y"], secrets=DEVICE_R1_SECRETS)

    rv = main(["-f", str(target)], prompter=p)

    assert rv == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    data = tomllib.loads(target.read_text())
    assert data["r1"]["hostname"] == "192.0.2.1"
    assert data["r1"]["password"].startswith("enc:")
    assert decrypt_value(data["r1"]["password"]) == "pw123"
    assert decrypt_value(data["r1"]["secret"]) == "enable123"
    assert data["groups"]["core"] == ["r1"]
    assert any("読み戻し検証 OK" in line for line in said)


def test_main_written_file_loads_via_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    p, _ = make_prompter([*DEVICE_R1_INPUTS, "q", "y"], secrets=DEVICE_R1_SECRETS)
    assert main(["-f", str(target)], prompter=p) == 0

    monkeypatch.setattr(inventory, "tomlpath", str(target))
    devs = inventory.load_config_toml()

    assert devs["r1"].password == "pw123"
    assert devs["r1"].port == 22


def test_main_append_preserves_existing_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text(
        """\
# hand-written comment
[r1]
hostname = "192.0.2.1"
device_type = "cisco_ios"
username = "admin"
password = "enc:AAAA-existing-token"

[groups]
core = ["r1"]
"""
    )
    inputs = ["a", "r2", "192.0.2.2", "admin", "1", "cisco_ios", "", "core", "q", "y"]
    p, _ = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    rv = main(["-f", str(target)], prompter=p)

    assert rv == 0
    text = target.read_text()
    assert "# hand-written comment" in text
    assert "enc:AAAA-existing-token" in text
    data = tomllib.loads(text)
    assert data["groups"]["core"] == ["r1", "r2"]
    assert data["r2"]["password"].startswith("enc:")


def test_main_append_rejects_duplicate_of_existing_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text(
        """\
[r1]
hostname = "192.0.2.1"
device_type = "cisco_ios"
"""
    )
    inputs = ["a", "r1", "r2", "192.0.2.2", "admin", "1", "cisco_ios", "", "", "q", "y"]
    p, said = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    assert any("既に存在します" in line for line in said)


def test_main_overwrite_writes_backup_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    original = '[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n'
    target.write_text(original)
    inputs = ["o", "r9", "192.0.2.9", "admin", "1", "cisco_ios", "", "", "q", "y", "y"]
    p, _ = make_prompter(inputs, secrets=["pw9", "pw9", ""])

    rv = main(["-f", str(target)], prompter=p)

    assert rv == 0
    assert (tmp_path / "devices.toml.bak").read_text() == original
    data = tomllib.loads(target.read_text())
    assert "r9" in data
    assert "r1" not in data


def test_main_quit_immediately_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    p, said = make_prompter(["q"])

    assert main(["-f", str(target)], prompter=p) == 0
    assert not target.exists()
    assert any("保存するデバイスがありません" in line for line in said)


def test_main_keyboard_interrupt_offers_partial_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    inputs = [*DEVICE_R1_INPUTS, CTRL_C, "y", "y"]
    p, _ = make_prompter(inputs, secrets=DEVICE_R1_SECRETS)

    rv = main(["-f", str(target)], prompter=p)

    assert rv == 0
    assert "r1" in tomllib.loads(target.read_text())


def test_main_keyboard_interrupt_discard_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    inputs = [*DEVICE_R1_INPUTS, CTRL_C, "n"]
    p, _ = make_prompter(inputs, secrets=DEVICE_R1_SECRETS)

    assert main(["-f", str(target)], prompter=p) == 1
    assert not target.exists()


def test_main_second_interrupt_during_partial_save_prompt_discards(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Ctrl+C at the 'save partial devices?' question discards cleanly."""
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    inputs = [*DEVICE_R1_INPUTS, CTRL_C, CTRL_C]
    p, said = make_prompter(inputs, secrets=DEVICE_R1_SECRETS)

    assert main(["-f", str(target)], prompter=p) == 1
    assert not target.exists()
    assert any("入力を破棄しました" in line for line in said)


def test_main_interrupt_at_password_prompt_is_handled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl+C inside getpass reaches the same interrupt path as Ctrl+C at input."""
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    inputs = ["r1", "192.0.2.1", "admin", "1"]
    p, said = make_prompter(inputs, secrets=[CTRL_C])

    assert main(["-f", str(target)], prompter=p) == 1
    assert not target.exists()
    assert any("保存するデバイスはありません" in line for line in said)


def test_main_rejects_directory_path(tmp_path: Path) -> None:
    p, said = make_prompter([])

    assert main(["-f", str(tmp_path)], prompter=p) == 1
    assert any("ディレクトリ" in line for line in said)


def test_main_rejects_missing_parent_directory(tmp_path: Path) -> None:
    p, said = make_prompter([])

    assert main(["-f", str(tmp_path / "nosuchdir" / "devices.toml")], prompter=p) == 1
    assert any("保存先ディレクトリが存在しません" in line for line in said)


def test_main_rejects_invalid_existing_toml(tmp_path: Path) -> None:
    target = tmp_path / "devices.toml"
    target.write_text("this is [not valid toml")
    p, said = make_prompter(["a"])

    assert main(["-f", str(target)], prompter=p) == 1
    assert any("TOML" in line for line in said)


def test_main_overwrite_survives_unparseable_existing_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Overwrite is chosen precisely when the old file is broken."""
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text("this is [not valid toml")
    inputs = ["o", "r9", "192.0.2.9", "admin", "1", "cisco_ios", "", "", "q", "y", "y"]
    p, said = make_prompter(inputs, secrets=["pw9", "pw9", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    assert "r9" in tomllib.loads(target.read_text())
    assert any("解析できませんでした" in line for line in said)


def test_main_append_writes_backup_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    original = '[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n'
    target.write_text(original)
    inputs = ["a", "r2", "192.0.2.2", "admin", "1", "cisco_ios", "", "", "q", "y"]
    p, _ = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    assert (tmp_path / "devices.toml.bak").read_text() == original


def test_main_rejects_group_named_after_a_device(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """inventory.get_device_names() would resolve the device, hiding the group."""
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text('[core]\nhostname = "192.0.2.9"\ndevice_type = "cisco_ios"\n')
    inputs = [
        "a",
        "r2",
        "192.0.2.2",
        "admin",
        "1",
        "cisco_ios",
        "",
        "core",
        "",
        "q",
        "y",
    ]
    p, said = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    assert any("同名のデバイスが存在する" in line for line in said)
    assert "groups" not in tomllib.loads(target.read_text())


def test_main_rejects_device_named_after_a_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text(
        '[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n\n'
        '[groups]\ncore = ["r1"]\n'
    )
    inputs = [
        "a",
        "core",
        "r2",
        "192.0.2.2",
        "admin",
        "1",
        "cisco_ios",
        "",
        "",
        "q",
        "y",
    ]
    p, said = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    assert any("同名のグループが存在する" in line for line in said)
    assert "core" not in tomllib.loads(target.read_text())


def test_main_reports_malformed_groups_table_before_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text('groups = "oops"\n[r1]\nhostname = "1.1.1.1"\n')
    p, said = make_prompter(["a"])

    assert main(["-f", str(target)], prompter=p) == 1
    assert any("groups" in line for line in said)


def test_main_backup_is_owner_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The .bak of a world-readable inventory must not leak credentials."""
    monkeypatch.setenv(KEY_ENV_VAR, generate_key())
    target = tmp_path / "devices.toml"
    target.write_text('[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n')
    target.chmod(0o644)
    inputs = ["a", "r2", "192.0.2.2", "admin", "1", "cisco_ios", "", "", "q", "y"]
    p, _ = make_prompter(inputs, secrets=["pw2", "pw2", ""])

    assert main(["-f", str(target)], prompter=p) == 0
    backup = tmp_path / "devices.toml.bak"
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_main_does_not_swallow_unrelated_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only InventoryDataError is user-facing; a real bug must not look like one."""
    import import_inventory

    monkeypatch.setenv(KEY_ENV_VAR, generate_key())

    def boom(*_args: Any, **_kwargs: Any) -> None:
        raise ValueError("bug in a helper")

    monkeypatch.setattr(import_inventory, "merge_devices", boom)
    target = tmp_path / "devices.toml"
    p, _ = make_prompter([*DEVICE_R1_INPUTS, "q", "y"], secrets=DEVICE_R1_SECRETS)

    with pytest.raises(ValueError, match="bug in a helper"):
        main(["-f", str(target)], prompter=p)


def test_verify_written_file_reports_unknown_device_key(tmp_path: Path) -> None:
    """Device.__init__ raises TypeError, not ValueError, for an unknown key."""
    toml_file = tmp_path / "devices.toml"
    toml_file.write_text(
        '[r1]\nhostname = "192.0.2.1"\ndevice_type = "cisco_ios"\n'
        'enable_password = "x"\n'
    )

    status, message = verify_written_file(toml_file)

    assert status == "error"
    assert "enable_password" in message
