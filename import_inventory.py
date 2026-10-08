"""Interactive CLI to create or update the device inventory TOML.

Runs fully offline: prompts for each device with per-field validation,
optionally encrypts credentials with the key from
NETMIKO_MCP_SERVER_INVENTORY_KEY, and writes the file atomically with
owner-only permissions. Append mode preserves existing comments, key order,
and already-encrypted values.

Usage:
    uv run python import_inventory.py [-f network_devices.toml]
"""

import argparse
import getpass
import os
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

import tomlkit
from tomlkit import TOMLDocument
from tomlkit.exceptions import TOMLKitError

import inventory
from credential_crypto import KEY_ENV_VAR, encrypt_value
from inventory_builder import (
    EnteredDevice,
    InventoryDataError,
    atomic_write,
    backup_file,
    collect_existing_group_names,
    collect_existing_names,
    count_devices_and_groups,
    merge_devices,
    suggest_device_types,
    validate_device_name,
    validate_device_type,
    validate_group_names,
    validate_hostname,
    validate_port,
    validate_tags,
    validate_username,
)

DEFAULT_INVENTORY_FILE = "network_devices.toml"
QUIT_KEY = "q"
MASK = "********"

T = TypeVar("T")


class AbortRun(Exception):
    """Stop the run with an exit code.

    Every abort path raises this instead of SystemExit so main() stays the
    single place that turns an outcome into an exit code, and callers get the
    int its signature promises. `raise SystemExit(main())` is the only exit.
    """

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Prompter:
    """Injectable console I/O so tests can script an interactive session."""

    input_fn: Callable[[str], str] = input
    getpass_fn: Callable[[str], str] = getpass.getpass
    print_fn: Callable[[str], None] = print

    def ask(self, prompt: str) -> str:
        return self.input_fn(prompt)

    def ask_secret(self, prompt: str) -> str:
        return self.getpass_fn(prompt)

    def say(self, message: str) -> None:
        self.print_fn(message)


def ask_validated(p: Prompter, prompt: str, validator: Callable[[str], T]) -> T:
    """Re-prompt until validator accepts the input."""
    while True:
        raw = p.ask(prompt)
        try:
            return validator(raw)
        except ValueError as exc:
            p.say(f"[エラー] {exc}")


def ask_yes_no(p: Prompter, prompt: str) -> bool:
    while True:
        answer = p.ask(prompt).strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        p.say("[エラー] y または n を入力してください。")


def prompt_device_name(
    p: Prompter, existing: Collection[str], group_names: Collection[str] = ()
) -> str | None:
    """Ask for a device name; returns None when the user quits with 'q'."""
    while True:
        raw = p.ask(f"デバイス名 (終了して保存するには '{QUIT_KEY}'): ")
        if raw.strip() == QUIT_KEY:
            return None
        try:
            return validate_device_name(raw, existing, group_names)
        except ValueError as exc:
            p.say(f"[エラー] {exc}")


def _ask_secret_twice(p: Prompter, prompt: str, confirm_prompt: str) -> str | None:
    """Ask for a secret and its confirmation; None when the first entry is empty.

    Re-prompts until the two entries match. Secrets are never echoed, so an
    unconfirmed typo would stay invisible until the device rejects it.
    """
    while True:
        first = p.ask_secret(prompt)
        if not first:
            return None
        second = p.ask_secret(confirm_prompt)
        if first == second:
            return first
        p.say("[エラー] 入力が一致しません。もう一度入力してください。")


def _prompt_password(p: Prompter) -> str:
    while True:
        value = _ask_secret_twice(p, "パスワード: ", "パスワード (確認): ")
        if value is not None:
            return value
        p.say("[エラー] パスワードは空にできません。")


def _prompt_key_file(p: Prompter) -> str:
    while True:
        raw = p.ask("秘密鍵ファイルのパス: ").strip()
        if not raw:
            p.say("[エラー] パスは空にできません。")
            continue
        if Path(raw).expanduser().exists():
            return raw
        p.say(f"[警告] ファイルが見つかりません: {raw}")
        if ask_yes_no(p, "このパスのまま進めますか? (y/n): "):
            return raw


def prompt_auth(p: Prompter) -> tuple[str | None, bool, str | None]:
    """Returns (password, use_keys, key_file) for the chosen auth method."""
    while True:
        choice = p.ask("認証方法 (1=パスワード / 2=秘密鍵): ").strip()
        if choice == "1":
            return _prompt_password(p), False, None
        if choice == "2":
            return None, True, _prompt_key_file(p)
        p.say("[エラー] 1 または 2 を入力してください。")


def prompt_secret(p: Prompter) -> str | None:
    return _ask_secret_twice(
        p,
        "特権(enable)パスワード (任意, Enterでスキップ): ",
        "特権(enable)パスワード (確認): ",
    )


def prompt_device_type(p: Prompter) -> str:
    while True:
        raw = p.ask("device_type (例: cisco_ios): ")
        try:
            return validate_device_type(raw)
        except ValueError as exc:
            p.say(f"[エラー] {exc}")
            suggestions = suggest_device_types(raw)
            if suggestions:
                p.say("候補: " + ", ".join(suggestions))


def prompt_one_device(
    p: Prompter,
    existing: Collection[str],
    index: int,
    group_names: Collection[str] = (),
    include_metadata: bool = False,
) -> EnteredDevice | None:
    """Prompt all fields for one device; returns None when the user quits."""
    p.say("-" * 50)
    p.say(f"[デバイス #{index}]")
    name = prompt_device_name(p, existing, group_names)
    if name is None:
        return None
    hostname = ask_validated(p, "ホスト名またはIPアドレス: ", validate_hostname)
    username = ask_validated(p, "ユーザー名: ", validate_username)
    password, use_keys, key_file = prompt_auth(p)
    secret = prompt_secret(p)
    device_type = prompt_device_type(p)
    port = ask_validated(p, "ポート番号 (Enterで既定 22/23): ", validate_port)
    taken_device_names = frozenset(existing) | {name}
    groups = ask_validated(
        p,
        "所属グループ (カンマ区切り, 任意): ",
        lambda raw: validate_group_names(raw, taken_device_names),
    )
    site = role = environment = description = None
    tags: tuple[str, ...] = ()
    if include_metadata:
        site = p.ask("拠点 (任意): ").strip() or None
        role = p.ask("役割 (例: core-switch, 任意): ").strip() or None
        environment = p.ask("環境 (例: production / lab, 任意): ").strip() or None
        description = p.ask("説明 (任意, 認証情報は入力しない): ").strip() or None
        tags = ask_validated(p, "タグ (カンマ区切り, 任意): ", validate_tags)
    return EnteredDevice(
        name=name,
        hostname=hostname,
        device_type=device_type,
        username=username,
        password=password,
        use_keys=use_keys,
        key_file=key_file,
        secret=secret,
        port=port,
        groups=groups,
        site=site,
        role=role,
        environment=environment,
        description=description,
        tags=tags,
    )


def _handle_interrupt(p: Prompter, devices: list[EnteredDevice]) -> list[EnteredDevice]:
    p.say("")
    if not devices:
        raise AbortRun(1, "入力を中断しました。保存するデバイスはありません。")
    try:
        count = len(devices)
        if ask_yes_no(
            p, f"入力を中断しました。ここまでの {count} 台を保存しますか? (y/n): "
        ):
            return devices
    except (KeyboardInterrupt, EOFError):
        pass
    raise AbortRun(1, "入力を破棄しました。")


def collect_devices(
    p: Prompter,
    existing_names: frozenset[str],
    existing_groups: frozenset[str] = frozenset(),
    include_metadata: bool = False,
) -> list[EnteredDevice]:
    devices: list[EnteredDevice] = []
    while True:
        taken = existing_names | {d.name for d in devices}
        groups = existing_groups | {g for d in devices for g in d.groups}
        try:
            dev = prompt_one_device(
                p, taken, len(devices) + 1, groups, include_metadata
            )
        except (KeyboardInterrupt, EOFError):
            return _handle_interrupt(p, devices)
        if dev is None:
            return devices
        devices.append(dev)


def render_summary(devices: Sequence[EnteredDevice]) -> str:
    """Human-readable confirmation listing; credentials are always masked."""
    lines = ["", "===== 入力内容の確認 ====="]
    for dev in devices:
        lines.append(f"[{dev.name}]")
        lines.append(f"  hostname: {dev.hostname}")
        lines.append(f"  device_type: {dev.device_type}")
        lines.append(f"  username: {dev.username}")
        if dev.use_keys:
            lines.append(f"  key_file: {dev.key_file}")
        else:
            lines.append(f"  password: {MASK}")
        if dev.secret is not None:
            lines.append(f"  secret: {MASK}")
        if dev.port is not None:
            lines.append(f"  port: {dev.port}")
        if dev.groups:
            lines.append(f"  groups: {', '.join(dev.groups)}")
        for field in ("site", "role", "environment", "description"):
            value = getattr(dev, field)
            if value:
                lines.append(f"  {field}: {value}")
        if dev.tags:
            lines.append(f"  tags: {', '.join(dev.tags)}")
    return "\n".join(lines)


def resolve_encryption_key(p: Prompter) -> str | None:
    """Key from the environment, or the user's plaintext/abort decision."""
    key = os.environ.get(KEY_ENV_VAR, "").strip()
    if key:
        try:
            encrypt_value("probe", key)
        except (ValueError, TypeError) as exc:
            raise AbortRun(
                1, f"Error: {KEY_ENV_VAR} is not a valid Fernet key: {exc}"
            ) from exc
        return key
    p.say(f"[警告] {KEY_ENV_VAR} が未設定のため、認証情報を暗号化できません。")
    while True:
        choice = p.ask("1=平文のまま保存 / 2=中断: ").strip()
        if choice == "1":
            return None
        if choice == "2":
            raise AbortRun(
                1,
                "中断しました。`uv run python main.py --generate-key` で鍵を生成し、"
                f"環境変数 {KEY_ENV_VAR} に設定してから再実行してください。",
            )
        p.say("[エラー] 1 または 2 を入力してください。")


def choose_file_mode(p: Prompter, path: Path) -> str:
    """Returns 'new', 'append', or 'overwrite'; aborting exits with code 0."""
    if not path.exists():
        return "new"
    while True:
        choice = (
            p.ask(f"'{path}' は既に存在します (a=追記 / o=上書き / q=中断): ")
            .strip()
            .lower()
        )
        if choice in ("a", "append"):
            return "append"
        if choice in ("o", "overwrite"):
            return "overwrite"
        if choice in ("q", "quit"):
            raise AbortRun(0, "中断しました。ファイルは変更されていません。")
        p.say("[エラー] a / o / q のいずれかを入力してください。")


def load_existing_doc(path: Path) -> TOMLDocument:
    try:
        return tomlkit.parse(path.read_text(encoding="utf-8"))
    except (OSError, TOMLKitError) as exc:
        raise AbortRun(
            1, f"Error: 既存の TOML を読み込めません ({path}): {exc}"
        ) from exc


def _overwrite_warning(path: Path) -> str:
    """Describe what an overwrite discards.

    Overwrite is exactly the mode chosen when the existing file is broken, so
    an unparseable or malformed file must not abort the run here — by this
    point every device has already been entered.
    """
    try:
        n_dev, n_grp = count_devices_and_groups(load_existing_doc(path))
    except (AbortRun, ValueError):
        # Broad on purpose, unlike main(): this is only a display helper, and
        # by now every device has been entered — nothing here may abort.
        return (
            "[警告] 既存ファイルを解析できませんでした。上書きすると内容が失われます。"
        )
    return (
        f"[警告] 上書きすると既存の {n_dev} デバイス / {n_grp} グループが失われます。"
    )


def save_inventory(
    p: Prompter,
    path: Path,
    mode: str,
    doc: TOMLDocument,
    devices: Sequence[EnteredDevice],
    key: str | None,
) -> None:
    merge_devices(doc, devices, key)
    if mode == "overwrite":
        p.say(_overwrite_warning(path))
        if not ask_yes_no(p, "本当に上書きしますか? (y/n): "):
            raise AbortRun(0, "中断しました。ファイルは変更されていません。")
    # Append rewrites the whole file too, so back up whenever one already
    # exists rather than only on the overwrite branch.
    if path.exists():
        backup = backup_file(path)
        p.say(f"バックアップを作成しました: {backup}")
    atomic_write(path, tomlkit.dumps(doc))


def verify_written_file(path: Path) -> tuple[str, str]:
    """Round-trip the written file through inventory loading.

    Returns ('ok', ''), ('warning', msg) when encrypted values cannot be
    checked without the key, or ('error', msg) when a device is invalid.
    """
    saved = inventory.tomlpath
    inventory.tomlpath = str(path)
    try:
        inventory.load_config_toml()
        inventory.load_groups()
        return "ok", ""
    except RuntimeError as exc:
        return "warning", str(exc)
    except (ValueError, TypeError) as exc:
        # TypeError: a device table carries a key Device.__init__ does not take.
        return "error", str(exc)
    finally:
        inventory.tomlpath = saved


def _report_verification(p: Prompter, path: Path) -> int:
    status, message = verify_written_file(path)
    if status == "error":
        p.say(f"[エラー] 保存したファイルの検証に失敗しました: {message}")
        return 1
    if status == "warning":
        p.say(f"[警告] 完全な検証はできませんでした: {message}")
    else:
        p.say("読み戻し検証 OK。")
    return 0


def _run(p: Prompter, path: Path, include_metadata: bool = False) -> int:
    mode = choose_file_mode(p, path)
    doc = load_existing_doc(path) if mode == "append" else tomlkit.document()
    # Resolved before any device is entered: a malformed key or the "abort"
    # choice must not discard a whole session's worth of typing.
    key = resolve_encryption_key(p)
    devices = collect_devices(
        p,
        collect_existing_names(doc),
        collect_existing_group_names(doc),
        include_metadata,
    )
    if not devices:
        p.say("保存するデバイスがありません。ファイルは変更されていません。")
        return 0
    p.say(render_summary(devices))
    if not ask_yes_no(p, "この内容で保存しますか? (y/n): "):
        p.say("中断しました。ファイルは変更されていません。")
        return 0
    save_inventory(p, path, mode, doc, devices, key)
    p.say(f"保存しました: {path}")
    return _report_verification(p, path)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactively build or update the device inventory TOML."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        default=DEFAULT_INVENTORY_FILE,
        help=f"path to the inventory TOML (default: {DEFAULT_INVENTORY_FILE})",
    )
    parser.add_argument(
        "--metadata",
        action="store_true",
        help="prompt for public site, role, environment, description, and tags",
    )
    return parser.parse_args(argv)


def _validate_target_path(path: Path) -> None:
    """Reject an unusable output path before any prompting.

    atomic_write() creates its temp file in path.parent, so a missing parent
    would otherwise only fail once every device has been entered.
    """
    if path.is_dir():
        raise AbortRun(1, f"Error: '{path}' はディレクトリです。")
    if not path.parent.is_dir():
        raise AbortRun(1, f"Error: 保存先ディレクトリが存在しません: {path.parent}")


def main(argv: Sequence[str] | None = None, prompter: Prompter | None = None) -> int:
    p = prompter if prompter is not None else Prompter()
    args = _parse_args(argv)
    path = Path(args.file)
    try:
        _validate_target_path(path)
        return _run(p, path, args.metadata)
    except AbortRun as exc:
        if exc.message:
            p.say(exc.message)
        return exc.code
    except InventoryDataError as exc:
        # Narrow on purpose: a bare `except ValueError` here would also report
        # a genuine bug as if it were the user's data problem.
        p.say(f"[エラー] {exc}")
        return 1
    except (KeyboardInterrupt, EOFError):
        p.say("\n中断しました。ファイルは変更されていません。")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
