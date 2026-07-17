# TDD Evidence: import_inventory.py（対話型インベントリ作成CLI）

- **Source plan**: `~/.claude/plans/toasty-tinkering-robin.md`（承認済み、2026-07-17）
- **User journey**: 運用者として、LLM トークンを使わずローカルで対話的に `network_devices.toml` を安全に作成・追記したい（検証付き入力、暗号化、コメント保持、アトミック書込）。

## RED / GREEN evidence

| Stage | Command | Result |
|---|---|---|
| RED (builder) | `uv run --frozen python -m pytest tests/test_inventory_builder.py -x -q` | `ModuleNotFoundError: No module named 'inventory_builder'`（意図した未実装失敗） |
| GREEN (builder) | 同上（実装後） | `44 passed` |
| RED (CLI) | `uv run --frozen python -m pytest tests/test_import_inventory.py -q` | collection error: `import_inventory` 未実装 |
| GREEN (full) | `uv run --frozen python -m pytest -q` | `157 passed`（既存 92 件回帰なし + 新規 65 件） |

## Quality gates（すべて実行・通過を確認済み）

- `uv run --frozen ruff format --check .` → 19 files formatted
- `uv run --frozen ruff check .` → All checks passed
- `uv run --frozen python -m mypy .` → Success: no issues in 19 source files
- Coverage（`--with pytest-cov`）: `inventory_builder.py` 97% / `import_inventory.py` 91% / 計 94%（目標 80%+）

## 保証される主な振る舞い（テスト仕様の抜粋）

| # | Guarantee | Test | Result |
|---|---|---|---|
| 1 | 予約名 `default`/`groups`/`q` はデバイス名にできない | test_validate_device_name_rejects_reserved_names | PASS |
| 2 | IPv6 リテラルがホスト名として受理される | test_validate_hostname_accepts_ipv6 | PASS |
| 3 | 鍵設定時 password と secret の両方が `enc:` 暗号化され復号可能 | test_device_to_table_encrypts_password_and_secret | PASS |
| 4 | 追記時に既存コメント・`enc:` 値が保持される | test_main_append_preserves_existing_content | PASS |
| 5 | 鍵認証は `use_keys=true`+`key_file` で出力され password を含まない | test_device_to_table_key_auth_writes_use_keys_and_key_file | PASS |
| 6 | 書込ファイルは 0600 パーミッション、アトミック置換 | test_atomic_write_sets_0600_permissions ほか | PASS |
| 7 | 上書き時に `.bak` を作成 | test_main_overwrite_writes_backup_file | PASS |
| 8 | 鍵未設定時は警告し平文保存/中断を選択（中断は `--generate-key` 案内） | test_resolve_encryption_key_* (3件) | PASS |
| 9 | Ctrl+C で部分保存を提案、破棄時は exit 1 でファイル無変更 | test_main_keyboard_interrupt_* (2件) | PASS |
| 10 | 保存後に `inventory.load_config_toml()` で読み戻し検証、`tomlpath` は復元 | test_main_written_file_loads_via_inventory / test_verify_written_file_restores_tomlpath | PASS |

## Manual smoke（scratchpad で実施）

- 新規作成: exit 0、`-rw-------`、`enc:` 1件、`inventory.load_config_toml()` で port=22 の r1 取得、groups `{'core': ['r1']}`
- 追記: 手書きコメント保持、`core = ["r1", "r2"]` に更新、exit 0（別鍵環境での既存 enc 値は警告に降格 = 設計どおり）

## Known gaps / notes

- 実 tty での `getpass` 挙動はテスト対象外（注入 I/O でバイパス）。
- Git checkpoint コミットは未作成 — ユーザーからのコミット依頼がないため（グローバル規約優先）。コミット時は本レポートを evidence として参照可能。
- `CLAUDE.md` は `.gitignore:11` で除外されているため更新はローカル専用。
