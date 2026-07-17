[English](README.md) | 日本語

# netmiko-mcp-server

NW機器をチャット形式で操作するためのMCPサーバーです。`netmiko` を使って SSH / Telnet に対応し、`enable` パスワードにも対応します。

> **警告:** このツールはネットワーク機器に直接コマンドを送信します。設定変更ツールはデフォルトで無効、show系コマンドもコマンドファイルを指定しない限り全て拒否されます。本番環境に接続する前に、必ずラボ環境で動作を確認してください。

## 特徴
- SSH / Telnet 両対応
- `enable` パスワード (`secret`) 対応
- SSH公開鍵認証 (`use_keys`, `key_file`) 対応
- MCP stdio / SSE モード
- コマンドはデフォルト全拒否、`commands.toml` の allow/deny リストで明示的に許可したものだけ実行可能
- 設定変更ツール (`set_config_commands_and_commit_or_save`) はデフォルト無効。`--enable-config` で明示的に有効化
- SSEモードは Bearer トークン認証が必須（`--no-http-auth` で明示的に無効化可能。非推奨）
- 全てのコマンド試行・接続結果をJSON形式で監査ログに記録（fail-closed: ログ書き込みに失敗した場合は操作自体が失敗する）
- 巨大な出力は自動的にファイル保存し、ページング付きで読み出し可能（LLMのコンテキストを圧迫しない）
- `[groups]` でグループ化した複数デバイスへの並列コマンド実行に対応
- `use_textfsm=True` でntc-templatesによる構造化(JSON)出力に対応
- インベントリの `password`/`secret` を暗号化して保存可能（Fernet対称鍵暗号）
- `import_inventory.py` で対話的にインベントリを作成・追記可能（LLMトークン不要、フィールド別バリデーション付き）

## 使い方

### 1. デバイス定義 (TOML)
`network_devices.toml` を編集して、`[default]` と個別デバイスを定義します。

```toml
[default]
username = "netops"
password = "password"
secret = "enablepassword"

[router_telnet]
hostname = "192.0.2.10"
device_type = "cisco_ios_telnet"

[switch_ssh]
hostname = "192.0.2.11"
device_type = "cisco_ios"
use_keys = true
key_file = "/home/user/.ssh/id_rsa"

[c1200coreSW]
hostname = "192.0.2.12"
device_type = "cisco_ios"
pre_commands = ["terminal datadump"]
ansi_escape_codes = true
```

#### 対話的にインベントリを作成する (import_inventory.py)

手書きの代わりに、対話型スクリプトでインベントリを作成・追記できます。

```bash
uv run python import_inventory.py                  # 既定: network_devices.toml
uv run python import_inventory.py -f my_devices.toml
```

- デバイス名・ホスト名(IPv4/IPv6/FQDN)・device_type(netmiko のプラットフォーム名)などを1項目ずつ検証しながら入力します。device_type を間違えると部分一致の候補が表示されます。デバイス名の入力時に `q` で入力を終了し、確認のうえ保存します
- 既存ファイルがある場合は **追記 / 上書き / 中断** を選択できます。追記時は既存のコメント・記述順・暗号化済みの値(`enc:`)をそのまま保持します。上書き時は `<ファイル名>.bak` にバックアップを作成します
- 所属グループをカンマ区切りで指定すると `[groups]` テーブルも自動更新されます
- `NETMIKO_MCP_SERVER_INVENTORY_KEY` が設定されていれば `password`/`secret` を自動で暗号化して保存します（[認証情報の暗号化](#4-認証情報の暗号化-任意) を参照）。未設定の場合は「平文のまま保存 / 中断」を選択できます
- ファイルは所有者のみ読み書き可能なパーミッション (0600) でアトミックに書き出され、保存後にインベントリローダーで読み戻し検証されます
- 既存デバイスの編集・削除、`[default]` セクションの作成、`pre_commands` / `ansi_escape_codes` / タイムアウト類の入力はスコープ外です（手動で編集してください）。なお追記時、既存ファイルの末尾に `[groups]` がある場合、新しいデバイステーブルはその後ろに追加されます（TOML として有効で、正しく読み込まれます）

### 2. コマンド許可リスト (TOML)

`commands.toml` を作成し、LLMが実行してよいコマンドを明示的に列挙します。**このファイルを指定しない場合、全てのコマンドが拒否されます。**

```toml
allowed_commands = [
  "show version",
  "show ip interface brief",
  "show ip interface*",   # 末尾一致glob。"show ip interface" + 任意の続き
  "show ip route *",      # 空白+glob。"show ip route" 単体は許可されず、追加の引数が必須
]

denied_commands = [
  "show running-config",  # allowed_commands に一致しても、denyが常に優先される
]
```

**設定変更コマンド用の許可リスト（`--enable-config`使用時）**

同じ`commands.toml`に`config_allowed_commands`/`config_denied_commands`を書くと、`set_config_commands_and_commit_or_save`に渡された各コマンド行にもallow/denyリストが適用されます（未指定なら全拒否）。渡されたコマンドの中に1つでも拒否されたものがあれば、デバイスには何も送信されません。

```toml
config_allowed_commands = [
  "interface *",
  "description *",
  "ip address *",
  "no shutdown",
]

config_denied_commands = [
  "no ip address*",
]
```

さらに、`shutdown`（インターフェースを止める）と`clear*`は、上記の設定に関わらず**常に拒否**されます（コード側にハードコードされたベースライン保護。`security.py`の`BASELINE_CONFIG_DENIED_COMMANDS`）。`config_allowed_commands`に明示的に書いても上書きできません。`no shutdown`（インターフェースを起こす方向）は危険側の操作ではないためベースライン拒否には含まれていません。

### 3. デバイスグループ (任意)

`network_devices.toml` に `[groups]` テーブルを追加すると、`send_command_to_group` でまとめて並列実行できます。

```toml
[groups]
core_switches = ["switch_ssh", "c1200coreSW"]
```

グループ名の代わりに `all` を指定すると、インベントリ内の全デバイスが対象になります。

### 4. 認証情報の暗号化 (任意)

TOML内の平文パスワードが気になる場合、`password`/`secret` を暗号化できます。

```bash
# 1. 鍵を生成し、環境変数に設定(サーバー起動時にも同じ鍵が必要)
export NETMIKO_MCP_SERVER_INVENTORY_KEY=$(uv run --with cryptography main.py --generate-key)

# 2. パスワードを暗号化し、TOMLに貼り付ける
uv run --with cryptography main.py --encrypt-value "mypassword"
# => enc:gAAAAA...
```

```toml
[router1]
hostname = "192.0.2.10"
device_type = "cisco_ios"
password = "enc:gAAAAA..."
```

`NETMIKO_MCP_SERVER_INVENTORY_KEY` が未設定のまま暗号化済みの値を読み込もうとすると、起動時エラーになります。鍵はTOMLファイルに含めず、環境変数でのみ管理してください。

### 5. サーバー起動

#### stdio (ローカル)
```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml
```

設定変更ツールも使いたい場合は `--enable-config` を追加してください（デフォルトは無効）。

#### SSE (リモート接続向け)
SSEモードは Bearer トークン認証が必須です。まずトークンを環境変数に設定します。

```bash
export NETMIKO_MCP_SERVER_BEARER_TOKEN="$(openssl rand -hex 32)"
```

```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml \
  --sse --bind 10.70.72.1 --port 10000
```

SSE URL 例: `http://<server-ip>:10000/sse`（クライアント側で `Authorization: Bearer <token>` ヘッダーが必要）

`NETMIKO_MCP_SERVER_BEARER_TOKEN` を設定せずに `--sse` を起動しようとすると、起動時エラーで停止します。認証なしで動かしたい場合のみ `--no-http-auth` を明示的に付けてください（非推奨）。

#### 10.70.72.0/24 以外を遮断する設定
SSE モードでは `--allowed-subnet` で許可サブネットを指定できます（カンマ区切り）。デフォルトは `0.0.0.0/0` です。Bearerトークン認証と併用することで多層防御になります。

```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml \
  --sse --bind 10.70.72.1 --allowed-subnet 10.70.72.0/24,127.0.0.1/32 --port 10000
```

#### 監査ログ
デフォルトで `~/.netmiko_mcp_server_audit.log` にJSON Lines形式で記録されます。パスを変えたい場合は `--audit-log-file /path/to/audit.log` を指定してください。

#### 出力サイズ対策
デフォルトで1000行を超える出力は自動的に `~/.netmiko_mcp_server_outputs/<device>/` 配下に保存され、`list_device_outputs`/`read_device_output` ツールでページングしながら読み出せます。閾値は `--output-save-threshold`、保存先は `--output-dir` で変更できます。

#### グループ実行の並列数
`send_command_to_group` の同時接続数はデフォルト10です。`--max-workers` で変更できます。

#### Docker での起動

**公開イメージを使う（推奨）**

`main` ブランチへのpush、または `v*.*.*` タグのpushをトリガーに、GitHub Actions が GitHub Container Registry (GHCR) にイメージを自動ビルド・公開します（`.github/workflows/ci.yaml` の `publish` ジョブ）。lint・型チェック・テストが全て通った場合のみ公開されます。

```bash
docker pull ghcr.io/nagayon-935/netmiko_mcp_server:latest
```

利用可能なタグ:
| タグ | 内容 |
|---|---|
| `latest` | `main` ブランチの最新コミット |
| `sha-<short-sha>` | 特定コミット時点のビルド（トレーサビリティ用） |
| `v1.2.3` / `1.2` | `v*.*.*` 形式のgitタグをpushした場合のみ生成されるsemverタグ |

対応アーキテクチャ: `linux/amd64`, `linux/arm64`（Raspberry Piやapple silicon上のDocker/Podmanでも動作します）。

> **初回公開時の注意:** GHCRのパッケージはリポジトリが公開でも既定で非公開（Private）になることがあります。`docker pull` が403で失敗する場合は、GitHubの当該リポジトリ → Packages → 対象パッケージの Package settings から Visibility を Public に変更してください。また、Actions が `packages: write` できない場合は Settings → Actions → General → Workflow permissions で "Read and write permissions" が有効か確認してください。

**自分でビルドする場合**

```bash
docker build -t netmiko-mcp-server .
```

次に、デバイス設定ファイルとコマンド許可リストをマウントしてコンテナを起動します（公開イメージを使う場合は `netmiko-mcp-server` を `ghcr.io/nagayon-935/netmiko_mcp_server:latest` に読み替えてください）。

```bash
docker run -d -p 10000:10000 \
  -v $(pwd)/network_devices.toml:/app/config.toml \
  -v $(pwd)/commands.toml:/app/commands.toml \
  -e NETMIKO_MCP_SERVER_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --name netmiko-mcp netmiko-mcp-server \
  --sse --port 10000 --commands-file /app/commands.toml
```

## MCP ツール一覧

| ツール | 説明 |
|---|---|
| `get_network_device_list` | インベントリ内の全デバイス一覧を返す（認証情報は含まない） |
| `send_command_and_get_output` | 単一デバイスにコマンドを送信。`use_textfsm`、`save_output` オプション付き |
| `send_command_to_group` | デバイス名/グループ名/`all` に対してコマンドを並列実行。`use_textfsm`、`save_output` オプション付き |
| `list_device_outputs` | 保存済み出力ファイルの一覧を取得 |
| `read_device_output` | 保存済み出力ファイルをページングして読み出し |
| `set_config_commands_and_commit_or_save` | 設定変更コマンドを送信（`--enable-config` 必須） |

## Gemini CLI での利用 (例)
Gemini CLI の MCP 設定にサーバー情報を登録してください。

```json
{
  "mcpServers": {
    "netmiko server": {
      "url": "http://<server-ip>:10000/sse"
    }
  }
}
```

Bearerトークン認証を有効にしている場合（デフォルト）、クライアント側から `Authorization: Bearer <token>` ヘッダーを送信する設定が別途必要です。ヘッダーの指定方法はAIクライアントごとに異なるため、各クライアントのMCPサーバー設定ドキュメントを確認してください。`--no-http-auth` で認証を無効化した場合は不要です（非推奨）。

## 注意
- `device_type` は `netmiko` のサポート名を指定してください。
- `secret` がある場合は自動で `enable()` を試みます。
- `--commands-file` を指定しない場合、`send_command_and_get_output` は常に拒否されます（デフォルト全拒否）。
- `set_config_commands_and_commit_or_save` は `--enable-config` を付けない限り常に拒否されます。
- `send_command_and_get_output`/`send_command_to_group`（show系）には`allowed_commands`/`denied_commands`が、`set_config_commands_and_commit_or_save`（設定変更）には`config_allowed_commands`/`config_denied_commands`が適用されます。`--commands-file`未指定、または`config_allowed_commands`未指定の場合はそれぞれ全拒否です。
- `shutdown`と`clear*`は設定にかかわらず常に拒否されます（ベースライン保護、詳細は上記「コマンド許可リスト」参照）。それ以外の設定コマンドについては、`config_allowed_commands`の範囲内で信頼できる運用者のみが利用してください。

## 旧バージョンからの移行
以前のバージョンにあった `--secured` フラグと `--disable-config` フラグは廃止されました。
- `--secured`（先頭文字列によるブロックリスト）→ `--commands-file` によるallow/denyリストに置き換え
- `--disable-config`（デフォルト有効・オプトアウト）→ `--enable-config`（デフォルト無効・オプトイン）に置き換え

## License
MIT License. 詳細は [LICENSE](LICENSE) を参照してください。
