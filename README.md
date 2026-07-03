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

### 3. サーバー起動

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

#### Docker での起動
まず、イメージをビルドします。

```bash
docker build -t netmiko-mcp-server .
```

次に、デバイス設定ファイルとコマンド許可リストをマウントしてコンテナを起動します。

```bash
docker run -d -p 10000:10000 \
  -v $(pwd)/network_devices.toml:/app/config.toml \
  -v $(pwd)/commands.toml:/app/commands.toml \
  -e NETMIKO_MCP_SERVER_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --name netmiko-mcp netmiko-mcp-server \
  --sse --port 10000 --commands-file /app/commands.toml
```

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

## 注意
- `device_type` は `netmiko` のサポート名を指定してください。
- `secret` がある場合は自動で `enable()` を試みます。
- `--commands-file` を指定しない場合、`send_command_and_get_output` は常に拒否されます（デフォルト全拒否）。
- `set_config_commands_and_commit_or_save` は `--enable-config` を付けない限り常に拒否されます。
- コマンドの許可/拒否リストは現状 `send_command_and_get_output`（show系）のみに適用されます。`--enable-config` で設定変更を有効化した場合、個別コマンドの検証は行われないため、信頼できる運用者のみが利用してください。

## 旧バージョンからの移行
以前のバージョンにあった `--secured` フラグと `--disable-config` フラグは廃止されました。
- `--secured`（先頭文字列によるブロックリスト）→ `--commands-file` によるallow/denyリストに置き換え
- `--disable-config`（デフォルト有効・オプトアウト）→ `--enable-config`（デフォルト無効・オプトイン）に置き換え
