# netmiko-mcp-server (lab)

研究室内のNW機器をチャット形式で操作するためのMCPサーバーです。`netmiko` を使って SSH / Telnet に対応し、`enable` パスワードにも対応します。

## 特徴
- SSH / Telnet 両対応
- `enable` パスワード (`secret`) 対応
- SSH公開鍵認証 (`use_keys`, `key_file`) 対応
- MCP stdio / SSE モード

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

### 2. サーバー起動

#### stdio (ローカル)
```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml
```

#### SSE (リモート接続向け)
```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml --sse --bind 10.70.72.1 --port 10000
```

SSE URL 例: `http://<server-ip>:10000/sse`

#### 10.70.72.0/24 以外を遮断する設定
SSE モードでは `--allowed-subnet` で許可サブネットを指定できます（カンマ区切り）。デフォルトは `0.0.0.0/0` です。

```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml --sse --bind 10.70.72.1 --allowed-subnet 10.70.72.0/24,127.0.0.1/32 --port 10000
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
- `--secured` を付けると破壊的コマンドをブロックします。
