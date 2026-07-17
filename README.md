English | [日本語](README.ja.md)

# netmiko-mcp-server

An MCP server for operating network devices through chat. It uses `netmiko` for SSH / Telnet connectivity and supports `enable` passwords.

> **Warning:** This tool sends commands directly to network devices. Configuration-change tools are disabled by default, and even show-style commands are all denied unless a commands file is supplied. Always verify behavior in a lab environment before connecting to production devices.

## Features
- SSH / Telnet support
- `enable` password (`secret`) support
- SSH public-key authentication (`use_keys`, `key_file`) support
- MCP stdio / SSE modes
- Commands are denied by default; only commands explicitly allowed by the allow/deny lists in `commands.toml` can run
- The configuration-change tool (`set_config_commands_and_commit_or_save`) is disabled by default; enable it explicitly with `--enable-config`
- SSE mode requires Bearer token authentication (can be explicitly disabled with `--no-http-auth`, not recommended)
- Every command attempt and connection result is recorded to a JSON audit log (fail-closed: the operation itself fails if the log write fails)
- Large output is automatically saved to a file and can be read back with paging (keeps the LLM's context from being overwhelmed)
- Parallel command execution across multiple devices grouped via `[groups]`
- Structured (JSON) output via ntc-templates with `use_textfsm=True`
- Inventory `password`/`secret` values can be stored encrypted (Fernet symmetric encryption)
- `import_inventory.py` lets you build or append to the inventory interactively (no LLM tokens needed, with per-field validation)

## Usage

### 1. Define devices (TOML)
Edit `network_devices.toml` to define `[default]` and individual devices.

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

#### Build the inventory interactively (import_inventory.py)

Instead of editing the TOML by hand, you can build or append to the inventory with an interactive script.

```bash
uv run python import_inventory.py                  # default: network_devices.toml
uv run python import_inventory.py -f my_devices.toml
```

- Prompts for each field (device name, hostname/IP with IPv4/IPv6/FQDN support, device_type from netmiko's platform list, etc.) with validation and re-prompting on invalid input. A wrong `device_type` shows partial-match suggestions. Enter `q` at the device-name prompt to finish and move to the save/confirm step.
- If the target file already exists, choose **append / overwrite / abort**. Append mode preserves existing comments, key order, and already-encrypted (`enc:`) values untouched. Overwrite mode creates a `<filename>.bak` backup first.
- Entering group names (comma-separated) per device automatically updates the `[groups]` table.
- If `NETMIKO_MCP_SERVER_INVENTORY_KEY` is set, `password`/`secret` are encrypted automatically before saving (see [Encrypting credentials](#4-encrypting-credentials-optional)). If it isn't set, you can choose to save in plaintext or abort.
- The file is written atomically with owner-only permissions (0600), and the saved file is round-trip verified through the inventory loader after writing.
- Out of scope: editing/deleting existing devices, creating the `[default]` section, and prompting for `pre_commands` / `ansi_escape_codes` / timeout fields (edit these by hand). Note that in append mode, if an existing `[groups]` table is at the end of the file, new device tables are appended after it — this is still valid TOML and loads correctly.

### 2. Command allowlist (TOML)

Create `commands.toml` to explicitly list the commands the LLM is allowed to run. **If this file is not provided, every command is denied.**

```toml
allowed_commands = [
  "show version",
  "show ip interface brief",
  "show ip interface*",   # trailing glob: matches "show ip interface" plus anything after it
  "show ip route *",      # space + glob: "show ip route" alone is not allowed; an argument is required
]

denied_commands = [
  "show running-config",  # deny always wins, even if it also matches allowed_commands
]
```

**Allowlist for configuration-change commands (when using `--enable-config`)**

Adding `config_allowed_commands`/`config_denied_commands` to the same `commands.toml` applies allow/deny checks to each line passed to `set_config_commands_and_commit_or_save` (denied entirely if unset). If even one command in the batch is denied, nothing is sent to the device.

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

In addition, `shutdown` (bringing an interface down) and `clear*` are **always denied** regardless of the above configuration (a hardcoded baseline protection — see `BASELINE_CONFIG_DENIED_COMMANDS` in `security.py`). Listing them in `config_allowed_commands` cannot override this. `no shutdown` (bringing an interface back up) is not on the dangerous side of the operation, so it is not included in the baseline deny list.

### 3. Device groups (optional)

Add a `[groups]` table to `network_devices.toml` to run commands in parallel across a set of devices with `send_command_to_group`.

```toml
[groups]
core_switches = ["switch_ssh", "c1200coreSW"]
```

Use `all` instead of a group name to target every device in the inventory.

### 4. Encrypting credentials (optional)

If plaintext passwords in the TOML file are a concern, `password`/`secret` can be encrypted.

```bash
# 1. Generate a key and set it as an environment variable (the server needs the same key at startup)
export NETMIKO_MCP_SERVER_INVENTORY_KEY=$(uv run --with cryptography main.py --generate-key)

# 2. Encrypt the password and paste the result into the TOML file
uv run --with cryptography main.py --encrypt-value "mypassword"
# => enc:gAAAAA...
```

```toml
[router1]
hostname = "192.0.2.10"
device_type = "cisco_ios"
password = "enc:gAAAAA..."
```

If `NETMIKO_MCP_SERVER_INVENTORY_KEY` is not set while an encrypted value is being loaded, the server fails at startup. Keep the key out of the TOML file and manage it only through the environment variable.

### 5. Starting the server

#### stdio (local)
```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml
```

Add `--enable-config` if you also want to use the configuration-change tool (disabled by default).

#### SSE (for remote connections)
SSE mode requires Bearer token authentication. First set the token as an environment variable.

```bash
export NETMIKO_MCP_SERVER_BEARER_TOKEN="$(openssl rand -hex 32)"
```

```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml \
  --sse --bind 10.70.72.1 --port 10000
```

Example SSE URL: `http://<server-ip>:10000/sse` (the client must send an `Authorization: Bearer <token>` header)

Starting `--sse` without `NETMIKO_MCP_SERVER_BEARER_TOKEN` set stops the server with a startup error. Only pass `--no-http-auth` explicitly if you want to run without authentication (not recommended).

#### Restricting access to a specific subnet (e.g. 10.70.72.0/24)
In SSE mode, `--allowed-subnet` lets you specify allowed subnets (comma-separated). The default is `0.0.0.0/0`. Combining this with Bearer token authentication provides defense in depth.

```bash
uv run --with "mcp[cli]" --with netmiko --with uvicorn main.py /path/to/devices.toml \
  --commands-file /path/to/commands.toml \
  --sse --bind 10.70.72.1 --allowed-subnet 10.70.72.0/24,127.0.0.1/32 --port 10000
```

#### Audit log
By default, entries are recorded in JSON Lines format at `~/.netmiko_mcp_server_audit.log`. Use `--audit-log-file /path/to/audit.log` to change the path.

#### Handling large output
By default, output exceeding 1000 lines is automatically saved under `~/.netmiko_mcp_server_outputs/<device>/` and can be read back with paging via the `list_device_outputs`/`read_device_output` tools. The threshold is configurable with `--output-save-threshold`, and the save location with `--output-dir`.

#### Parallelism for group execution
`send_command_to_group` defaults to 10 concurrent connections. Change this with `--max-workers`.

#### Running with Docker

**Use the published image (recommended)**

GitHub Actions automatically builds and publishes an image to the GitHub Container Registry (GHCR) on every push to `main` or on `v*.*.*` tag pushes (the `publish` job in `.github/workflows/ci.yaml`). The image is only published once lint, type-check, and tests all pass.

```bash
docker pull ghcr.io/nagayon-935/netmiko_mcp_server:latest
```

Available tags:
| Tag | Meaning |
|---|---|
| `latest` | latest commit on the `main` branch |
| `sha-<short-sha>` | build for a specific commit (for traceability) |
| `v1.2.3` / `1.2` | semver tags, generated only when a `v*.*.*` git tag is pushed |

Supported architectures: `linux/amd64`, `linux/arm64` (also works with Docker/Podman on a Raspberry Pi or Apple Silicon).

> **Note for first-time publishing:** GHCR packages can default to Private even when the repository is public. If `docker pull` fails with a 403, go to the repository's GitHub page → Packages → the package's Package settings, and change Visibility to Public. Also check that Actions has `packages: write` permission under Settings → Actions → General → Workflow permissions ("Read and write permissions" must be enabled).

**Building it yourself**

```bash
docker build -t netmiko-mcp-server .
```

Then mount the device config file and the command allowlist and start the container (replace `netmiko-mcp-server` with `ghcr.io/nagayon-935/netmiko_mcp_server:latest` if you're using the published image).

```bash
docker run -d -p 10000:10000 \
  -v $(pwd)/network_devices.toml:/app/config.toml \
  -v $(pwd)/commands.toml:/app/commands.toml \
  -e NETMIKO_MCP_SERVER_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --name netmiko-mcp netmiko-mcp-server \
  --sse --port 10000 --commands-file /app/commands.toml
```

## MCP tools

| Tool | Description |
|---|---|
| `get_network_device_list` | Returns the list of all devices in the inventory (no credentials included) |
| `send_command_and_get_output` | Sends a command to a single device, with `use_textfsm` and `save_output` options |
| `send_command_to_group` | Runs a command in parallel across a device name, group name, or `all`, with `use_textfsm` and `save_output` options |
| `list_device_outputs` | Lists saved output files |
| `read_device_output` | Reads a saved output file with paging |
| `set_config_commands_and_commit_or_save` | Sends configuration-change commands (requires `--enable-config`) |

## Using it from the Gemini CLI (example)
Register the server in the Gemini CLI's MCP configuration.

```json
{
  "mcpServers": {
    "netmiko server": {
      "url": "http://<server-ip>:10000/sse"
    }
  }
}
```

If Bearer token authentication is enabled (the default), the client also needs to be configured to send an `Authorization: Bearer <token>` header. How to set headers varies by AI client, so check your client's MCP server configuration documentation. This is not needed if authentication was disabled with `--no-http-auth` (not recommended).

## Notes
- Set `device_type` to a name supported by `netmiko`.
- If `secret` is set, `enable()` is attempted automatically.
- Without `--commands-file`, `send_command_and_get_output` is always denied (deny-by-default).
- `set_config_commands_and_commit_or_save` is always denied unless `--enable-config` is passed.
- `send_command_and_get_output`/`send_command_to_group` (show-style commands) are governed by `allowed_commands`/`denied_commands`; `set_config_commands_and_commit_or_save` (configuration changes) is governed by `config_allowed_commands`/`config_denied_commands`. Everything is denied if `--commands-file` (or `config_allowed_commands`) is not set.
- `shutdown` and `clear*` are always denied regardless of configuration (baseline protection; see "Command allowlist" above for details). For other configuration commands, only trusted operators should use them, and only within the scope of `config_allowed_commands`.

## Migrating from older versions
The `--secured` and `--disable-config` flags from earlier versions have been removed.
- `--secured` (prefix-based blocklist) → replaced by the allow/deny list in `--commands-file`
- `--disable-config` (enabled by default, opt-out) → replaced by `--enable-config` (disabled by default, opt-in)

## License
MIT License. See [LICENSE](LICENSE) for details.
