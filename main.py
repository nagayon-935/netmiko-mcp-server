import argparse
import ipaddress
import logging
import os
from typing import Any

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Mount

import inventory
import output_store
import server
from audit import configure_audit_logger
from credential_crypto import KEY_ENV_VAR, encrypt_value, generate_key
from http_auth import BearerTokenMiddleware
from security import (
    load_command_policy,
    load_config_command_policy,
    validate_command_lists,
)

logger = logging.getLogger("netmiko-mcp-server")
logging.basicConfig(level=logging.INFO)


BEARER_TOKEN_ENV_VAR = "NETMIKO_MCP_SERVER_BEARER_TOKEN"


def main() -> None:
    desc = "netmiko-mcp-server"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        "--enable-config",
        action="store_true",
        help="allow the set_config_commands_and_commit_or_save tool (disabled by default)",
    )
    parser.add_argument(
        "--commands-file",
        type=str,
        default=None,
        help=(
            "path to a TOML file with allowed_commands/denied_commands. "
            "Without this, ALL commands are denied by default."
        ),
    )
    parser.add_argument(
        "--audit-log-file",
        type=str,
        default="~/.netmiko_mcp_server_audit.log",
        help="path to the JSON audit log file",
    )
    parser.add_argument(
        "--sse", action="store_true", help="run as an SSE server (default stdio)"
    )
    parser.add_argument(
        "--port", type=int, default=10000, help="port number for SSE server"
    )
    parser.add_argument(
        "--bind",
        type=str,
        default="0.0.0.0",
        help="bind address for SSE server",
    )
    parser.add_argument(
        "--allowed-subnet",
        type=str,
        default="0.0.0.0/0",
        help=(
            "allow client and bind addresses only from these subnets (SSE only). "
            "comma-separated, e.g. 10.70.72.0/24,127.0.0.1/32"
        ),
    )
    parser.add_argument(
        "--no-http-auth",
        action="store_true",
        help=(
            "disable bearer token authentication for the SSE server (INSECURE, "
            f"SSE only). Without this flag, {BEARER_TOKEN_ENV_VAR} must be set "
            "in the environment."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable starlette debug mode for SSE server",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=output_store.DEFAULT_OUTPUT_DIR,
        help="directory for saved command output files",
    )
    parser.add_argument(
        "--output-save-threshold",
        type=int,
        default=1000,
        help="line count above which output is auto-saved instead of returned inline",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=10,
        help="max concurrent connections for send_command_to_group",
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help=f"print a new {KEY_ENV_VAR} value and exit (does not start the server)",
    )
    parser.add_argument(
        "--encrypt-value",
        type=str,
        default=None,
        metavar="VALUE",
        help=(
            f"encrypt VALUE using {KEY_ENV_VAR} from the environment, print the "
            "result, and exit (does not start the server)"
        ),
    )

    parser.add_argument(
        "tomlpath", nargs="?", default=None, help="path to config toml file"
    )

    args = parser.parse_args()

    if args.generate_key:
        print(generate_key())
        return

    if args.encrypt_value is not None:
        key = os.environ.get(KEY_ENV_VAR, "").strip()
        if not key:
            raise SystemExit(
                f"Startup Error: {KEY_ENV_VAR} must be set to encrypt a value."
            )
        print(encrypt_value(args.encrypt_value, key))
        return

    if args.tomlpath is None:
        parser.error(
            "tomlpath is required unless --generate-key or --encrypt-value is used"
        )

    inventory.tomlpath = args.tomlpath
    server.enable_config = args.enable_config
    server.output_save_threshold = args.output_save_threshold
    server.max_workers = args.max_workers
    output_store.output_dir = args.output_dir

    server.command_policy = load_command_policy(args.commands_file)
    server.config_command_policy = load_config_command_policy(args.commands_file)
    policy_errors = validate_command_lists(
        server.command_policy
    ) + validate_command_lists(server.config_command_policy)
    if policy_errors:
        raise SystemExit("Startup Error: " + " ".join(policy_errors))
    if args.commands_file is None:
        logger.warning(
            "no --commands-file specified: ALL commands will be denied by default"
        )

    configure_audit_logger(args.audit_log_file)

    inventory.load_config_toml()

    if args.sse:
        allowed_subnets = [
            ipaddress.ip_network(item.strip(), strict=False)
            for item in args.allowed_subnet.split(",")
            if item.strip()
        ]
        bind_ip = ipaddress.ip_address(args.bind)
        if not any(bind_ip in net for net in allowed_subnets):
            raise SystemExit(
                f"--bind {args.bind} is not inside --allowed-subnet {args.allowed_subnet}"
            )

        sse_app = server.mcp.sse_app()

        @sse_app.middleware("http")
        async def restrict_subnet(request, call_next):
            client_host = request.client.host if request.client else ""
            try:
                client_ip = ipaddress.ip_address(client_host)
            except ValueError:
                return PlainTextResponse("Forbidden", status_code=403)
            if not any(client_ip in net for net in allowed_subnets):
                return PlainTextResponse("Forbidden", status_code=403)
            return await call_next(request)

        app: Any = Starlette(debug=args.debug, routes=[Mount("/", app=sse_app)])

        if not args.no_http_auth:
            token = os.environ.get(BEARER_TOKEN_ENV_VAR, "").strip()
            if not token:
                raise SystemExit(
                    f"Startup Error: {BEARER_TOKEN_ENV_VAR} must be set in the "
                    "environment when running --sse. Use --no-http-auth to run "
                    "without authentication (not recommended)."
                )
            app = BearerTokenMiddleware(app, token)

        import uvicorn

        uvicorn.run(app, host=args.bind, port=args.port)
    else:
        server.mcp.run()


if __name__ == "__main__":
    main()
