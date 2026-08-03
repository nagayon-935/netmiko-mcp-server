import ipaddress

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Mount, Route
from starlette.testclient import TestClient

import server
from http_auth import BearerTokenMiddleware


def _build_test_app(allowed_subnet="127.0.0.1/32"):
    server.mcp._session_manager = None
    allowed_subnets = [
        ipaddress.ip_network(item.strip(), strict=False)
        for item in allowed_subnet.split(",")
        if item.strip()
    ]

    sse_app = server.mcp.sse_app()
    http_app = server.mcp.streamable_http_app()

    sse_endpoint = sse_app.routes[0].endpoint
    messages_app = sse_app.routes[1].app
    http_endpoint = http_app.routes[0].endpoint

    routes = [
        Route("/sse", endpoint=sse_endpoint, methods=["GET", "HEAD"]),
        Route("/sse", endpoint=http_endpoint, methods=["POST"]),
        Route("/mcp", endpoint=http_endpoint),
        Route("/", endpoint=http_endpoint, methods=["POST"]),
        Route("/", endpoint=sse_endpoint, methods=["GET", "HEAD"]),
        Mount("/messages", app=messages_app),
    ]

    async def restrict_subnet(request, call_next):
        client_host = request.client.host if request.client else ""
        try:
            client_ip = ipaddress.ip_address(client_host)
        except ValueError:
            return PlainTextResponse("Forbidden", status_code=403)
        if not any(client_ip in net for net in allowed_subnets):
            return PlainTextResponse("Forbidden", status_code=403)
        return await call_next(request)

    starlette_app = server.mcp.sse_app()  # dummy placeholder reference
    from starlette.applications import Starlette

    starlette_app = Starlette(
        debug=True,
        routes=routes,
        middleware=[Middleware(BaseHTTPMiddleware, dispatch=restrict_subnet)],
        lifespan=http_app.router.lifespan_context,
    )
    return starlette_app


def test_post_sse_accepts_initialize():
    app = _build_test_app()
    headers = {
        "host": "127.0.0.1:10000",
        "accept": "application/json, text/event-stream",
    }
    with TestClient(
        app, base_url="http://127.0.0.1:10000", client=("127.0.0.1", 50000), headers=headers
    ) as client:
        res = client.post(
            "/sse",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                    "protocolVersion": "2024-11-05",
                },
            },
        )
        assert res.status_code == 200


def test_post_mcp_accepts_initialize():
    app = _build_test_app()
    headers = {
        "host": "127.0.0.1:10000",
        "accept": "application/json, text/event-stream",
    }
    with TestClient(
        app, base_url="http://127.0.0.1:10000", client=("127.0.0.1", 50000), headers=headers
    ) as client:
        res = client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                    "protocolVersion": "2024-11-05",
                },
            },
        )
        assert res.status_code == 200


def test_post_root_accepts_initialize():
    app = _build_test_app()
    headers = {
        "host": "127.0.0.1:10000",
        "accept": "application/json, text/event-stream",
    }
    with TestClient(
        app, base_url="http://127.0.0.1:10000", client=("127.0.0.1", 50000), headers=headers
    ) as client:
        res = client.post(
            "/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                    "protocolVersion": "2024-11-05",
                },
            },
        )
        assert res.status_code == 200


def test_subnet_restriction_blocks_disallowed_ip():
    app = _build_test_app(allowed_subnet="127.0.0.1/32")
    headers = {
        "host": "127.0.0.1:10000",
        "accept": "application/json, text/event-stream",
    }
    with TestClient(
        app, base_url="http://127.0.0.1:10000", client=("10.0.0.1", 50000), headers=headers
    ) as client:
        res = client.post("/sse")
        assert res.status_code == 403


def test_http_auth_middleware_integration():
    # Without token -> 401
    app1 = _build_test_app()
    auth_app1 = BearerTokenMiddleware(app1, "secret-token")
    with TestClient(
        auth_app1,
        base_url="http://127.0.0.1:10000",
        client=("127.0.0.1", 50000),
    ) as client:
        res = client.post("/sse")
        assert res.status_code == 401

    # With valid token -> 200
    app2 = _build_test_app()
    auth_app2 = BearerTokenMiddleware(app2, "secret-token")
    headers = {
        "host": "127.0.0.1:10000",
        "accept": "application/json, text/event-stream",
        "authorization": "Bearer secret-token",
    }
    with TestClient(
        auth_app2,
        base_url="http://127.0.0.1:10000",
        client=("127.0.0.1", 50000),
        headers=headers,
    ) as client:
        res = client.post(
            "/sse",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1.0"},
                    "protocolVersion": "2024-11-05",
                },
            },
        )
        assert res.status_code == 200
