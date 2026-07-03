"""RFC 6750 bearer token authentication middleware for the SSE transport.

Every incoming HTTP request must carry `Authorization: Bearer <token>`.
Requests missing the header, using the wrong scheme, or carrying the wrong
token receive an HTTP 401 with a WWW-Authenticate: Bearer header per RFC 6750.

Token comparison uses hmac.compare_digest to avoid timing side-channel
attacks. Non-HTTP ASGI scopes (lifespan, etc.) pass through unchecked.
"""

import hmac

from starlette.types import ASGIApp, Receive, Scope, Send


class BearerTokenMiddleware:
    def __init__(self, app: ASGIApp, token: str) -> None:
        self._app = app
        self._token_bytes = token.encode("utf-8")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and not self._is_authorized(scope):
            await self._send_401(send)
            return
        await self._app(scope, receive, send)

    def _is_authorized(self, scope: Scope) -> bool:
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        for name, value in headers:
            if name.lower() == b"authorization":
                auth = value.decode("latin-1")
                if auth[:7].lower() == "bearer ":
                    candidate = auth[7:].encode("utf-8")
                    return hmac.compare_digest(candidate, self._token_bytes)
                return False
        return False

    async def _send_401(self, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"www-authenticate", b'Bearer realm="netmiko-mcp-server"'),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error": "Unauthorized"}',
                "more_body": False,
            }
        )
