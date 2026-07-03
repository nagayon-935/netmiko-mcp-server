import asyncio

from http_auth import BearerTokenMiddleware


def _http_scope(auth_header: bytes | None) -> dict:
    headers = []
    if auth_header is not None:
        headers.append((b"authorization", auth_header))
    return {"type": "http", "headers": headers}


class _Recorder:
    def __init__(self) -> None:
        self.app_called = False
        self.sent_messages: list[dict] = []

    async def app(self, scope, receive, send) -> None:
        self.app_called = True

    async def send(self, message: dict) -> None:
        self.sent_messages.append(message)


def _run(coro):
    return asyncio.run(coro)


async def _noop_receive() -> dict:
    return {}


def test_valid_token_passes_through():
    recorder = _Recorder()
    middleware = BearerTokenMiddleware(recorder.app, "secret-token")
    scope = _http_scope(b"Bearer secret-token")

    _run(middleware(scope, _noop_receive, recorder.send))

    assert recorder.app_called is True
    assert recorder.sent_messages == []


def test_missing_header_returns_401():
    recorder = _Recorder()
    middleware = BearerTokenMiddleware(recorder.app, "secret-token")
    scope = _http_scope(None)

    _run(middleware(scope, _noop_receive, recorder.send))

    assert recorder.app_called is False
    assert recorder.sent_messages[0]["status"] == 401


def test_wrong_token_returns_401():
    recorder = _Recorder()
    middleware = BearerTokenMiddleware(recorder.app, "secret-token")
    scope = _http_scope(b"Bearer wrong-token")

    _run(middleware(scope, _noop_receive, recorder.send))

    assert recorder.app_called is False
    assert recorder.sent_messages[0]["status"] == 401


def test_wrong_scheme_returns_401():
    recorder = _Recorder()
    middleware = BearerTokenMiddleware(recorder.app, "secret-token")
    scope = _http_scope(b"Basic dXNlcjpwYXNz")

    _run(middleware(scope, _noop_receive, recorder.send))

    assert recorder.app_called is False
    assert recorder.sent_messages[0]["status"] == 401


def test_non_http_scope_passes_through_without_check():
    recorder = _Recorder()
    middleware = BearerTokenMiddleware(recorder.app, "secret-token")
    scope = {"type": "lifespan"}

    _run(middleware(scope, _noop_receive, recorder.send))

    assert recorder.app_called is True
