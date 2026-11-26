from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyLimit:
    """Ограничивает поток до передачи тела в JSON-парсер."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        limit = scope["app"].state.settings.max_request_body_bytes
        headers = Headers(scope=scope)
        if headers.get("content-encoding", "identity").lower() != "identity":
            await JSONResponse({"detail": "Неподдерживаемое кодирование"}, 415)(
                scope, receive, send
            )
            return
        length = headers.get("content-length", "0")
        if not length.isascii() or not length.isdecimal():
            await JSONResponse({"detail": "Некорректный Content-Length"}, 400)(
                scope, receive, send
            )
            return
        digits = length.lstrip("0")
        oversized = len(digits) > len(str(limit)) or int(digits or "0") > limit
        body = bytearray()
        while not oversized:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            oversized = len(body) + len(chunk) > limit
            if not oversized:
                body.extend(chunk)
                if not message.get("more_body", False):
                    break
        if oversized:
            await JSONResponse({"detail": "Превышен размер тела запроса"}, 413)(
                scope, receive, send
            )
            return

        pending = True

        async def replay() -> Message:
            nonlocal pending
            if pending:
                pending = False
                return {"type": "http.request", "body": bytes(body)}
            return await receive()

        await self.app(scope, replay, send)
