"""Witness backend.

For every request, reports what actually arrived: length and SHA-256 of the
watched headers, of the request line and of the body, and the list of the
received headers. The harness compares this report with what it sent, which
is how a silent degradation (truncated or dropped header) is detected.

No header value, target or body is ever logged or echoed back.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

LAB_KEY_HEADER = "x-lab-key"
# Fixed length of the shared bench key, in characters (bench setting). The
# harness counts it in the size of every request it sends.
LAB_KEY_LENGTH = 64
WATCHED_HEADERS = ("authorization", "dpop", "cookie")
REQUEST_ID_HEADER = "x-request-id"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HOP = {"X-Hop-Echo": "1", "Cache-Control": "no-store"}

logger = logging.getLogger("echo")


def _measure(value: bytes) -> dict[str, object]:
    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def load_lab_key() -> str:
    """Shared key from LAB_KEY_FILE or LAB_KEY. Refuses any other length."""
    path = os.environ.get("LAB_KEY_FILE")
    if path:
        with open(path, encoding="ascii") as handle:
            key = handle.read().strip()
    else:
        key = os.environ.get("LAB_KEY", "")
    if len(key) != LAB_KEY_LENGTH:
        raise RuntimeError(f"the lab key must be exactly {LAB_KEY_LENGTH} characters long")
    return key


def create_app(lab_key: str | None = None) -> FastAPI:
    lab_key = load_lab_key() if lab_key is None else lab_key
    if len(lab_key) != LAB_KEY_LENGTH:
        raise RuntimeError(f"the lab key must be exactly {LAB_KEY_LENGTH} characters long")
    expected = lab_key.encode("ascii")

    app = FastAPI(title="pqc-oidc-bench echo", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def echo(request: Request) -> JSONResponse:
        scope = request.scope
        headers: list[tuple[bytes, bytes]] = scope["headers"]
        request_id = request.headers.get(REQUEST_ID_HEADER, "")
        if not _REQUEST_ID.fullmatch(request_id):
            request_id = "-"

        presented = [value for name, value in headers if name == LAB_KEY_HEADER.encode()]
        if len(presented) != 1 or not hmac.compare_digest(presented[0], expected):
            logger.info("request_id=%s method=%s status=401", request_id, request.method)
            return JSONResponse({"service": "echo", "error": "lab_key_required"}, status_code=401, headers=_HOP)

        # Request line as the server parsed it: method, raw target, version.
        target = scope.get("raw_path") or scope["path"].encode("utf-8")
        if scope.get("query_string"):
            target += b"?" + scope["query_string"]
        request_line = b" ".join((request.method.encode("ascii"), target, f"HTTP/{scope['http_version']}".encode()))
        body = await request.body()

        watched = {}
        for watched_name in WATCHED_HEADERS:
            values = [value for name, value in headers if name == watched_name.encode()]
            watched[watched_name] = {"count": len(values), "values": [_measure(value) for value in values]}

        report = {
            "service": "echo",
            "request_id": request_id,
            "method": request.method,
            "http_version": scope["http_version"],
            "request_line": _measure(request_line),
            "target": _measure(target),
            "body": _measure(body),
            "watched_headers": watched,
            "headers": [{"name": name.decode("latin-1"), "length": len(value)} for name, value in headers],
            "lab_key_length": LAB_KEY_LENGTH,
        }
        logger.info(
            "request_id=%s method=%s status=200 request_line_length=%d body_length=%d header_count=%d",
            request_id,
            request.method,
            len(request_line),
            len(body),
            len(headers),
        )
        return JSONResponse(report, headers=_HOP)

    return app
