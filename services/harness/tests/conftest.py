"""In-process stand-in for the stack: real echo and emitter, simulated hops."""

from __future__ import annotations

import pytest
from echo.app import LAB_KEY_LENGTH
from echo.app import create_app as create_echo
from emitter.app import create_app as create_emitter
from fastapi.testclient import TestClient
from harness.client import Emitter, Transport
from harness.runner import Context

LAB_KEY = "k" * LAB_KEY_LENGTH  # worthless test key


class FakeHop:
    """Minimal reverse proxy following the hop conventions of the bench.

    limit     refuse any header value longer than this many bytes
    tagged    whether a refusal carries the X-Hop header ("origin")
    truncate  silently cut the Authorization header to this many bytes
    drop      silently remove this header
    """

    def __init__(self, name, network, limit=None, tagged=True, truncate=None, drop=None):
        self.name, self.network = name, network
        self.limit, self.tagged, self.truncate, self.drop = limit, tagged, truncate, drop

    async def __call__(self, scope, receive, send):
        headers = scope["headers"]
        if self.limit is not None and any(len(value) > self.limit for _, value in headers):
            tag = [(f"x-hop-{self.name}".encode(), b"origin")] if self.tagged else []
            await send({"type": "http.response.start", "status": 431, "headers": tag})
            await send({"type": "http.response.body", "body": b"too large"})
            return
        if self.truncate is not None:
            headers = [(n, v[: self.truncate] if n == b"authorization" else v) for n, v in headers]
        if self.drop is not None:
            headers = [(n, v) for n, v in headers if n != self.drop.encode()]

        parts = scope["path"].split("/")
        next_name = parts[2] if len(parts) > 2 and parts[1] == "via" and parts[2] != self.name else "echo"

        async def tagging_send(message):
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message["headers"], (f"x-hop-{self.name}".encode(), b"proxied")]}
            await send(message)

        await self.network.apps[next_name]({**scope, "headers": headers}, receive, tagging_send)


class FakeNetwork:
    """Dispatches on the Host header, as service names do in the Compose network."""

    def __init__(self):
        self.apps = {"echo": create_echo(LAB_KEY), "emitter": create_emitter()}

    def add(self, name, **behaviour):
        self.apps[name] = FakeHop(name, self, **behaviour)
        return self

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                await send({"type": message["type"] + ".complete"})
                if message["type"] == "lifespan.shutdown":
                    return
        host = dict(scope["headers"])[b"host"].decode().split(":")[0]
        await self.apps[host](scope, receive, send)

    def context(self) -> Context:
        def factory(http_version):
            return TestClient(self)

        return Context(Transport(factory), Emitter(factory), LAB_KEY, run_id="testrun")


@pytest.fixture
def network():
    return FakeNetwork().add("alpha").add("beta")
