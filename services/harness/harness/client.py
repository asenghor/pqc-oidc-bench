"""HTTP client side of the harness: sending requests, asking for tokens."""

from __future__ import annotations

import os
import ssl
import time
from collections.abc import Callable
from typing import Any

import hpack
import httpx2

from .channels import Request, entry_point
from .verdict import Observation

HTTP_VERSIONS = ("1.1", "2")
TIMEOUT_SECONDS = 15.0  # bench setting
_HOP_PREFIX = "x-hop-"

ClientFactory = Callable[[str], Any]


def base_url(component: str) -> str:
    """Where a component is reached: HARNESS_TARGET_<NAME>, else its service name."""
    override = os.environ.get(f"HARNESS_TARGET_{component.upper().replace('-', '_')}")
    return (override or f"https://{component}:8443").rstrip("/")


def send_http2_header_values_as_raw_literals() -> None:
    """Make the HTTP/2 client skip Huffman coding of header values.

    The HPACK encoder used by the client library is pure Python and its
    Huffman coding takes quadratic time: a header value of a megabyte keeps
    the harness busy for minutes before a single byte is sent. Raw literals
    are valid HPACK (RFC 7541, Section 5.2) and decode to the same value; only
    the size of the HEADERS frame on the wire differs.
    """
    original = hpack.Encoder.encode
    if getattr(original, "raw_literals", False):
        return

    def encode(self: hpack.Encoder, headers: Any, huffman: bool = False) -> bytes:
        return original(self, headers, huffman=False)

    encode.raw_literals = True  # type: ignore[attr-defined]
    hpack.Encoder.encode = encode  # type: ignore[method-assign]


def tls_client_factory(ca_file: str) -> ClientFactory:
    """Clients that only trust the bench certificate authority."""
    send_http2_header_values_as_raw_literals()
    context = ssl.create_default_context(cafile=ca_file)

    def factory(http_version: str) -> httpx2.Client:
        # "2" offers both protocols: a component without HTTP/2 answers in
        # HTTP/1.1, and the version actually used is recorded with the result.
        return httpx2.Client(
            verify=context,
            http1=True,
            http2=http_version == "2",
            trust_env=False,
            timeout=TIMEOUT_SECONDS,
        )

    return factory


class Transport:
    """Sends one request on a fresh connection and reports what came back."""

    def __init__(self, client_factory: ClientFactory) -> None:
        self._client_factory = client_factory

    def send(self, request: Request, chain: tuple[str, ...], http_version: str = "1.1") -> Observation:
        if http_version not in HTTP_VERSIONS:
            raise ValueError(f"unknown HTTP version: {http_version}")
        url = base_url(entry_point(chain)) + request.target
        started = time.perf_counter()
        try:
            with self._client_factory(http_version) as client:
                response = client.request(
                    request.method, url, headers=list(request.headers), content=request.body or None
                )
        except httpx2.HTTPError as error:
            elapsed = (time.perf_counter() - started) * 1000
            return Observation(error=type(error).__name__, latency_ms=elapsed)
        elapsed = (time.perf_counter() - started) * 1000
        hops = {
            name[len(_HOP_PREFIX):]: value
            for name, value in response.headers.multi_items()
            if name.lower().startswith(_HOP_PREFIX)
        }
        try:
            report = response.json()
        except ValueError:
            report = None
        return Observation(
            status=response.status_code,
            http_version=response.http_version.removeprefix("HTTP/"),
            hops={name.lower(): value for name, value in hops.items()},
            report=report if isinstance(report, dict) else None,
            latency_ms=elapsed,
        )


class Emitter:
    """Client of the emitter's POST /token, with a per-run cache."""

    def __init__(self, client_factory: ClientFactory) -> None:
        self._client_factory = client_factory
        self._cache: dict[tuple[str, str, str], dict[str, Any]] = {}

    def token(self, variant: str, profile: str, header_variant: str) -> dict[str, Any]:
        key = (variant, profile, header_variant)
        if key not in self._cache:
            parameters = {"variant": variant, "profile": profile, "header": header_variant}
            with self._client_factory("1.1") as client:
                response = client.post(base_url("emitter") + "/token", json=parameters)
            response.raise_for_status()
            self._cache[key] = response.json()
        return self._cache[key]
