"""HTTP API of the emitter: calibrated tokens, JWKS, introspection, PAR."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .calibration import CalibrationError, issue
from .catalog import HEADER_VARIANTS, load_profiles, load_variants
from .keys import Keyring

# Bench settings (not product limits).
REFERENCE_TOKEN_BYTES = 32  # entropy of an opaque token
REFERENCE_TOKEN_LIFETIME = 300  # seconds
PAR_LIFETIME = 60  # seconds a pushed request stays redeemable
STORE_CAPACITY = 10_000  # entries kept per in-memory store
JWKS_MAX_KEYS_PER_VARIANT = 16

PAR_URN_PREFIX = "urn:ietf:params:oauth:request_uri:"  # RFC 9126, Section 2.2
_CACHE_CONTROL = re.compile(r"^[A-Za-z0-9=,\- ]{1,128}$")
_NO_STORE = {"Cache-Control": "no-store"}


@dataclass
class Settings:
    issuer: str = "https://emitter.bench.test"
    jwks_keys: str = "ES256:1,RS256:1"
    jwks_cache_control: str = ""
    introspection_client_id: str = "bench-resource-server"
    # Without a configured secret a random one is drawn: the endpoint stays closed.
    introspection_client_secret: str = field(default_factory=lambda: secrets.token_urlsafe(32))

    @classmethod
    def from_env(cls) -> Settings:
        defaults = cls()
        return cls(
            issuer=os.environ.get("EMITTER_ISSUER", defaults.issuer),
            jwks_keys=os.environ.get("JWKS_KEYS", defaults.jwks_keys),
            jwks_cache_control=os.environ.get("JWKS_CACHE_CONTROL", defaults.jwks_cache_control),
            introspection_client_id=os.environ.get("INTROSPECTION_CLIENT_ID", defaults.introspection_client_id),
            introspection_client_secret=os.environ.get("INTROSPECTION_CLIENT_SECRET")
            or defaults.introspection_client_secret,
        )


class RequestError(Exception):
    def __init__(self, status: int, error: str, description: str) -> None:
        self.status, self.error, self.description = status, error, description


class Store:
    """Bounded in-memory store with expiry. Lost when the process stops."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, Any]] = {}

    def put(self, key: str, value: Any, lifetime: int) -> None:
        while len(self._entries) >= STORE_CAPACITY:
            self._entries.pop(next(iter(self._entries)))
        self._entries[key] = (time.time() + lifetime, value)

    def get(self, key: str) -> Any | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[0] < time.time():
            del self._entries[key]
            return None
        return entry[1]


async def _parameters(request: Request) -> dict[str, str]:
    """Request parameters from a JSON object or a form-encoded body."""
    body = await request.body()
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    try:
        if content_type == "application/json":
            document = json.loads(body or b"{}")
            if not isinstance(document, dict):
                raise ValueError("a JSON object is expected")
            return {str(name): str(value) for name, value in document.items()}
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except ValueError as error:
        raise RequestError(400, "invalid_request", f"unreadable body: {error}") from None
    repeated = sorted(name for name, values in parsed.items() if len(values) > 1)
    if repeated:
        raise RequestError(400, "invalid_request", f"repeated parameter: {repeated[0]}")
    return {name: values[0] for name, values in parsed.items()}


def parse_jwks_keys(spec: str, variants: dict) -> dict[str, int]:
    """Parse `ES256:1,ML-DSA-65:2` into an ordered variant-to-count mapping."""
    counts: dict[str, int] = {}
    for item in filter(None, (part.strip() for part in spec.split(","))):
        name, _, count = item.partition(":")
        if name not in variants:
            raise RequestError(400, "invalid_request", f"unknown variant: {name}")
        if not count.isdigit() or int(count) > JWKS_MAX_KEYS_PER_VARIANT:
            raise RequestError(400, "invalid_request", f"{name}: key count must be 0 to {JWKS_MAX_KEYS_PER_VARIANT}")
        counts[name] = int(count)
    return counts


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    variants = load_variants()
    profiles = load_profiles()
    keyring = Keyring(variants)
    reference_tokens = Store()
    pushed_requests = Store()
    parse_jwks_keys(settings.jwks_keys, variants)

    app = FastAPI(title="pqc-oidc-bench emitter", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.keyring = keyring
    app.state.variants = variants
    app.state.profiles = profiles
    app.state.settings = settings

    @app.exception_handler(RequestError)
    async def request_error(_: Request, error: RequestError) -> JSONResponse:
        headers = dict(_NO_STORE)
        if error.status == 401:
            headers["WWW-Authenticate"] = 'Basic realm="introspection"'
        return JSONResponse(
            {"error": error.error, "error_description": error.description}, status_code=error.status, headers=headers
        )

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/token")
    async def token(request: Request) -> JSONResponse:
        parameters = await _parameters(request)
        mode = parameters.get("mode", "calibrated")
        if mode == "real":
            raise RequestError(501, "real_mode_disabled", "real ML-DSA signatures are disabled and not implemented")
        if mode != "calibrated":
            raise RequestError(400, "invalid_request", "mode must be calibrated")
        profile = profiles.get(parameters.get("profile", ""))
        if profile is None:
            raise RequestError(400, "invalid_request", f"profile must be one of: {', '.join(profiles)}")

        token_format = parameters.get("format", "jws")
        if token_format == "reference":
            handle = secrets.token_urlsafe(REFERENCE_TOKEN_BYTES)
            reference_tokens.put(handle, profile.render(settings.issuer), REFERENCE_TOKEN_LIFETIME)
            body = {"token": handle, "format": "reference", "profile": profile.name, "length": len(handle)}
            return JSONResponse(body, headers=_NO_STORE)
        if token_format != "jws":
            raise RequestError(400, "invalid_request", "format must be jws or reference")

        variant = variants.get(parameters.get("variant", ""))
        if variant is None:
            raise RequestError(400, "invalid_request", f"variant must be one of: {', '.join(variants)}")
        header_variant = parameters.get("header", "kid")
        if header_variant not in HEADER_VARIANTS:
            raise RequestError(400, "invalid_request", f"header must be one of: {', '.join(HEADER_VARIANTS)}")
        try:
            issued = issue(variant, profile, header_variant, keyring, settings.issuer, parameters.get("carrier"))
        except CalibrationError as error:
            raise RequestError(422, "calibration_failed", str(error)) from None
        body = {
            "token": issued.token,
            "format": "jws",
            "variant": issued.variant,
            "profile": issued.profile,
            "header": issued.header_variant,
            "signed_with": issued.signed_with,
            "calibrated": issued.calibrated,
            "length": issued.length,
            "target_length": issued.target_length,
            "padding_bytes": issued.padding_bytes,
        }
        return JSONResponse(body, headers=_NO_STORE)

    @app.get("/jwks")
    async def jwks(keys: str | None = None, cache_control: str | None = None) -> JSONResponse:
        counts = parse_jwks_keys(settings.jwks_keys if keys is None else keys, variants)
        directive = settings.jwks_cache_control if cache_control is None else cache_control
        headers = {}
        if directive:
            if not _CACHE_CONTROL.fullmatch(directive):
                raise RequestError(400, "invalid_request", "cache_control contains unsupported characters")
            headers["Cache-Control"] = directive
        return JSONResponse(keyring.jwks(counts), media_type="application/jwk-set+json", headers=headers)

    def _authenticate(request: Request) -> None:
        scheme, _, encoded = request.headers.get("authorization", "").partition(" ")
        try:
            client_id, _, client_secret = base64.b64decode(encoded, validate=True).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            client_id = client_secret = ""
        valid = (
            scheme.lower() == "basic"
            and hmac.compare_digest(client_id.encode(), settings.introspection_client_id.encode())
            and hmac.compare_digest(client_secret.encode(), settings.introspection_client_secret.encode())
        )
        if not valid:
            raise RequestError(401, "invalid_client", "client authentication failed")

    @app.post("/introspect")
    async def introspect(request: Request) -> JSONResponse:
        """RFC 7662, Section 2. Only the reference tokens issued here are active."""
        _authenticate(request)
        parameters = await _parameters(request)
        if "token" not in parameters:
            raise RequestError(400, "invalid_request", "token is required")
        claims = reference_tokens.get(parameters["token"])
        if claims is None:
            return JSONResponse({"active": False}, headers=_NO_STORE)
        return JSONResponse({"active": True, "token_type": "Bearer", **claims}, headers=_NO_STORE)

    @app.post("/par")
    async def pushed_authorization_request(request: Request) -> JSONResponse:
        """RFC 9126, Section 2, for public clients: stores the request, returns its reference."""
        parameters = await _parameters(request)
        if not parameters.get("client_id"):
            raise RequestError(400, "invalid_request", "client_id is required")
        if "request_uri" in parameters:
            raise RequestError(400, "invalid_request", "request_uri must not be provided")
        request_uri = PAR_URN_PREFIX + secrets.token_urlsafe(REFERENCE_TOKEN_BYTES)
        pushed_requests.put(request_uri, parameters, PAR_LIFETIME)
        body = {"request_uri": request_uri, "expires_in": PAR_LIFETIME}
        return JSONResponse(body, status_code=201, headers=_NO_STORE)

    return app
