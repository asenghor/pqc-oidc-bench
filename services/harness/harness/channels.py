"""Transport channels: where a token travels in an HTTP request."""

from __future__ import annotations

from dataclasses import dataclass, field

CHANNELS = ("authorization", "dpop", "cookie", "query", "form_post")
WATCHED_HEADERS = ("authorization", "dpop", "cookie")
MAX_CHAIN_LENGTH = 2  # the /via/<name>/ routing of the proxies handles one extra hop


@dataclass(frozen=True)
class Request:
    """One request, exactly as the harness sends it."""

    method: str
    target: str
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""
    # Value sent in each watched header, to compare with what the echo received.
    watched: dict[str, str] = field(default_factory=dict)
    # Bytes carried by the channel: the token-bearing values.
    channel_bytes: int = 0


def entry_point(chain: tuple[str, ...]) -> str:
    """Component the harness connects to."""
    return chain[0] if chain else "echo"


def path(chain: tuple[str, ...]) -> str:
    if len(chain) > MAX_CHAIN_LENGTH:
        raise ValueError(f"a chain holds at most {MAX_CHAIN_LENGTH} intermediaries")
    return f"/via/{chain[1]}/bench" if len(chain) == MAX_CHAIN_LENGTH else "/bench"


def build(
    channel: str, token: str, chain: tuple[str, ...], lab_key: str, request_id: str, proof: str = ""
) -> Request:
    """Request carrying `token` on `channel` through `chain`.

    `proof` is the DPoP proof, only used by the dpop channel. The request
    identifier and the lab key come first so that an intermediary reads them
    before any oversized header.
    """
    headers = [("X-Request-Id", request_id), ("X-Lab-Key", lab_key)]
    target, method, body, watched = path(chain), "GET", b"", {}
    if channel == "authorization":
        watched["authorization"] = f"Bearer {token}"
    elif channel == "dpop":
        watched["authorization"] = f"DPoP {token}"
        watched["dpop"] = proof
    elif channel == "cookie":
        watched["cookie"] = f"session={token}"
    elif channel == "query":
        target += f"?id_token_hint={token}"
    elif channel == "form_post":
        method = "POST"
        body = f"id_token={token}".encode("ascii")
        headers.append(("Content-Type", "application/x-www-form-urlencoded"))
    else:
        raise ValueError(f"unknown channel: {channel}")
    names = {"authorization": "Authorization", "dpop": "DPoP", "cookie": "Cookie"}
    headers.extend((names[name], value) for name, value in watched.items())
    channel_bytes = sum(len(value) for value in watched.values()) or len(token)
    return Request(method, target, tuple(headers), body, watched, channel_bytes)
