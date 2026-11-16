"""Minimal JOSE helpers: base64url, compact JSON, length arithmetic."""

from __future__ import annotations

import base64
import json
from typing import Any


def b64url(data: bytes) -> str:
    """Base64url without padding (RFC 7515, Section 2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_length(byte_count: int) -> int:
    """Length of the unpadded base64url encoding of `byte_count` bytes."""
    return (4 * byte_count + 2) // 3


def compact_json(value: Any) -> bytes:
    """UTF-8 JSON without insignificant whitespace, members in insertion order."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
