"""Loading of the declarative bench inputs: sizes and payload profiles."""

from __future__ import annotations

import base64
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

HEADER_VARIANTS = ("kid", "jwk", "x5c")
CLASSICAL = "classical"


class CatalogError(ValueError):
    """Raised when sizes.yaml or a profile is malformed."""


def bench_dir() -> Path:
    """Directory holding sizes.yaml and profiles/ (BENCH_DIR, else the repository)."""
    configured = os.environ.get("BENCH_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "bench"


@dataclass(frozen=True)
class Variant:
    name: str
    family: str
    jose_alg: str
    jwk_kty: str
    signature_bytes: int
    signature_length: str
    public_key_bytes: int
    status: str
    source: str
    jose_source: str

    @property
    def classical(self) -> bool:
        return self.family == CLASSICAL


def load_variants(path: Path | None = None) -> dict[str, Variant]:
    path = path or bench_dir() / "sizes.yaml"
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    variants: dict[str, Variant] = {}
    for row in document["variants"]:
        try:
            variant = Variant(
                name=row["name"],
                family=row["family"],
                jose_alg=row["jose_alg"],
                jwk_kty=row["jwk_kty"],
                signature_bytes=row["signature_bytes"],
                signature_length=row["signature_length"],
                public_key_bytes=row["public_key_bytes"],
                status=row["status"],
                source=row["source"].strip(),
                jose_source=row["jose_source"].strip(),
            )
        except KeyError as missing:
            raise CatalogError(f"{path.name}: {row.get('name', '?')}: missing field {missing}") from None
        for size in (variant.signature_bytes, variant.public_key_bytes):
            if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
                raise CatalogError(f"{path.name}: {variant.name}: sizes must be positive integers")
        if variant.signature_length not in ("fixed", "maximum"):
            raise CatalogError(f"{path.name}: {variant.name}: signature_length must be fixed or maximum")
        if variant.status not in ("final", "draft"):
            raise CatalogError(f"{path.name}: {variant.name}: status must be final or draft")
        if not variant.source or not variant.jose_source:
            raise CatalogError(f"{path.name}: {variant.name}: a source reference is mandatory")
        if variant.name in variants:
            raise CatalogError(f"{path.name}: duplicate variant {variant.name}")
        variants[variant.name] = variant
    return variants


@dataclass(frozen=True)
class Profile:
    name: str
    typ: str
    embed_jwk: bool
    claims: dict[str, Any] = field(default_factory=dict)
    dynamic: dict[str, str] = field(default_factory=dict)

    def render(self, issuer: str, now: int | None = None) -> dict[str, Any]:
        """Claims set for one issuance: static claims, then computed ones."""
        now = int(time.time()) if now is None else now
        claims = dict(self.claims)
        for claim, rule in self.dynamic.items():
            claims[claim] = _generate(rule, issuer, now)
        return claims


def _generate(rule: str, issuer: str, now: int) -> Any:
    if rule == "issuer":
        return issuer
    if rule == "now":
        return now
    if rule.startswith("now+"):
        return now + int(rule[4:])
    if rule == "uuid":
        return str(uuid.uuid4())
    if rule.startswith("random:"):
        return base64.urlsafe_b64encode(os.urandom(int(rule[7:]))).rstrip(b"=").decode()
    raise CatalogError(f"unknown dynamic claim rule: {rule}")


def load_profiles(directory: Path | None = None) -> dict[str, Profile]:
    directory = directory or bench_dir() / "profiles"
    profiles: dict[str, Profile] = {}
    for path in sorted(directory.glob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if document["name"] != path.stem:
            raise CatalogError(f"{path.name}: name must equal the file name")
        profile = Profile(
            name=document["name"],
            typ=document["header"]["typ"],
            embed_jwk=bool(document["header"].get("embed_jwk", False)),
            claims=document.get("claims") or {},
            dynamic=document.get("dynamic") or {},
        )
        for rule in profile.dynamic.values():
            _generate(rule, "https://issuer.invalid", 0)
        profiles[profile.name] = profile
    return profiles
