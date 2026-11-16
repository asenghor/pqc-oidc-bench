"""Signing keys of the emitter.

Everything here is generated in memory when the process starts and is lost
when it stops. Nothing is read from or written to disk.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import os
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from .catalog import Variant
from .jose import b64url, compact_json

CARRIERS = ("ES256", "RS256")
CERTIFICATE_SUBJECT = "pqc-oidc-bench emitter"
CERTIFICATE_LIFETIME = datetime.timedelta(days=30)


def _uint(value: int, length: int) -> str:
    return b64url(value.to_bytes(length, "big"))


def thumbprint(jwk: dict[str, Any]) -> str:
    """JWK SHA-256 thumbprint (RFC 7638; RFC 9964, Section 6 for AKP keys)."""
    required = {
        "EC": ("crv", "kty", "x", "y"),
        "RSA": ("e", "kty", "n"),
        "AKP": ("alg", "kty", "pub"),
    }[jwk["kty"]]
    canonical = compact_json({name: jwk[name] for name in required})
    return b64url(hashlib.sha256(canonical).digest())


@dataclass
class SigningKey:
    """One classical key pair with its public representations."""

    alg: str
    private_key: Any
    jwk: dict[str, Any]
    kid: str
    certificate_der: bytes
    signature_bytes: int

    def sign(self, signing_input: bytes) -> bytes:
        if self.alg == "ES256":
            der = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            r, s = decode_dss_signature(der)
            half = self.signature_bytes // 2
            return r.to_bytes(half, "big") + s.to_bytes(half, "big")
        return self.private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    @property
    def raw_public_key(self) -> bytes:
        """Public key in the form whose size sizes.yaml records."""
        public = self.private_key.public_key()
        if self.alg == "ES256":
            point = public.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            return point[1:]
        return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)


def generate_signing_key(alg: str, variants: dict[str, Variant]) -> SigningKey:
    if alg == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        numbers = private_key.public_key().public_numbers()
        coordinate_bytes = variants["ES256"].public_key_bytes // 2
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": _uint(numbers.x, coordinate_bytes),
            "y": _uint(numbers.y, coordinate_bytes),
        }
        digest = hashes.SHA256()
    elif alg == "RS256":
        # The modulus length is derived from the signature size in sizes.yaml.
        modulus_bytes = variants["RS256"].signature_bytes
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=modulus_bytes * 8)
        numbers = private_key.public_key().public_numbers()
        exponent_bytes = (numbers.e.bit_length() + 7) // 8
        jwk = {"kty": "RSA", "n": _uint(numbers.n, modulus_bytes), "e": _uint(numbers.e, exponent_bytes)}
        digest = hashes.SHA256()
    else:
        raise ValueError(f"unsupported signing algorithm: {alg}")

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CERTIFICATE_SUBJECT)])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + CERTIFICATE_LIFETIME)
        .sign(private_key, digest)
    )
    return SigningKey(
        alg=alg,
        private_key=private_key,
        jwk=jwk,
        kid=thumbprint(jwk),
        certificate_der=certificate.public_bytes(serialization.Encoding.DER),
        signature_bytes=variants[alg].signature_bytes,
    )


def x5c_entry(certificate_der: bytes) -> str:
    """One element of the x5c array: standard base64, with padding (RFC 7515, Section 4.1.6)."""
    return base64.b64encode(certificate_der).decode("ascii")


class Keyring:
    """Keys served by the emitter: real classical keys and sized placeholders."""

    def __init__(self, variants: dict[str, Variant]) -> None:
        self._variants = variants
        # Index 0 of each classical algorithm is the active signing key.
        self._classical: dict[str, list[SigningKey]] = {alg: [generate_signing_key(alg, variants)] for alg in CARRIERS}
        self._placeholders: dict[tuple[str, int], dict[str, Any]] = {}

    def signing_key(self, alg: str) -> SigningKey:
        return self._classical[alg][0]

    def _classical_jwk(self, alg: str, index: int) -> dict[str, Any]:
        keys = self._classical[alg]
        while len(keys) <= index:
            keys.append(generate_signing_key(alg, self._variants))
        key = keys[index]
        return {**key.jwk, "kid": key.kid, "use": "sig", "alg": alg}

    def _placeholder_jwk(self, variant: Variant, index: int) -> dict[str, Any]:
        """AKP key of the exact public key size, filled with random bytes.

        It cannot verify anything: it only gives the JWKS document the size it
        would have with real keys of that variant.
        """
        cached = self._placeholders.get((variant.name, index))
        if cached is None:
            jwk = {"kty": "AKP", "alg": variant.jose_alg, "pub": b64url(os.urandom(variant.public_key_bytes))}
            cached = {**jwk, "kid": thumbprint(jwk), "use": "sig"}
            self._placeholders[(variant.name, index)] = cached
        return cached

    def jwks(self, counts: dict[str, int]) -> dict[str, Any]:
        """JWK Set with `counts[variant]` keys per variant, stable across calls."""
        keys = []
        for name, count in counts.items():
            variant = self._variants[name]
            for index in range(count):
                if variant.classical:
                    keys.append(self._classical_jwk(name, index))
                else:
                    keys.append(self._placeholder_jwk(variant, index))
        return {"keys": keys}
