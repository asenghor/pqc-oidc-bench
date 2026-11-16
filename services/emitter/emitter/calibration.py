"""Calibrated tokens.

A calibrated token is a genuine RS256 or ES256 JWS (the carrier), so relying
parties can verify it, whose total length equals, to the byte, the length of
the equivalent token in the targeted variant. The difference is filled by a
padding claim.

Target model
------------
The equivalent token in the targeted variant is the JWS compact serialization

    BASE64URL(header) "." BASE64URL(payload) "." BASE64URL(signature)

where the payload is the rendered profile, the signature has the size given
by sizes.yaml, and the header is, in this member order:

    alg   the variant's JWS algorithm name
    typ   the profile's type
    jwk   only when the profile embeds the key (DPoP) or for the jwk variant
    kid   kid variant: a JWK SHA-256 thumbprint (same length for any key)
    x5c   x5c variant: one self-signed certificate

For classical variants the key material is the emitter's real key, and the
token is emitted natively: no carrier, no padding. For the other variants the
JWK is an AKP key (RFC 9964, Section 3) whose `pub` has the public key size
of sizes.yaml, and the certificate is the model certificate built by
`model_certificate`.

The x5c model is an approximation, unlike the kid and jwk variants: a real
certificate carries registered algorithm identifiers, possibly parameters and
extensions, and usually comes with its chain.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from typing import Any

from .catalog import HEADER_VARIANTS, Profile, Variant
from .jose import b64url, b64url_length, compact_json
from .keys import CARRIERS, Keyring, x5c_entry

PAD = "pad"
DEFAULT_CARRIER = "ES256"

# Model certificate (x5c variant, non-classical targets). The object
# identifier below is a placeholder, not a registered algorithm: the example
# arc 2.999 followed by seven sub-identifiers equal to 1.
_PLACEHOLDER_OID = bytes([0x88, 0x37, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01])
_OID_COMMON_NAME = bytes([0x55, 0x04, 0x03])
_MODEL_SUBJECT = b"pqc-oidc-bench model"
_MODEL_NOT_BEFORE = b"260101000000Z"
_MODEL_NOT_AFTER = b"270101000000Z"
_MODEL_SERIAL = bytes([0x01] * 16)


class CalibrationError(ValueError):
    """The requested combination cannot be produced."""


def _der(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + content


def model_certificate(variant: Variant) -> bytes:
    """Minimal self-signed X.509 v3 certificate of the variant's key and signature sizes.

    Structure of RFC 5280, Section 4.1, without extensions. The key and the
    signature are zero bytes: only the length of the encoding matters.
    """
    algorithm = _der(0x30, _der(0x06, _PLACEHOLDER_OID))
    name = _der(0x30, _der(0x31, _der(0x30, _der(0x06, _OID_COMMON_NAME) + _der(0x0C, _MODEL_SUBJECT))))
    validity = _der(0x30, _der(0x17, _MODEL_NOT_BEFORE) + _der(0x17, _MODEL_NOT_AFTER))
    public_key = _der(0x30, algorithm + _der(0x03, b"\x00" + bytes(variant.public_key_bytes)))
    version = _der(0xA0, _der(0x02, b"\x02"))
    serial = _der(0x02, _MODEL_SERIAL)
    to_be_signed = _der(0x30, version + serial + algorithm + name + validity + name + public_key)
    signature = _der(0x03, b"\x00" + bytes(variant.signature_bytes))
    return _der(0x30, to_be_signed + algorithm + signature)


def model_jwk(variant: Variant) -> dict[str, Any]:
    """AKP public key of the variant's size (RFC 9964, Section 3)."""
    return {"kty": "AKP", "alg": variant.jose_alg, "pub": b64url(bytes(variant.public_key_bytes))}


def _header(alg: str, profile: Profile, header_variant: str, jwk: dict, kid: str, certificate: bytes) -> dict[str, Any]:
    header: dict[str, Any] = {"alg": alg, "typ": profile.typ}
    if profile.embed_jwk or header_variant == "jwk":
        header["jwk"] = jwk
    if header_variant == "kid":
        header["kid"] = kid
    elif header_variant == "x5c":
        header["x5c"] = [x5c_entry(certificate)]
    return header


def target_header(variant: Variant, profile: Profile, header_variant: str, keyring: Keyring) -> dict[str, Any]:
    """Protected header of the equivalent token in the targeted variant."""
    if variant.classical:
        key = keyring.signing_key(variant.name)
        return _header(variant.jose_alg, profile, header_variant, key.jwk, key.kid, key.certificate_der)
    # A thumbprint has the same length whatever the key: reuse a real one.
    kid = keyring.signing_key(DEFAULT_CARRIER).kid
    return _header(variant.jose_alg, profile, header_variant, model_jwk(variant), kid, model_certificate(variant))


def compact_length(header: dict[str, Any], payload: bytes, signature_bytes: int) -> int:
    return b64url_length(len(compact_json(header))) + 1 + b64url_length(len(payload)) + 1 + b64url_length(signature_bytes)


@dataclass(frozen=True)
class Issued:
    token: str
    variant: str
    profile: str
    header_variant: str
    signed_with: str
    calibrated: bool
    target_length: int
    padding_bytes: int

    @property
    def length(self) -> int:
        return len(self.token)


def _random_text(length: int) -> str:
    """Random base64url characters, as incompressible as JSON text allows."""
    return base64.urlsafe_b64encode(os.urandom(length * 3 // 4 + 3)).decode("ascii")[:length]


def _sign(keyring: Keyring, alg: str, header: dict[str, Any], payload: bytes) -> str:
    signing_input = f"{b64url(compact_json(header))}.{b64url(payload)}".encode("ascii")
    return f"{signing_input.decode('ascii')}.{b64url(keyring.signing_key(alg).sign(signing_input))}"


def issue(
    variant: Variant,
    profile: Profile,
    header_variant: str,
    keyring: Keyring,
    issuer: str,
    carrier: str | None = None,
    now: int | None = None,
) -> Issued:
    """Issue one token for `variant`, natively when classical, calibrated otherwise."""
    if header_variant not in HEADER_VARIANTS:
        raise CalibrationError(f"unknown header variant: {header_variant}")
    claims = profile.render(issuer, now)
    if PAD in claims:
        raise CalibrationError(f"profile {profile.name} already uses the reserved claim '{PAD}'")
    payload = compact_json(claims)
    target = compact_length(target_header(variant, profile, header_variant, keyring), payload, variant.signature_bytes)

    if variant.classical:
        if carrier not in (None, variant.name):
            raise CalibrationError(f"{variant.name} is emitted natively: carrier must be omitted")
        header = target_header(variant, profile, header_variant, keyring)
        token = _sign(keyring, variant.name, header, payload)
        return Issued(token, variant.name, profile.name, header_variant, variant.name, False, target, 0)

    carrier = carrier or DEFAULT_CARRIER
    if carrier not in CARRIERS:
        raise CalibrationError(f"carrier must be one of {', '.join(CARRIERS)}")
    key = keyring.signing_key(carrier)
    base_header = _header(carrier, profile, header_variant, key.jwk, key.kid, key.certificate_der)
    # Base64url length of header plus payload that the padding must reach.
    remaining = target - 2 - b64url_length(key.signature_bytes)

    # An unpadded base64url string never has a length of 1 modulo 4. When the
    # payload would need one, a one-character header parameter shifts the
    # header length to the next residue; verifiers ignore unknown parameters
    # (RFC 7515, Section 4).
    for header in (base_header, {**base_header, PAD: "x"}):
        payload_chars = remaining - b64url_length(len(compact_json(header)))
        if payload_chars % 4 == 1:
            continue
        payload_bytes = payload_chars * 3 // 4
        if payload_bytes == len(payload):
            padded, fill = payload, 0
        else:
            fill = payload_bytes - len(compact_json({**claims, PAD: ""}))
            if fill < 0:
                continue
            padded = compact_json({**claims, PAD: _random_text(fill)})
        token = _sign(keyring, carrier, header, padded)
        if len(token) != target:
            raise CalibrationError(f"internal error: produced {len(token)} characters instead of {target}")
        return Issued(token, variant.name, profile.name, header_variant, carrier, True, target, fill)

    raise CalibrationError(
        f"{variant.name} with profile {profile.name} and header variant {header_variant} "
        f"is too short to be carried by {carrier} (target length {target})"
    )
