"""Calibrated mode: byte-exact length for every cell of the matrix."""

from __future__ import annotations

import base64
import json

import jwt
import pytest
from cryptography import x509
from emitter.calibration import PAD, CalibrationError, issue, model_certificate
from emitter.catalog import HEADER_VARIANTS, load_profiles, load_variants
from emitter.keys import CARRIERS

ISSUER = "https://emitter.bench.test"

# Collected at import time so that every cell is a separate test.
_VARIANTS = load_variants()
_PROFILES = load_profiles()
CELLS = [
    pytest.param(variant, profile, header, carrier, id=f"{variant}/{profile}/{header}/{carrier or 'native'}")
    for variant in _VARIANTS
    for profile in _PROFILES
    for header in HEADER_VARIANTS
    for carrier in ((None,) if _VARIANTS[variant].classical else CARRIERS)
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode(segment: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def _compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def reference_token(variant, profile, header_variant, claims, keyring) -> str:
    """The equivalent token in the targeted variant, built independently of the emitter.

    Key and signature are dummies of the sizes given by sizes.yaml: only the
    length of the result is meaningful.
    """
    header = {"alg": variant.jose_alg, "typ": profile.typ}
    if variant.classical:
        key = keyring.signing_key(variant.name)
        jwk, kid, certificate = key.jwk, key.kid, key.certificate_der
    else:
        jwk = {"kty": "AKP", "alg": variant.jose_alg, "pub": _b64url(b"\0" * variant.public_key_bytes)}
        kid = _b64url(b"\0" * 32)  # a SHA-256 thumbprint
        certificate = model_certificate(variant)
    if profile.embed_jwk or header_variant == "jwk":
        header["jwk"] = jwk
    if header_variant == "kid":
        header["kid"] = kid
    if header_variant == "x5c":
        header["x5c"] = [base64.b64encode(certificate).decode()]
    signature = b"\0" * variant.signature_bytes
    return ".".join(_b64url(part) for part in (_compact(header), _compact(claims), signature))


def test_matrix_covers_every_variant_profile_and_header():
    assert len(_PROFILES) == 4
    assert len(CELLS) == sum(len(_PROFILES) * len(HEADER_VARIANTS) * (1 if v.classical else len(CARRIERS)) for v in _VARIANTS.values())


@pytest.mark.parametrize(("variant_name", "profile_name", "header_variant", "carrier"), CELLS)
def test_length_equals_target_variant_to_the_byte(variant_name, profile_name, header_variant, carrier, keyring):
    variant, profile = _VARIANTS[variant_name], _PROFILES[profile_name]
    issued = issue(variant, profile, header_variant, keyring, ISSUER, carrier)

    header_segment, payload_segment, _ = issued.token.split(".")
    header, claims = _decode(header_segment), _decode(payload_segment)
    original_claims = {name: value for name, value in claims.items() if name != PAD}

    # 1. Byte-exact equality with an independently built token of the variant.
    reference = reference_token(variant, profile, header_variant, original_claims, keyring)
    assert len(issued.token) == len(reference) == issued.target_length

    # 2. The token is a genuine classical JWS that a relying party can verify.
    signed_with = carrier or variant_name
    assert header["alg"] == signed_with == issued.signed_with
    public_key = keyring.signing_key(signed_with).private_key.public_key()
    verified = jwt.decode(issued.token, public_key, algorithms=[signed_with], options={"verify_aud": False, "verify_exp": False})
    assert verified == claims

    # 3. The profile's claims are untouched; only the padding is added.
    assert set(original_claims) == set(profile.claims) | set(profile.dynamic)
    assert issued.calibrated is (not variant.classical)
    assert issued.padding_bytes == len(claims.get(PAD, ""))
    if variant.classical:
        assert PAD not in claims and PAD not in header

    # 4. The header carries what the header variant announces.
    assert (header_variant in header) and header["typ"] == profile.typ
    assert ("jwk" in header) is (profile.embed_jwk or header_variant == "jwk")


def test_padding_is_not_constant(keyring):
    first, second = (
        issue(_VARIANTS["ML-DSA-65"], _PROFILES["id_token_minimal"], "kid", keyring, ISSUER) for _ in range(2)
    )
    assert first.length == second.length
    assert first.token != second.token


@pytest.mark.parametrize("variant_name", [name for name, v in _VARIANTS.items() if not v.classical])
def test_model_certificate_is_well_formed_der(variant_name):
    variant = _VARIANTS[variant_name]
    der = model_certificate(variant)
    certificate = x509.load_der_x509_certificate(der)
    assert certificate.version is x509.Version.v3
    assert certificate.subject == certificate.issuer
    assert len(certificate.signature) == variant.signature_bytes
    assert len(der) > variant.signature_bytes + variant.public_key_bytes


def test_classical_variant_refuses_a_foreign_carrier(keyring):
    with pytest.raises(CalibrationError):
        issue(_VARIANTS["ES256"], _PROFILES["id_token_minimal"], "kid", keyring, ISSUER, carrier="RS256")


def test_unknown_header_variant_is_refused(keyring):
    with pytest.raises(CalibrationError):
        issue(_VARIANTS["ML-DSA-44"], _PROFILES["id_token_minimal"], "x5u", keyring, ISSUER)
