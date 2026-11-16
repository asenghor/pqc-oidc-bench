"""HTTP surface of the emitter."""

from __future__ import annotations

import base64
import json

import jwt
import pytest

from .conftest import CLIENT_ID, CLIENT_SECRET

BASIC = (CLIENT_ID, CLIENT_SECRET)


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_token_accepts_json(client, variants):
    response = client.post("/token", json={"variant": "ML-DSA-65", "profile": "access_token_rfc9068", "header": "jwk"})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["calibrated"] is True and body["signed_with"] == "ES256"
    assert body["length"] == len(body["token"]) == body["target_length"]
    assert body["padding_bytes"] > variants["ML-DSA-65"].signature_bytes - variants["ES256"].signature_bytes


def test_token_accepts_form_and_carrier(client, keyring):
    response = client.post("/token", data={"variant": "FN-DSA-512", "profile": "id_token_minimal", "carrier": "RS256"})
    body = response.json()
    assert response.status_code == 200 and body["signed_with"] == "RS256" and body["header"] == "kid"
    public_key = keyring.signing_key("RS256").private_key.public_key()
    claims = jwt.decode(body["token"], public_key, algorithms=["RS256"], audience="bench-client")
    assert claims["iss"] == "https://emitter.bench.test"


def test_token_native_classical(client):
    body = client.post("/token", json={"variant": "ES256", "profile": "id_token_minimal"}).json()
    assert body["calibrated"] is False and body["padding_bytes"] == 0 and body["length"] == body["target_length"]


@pytest.mark.parametrize(
    ("parameters", "status", "error"),
    [
        ({"variant": "ML-DSA-65", "profile": "id_token_minimal", "mode": "real"}, 501, "real_mode_disabled"),
        ({"variant": "ML-DSA-65", "profile": "id_token_minimal", "mode": "other"}, 400, "invalid_request"),
        ({"variant": "ML-DSA-99", "profile": "id_token_minimal"}, 400, "invalid_request"),
        ({"variant": "ML-DSA-65", "profile": "unknown"}, 400, "invalid_request"),
        ({"variant": "ML-DSA-65", "profile": "id_token_minimal", "header": "x5u"}, 400, "invalid_request"),
        ({"variant": "ML-DSA-65", "profile": "id_token_minimal", "format": "jwe"}, 400, "invalid_request"),
        ({"variant": "ML-DSA-65", "profile": "id_token_minimal", "carrier": "HS256"}, 422, "calibration_failed"),
        ({"variant": "ES256", "profile": "id_token_minimal", "carrier": "RS256"}, 422, "calibration_failed"),
    ],
)
def test_token_errors(client, parameters, status, error):
    response = client.post("/token", json=parameters)
    assert response.status_code == status
    assert response.json()["error"] == error


def test_token_rejects_repeated_and_malformed_parameters(client):
    form = {"content-type": "application/x-www-form-urlencoded"}
    assert client.post("/token", content="variant=ES256&variant=RS256", headers=form).status_code == 400
    assert client.post("/token", content="[1]", headers={"content-type": "application/json"}).status_code == 400
    assert client.post("/token", content="{", headers={"content-type": "application/json"}).status_code == 400


def test_jwks_default_serves_the_verification_keys(client, keyring):
    response = client.get("/jwks")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/jwk-set+json"
    assert "cache-control" not in response.headers
    keys = response.json()["keys"]
    assert [key["alg"] for key in keys] == ["ES256", "RS256"]
    assert [key["kid"] for key in keys] == [keyring.signing_key(alg).kid for alg in ("ES256", "RS256")]
    assert all("d" not in key and "priv" not in key for key in keys)


def test_jwks_key_counts_and_sizes(client, variants):
    response = client.get("/jwks", params={"keys": "ES256:2,ML-DSA-65:3,FN-DSA-1024:1,RS256:0"})
    keys = response.json()["keys"]
    assert [key["alg"] for key in keys] == ["ES256"] * 2 + ["ML-DSA-65"] * 3 + ["FN-DSA-1024"]
    assert len({key["kid"] for key in keys}) == len(keys)
    for key in keys:
        if key["kty"] == "AKP":
            pub = base64.urlsafe_b64decode(key["pub"] + "=" * (-len(key["pub"]) % 4))
            assert len(pub) == variants[key["alg"]].public_key_bytes
    # A rotation scenario must be reproducible: same request, same document.
    assert client.get("/jwks", params={"keys": "ES256:2,ML-DSA-65:3,FN-DSA-1024:1,RS256:0"}).content == response.content


def test_jwks_cache_control(client):
    response = client.get("/jwks", params={"cache_control": "public, max-age=300"})
    assert response.headers["cache-control"] == "public, max-age=300"
    assert client.get("/jwks", params={"cache_control": "bad\r\nvalue"}).status_code == 400


@pytest.mark.parametrize("keys", ["ML-DSA-99:1", "ES256:x", "ES256:17", "ES256"])
def test_jwks_rejects_bad_key_spec(client, keys):
    assert client.get("/jwks", params={"keys": keys}).status_code == 400


def test_reference_token_and_introspection(client):
    issued = client.post("/token", json={"profile": "access_token_loaded", "format": "reference"}).json()
    assert issued["format"] == "reference" and issued["length"] == len(issued["token"])
    assert "." not in issued["token"]

    active = client.post("/introspect", data={"token": issued["token"]}, auth=BASIC)
    assert active.status_code == 200 and active.headers["cache-control"] == "no-store"
    body = active.json()
    assert body["active"] is True and body["client_id"] == "bench-client" and len(body["groups"]) == 20

    unknown = client.post("/introspect", data={"token": "not-issued-here"}, auth=BASIC)
    assert unknown.json() == {"active": False}
    assert client.post("/introspect", data={}, auth=BASIC).status_code == 400


def test_introspection_requires_client_authentication(client):
    assert client.post("/introspect", data={"token": "x"}).status_code == 401
    wrong = client.post("/introspect", data={"token": "x"}, auth=(CLIENT_ID, "wrong"))
    assert wrong.status_code == 401 and wrong.headers["www-authenticate"].startswith("Basic")
    assert client.post("/introspect", data={"token": "x"}, headers={"authorization": "Basic !!!"}).status_code == 401


def test_par(client):
    request_object = "e30." + "A" * 6000 + ".sig"
    response = client.post("/par", data={"client_id": "bench-client", "request": request_object})
    assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:") and body["expires_in"] > 0
    assert set(body) == {"request_uri", "expires_in"}

    assert client.post("/par", data={"request": request_object}).status_code == 400
    refused = client.post("/par", data={"client_id": "bench-client", "request_uri": "urn:example:x"})
    assert refused.status_code == 400 and json.loads(refused.content)["error"] == "invalid_request"
