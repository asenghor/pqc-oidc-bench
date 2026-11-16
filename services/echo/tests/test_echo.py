"""Witness backend: exact lengths and digests, shared key, silent logs."""

from __future__ import annotations

import base64
import hashlib
import logging

import pytest
from echo.app import LAB_KEY_LENGTH, create_app, load_lab_key
from fastapi.testclient import TestClient

LAB_KEY = "k" * LAB_KEY_LENGTH  # worthless test key
# Token-shaped marker, assembled here so that no credential-like literal is versioned.
TOKEN = ".".join((base64.urlsafe_b64encode(b'{"alg":"ES256"}').decode(), "S3cr3tPayload" * 40, "signature"))


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(LAB_KEY))


def measure(value: bytes) -> dict:
    return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def test_reports_length_and_digest_of_watched_headers_line_and_body(client):
    authorization = f"Bearer {TOKEN}"
    dpop = "proof." + "p" * 300
    cookie = "session=" + "c" * 500
    body = b"token=" + TOKEN.encode()
    response = client.post(
        f"/resource/1?id_token_hint={TOKEN}",
        content=body,
        headers={"X-Lab-Key": LAB_KEY, "Authorization": authorization, "DPoP": dpop, "Cookie": cookie, "X-Request-Id": "run-1.42"},
    )
    assert response.status_code == 200
    assert response.headers["x-hop-echo"] == "1"
    report = response.json()

    assert report["service"] == "echo" and report["request_id"] == "run-1.42" and report["method"] == "POST"
    assert report["watched_headers"]["authorization"] == {"count": 1, "values": [measure(authorization.encode())]}
    assert report["watched_headers"]["dpop"] == {"count": 1, "values": [measure(dpop.encode())]}
    assert report["watched_headers"]["cookie"] == {"count": 1, "values": [measure(cookie.encode())]}
    target = f"/resource/1?id_token_hint={TOKEN}".encode()
    assert report["target"] == measure(target)
    assert report["request_line"] == measure(b"POST " + target + b" HTTP/1.1")
    assert report["body"] == measure(body)
    assert report["lab_key_length"] == LAB_KEY_LENGTH

    received = {header["name"]: header["length"] for header in report["headers"]}
    assert received["authorization"] == len(authorization)
    assert received["x-lab-key"] == LAB_KEY_LENGTH
    # Nothing but names and lengths comes back.
    assert TOKEN not in response.text and LAB_KEY not in response.text


def test_absent_and_truncated_headers_are_visible(client):
    report = client.get("/", headers={"X-Lab-Key": LAB_KEY, "Authorization": f"Bearer {TOKEN[:100]}"}).json()
    assert report["watched_headers"]["dpop"] == {"count": 0, "values": []}
    assert report["watched_headers"]["cookie"] == {"count": 0, "values": []}
    truncated = report["watched_headers"]["authorization"]["values"][0]
    assert truncated["length"] == len("Bearer ") + 100
    assert truncated["sha256"] != hashlib.sha256(f"Bearer {TOKEN}".encode()).hexdigest()
    assert report["body"] == measure(b"")
    assert report["request_id"] == "-"


def test_repeated_header_is_reported_per_occurrence(client):
    headers = [("X-Lab-Key", LAB_KEY), ("Cookie", "a=1"), ("Cookie", "b=22")]
    report = client.get("/", headers=headers).json()
    assert report["watched_headers"]["cookie"] == {"count": 2, "values": [measure(b"a=1"), measure(b"b=22")]}


@pytest.mark.parametrize("method", ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_every_method_and_path_is_served(client, method):
    response = client.request(method, "/any/depth/of/path", headers={"X-Lab-Key": LAB_KEY})
    assert response.status_code == 200 and response.json()["method"] == method


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"X-Lab-Key": "x" * LAB_KEY_LENGTH},
        {"X-Lab-Key": LAB_KEY[:-1]},
        {"X-Lab-Key": LAB_KEY + "k"},
    ],
)
def test_lab_key_is_required(client, headers):
    response = client.get("/resource", headers={**headers, "Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 401
    assert response.json() == {"service": "echo", "error": "lab_key_required"}
    assert response.headers["x-hop-echo"] == "1"


def test_healthz_needs_no_key(client):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_logs_carry_no_token_no_key_no_target(client, caplog):
    caplog.set_level(logging.DEBUG)
    headers = {"X-Lab-Key": LAB_KEY, "Authorization": f"Bearer {TOKEN}", "DPoP": TOKEN, "Cookie": f"s={TOKEN}"}
    client.post(f"/logout?id_token_hint={TOKEN}", content=TOKEN, headers={**headers, "X-Request-Id": TOKEN})
    client.get(f"/?t={TOKEN}", headers={"Authorization": f"Bearer {TOKEN}"})
    # Everything the server side logged; the test's own HTTP client is not the service.
    records = [record for record in caplog.records if not record.name.startswith("httpx")]
    assert sum(record.name == "echo" for record in records) == 2
    logged = "\n".join(record.getMessage() for record in records)
    for fragment in (TOKEN, "S3cr3tPayload", LAB_KEY, "id_token_hint", "logout"):
        assert fragment not in logged


def test_lab_key_of_wrong_length_is_refused_at_startup(monkeypatch, tmp_path):
    with pytest.raises(RuntimeError):
        create_app("short")
    monkeypatch.delenv("LAB_KEY_FILE", raising=False)
    monkeypatch.setenv("LAB_KEY", "short")
    with pytest.raises(RuntimeError):
        load_lab_key()
    key_file = tmp_path / "lab-key"
    key_file.write_text(LAB_KEY + "\n", encoding="ascii")
    monkeypatch.setenv("LAB_KEY_FILE", str(key_file))
    assert load_lab_key() == LAB_KEY
