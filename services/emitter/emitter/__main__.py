"""Entry point: serves the emitter over HTTPS only."""

from __future__ import annotations

import os
import sys

import uvicorn

from .app import create_app


def main() -> None:
    certificate = os.environ.get("TLS_CERT_FILE")
    key = os.environ.get("TLS_KEY_FILE")
    if not certificate or not key:
        sys.exit("TLS_CERT_FILE and TLS_KEY_FILE are required: the bench has no plain HTTP listener.")
    uvicorn.run(
        create_app(),
        host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("LISTEN_PORT", "8443")),
        ssl_certfile=certificate,
        ssl_keyfile=key,
        access_log=False,  # request lines can carry tokens
        server_header=False,
    )


if __name__ == "__main__":
    main()
