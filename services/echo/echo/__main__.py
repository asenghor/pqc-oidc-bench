"""Entry point: serves the echo backend over HTTPS only."""

from __future__ import annotations

import logging
import os
import sys

import uvicorn

from .app import create_app

# Bench setting, not a product limit: the witness must accept more than any
# intermediary placed in front of it, otherwise it would be the component
# that rejects. Left unset, the h11 parser used by uvicorn keeps its own
# default (DEFAULT_MAX_INCOMPLETE_EVENT_SIZE, 16 KiB in h11 0.16.0).
MAX_REQUEST_HEAD_BYTES = 16 * 1024 * 1024


def main() -> None:
    certificate = os.environ.get("TLS_CERT_FILE")
    key = os.environ.get("TLS_KEY_FILE")
    if not certificate or not key:
        sys.exit("TLS_CERT_FILE and TLS_KEY_FILE are required: the bench has no plain HTTP listener.")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    uvicorn.run(
        create_app(),
        host=os.environ.get("LISTEN_HOST", "0.0.0.0"),
        port=int(os.environ.get("LISTEN_PORT", "8443")),
        ssl_certfile=certificate,
        ssl_keyfile=key,
        http="h11",
        h11_max_incomplete_event_size=MAX_REQUEST_HEAD_BYTES,
        access_log=False,  # request lines can carry tokens
        server_header=False,
    )


if __name__ == "__main__":
    main()
