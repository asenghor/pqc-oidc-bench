from __future__ import annotations

import pytest
from emitter.app import Settings, create_app
from fastapi.testclient import TestClient

CLIENT_ID = "test-resource-server"
CLIENT_SECRET = "test-only-secret-without-value"


@pytest.fixture(scope="session")
def app():
    settings = Settings(introspection_client_id=CLIENT_ID, introspection_client_secret=CLIENT_SECRET)
    return create_app(settings)


@pytest.fixture(scope="session")
def client(app):
    return TestClient(app)


@pytest.fixture(scope="session")
def keyring(app):
    return app.state.keyring


@pytest.fixture(scope="session")
def variants(app):
    return app.state.variants


@pytest.fixture(scope="session")
def profiles(app):
    return app.state.profiles
