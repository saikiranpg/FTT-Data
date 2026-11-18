"""Shared fixtures: the app wired to an isolated Redis and a temporary data directory.

Redis is fakeredis by default (no services needed). To run the suite against a real Redis, set
TEST_REDIS_URL=redis://localhost:6379/15 — that database is FLUSHED before every test, so point
it at a scratch DB.
"""
from __future__ import annotations

import os
from contextlib import ExitStack
from dataclasses import replace

import fakeredis
import pytest
import redis
import redis.asyncio as aioredis
from fastapi.testclient import TestClient

from config import Settings
from main import create_app

KiB = 1024

# Small limits keep the suite fast. test_flow.py::test_production_defaults covers the real values.
TEST_SETTINGS = Settings(
    chunk_size=1 * KiB,
    max_text_bytes=1 * KiB,
    max_file_bytes=10 * KiB,
    disk_cap_bytes=256 * KiB,
    ttl_min=1,
    rate_create=10_000,
    rate_open=10_000,
    rate_chunk=10_000,
    sweep_interval=3600,  # tests trigger sweeps explicitly unless they opt in
)


class RedisBackend:
    """Hands out async clients for the app and a sync client for inspecting what was stored."""

    def __init__(self) -> None:
        url = os.environ.get("TEST_REDIS_URL")
        if url:
            self.sync = redis.Redis.from_url(url)
            self.sync.flushdb()
            self._new = lambda: aioredis.from_url(url, decode_responses=True)
        else:
            server = fakeredis.FakeServer()
            self.sync = fakeredis.FakeRedis(server=server)
            self._new = lambda: fakeredis.FakeAsyncRedis(server=server, decode_responses=True)

    def new_async(self):
        return self._new()


@pytest.fixture
def backend() -> RedisBackend:
    return RedisBackend()


@pytest.fixture
def make_settings(tmp_path):
    def make(**overrides) -> Settings:
        return replace(TEST_SETTINGS, data_dir=tmp_path / "drops", **overrides)

    return make


@pytest.fixture
def make_client(make_settings, backend):
    """Factory for a running app (lifespan entered) with optional setting overrides."""
    with ExitStack() as stack:

        def make(peer: tuple[str, int] = ("testclient", 50000), **overrides) -> TestClient:
            app = create_app(make_settings(**overrides), redis=backend.new_async())
            return stack.enter_context(TestClient(app, client=peer))

        yield make


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client()


@pytest.fixture
def settings(client) -> Settings:
    return client.app.state.settings


def drop_dir(client: TestClient, drop_id: str):
    return client.app.state.settings.data_dir / drop_id


def run(client: TestClient, fn, *args):
    """Run an async store method on the app's own event loop."""
    return client.portal.call(fn, *args)
