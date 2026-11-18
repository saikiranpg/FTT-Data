"""TTL is exact, expired drops are unreadable at once, and their files are deleted from disk."""
import time

import pytest

from conftest import drop_dir, run
from ftt_client import build_drop, create, open_drop, upload
from storage import QUOTA_KEY


@pytest.mark.parametrize("ttl", [180, 300, 600, 3600, 37 * 60])
def test_ttl_is_exact_once_upload_completes(client, settings, backend, ttl):
    drop = build_drop(b"x", settings.chunk_size)
    upload(client, drop, ttl=ttl)
    pttl = backend.sync.pttl(f"drop:{drop.id}")
    assert ttl * 1000 - 1000 < pttl <= ttl * 1000


def test_open_reports_remaining_lifetime(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    upload(client, drop, ttl=600)
    remaining = open_drop(client, drop.id, drop.auth_token).json()["expires_in_ms"]
    assert 599_000 < remaining <= 600_000


def test_unfinished_upload_lives_only_for_the_upload_window(client, settings, backend):
    drop = build_drop(b"x", settings.chunk_size)
    create(client, drop, ttl=180)
    pttl = backend.sync.pttl(f"drop:{drop.id}")
    assert settings.upload_window * 1000 - 1000 < pttl <= settings.upload_window * 1000


@pytest.mark.parametrize("ttl", [59, 3601, 0, -5])
def test_ttl_outside_bounds_rejected(make_client, ttl):
    client = make_client(ttl_min=60, ttl_max=3600)
    assert create(client, build_drop(b"x", 1024), ttl=ttl).status_code == 422


def test_expired_drop_is_unreadable_and_its_files_are_deleted(client, settings, backend):
    drop = build_drop(b"short-lived", settings.chunk_size)
    upload(client, drop, ttl=1)
    assert open_drop(client, drop.id, drop.auth_token).status_code == 200

    time.sleep(1.1)
    assert open_drop(client, drop.id, drop.auth_token).status_code == 404  # unreadable the instant TTL ends

    assert run(client, client.app.state.store.sweep) == 1
    assert not drop_dir(client, drop.id).exists()
    assert not backend.sync.hexists(QUOTA_KEY, drop.id)  # disk quota released


def test_background_sweeper_deletes_expired_files_unprompted(make_client):
    client = make_client(sweep_interval=0.05)
    drop = build_drop(b"bye", 1024)
    upload(client, drop, ttl=1)
    assert drop_dir(client, drop.id).exists()

    deadline = time.monotonic() + 3
    while drop_dir(client, drop.id).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not drop_dir(client, drop.id).exists()


def test_startup_sweep_removes_orphans_from_a_previous_run(make_settings, make_client):
    orphan = make_settings().data_dir / "ABCDEF"
    orphan.mkdir(parents=True)
    (orphan / "00000.bin").write_bytes(b"left over ciphertext")
    make_client()  # Redis has no record of ABCDEF, so startup deletes it
    assert not orphan.exists()
