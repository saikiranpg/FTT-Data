"""Oversized payloads and the disk cap are refused cleanly, leaving nothing behind."""
import os

from conftest import drop_dir
from ftt_client import build_drop, create, download, put_chunk, upload


def _no_partial_files(client, drop_id):
    return not any(p.name.endswith(".part") for p in drop_dir(client, drop_id).iterdir())


def test_drop_larger_than_file_limit_rejected(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    r = create(client, drop, chunks=settings.max_chunks, size=settings.max_drop_bytes + 1)
    assert r.status_code == 413


def test_too_many_chunks_rejected(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    r = create(client, drop, chunks=settings.max_chunks + 1, size=(settings.max_chunks + 1) * 100)
    assert r.status_code == 413


def test_declared_size_must_fit_chunk_count(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    r = create(client, drop, chunks=1, size=settings.max_chunk_bytes + 1)
    assert r.status_code == 422


def test_create_body_size_is_capped(client):
    r = client.post("/api/drops", content=b"{" + b" " * 20_000 + b"}", headers={"Content-Type": "application/json"})
    assert r.status_code == 413


def test_oversized_chunk_rejected_by_content_length(client, settings):
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    token = create(client, drop).json()["upload_token"]
    r = put_chunk(client, drop, 0, token, body=b"x" * (settings.max_chunk_bytes + 1))
    assert r.status_code == 413
    assert _no_partial_files(client, drop.id)
    assert put_chunk(client, drop, 0, token).status_code == 204  # the slot is still free


def test_oversized_chunk_rejected_while_streaming(client, settings):
    """No Content-Length (chunked transfer encoding): the server counts bytes as they arrive."""
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    token = create(client, drop).json()["upload_token"]
    pieces = iter([b"x" * 600, b"x" * 600])  # 1200 > max_chunk_bytes (1052)
    r = client.put(f"/api/drops/{drop.id}/chunks/0", content=pieces, headers={"X-Upload-Token": token})
    assert r.status_code == 413
    assert _no_partial_files(client, drop.id)
    assert not (drop_dir(client, drop.id) / "00000.bin").exists()


def test_chunks_cannot_exceed_declared_total(client, settings):
    drop = build_drop(b"small", settings.chunk_size)  # declares a 33-byte drop
    token = create(client, drop).json()["upload_token"]
    r = put_chunk(client, drop, 0, token, body=os.urandom(drop.size + 1))
    assert r.status_code == 413


def test_disk_cap_returns_507_then_recovers(make_client):
    client = make_client(disk_cap_bytes=5000)
    first = build_drop(os.urandom(3000), 1024)
    second = build_drop(os.urandom(3000), 1024)
    upload(client, first, burn=True)

    r = create(client, second)
    assert r.status_code == 507
    assert "full" in r.json()["detail"]

    download(client, first, claim=True)  # burning the first drop releases its reservation
    upload(client, second)
