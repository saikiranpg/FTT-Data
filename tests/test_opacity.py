"""Cipher opacity: nothing the server stores reveals plaintext, metadata or keys."""
import base64
import os

from conftest import drop_dir
from ftt_client import chunk_aad, upload, unseal, build_drop

MARKER = b"TOP-SECRET-PLAINTEXT-MARKER-0123456789"
FILENAME = "quarterly-merger-plans.pdf"


def _everything_redis_holds(sync) -> list[bytes]:
    blobs = []
    for key in sync.keys("*"):
        blobs.append(key)
        kind = sync.type(key)
        if kind == b"hash":
            for field, value in sync.hgetall(key).items():
                blobs += [field, value]
        elif kind == b"string":
            blobs.append(sync.get(key))
    return blobs


def _everything_on_disk(root) -> list[bytes]:
    return [p.read_bytes() for p in root.rglob("*") if p.is_file()] + [p.name.encode() for p in root.rglob("*")]


def test_server_stores_only_ciphertext(client, settings, backend):
    content = MARKER * 60  # several chunks of highly recognisable plaintext
    drop = build_drop(content, settings.chunk_size, name=FILENAME, mime="application/pdf")
    upload(client, drop)

    stored = _everything_redis_holds(backend.sync) + _everything_on_disk(settings.data_dir)
    token_bytes = base64.urlsafe_b64decode(drop.auth_token + "=")
    secrets_that_must_not_appear = {
        "plaintext": MARKER,
        "plaintext prefix": MARKER[:12],
        "file name": FILENAME.encode(),
        "MIME type": b"application/pdf",
        "master key": drop.master,
        "master key (hex)": drop.master.hex().encode(),
        "master key (link fragment)": base64.urlsafe_b64encode(drop.master).rstrip(b"="),
        "encryption key": drop.keys.enc_key,
        "auth token": drop.auth_token.encode(),
        "auth token (raw)": token_bytes,
    }
    for label, needle in secrets_that_must_not_appear.items():
        leaks = [blob for blob in stored if needle in blob]
        assert not leaks, f"{label} found in server storage"

    # Sanity: we inspected the right data — the token's hash *is* stored.
    assert any(drop.keys.auth_hash.encode() in blob for blob in stored)


def test_stored_chunks_are_the_exact_client_ciphertext(client, settings):
    content = os.urandom(settings.chunk_size * 2 + 50)
    drop = build_drop(content, settings.chunk_size)
    upload(client, drop)
    files = sorted(drop_dir(client, drop.id).glob("*.bin"))
    on_disk = [f.read_bytes() for f in files]

    assert on_disk == drop.chunks  # stored byte-for-byte, never transformed
    assert len({blob[:12] for blob in on_disk}) == len(on_disk)  # a fresh IV per chunk
    assert b"".join(
        unseal(drop.keys.enc_key, blob, chunk_aad(drop.id, i, len(on_disk))) for i, blob in enumerate(on_disk)
    ) == content
