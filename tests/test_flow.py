"""Protocol round trips, invalid-code rejection, upload validation and response hardening."""
import os

import pytest
from cryptography.exceptions import InvalidTag

from config import GiB, MiB, Settings
from conftest import drop_dir
from ftt_client import (
    build_drop,
    complete,
    create,
    derive_keys,
    derive_master,
    download,
    get_chunk,
    open_drop,
    put_chunk,
    random_code,
    upload,
)


# ------------------------------------------------------------------ round trips


def test_text_round_trip(client, settings):
    text = "héllo 👋 from device A".encode()
    drop = build_drop(text, settings.chunk_size, kind="text", name="", mime="text/plain;charset=utf-8")
    upload(client, drop)
    manifest, data = download(client, drop)
    assert data == text
    assert manifest["kind"] == "text"


def test_multi_chunk_file_round_trip(client, settings):
    content = os.urandom(settings.chunk_size * 3 + 123)
    drop = build_drop(content, settings.chunk_size, name="photo.jpg", mime="image/jpeg")
    assert len(drop.chunks) == 4
    upload(client, drop)
    manifest, data = download(client, drop)
    assert data == content
    assert (manifest["name"], manifest["chunks"]) == ("photo.jpg", 4)


def test_non_burn_drop_can_be_read_repeatedly(client, settings):
    drop = build_drop(b"again and again", settings.chunk_size)
    upload(client, drop)
    for _ in range(3):
        assert download(client, drop)[1] == b"again and again"


# ------------------------------------------------------------------ invalid codes


def test_typed_code_works_and_wrong_code_is_rejected(client, settings):
    """Uses the real 600k-iteration PBKDF2 path a typed code takes."""
    drop_id = random_code(6)
    drop = build_drop(b"typed", settings.chunk_size, drop_id=drop_id, master=derive_master("9XTR2PWD", drop_id))
    upload(client, drop)
    assert download(client, drop)[1] == b"typed"

    wrong = derive_keys(derive_master("9XTR2PWE", drop_id), drop_id).auth_token  # one character off
    r = open_drop(client, drop_id, wrong)
    assert r.status_code == 403
    assert "4 attempts left" in r.json()["detail"]


def test_lockout_destroys_drop_after_max_failed_attempts(client, settings):
    drop = build_drop(b"guess me", settings.chunk_size)
    upload(client, drop)
    for attempt in range(1, settings.max_failed_attempts + 1):
        wrong = derive_keys(os.urandom(32), drop.id).auth_token
        r = open_drop(client, drop.id, wrong)
        assert r.status_code == 403
    assert "destroyed" in r.json()["detail"]
    assert open_drop(client, drop.id, drop.auth_token).status_code == 404  # even the right key is too late
    assert not drop_dir(client, drop.id).exists()


def test_wrong_keys_on_chunk_endpoint_also_count(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    upload(client, drop)
    for _ in range(settings.max_failed_attempts):
        assert get_chunk(client, drop.id, 0, derive_keys(os.urandom(32), drop.id).auth_token).status_code == 403
    assert get_chunk(client, drop.id, 0, drop.auth_token).status_code == 404


@pytest.mark.parametrize("token", [None, "", "not base64 !!", "A" * 43])
def test_missing_or_malformed_token_rejected(client, settings, token):
    drop = build_drop(b"x", settings.chunk_size)
    upload(client, drop)
    assert open_drop(client, drop.id, token).status_code == 403


def test_unknown_drop_is_404(client):
    assert open_drop(client, "ZZZZZZ", derive_keys(os.urandom(32), "ZZZZZZ").auth_token).status_code == 404


@pytest.mark.parametrize("bad_id", ["abc", "ABCDEFG", "ABCDEI", "abcdef", "ABC-EF"])
def test_malformed_ids_rejected(client, bad_id):
    assert client.post(f"/api/drops/{bad_id}/open", headers={"X-Auth-Token": "x"}).status_code == 422


def test_tampered_ciphertext_fails_to_decrypt(client, settings):
    drop = build_drop(b"integrity matters", settings.chunk_size)
    upload(client, drop)
    stored = drop_dir(client, drop.id) / "00000.bin"
    blob = bytearray(stored.read_bytes())
    blob[20] ^= 0x01
    stored.write_bytes(bytes(blob))
    with pytest.raises(InvalidTag):
        download(client, drop)


# ------------------------------------------------------------------ upload validation


def test_chunks_must_arrive_in_order(client, settings):
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    token = create(client, drop).json()["upload_token"]
    r = put_chunk(client, drop, 1, token)
    assert r.status_code == 409 and "expected chunk 0" in r.json()["detail"]


def test_upload_token_required(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    create(client, drop)
    assert put_chunk(client, drop, 0, "wrong-token").status_code == 403
    assert complete(client, drop, "wrong-token").status_code == 403


def test_chunk_cannot_be_overwritten(client, settings):
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    token = create(client, drop).json()["upload_token"]
    assert put_chunk(client, drop, 0, token).status_code == 204
    assert put_chunk(client, drop, 0, token).status_code == 409


def test_complete_requires_every_chunk(client, settings):
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    token = create(client, drop).json()["upload_token"]
    put_chunk(client, drop, 0, token)
    r = complete(client, drop, token)
    assert r.status_code == 409 and "missing" in r.json()["detail"]


def test_open_before_upload_completes_is_409(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    create(client, drop)
    assert open_drop(client, drop.id, drop.auth_token).status_code == 409


def test_duplicate_id_rejected(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    assert create(client, drop).status_code == 201
    assert create(client, drop).status_code == 409


def test_no_uploads_after_complete(client, settings):
    drop = build_drop(b"x", settings.chunk_size)
    token = upload(client, drop)
    assert put_chunk(client, drop, 0, token).status_code == 409
    assert complete(client, drop, token).status_code == 409


@pytest.mark.parametrize(
    "overrides",
    [
        {"auth_hash": "not-a-hash"},
        {"manifest": "%%% not base64 %%%"},
        {"manifest": "AAAA"},  # decodes to 3 bytes: too small to be ciphertext
        {"chunks": 0},
        {"size": 5},  # smaller than one chunk's overhead
        {"ttl": "300"},  # strict types
        {"extra": "field"},
    ],
)
def test_create_rejects_malformed_requests(client, settings, overrides):
    drop = build_drop(b"x", settings.chunk_size)
    assert create(client, drop, **overrides).status_code == 422


# ------------------------------------------------------------------ hardening & config


def test_security_headers_on_page(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe" not in csp
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_receive_route_serves_the_app(client):
    assert client.get("/r/K7QM3F").text == client.get("/").text


def test_ciphertext_is_served_as_opaque_attachment(client, settings):
    drop = build_drop(b"<script>alert(1)</script>", settings.chunk_size, name="x.html", mime="text/html")
    upload(client, drop)
    r = get_chunk(client, drop.id, 0, drop.auth_token)
    assert r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"] == "attachment"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"


def test_config_endpoint(client, settings):
    cfg = client.get("/api/config").json()
    assert cfg["chunk_size"] == settings.chunk_size
    assert cfg["ttl"]["presets"] == [180, 300, 600, 3600]
    assert {"blocked_extensions", "blocked_mime_types", "blocked_signatures", "text_rules"} <= cfg["rules"].keys()
    assert "_about" not in cfg["rules"]


def test_production_defaults():
    s = Settings()
    assert s.ttl_presets == (180, 300, 600, 3600) and (s.ttl_min, s.ttl_max) == (60, 3600)
    assert (s.chunk_size, s.max_text_bytes, s.max_file_bytes) == (5 * MiB, 5 * MiB, 500 * MiB)
    assert s.max_chunks == 100
    assert s.disk_cap_bytes == 5 * GiB
    assert s.data_dir.as_posix() == "/tmp/drops"


def test_settings_from_env():
    s = Settings.from_env({"TRUSTED_PROXIES": "10.0.0.1, 172.16.0.0/12", "TTL_MAX_SECONDS": "1800", "DATA_DIR": "/srv/d"})
    assert s.trusted_proxies == ("10.0.0.1", "172.16.0.0/12")
    assert s.ttl_max == 1800 and s.data_dir.as_posix() == "/srv/d"
