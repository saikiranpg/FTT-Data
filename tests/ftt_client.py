"""Independent Python implementation of the ftt/v2 client protocol (tests only).

It mirrors static/crypto.js using `hashlib` and `cryptography`, so the server is exercised
exactly as a browser would use it, and test_vectors.py can prove both implementations agree.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROTOCOL = "ftt/v2"
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PBKDF2_ITERATIONS = 600_000


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def random_code(length: int) -> str:
    return "".join(ALPHABET[b & 31] for b in os.urandom(length))


def derive_master(secret: str, drop_id: str, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), f"{PROTOCOL}/salt/{drop_id}".encode(), iterations, 32)


def _hkdf(master: bytes, label: str, drop_id: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"{PROTOCOL}/{label}/{drop_id}".encode()).derive(master)


@dataclass
class Keys:
    enc_key: bytes
    auth_token: str
    auth_hash: str


def derive_keys(master: bytes, drop_id: str) -> Keys:
    token = _hkdf(master, "auth", drop_id)
    return Keys(_hkdf(master, "enc", drop_id), b64url(token), hashlib.sha256(token).hexdigest())


def chunk_aad(drop_id: str, index: int, total: int) -> bytes:
    return f"{PROTOCOL}|{drop_id}|chunk|{index}|{total}".encode()


def manifest_aad(drop_id: str, total: int) -> bytes:
    return f"{PROTOCOL}|{drop_id}|manifest|{total}".encode()


def seal(key: bytes, plaintext: bytes, aad: bytes, iv: bytes | None = None) -> bytes:
    iv = iv or os.urandom(12)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)


@dataclass
class Drop:
    id: str
    master: bytes
    keys: Keys
    manifest_b64: str
    chunks: list[bytes]

    @property
    def size(self) -> int:
        return sum(map(len, self.chunks))

    @property
    def auth_token(self) -> str:
        return self.keys.auth_token


def build_drop(
    content: bytes,
    chunk_size: int,
    *,
    kind: str = "file",
    name: str = "file.bin",
    mime: str = "application/octet-stream",
    drop_id: str | None = None,
    master: bytes | None = None,
) -> Drop:
    """Encrypt `content` exactly like the browser does (link-only mode unless `master` is given)."""
    drop_id = drop_id or random_code(6)
    master = master or os.urandom(32)
    keys = derive_keys(master, drop_id)
    total = max(1, math.ceil(len(content) / chunk_size))
    manifest = {"v": 2, "kind": kind, "name": name, "mime": mime, "size": len(content), "chunkSize": chunk_size, "chunks": total}
    manifest_blob = seal(keys.enc_key, json.dumps(manifest).encode(), manifest_aad(drop_id, total))
    chunks = [
        seal(keys.enc_key, content[i * chunk_size : (i + 1) * chunk_size], chunk_aad(drop_id, i, total))
        for i in range(total)
    ]
    return Drop(drop_id, master, keys, base64.b64encode(manifest_blob).decode(), chunks)


def create_body(drop: Drop, *, ttl: int = 300, burn: bool = False, **overrides) -> dict:
    body = {
        "id": drop.id,
        "ttl": ttl,
        "burn": burn,
        "auth_hash": drop.keys.auth_hash,
        "chunks": len(drop.chunks),
        "size": drop.size,
        "manifest": drop.manifest_b64,
    }
    return {**body, **overrides}


def create(client, drop: Drop, **kwargs):
    return client.post("/api/drops", json=create_body(drop, **kwargs))


def put_chunk(client, drop: Drop, index: int, token: str, body: bytes | None = None):
    return client.put(
        f"/api/drops/{drop.id}/chunks/{index}",
        content=drop.chunks[index] if body is None else body,
        headers={"X-Upload-Token": token},
    )


def complete(client, drop: Drop, token: str):
    return client.post(f"/api/drops/{drop.id}/complete", headers={"X-Upload-Token": token})


def upload(client, drop: Drop, *, ttl: int = 300, burn: bool = False) -> str:
    """Full sender flow. Returns the upload token."""
    r = create(client, drop, ttl=ttl, burn=burn)
    assert r.status_code == 201, r.text
    token = r.json()["upload_token"]
    for i in range(len(drop.chunks)):
        r = put_chunk(client, drop, i, token)
        assert r.status_code == 204, r.text
    r = complete(client, drop, token)
    assert r.status_code == 200, r.text
    return token


def open_drop(client, drop_id: str, auth_token: str | None, *, claim: bool = False):
    headers = {"X-Auth-Token": auth_token} if auth_token else {}
    if claim:
        headers["X-Claim"] = "1"
    return client.post(f"/api/drops/{drop_id}/open", headers=headers)


def get_chunk(client, drop_id: str, index: int, auth_token: str | None, claim_token: str | None = None):
    headers = {"X-Auth-Token": auth_token} if auth_token else {}
    if claim_token:
        headers["X-Claim-Token"] = claim_token
    return client.get(f"/api/drops/{drop_id}/chunks/{index}", headers=headers)


def download(client, drop: Drop, *, claim: bool = False) -> tuple[dict, bytes]:
    """Full receiver flow: open, fetch every chunk, decrypt. Returns (manifest, plaintext)."""
    r = open_drop(client, drop.id, drop.auth_token, claim=claim)
    assert r.status_code == 200, r.text
    info = r.json()
    total = info["chunks"]
    manifest = json.loads(unseal(drop.keys.enc_key, base64.b64decode(info["manifest"]), manifest_aad(drop.id, total)))
    plaintext = b""
    for i in range(total):
        r = get_chunk(client, drop.id, i, drop.auth_token, info.get("claim_token"))
        assert r.status_code == 200, r.text
        plaintext += unseal(drop.keys.enc_key, r.content, chunk_aad(drop.id, i, total))
    return manifest, plaintext
