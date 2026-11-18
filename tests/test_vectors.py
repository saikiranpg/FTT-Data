"""Cross-implementation check: Python recomputes the vector that static/crypto.js produced.

`hashlib` (PBKDF2), `cryptography` (HKDF, AES-GCM) and the browser's Web Crypto share no code,
so agreement byte-for-byte proves the ftt/v2 format is fully specified.
"""
import hashlib
import json
from pathlib import Path

from ftt_client import b64url, chunk_aad, derive_keys, derive_master, manifest_aad, seal, unseal

VECTOR = json.loads((Path(__file__).parent / "vectors" / "ftt_v2.json").read_text())


def test_key_schedule_matches_javascript():
    master = derive_master(VECTOR["secret"], VECTOR["id"], VECTOR["iterations"])
    assert master.hex() == VECTOR["master_hex"]
    assert b64url(master) == VECTOR["fragment"]
    keys = derive_keys(master, VECTOR["id"])
    assert keys.auth_token == VECTOR["auth_token"]
    assert keys.auth_hash == VECTOR["auth_hash"]


def test_chunk_and_manifest_ciphertext_match_javascript():
    vid = VECTOR["id"]
    keys = derive_keys(bytes.fromhex(VECTOR["master_hex"]), vid)
    iv = bytes.fromhex(VECTOR["iv_hex"])
    index, total = VECTOR["chunk_index"], VECTOR["chunk_total"]

    chunk = seal(keys.enc_key, bytes.fromhex(VECTOR["plaintext_hex"]), chunk_aad(vid, index, total), iv)
    assert chunk.hex() == VECTOR["chunk_hex"]
    manifest = seal(keys.enc_key, VECTOR["manifest_json"].encode(), manifest_aad(vid, total), iv)
    assert manifest.hex() == VECTOR["manifest_hex"]

    assert unseal(keys.enc_key, bytes.fromhex(VECTOR["chunk_hex"]), chunk_aad(vid, index, total)) == bytes.fromhex(
        VECTOR["plaintext_hex"]
    )


def test_server_side_hash_of_token_matches():
    from storage import token_hash

    assert token_hash(VECTOR["auth_token"]) == VECTOR["auth_hash"]
    assert hashlib.sha256(bytes.fromhex(VECTOR["iv_hex"])).hexdigest() != VECTOR["auth_hash"]  # sanity
