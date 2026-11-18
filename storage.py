"""Drop storage: metadata and TTL in Redis, encrypted chunks on disk.

Everything stored here is opaque ciphertext produced in the browser. One Redis hash per drop,
``drop:{id}``, holds its metadata, and that key's TTL *is* the drop's lifetime. Chunk files live
in ``{data_dir}/{id}/`` and are deleted on burn, on lockout, and by the sweeper as soon as the
Redis key is gone. ``drops:bytes`` reserves disk quota per drop so the total stays under the cap.

Redis keys never outlive their TTL: every mutation of an existing drop runs in a Lua script that
first checks the key still exists, so a late write cannot resurrect an expired drop without a TTL.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import logging
import os
import re
import secrets
import shutil
from collections.abc import AsyncIterable
from pathlib import Path

import anyio

from config import CHUNK_OVERHEAD, Settings

log = logging.getLogger("ftt.storage")

ID_PATTERN = r"^[0-9A-HJKMNP-TV-Z]{6}$"  # 6 Crockford base32 characters, generated in the browser
_ID_RE = re.compile(ID_PATTERN)
QUOTA_KEY = "drops:bytes"

NOT_FOUND = "Drop not found. It may have expired or already been read."
ALREADY_OPENED = "This one-time drop has already been opened by someone else."
STILL_UPLOADING = "The sender is still uploading. Try again in a moment."


class StoreError(Exception):
    """A refused request; ``status`` is the HTTP status code to report."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def drop_key(drop_id: str) -> str:
    return f"drop:{drop_id}"


def token_hash(token: str) -> str:
    """SHA-256 (hex) of a base64url token's raw bytes. Only this hash is ever stored."""
    raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
    return hashlib.sha256(raw).hexdigest()


def token_matches(token: str | None, expected: str | None) -> bool:
    if not token or not expected:
        return False
    try:
        actual = token_hash(token)
    except (binascii.Error, ValueError):
        return False
    return hmac.compare_digest(actual, expected)


# Refuse a taken ID, enforce the disk quota, write metadata and start the upload window.
_CREATE = """
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
local used = 0
for _, v in ipairs(redis.call('HVALS', KEYS[2])) do used = used + tonumber(v) end
if used + tonumber(ARGV[2]) > tonumber(ARGV[3]) then return -2 end
for i = 5, #ARGV, 2 do redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1]) end
redis.call('PEXPIRE', KEYS[1], ARGV[4])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
return 1
"""

# Record chunk ARGV[1] (ARGV[2] bytes), but only if it is the next one expected.
_COMMIT_CHUNK = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
if tonumber(redis.call('HGET', KEYS[1], 'received')) ~= tonumber(ARGV[1]) then return -2 end
redis.call('HINCRBY', KEYS[1], 'received', 1)
redis.call('HINCRBY', KEYS[1], 'written', ARGV[2])
return 1
"""

# Seal an upload once every chunk arrived and the size matches. The drop's TTL starts now.
_COMPLETE = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
local m = redis.call('HMGET', KEYS[1], 'state', 'received', 'chunks', 'written', 'size', 'ttl')
if m[1] ~= 'uploading' then return -2 end
if m[2] ~= m[3] or m[4] ~= m[5] then return -3 end
redis.call('HSET', KEYS[1], 'state', 'ready')
redis.call('PEXPIRE', KEYS[1], tonumber(m[6]) * 1000)
return redis.call('PTTL', KEYS[1])
"""

_INCR_IF_EXISTS = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
return redis.call('HINCRBY', KEYS[1], ARGV[1], ARGV[2])
"""

# One-time claim of a burn-after-reading drop: 1 = claimed by this caller, 0 = taken.
_CLAIM = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
return redis.call('HSETNX', KEYS[1], 'claim', ARGV[1])
"""

# Mark chunk ARGV[1] as served; returns 1 once every chunk has been served (time to burn).
_MARK_SERVED = """
if redis.call('EXISTS', KEYS[1]) == 0 then return -1 end
if redis.call('HSETNX', KEYS[1], 'served:' .. ARGV[1], 1) == 1 then
  redis.call('HINCRBY', KEYS[1], 'served', 1)
end
if tonumber(redis.call('HGET', KEYS[1], 'served')) >= tonumber(redis.call('HGET', KEYS[1], 'chunks')) then
  return 1
end
return 0
"""


class DropStore:
    def __init__(self, redis, settings: Settings):
        self.redis = redis
        self.settings = settings
        self.root = Path(settings.data_dir)
        self._create = redis.register_script(_CREATE)
        self._commit_chunk = redis.register_script(_COMMIT_CHUNK)
        self._complete = redis.register_script(_COMPLETE)
        self._incr = redis.register_script(_INCR_IF_EXISTS)
        self._claim = redis.register_script(_CLAIM)
        self._mark_served = redis.register_script(_MARK_SERVED)

    def path(self, drop_id: str) -> Path:
        return self.root / drop_id

    # ------------------------------------------------------------------ upload

    async def create(
        self, drop_id: str, *, ttl: int, burn: bool, auth_hash: str, chunks: int, size: int, manifest: str
    ) -> dict:
        self.root.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(self.root).free < size:
            raise StoreError(507, "The server's disk is full. Try again later.")
        upload_token = secrets.token_urlsafe(32)
        fields = {
            "state": "uploading",
            "auth": auth_hash,
            "up": token_hash(upload_token),
            "burn": "1" if burn else "0",
            "ttl": ttl,
            "chunks": chunks,
            "size": size,
            "received": 0,
            "written": 0,
            "served": 0,
            "fails": 0,
            "manifest": manifest,
        }
        args: list = [drop_id, size, self.settings.disk_cap_bytes, self.settings.upload_window * 1000]
        for name, value in fields.items():
            args += [name, value]
        result = await self._create(keys=[drop_key(drop_id), QUOTA_KEY], args=args)
        if result == -1:
            raise StoreError(409, "That drop ID is already in use.")
        if result == -2:
            raise StoreError(507, "Server storage is full. Try again later or send something smaller.")
        directory = self.path(drop_id)
        await asyncio.to_thread(shutil.rmtree, directory, True)  # leftovers from an older drop with this ID
        directory.mkdir(parents=True, exist_ok=True)
        return {"upload_token": upload_token, "upload_window_s": self.settings.upload_window}

    async def put_chunk(
        self,
        drop_id: str,
        index: int,
        upload_token: str | None,
        body: AsyncIterable[bytes],
        content_length: int | None,
    ) -> None:
        """Stream one encrypted chunk to disk, refusing it (413) the moment it exceeds its limit."""
        key = drop_key(drop_id)
        state, up, received, chunks, written, size = await self.redis.hmget(
            key, "state", "up", "received", "chunks", "written", "size"
        )
        if state is None:
            raise StoreError(404, NOT_FOUND)
        if not token_matches(upload_token, up):
            raise StoreError(403, "Invalid upload token.")
        if state != "uploading":
            raise StoreError(409, "This upload is already complete.")
        if index >= int(chunks):
            raise StoreError(422, "Chunk index is out of range.")
        if index != int(received):
            raise StoreError(409, f"Chunks must be uploaded in order; expected chunk {received}.")
        limit = min(self.settings.max_chunk_bytes, int(size) - int(written))
        if content_length is not None and content_length > limit:
            raise StoreError(413, "Chunk is larger than allowed.")

        final = self.path(drop_id) / f"{index:05d}.bin"
        partial = final.with_name(f".{index:05d}.{secrets.token_hex(4)}.part")
        nbytes = 0
        try:
            async with await anyio.open_file(partial, "wb") as f:
                async for piece in body:
                    nbytes += len(piece)
                    if nbytes > limit:
                        raise StoreError(413, "Chunk is larger than allowed.")
                    await f.write(piece)
            if nbytes < CHUNK_OVERHEAD:
                raise StoreError(422, "Chunk is too small to be AES-GCM ciphertext.")
            os.link(partial, final)  # atomic, and refuses to overwrite an existing chunk
        except FileExistsError:
            raise StoreError(409, "This chunk was already uploaded.") from None
        except FileNotFoundError:  # the drop expired and was swept mid-upload
            raise StoreError(404, NOT_FOUND) from None
        finally:
            partial.unlink(missing_ok=True)

        result = await self._commit_chunk(keys=[key], args=[index, nbytes])
        if result != 1:
            final.unlink(missing_ok=True)
            raise StoreError(404, NOT_FOUND) if result == -1 else StoreError(409, "Chunk upload conflicted.")

    async def complete(self, drop_id: str, upload_token: str | None) -> dict:
        key = drop_key(drop_id)
        up = await self.redis.hget(key, "up")
        if up is None:
            raise StoreError(404, NOT_FOUND)
        if not token_matches(upload_token, up):
            raise StoreError(403, "Invalid upload token.")
        result = await self._complete(keys=[key])
        if result == -1:
            raise StoreError(404, NOT_FOUND)
        if result == -2:
            raise StoreError(409, "This upload is already complete.")
        if result == -3:
            raise StoreError(409, "Upload is incomplete: some chunks are missing.")
        return {"expires_in_ms": result}

    # ---------------------------------------------------------------- download

    async def _require_key(self, drop_id: str, token: str | None, expected: str | None) -> None:
        """Check the receiver's proof-of-key; wrong guesses count toward destroying the drop."""
        if token_matches(token, expected):
            return
        fails = await self._incr(keys=[drop_key(drop_id)], args=["fails", 1])
        if fails == -1:
            raise StoreError(404, NOT_FOUND)
        left = self.settings.max_failed_attempts - fails
        if left <= 0:
            await self.purge(drop_id)
            raise StoreError(403, "Wrong code. Too many failed attempts, so this drop has been destroyed.")
        raise StoreError(403, f"Wrong code. {left} attempt{'' if left == 1 else 's'} left before this drop is destroyed.")

    async def open(self, drop_id: str, auth_token: str | None, *, claim: bool) -> dict:
        key = drop_key(drop_id)
        meta = await self.redis.hgetall(key)
        if not meta:
            raise StoreError(404, NOT_FOUND)
        await self._require_key(drop_id, auth_token, meta.get("auth"))
        if meta["state"] != "ready":
            raise StoreError(409, STILL_UPLOADING)
        info = {
            "burn": meta["burn"] == "1",
            "chunks": int(meta["chunks"]),
            "size": int(meta["size"]),
            "expires_in_ms": max(0, await self.redis.pttl(key)),
        }
        if info["burn"]:
            if not claim:  # let the receiver confirm before the one-time read starts
                if meta.get("claim"):
                    raise StoreError(410, ALREADY_OPENED)
                return {**info, "claim_required": True}
            claim_token = secrets.token_urlsafe(32)
            result = await self._claim(keys=[key], args=[token_hash(claim_token)])
            if result == -1:
                raise StoreError(404, NOT_FOUND)
            if result == 0:
                raise StoreError(410, ALREADY_OPENED)
            info["claim_token"] = claim_token
        return {**info, "manifest": meta["manifest"]}

    async def chunk_for_read(
        self, drop_id: str, index: int, auth_token: str | None, claim_token: str | None
    ) -> tuple[Path, bool]:
        state, auth, burn, claim, chunks = await self.redis.hmget(
            drop_key(drop_id), "state", "auth", "burn", "claim", "chunks"
        )
        if state is None:
            raise StoreError(404, NOT_FOUND)
        await self._require_key(drop_id, auth_token, auth)
        if state != "ready":
            raise StoreError(409, STILL_UPLOADING)
        if index >= int(chunks):
            raise StoreError(404, "No such chunk.")
        is_burn = burn == "1"
        if is_burn and not token_matches(claim_token, claim):
            raise StoreError(403, "This one-time drop is reserved for whoever opened it first.")
        path = self.path(drop_id) / f"{index:05d}.bin"
        if not path.is_file():
            raise StoreError(404, NOT_FOUND)
        return path, is_burn

    async def mark_served(self, drop_id: str, index: int) -> None:
        """Burn-after-reading: once every chunk has been sent, delete the drop immediately."""
        if await self._mark_served(keys=[drop_key(drop_id)], args=[index]) == 1:
            await self.purge(drop_id)

    # ---------------------------------------------------------------- deletion

    async def purge(self, drop_id: str) -> None:
        await self.redis.delete(drop_key(drop_id))  # unreadable from this instant
        await asyncio.to_thread(shutil.rmtree, self.path(drop_id), True)
        await self.redis.hdel(QUOTA_KEY, drop_id)  # release quota only after the files are gone

    async def sweep(self) -> int:
        """Delete the files (and quota reservation) of every drop whose Redis key is gone."""
        candidates = set(await self.redis.hkeys(QUOTA_KEY))
        try:
            candidates |= {entry.name for entry in os.scandir(self.root) if entry.is_dir()}
        except FileNotFoundError:
            pass
        removed = 0
        for drop_id in candidates:
            if _ID_RE.fullmatch(drop_id) and not await self.redis.exists(drop_key(drop_id)):
                await asyncio.to_thread(shutil.rmtree, self.path(drop_id), True)
                await self.redis.hdel(QUOTA_KEY, drop_id)
                removed += 1
        return removed

    async def run_sweeper(self) -> None:
        while True:
            try:
                await self.sweep()
            except Exception:  # keep sweeping even if Redis hiccups
                log.exception("sweep failed")
            await asyncio.sleep(self.settings.sweep_interval)
