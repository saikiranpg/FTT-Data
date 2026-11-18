"""Runtime settings, read once from environment variables (see README for the full list)."""
from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
KiB, MiB, GiB = 1024, 1024**2, 1024**3

# Every encrypted blob is iv(12) | ciphertext | GCM tag(16) — see static/crypto.js.
CHUNK_OVERHEAD = 12 + 16


@dataclass(frozen=True)
class Settings:
    redis_url: str = "redis://localhost:6379/0"
    data_dir: Path = Path("/tmp/drops")
    disk_cap_bytes: int = 5 * GiB  # total reserved ciphertext on disk; beyond this → HTTP 507

    chunk_size: int = 5 * MiB  # plaintext bytes per encrypted chunk
    max_text_bytes: int = 5 * MiB  # text is always a single chunk
    max_file_bytes: int = 500 * MiB
    max_manifest_bytes: int = 4 * KiB

    ttl_presets: tuple[int, ...] = (180, 300, 600, 3600)
    ttl_default: int = 300
    ttl_min: int = 60
    ttl_max: int = 3600
    upload_window: int = 30 * 60  # an unfinished upload is discarded after this

    max_failed_attempts: int = 5  # wrong keys before a drop is destroyed

    rate_window: int = 60  # seconds per fixed rate-limit window
    rate_create: int = 10  # new drops per IP per window
    rate_open: int = 30  # open attempts per IP per window
    rate_chunk: int = 600  # chunk uploads/downloads per IP per window

    trusted_proxies: tuple[str, ...] = ()  # IPs/CIDRs whose X-Forwarded-For we believe
    sweep_interval: float = 1.0  # seconds between expired-file sweeps
    rules_path: Path = BASE_DIR / "safety_rules.json"

    def __post_init__(self) -> None:
        if self.max_text_bytes > self.chunk_size:
            raise ValueError("max_text_bytes must fit in a single chunk")
        if not 0 < self.ttl_min <= self.ttl_max:
            raise ValueError("require 0 < ttl_min <= ttl_max")

    @property
    def max_chunks(self) -> int:
        return max(1, math.ceil(self.max_file_bytes / self.chunk_size))

    @property
    def max_chunk_bytes(self) -> int:
        return self.chunk_size + CHUNK_OVERHEAD

    @property
    def max_drop_bytes(self) -> int:
        return self.max_file_bytes + self.max_chunks * CHUNK_OVERHEAD

    @classmethod
    def from_env(cls, env: os._Environ | dict = os.environ) -> Settings:
        kwargs = {field: parse(env[name]) for name, (field, parse) in _ENV.items() if env.get(name)}
        return cls(**kwargs)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


_ENV = {
    "REDIS_URL": ("redis_url", str),
    "DATA_DIR": ("data_dir", Path),
    "DISK_CAP_BYTES": ("disk_cap_bytes", int),
    "CHUNK_SIZE_BYTES": ("chunk_size", int),
    "MAX_TEXT_BYTES": ("max_text_bytes", int),
    "MAX_FILE_BYTES": ("max_file_bytes", int),
    "TTL_PRESETS_SECONDS": ("ttl_presets", lambda v: tuple(int(x) for x in _csv(v))),
    "TTL_DEFAULT_SECONDS": ("ttl_default", int),
    "TTL_MIN_SECONDS": ("ttl_min", int),
    "TTL_MAX_SECONDS": ("ttl_max", int),
    "UPLOAD_WINDOW_SECONDS": ("upload_window", int),
    "MAX_FAILED_ATTEMPTS": ("max_failed_attempts", int),
    "RATE_WINDOW_SECONDS": ("rate_window", int),
    "RATE_CREATE": ("rate_create", int),
    "RATE_OPEN": ("rate_open", int),
    "RATE_CHUNK": ("rate_chunk", int),
    "TRUSTED_PROXIES": ("trusted_proxies", _csv),
    "SWEEP_INTERVAL_SECONDS": ("sweep_interval", float),
    "SAFETY_RULES_PATH": ("rules_path", Path),
}


def load_rules(path: Path) -> dict:
    """Content-safety rules shared with the browser. Keys starting with "_" are comments."""
    with open(path, encoding="utf-8") as f:
        rules = json.load(f)
    return {key: value for key, value in rules.items() if not key.startswith("_")}
