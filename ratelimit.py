"""Per-IP fixed-window rate limiting in Redis, with trusted-proxy client IP resolution."""
from __future__ import annotations

import ipaddress
import math
import time
from collections.abc import Iterable

from fastapi import HTTPException, Request

from config import Settings

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(entries: Iterable[str]) -> tuple[Network, ...]:
    return tuple(ipaddress.ip_network(entry.strip(), strict=False) for entry in entries if entry.strip())


def _as_ip(value: str | None):
    try:
        return ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None


def _is_trusted(ip, networks: tuple[Network, ...]) -> bool:
    return ip is not None and any(ip in net for net in networks)


def client_ip(peer: str | None, forwarded_for: str | None, trusted: tuple[Network, ...]) -> str:
    """The address to rate-limit on.

    X-Forwarded-For is honoured only when the TCP peer is a trusted proxy. The header is read
    right to left (the hops our own proxies appended) and the first untrusted address wins, so a
    client cannot spoof its IP by sending its own X-Forwarded-For.
    """
    peer = peer or "unknown"
    if not forwarded_for or not _is_trusted(_as_ip(peer), trusted):
        return peer
    for hop in reversed(forwarded_for.split(",")):
        ip = _as_ip(hop)
        if ip is None:
            break  # malformed entry: trust nothing to its left
        if not _is_trusted(ip, trusted):
            return str(ip)
    return peer


class RateLimiter:
    def __init__(self, redis, settings: Settings):
        self.redis = redis
        self.window = settings.rate_window
        self.limits = {"create": settings.rate_create, "open": settings.rate_open, "chunk": settings.rate_chunk}
        self.trusted = parse_networks(settings.trusted_proxies)
        self.clock = time.time  # replaceable in tests

    async def hit(self, bucket: str, ip: str) -> int | None:
        """Count one request. Returns seconds to wait if the IP is over its limit, else None."""
        now = self.clock()
        window_id = int(now // self.window)
        key = f"rl:{bucket}:{ip}:{window_id}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, self.window + 1)
            count, _ = await pipe.execute()
        if count > self.limits[bucket]:
            return max(1, math.ceil((window_id + 1) * self.window - now))
        return None

    def limit(self, bucket: str):
        """FastAPI dependency enforcing `bucket`'s limit."""

        async def check(request: Request) -> None:
            peer = request.client.host if request.client else None
            ip = client_ip(peer, request.headers.get("x-forwarded-for"), self.trusted)
            retry_after = await self.hit(bucket, ip)
            if retry_after is not None:
                raise HTTPException(429, "Too many requests. Please slow down.", headers={"Retry-After": str(retry_after)})

        return check
