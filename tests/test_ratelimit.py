"""Per-IP rate limits, and X-Forwarded-For trusted only from configured proxies."""
import pytest

from ftt_client import build_drop, create, open_drop
from ratelimit import client_ip, parse_networks


class FrozenClock:
    """Stops time inside the rate limiter so window boundaries can't make tests flaky."""

    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def limited_client(make_client, **overrides):
    client = make_client(**overrides)
    clock = FrozenClock()
    client.app.state.limiter.clock = clock
    return client, clock


def test_create_is_rate_limited(make_client):
    client, _ = limited_client(make_client, rate_create=3)
    for _ in range(3):
        assert create(client, build_drop(b"x", 1024)).status_code == 201
    r = create(client, build_drop(b"x", 1024))
    assert r.status_code == 429
    assert r.headers["retry-after"] == "40"  # 1_700_000_000 is 20 s into a 60 s window


def test_limit_resets_with_the_next_window(make_client):
    client, clock = limited_client(make_client, rate_open=2)
    statuses = [open_drop(client, "ZZZZZZ", "x").status_code for _ in range(3)]
    assert statuses == [404, 404, 429]
    clock.now += 60
    assert open_drop(client, "ZZZZZZ", "x").status_code == 404


def test_trusted_proxy_forwards_real_client_ips(make_client):
    client, _ = limited_client(make_client, peer=("10.0.0.2", 4000), rate_open=2, trusted_proxies=("10.0.0.0/8",))

    def hit(ip):
        return client.post("/api/drops/ZZZZZZ/open", headers={"X-Forwarded-For": ip}).status_code

    assert [hit("203.0.113.5") for _ in range(3)] == [404, 404, 429]
    assert hit("203.0.113.6") == 404  # a different client behind the same proxy has its own budget


def test_untrusted_peer_cannot_dodge_limits_by_spoofing_xff(make_client):
    client, _ = limited_client(make_client, peer=("198.51.100.7", 4000), rate_open=2, trusted_proxies=("10.0.0.0/8",))
    statuses = [
        client.post("/api/drops/ZZZZZZ/open", headers={"X-Forwarded-For": f"203.0.113.{i}"}).status_code
        for i in range(3)
    ]
    assert statuses == [404, 404, 429]


TRUSTED = parse_networks(["10.0.0.0/8", "172.30.0.1"])


@pytest.mark.parametrize(
    ("peer", "xff", "expected"),
    [
        ("203.0.113.9", None, "203.0.113.9"),  # direct connection
        ("203.0.113.9", "1.2.3.4", "203.0.113.9"),  # untrusted peer: header ignored
        ("172.30.0.1", "198.51.100.1", "198.51.100.1"),  # through our proxy
        ("172.30.0.1", "6.6.6.6, 198.51.100.1", "198.51.100.1"),  # client-supplied prefix ignored
        ("10.0.0.5", "198.51.100.1, 10.0.0.9", "198.51.100.1"),  # chain of trusted proxies
        ("10.0.0.5", "garbage, 10.0.0.9", "10.0.0.5"),  # malformed hop: fall back to the peer
        ("172.30.0.1", "2001:db8::1", "2001:db8::1"),  # IPv6 client
    ],
)
def test_client_ip_resolution(peer, xff, expected):
    assert client_ip(peer, xff, TRUSTED) == expected


def test_no_trusted_proxies_means_xff_is_always_ignored():
    assert client_ip("172.30.0.1", "198.51.100.1", ()) == "172.30.0.1"
