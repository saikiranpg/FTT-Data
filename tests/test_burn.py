"""Burn after reading: exactly one reader, then the drop is deleted immediately."""
import asyncio
import os

from conftest import drop_dir
from ftt_client import build_drop, download, get_chunk, open_drop, upload
from storage import DropStore, StoreError


def test_burn_drop_is_deleted_right_after_the_last_chunk(client, settings, backend):
    content = os.urandom(settings.chunk_size * 2 + 7)
    drop = build_drop(content, settings.chunk_size)
    upload(client, drop, burn=True)

    peek = open_drop(client, drop.id, drop.auth_token).json()
    assert peek["claim_required"] is True and "manifest" not in peek  # nothing released before the claim

    assert download(client, drop, claim=True)[1] == content
    assert not drop_dir(client, drop.id).exists()
    assert not backend.sync.exists(f"drop:{drop.id}")
    assert open_drop(client, drop.id, drop.auth_token).status_code == 404


def test_second_reader_is_refused_once_claimed(client, settings):
    drop = build_drop(os.urandom(settings.chunk_size * 2), settings.chunk_size)
    upload(client, drop, burn=True)
    first = open_drop(client, drop.id, drop.auth_token, claim=True)
    assert first.status_code == 200

    assert open_drop(client, drop.id, drop.auth_token, claim=True).status_code == 410
    assert open_drop(client, drop.id, drop.auth_token).status_code == 410
    # Knowing the code is not enough to read chunks: the claim token is required.
    assert get_chunk(client, drop.id, 0, drop.auth_token).status_code == 403
    assert get_chunk(client, drop.id, 0, drop.auth_token, "forged-claim").status_code == 403
    assert get_chunk(client, drop.id, 0, drop.auth_token, first.json()["claim_token"]).status_code == 200


def test_concurrent_claims_have_exactly_one_winner(make_settings, backend):
    settings = make_settings()
    drop = build_drop(b"only one of you", settings.chunk_size)

    async def scenario():
        store = DropStore(backend.new_async(), settings)
        created = await store.create(
            drop.id, ttl=300, burn=True, auth_hash=drop.keys.auth_hash,
            chunks=1, size=drop.size, manifest=drop.manifest_b64,
        )

        async def body():
            yield drop.chunks[0]

        await store.put_chunk(drop.id, 0, created["upload_token"], body(), None)
        await store.complete(drop.id, created["upload_token"])
        return await asyncio.gather(
            *(store.open(drop.id, drop.auth_token, claim=True) for _ in range(20)), return_exceptions=True
        )

    results = asyncio.run(scenario())
    winners = [r for r in results if isinstance(r, dict)]
    losers = [r for r in results if isinstance(r, StoreError)]
    assert len(winners) == 1 and "claim_token" in winners[0]
    assert len(losers) == 19 and all(e.status == 410 for e in losers)
