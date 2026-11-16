"""Check cross-contact delivery and independent location polling."""

import asyncio
from argparse import Namespace
from unittest.mock import AsyncMock

from custom_components.apple_findmy_people.backend import native_people as people, people_keys


def test_existing_location_poll_skips_push_and_missing_key_does_not_block(monkeypatch):
    existing = people.PollTarget(Namespace(target="existing@example.invalid", relationship_id="share-a", keys=True))
    missing = people.PollTarget(Namespace(target="missing@example.invalid", relationship_id="share-b", keys=True))
    monkeypatch.setattr(people, "read_share_key", lambda handle: {"fm_id": "share-a"} if handle == existing.args.target else None)
    monkeypatch.setattr(people, "mark_reauth", lambda *args, **kwargs: None)
    collect = AsyncMock(return_value=True)
    monkeypatch.setattr(people, "collect_once", collect)

    async def exercise():
        await people.poll_target(missing, 60, shared_keys=True)
        await people.poll_target(existing, 60, shared_keys=True)

    asyncio.run(exercise())
    collect.assert_awaited_once()
    assert collect.await_args.args[0].target == existing.args.target
    assert collect.await_args.args[0].keys is False
    assert existing.args.keys is True
    assert missing.needs_refresh


def test_delayed_delivery_routes_to_verified_contact(monkeypatch, tmp_path):
    a = people.PollTarget(Namespace(target="a@example.invalid"))
    b = people.PollTarget(Namespace(target="b@example.invalid"))
    a_directory = {"identities": [{"push-token": b"a-device"}]}
    b_directory = {"identities": [{"push-token": b"b-device"}]}
    bindings = {a.args.target: (a, "mailto:a@example.invalid", "share-a", a_directory),
                b.args.target: (b, "mailto:b@example.invalid", "share-b", b_directory)}
    # Real cryptographic validation is covered by the encrypted-envelope tests.
    def decrypt(packet, directory, keys):
        assert directory is a_directory
        return "verified-envelopes"

    def select(envelopes, share):
        assert (envelopes, share) == ("verified-envelopes", "share-a")
        return {"fm_id": share}

    monkeypatch.setattr(people_keys, "message_identity", lambda: {})
    monkeypatch.setattr(people_keys, "decrypt_selected_message", decrypt)
    monkeypatch.setattr(people_keys, "selected_key", select)
    monkeypatch.setattr(people_keys, "account_generation", lambda: 1)
    monkeypatch.setattr(people, "NATIVE", tmp_path)
    receiver = AsyncMock()
    topic = "com.apple.private.alloy.fmd"
    packet = {"t": b"a-device"}
    assert asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, packet, 1))
    receiver.acknowledge_verified.assert_awaited_once_with(packet, a_directory, topic, target_uri="mailto:a@example.invalid")
    assert people.read_share_key(a.args.target) == {"fm_id": "share-a"}
    assert people.read_share_key(b.args.target) is None
    assert not asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, {"t": b"unknown"}, 1))
    assert not asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, packet, 2))
