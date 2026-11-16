"""Synthetic tests; do not import native frameworks or read account state."""
import asyncio
from argparse import Namespace
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    import native_people
    return native_people


def test_polling_uses_independent_state_for_each_family_member(monkeypatch, tmp_path):
    native = module(monkeypatch)
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps(["mailto:First@example.invalid", "tel:+12345678901"]))
    args = Namespace(target=None, targets_file=targets, snapshot=None)
    first, second = native.poll_targets(args)
    assert first.args.target == "first@example.invalid"
    assert second.args.target == "tel:+12345678901"

    async def collect(args, *, refresh_key):
        assert not refresh_key
        return args.target == second.args.target

    monkeypatch.setattr(native, "collect_once", collect)
    monkeypatch.setattr(native.time, "monotonic", lambda: 1000)
    assert asyncio.run(native.poll_target(first, 60)) == 0
    assert asyncio.run(native.poll_target(second, 60)) == 0
    assert first.needs_refresh and first.due == 1300
    assert not second.needs_refresh and second.due == 1060


def test_response_persists_only_exact_selected_relationship_and_location(monkeypatch, tmp_path):
    native = module(monkeypatch)
    monkeypatch.setattr(native, "NATIVE", tmp_path)
    client = native.PeopleClient.__new__(native.PeopleClient)
    client.target = "target@example.com"
    client.state = {"account": {"username": "synthetic@example.com"}}
    client.provider = SimpleNamespace(_os="test", _model="test")
    client.push = {"device_id": "test-device", "token": "YQ=="}
    client.base, client.dsid = "https://test.icloud.com/", "test-dsid"
    client.tokens = {"mmeFMFAppToken": "synthetic"}
    client.context, client.data_context, client.model, client.selected = {}, {}, "1", None
    fixture = {"following": [
        {"id": "other-id", "invitationAcceptedHandles": ["someone@example.com"]},
        {"id": "selected-id", "invitationAcceptedHandles": ["mailto:" + client.target]},
    ], "locations": [{"id": "other-id", "location": {"do_not_save": "other-location"}},
                     {"id": "selected-id", "location": {"selected_field": "synthetic-location"}}]}

    selections = []

    async def post(*args, **kwargs):
        selections.append(kwargs["json"]["clientContext"])
        return native.HttpResponse(200, json.dumps(fixture).encode())

    async def headers():
        return {}

    client.http, client.headers = SimpleNamespace(post=post), headers
    asyncio.run(client.friends("initClient"))
    asyncio.run(client.friends("minCallback/refreshClient"))
    asyncio.run(client.friends("minCallback/selFriend/refreshClient"))
    assert all("selectedHandlesMap" not in c for c in selections[:2])
    assert selections[2]["selectedHandlesMap"] == {client.target: selections[2]["currentTime"]}
    assert all(c["callerIdHandle"] == c["signedInAs"] == "synthetic@example.com" for c in selections)
    assert all("selectedFriend" not in c for c in selections)
    assert client.selected == "selected-id"
    saved = "".join(p.read_text() for p in tmp_path.iterdir())
    assert "other-location" not in saved and "someone@example.com" not in saved
    assert "synthetic-location" in saved


@pytest.mark.parametrize("url", ["http://gateway.icloud.com/fetch", "https://icloud.com.evil.test/fetch", "https://gateway.icloud.com:8443/fetch"])
def test_credentials_are_never_forwarded_to_non_apple_endpoint(monkeypatch, url):
    with pytest.raises(ValueError):
        module(monkeypatch).apple_url(url)


def test_application_ack_rejects_unselected_sender(monkeypatch):
    module(monkeypatch)
    from ids_receiver import Receiver
    receiver = Receiver.__new__(Receiver)
    receiver.target_uri = "mailto:target@example.com"
    with pytest.raises(ValueError, match="selected sender"):
        asyncio.run(receiver.acknowledge_verified({"sP": "mailto:other@example.com"}, {"identities": []}, "com.apple.private.alloy.fmd"))


def test_incoming_courier_topic_and_selected_device_alias(monkeypatch):
    module(monkeypatch)
    import ids_receiver
    import plistlib

    receiver = ids_receiver.Receiver.__new__(ids_receiver.Receiver)
    receiver.target_uri = "mailto:target@example.invalid"
    receiver.selected_push_tokens = {b"sender-push-token"}
    receiver.push = {"token": "YQ=="}
    receiver.reader = None
    receiver.pending = {}
    receiver.notifications = asyncio.Queue()
    receiver.unsolicited = {}
    receiver.counters = dict.fromkeys(
        ("notifications", "pair_ec_messages", "selected_sender", "selected_token", "selected_pair_ec"), 0,
    )
    topic = next(digest for digest, name in ids_receiver.TOPICS_BY_HASH.items()
                 if name == "com.apple.private.alloy.fmd")
    payload = {"c": 242, "E": "pair-ec", "sP": "tel:+12345678901", "t": b"sender-push-token"}
    frames = iter([(0x0A, [(1, b"receiver-token"), (2, topic),
                          (3, plistlib.dumps(payload)), (4, b"msg1")])])

    async def read_frame(_):
        result = next(frames, None)
        if result is None:
            raise asyncio.CancelledError
        return result

    async def drain():
        pass

    receiver.writer = SimpleNamespace(write=lambda _: None, drain=drain)
    monkeypatch.setattr(ids_receiver, "read_frame", read_frame)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(receiver.read_loop())
    assert receiver.notifications.get_nowait() == (topic, payload)
    assert receiver.counters["selected_sender"] == 0
    assert receiver.counters["selected_token"] == 1
    assert receiver.unsolicited == {"com.apple.private.alloy.fmd:242": 1}


def test_courier_disconnect_interrupts_key_wait(monkeypatch):
    module(monkeypatch)
    import ids_receiver

    async def run():
        receiver = ids_receiver.Receiver.__new__(ids_receiver.Receiver)
        receiver.notifications = asyncio.Queue()
        receiver.courier_error = "IncompleteReadError"
        receiver.task = asyncio.create_task(asyncio.sleep(0))
        with pytest.raises(ids_receiver.CourierDisconnected, match="IncompleteReadError"):
            await asyncio.wait_for(receiver.next_notification(300), 1)

    asyncio.run(run())


def test_key_request_refreshes_the_share_with_courier_already_online(monkeypatch, tmp_path):
    native = module(monkeypatch)
    monkeypatch.setattr(native, "NATIVE", tmp_path)
    events = []

    class Client:
        def __init__(self, target):
            self.target = target
            self.state = {"account": {"username": "owner@example.invalid"}}
            self.http = None
            self.selected = None

        async def friends(self, route):
            assert self.push == {"current": True}
            events.append(route)
            self.selected = "share"

        async def fetch(self):
            events.append("distribute")

        async def close(self):
            pass

    class Receiver:
        push = {"current": True}
        counters = {}
        unsolicited = {}

        def __init__(self, *args):
            pass

        async def start(self):
            events.append("courier")

        async def lookup_selected(self, _):
            events.append("directory")
            return {}

        async def next_notification(self, _):
            raise TimeoutError

        async def close(self):
            pass

    monkeypatch.setattr(native, "PeopleClient", Client)
    monkeypatch.setattr(native, "Receiver", Receiver)
    args = Namespace(target="member@example.invalid", self_uri=None, snapshot=None,
                     keys=True, check_receiver=False, wait=1)
    assert asyncio.run(native.collect_once(args)) is False
    assert events == ["courier", "directory", "initClient", "minCallback/refreshClient",
                      "minCallback/selFriend/refreshClient", "distribute"]


def test_discovery_only_lists_accepted_incoming_shares_and_deduplicates_aliases(monkeypatch):
    native = module(monkeypatch)
    contacts, = native.shared_contacts({
        "following": [
            {"id": "same-person", "invitationAcceptedHandles": ["mailto:Friend@example.invalid", "+12345678901"],
             "optedNotToShare": True},
            {"id": "same-person", "invitationAcceptedHandles": ["friend@example.invalid", "tel:+12345678901"]},
            {"id": "pending", "invitationFromHandles": ["pending@example.invalid"]},
            {"id": "event-only", "invitationAcceptedHandles": ["event@example.invalid"], "onlyInEvent": True},
        ],
        "followers": [{"id": "outgoing", "invitationAcceptedHandles": ["outgoing@example.invalid"]}],
    })
    assert contacts.handles == ("friend@example.invalid", "tel:+12345678901")
    assert contacts.name == "friend@example.invalid"
    renamed, = native.shared_contacts({"following": [
        {"id": "same-person", "invitationAcceptedHandles": ["new@example.invalid"], "displayName": "Other name"},
    ]})
    assert renamed.target == contacts.target
    assert renamed.snapshot_name != contacts.snapshot_name
    assert renamed.name == "Other name"
    assert native.shared_contacts({"following": []}) == ()
    with pytest.raises(ValueError, match="following list"):
        native.shared_contacts({"followers": []})


def test_selected_relationship_must_match_when_alias_is_reused(monkeypatch, tmp_path):
    native = module(monkeypatch)
    monkeypatch.setattr(native, "NATIVE", tmp_path)
    client = native.PeopleClient.__new__(native.PeopleClient)
    client.target = "tel:+12345678901"
    client.selected = "stale"
    client.relationship_id = "original-share"

    async def friends_request(route):
        return {"following": [
            {"id": "other-share", "invitationAcceptedHandles": ["tel:+12345678901"]},
            {"id": "original-share", "invitationAcceptedHandles": ["+12345678901"]},
        ], "locations": [
            {"id": "other-share", "location": {"other": True}},
            {"id": "original-share", "location": {"expected": True}},
        ]}, {}

    client.context = client.data_context = {}
    client._friends_request = friends_request
    assert asyncio.run(client.friends("initClient")) == [
        {"id": "original-share", "location": {"expected": True}},
    ]
    client.relationship_id = "revoked-share"
    assert asyncio.run(client.friends("initClient")) == []
    assert client.selected is None


def test_me_uses_apple_selected_device_and_only_matches_owned_location(monkeypatch):
    native = module(monkeypatch)
    from custom_components.apple_findmy_people.backend.native_devices import device_snapshot

    payload = {"myInfo": {"deviceId": "requesting-client", "meDeviceId": "selected"},
               "devices": [{"id": "selected", "idsDeviceId": "MATCH-ID"},
                           {"id": "requesting-client", "idsDeviceId": "client-id"}]}
    identifier = native.own_location_device(payload)
    assert identifier
    assert native.own_location_device(payload | {"devices": []}) is None

    now = native.datetime.now(native.timezone.utc)
    phone = {"deviceDiscoveryId": "match-id", "name": "Same name", "locationEnabled": True,
             "location": {"timeStamp": now.timestamp()*1000, "latitude": 1,
                          "longitude": 2, "horizontalAccuracy": 10}}
    devices = [phone | {"id": "owned", "fmlyShare": False},
               phone | {"id": "family", "fmlyShare": True}]
    owned, family = device_snapshot(devices, [], now)["devices"]
    assert owned["discovery_key"] == identifier
    assert "discovery_key" not in family
