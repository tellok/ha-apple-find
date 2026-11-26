"""Check cross-contact delivery and independent location polling."""

import asyncio
from argparse import Namespace
from datetime import datetime, timezone
import json
import logging
from unittest.mock import AsyncMock

import pytest

from custom_components.apple_find.backend import native_people as people, people_keys
from custom_components.apple_find.backend import environment as settings


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


def test_delayed_delivery_routes_to_verified_contact(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(settings, "environment", settings.Environment.for_core(tmp_path))
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
    with caplog.at_level(logging.DEBUG, logger="custom_components.apple_find"):
        assert asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, packet, 1))
    assert '"result": "verified"' in caplog.text
    assert all(value not in caplog.text for value in (a.args.target, b.args.target, "share-a", "a-device"))
    receiver.acknowledge_verified.assert_awaited_once_with(packet, a_directory, topic, target_uri="mailto:a@example.invalid")
    assert people.read_share_key(a.args.target) == {"fm_id": "share-a"}
    assert people.read_share_key(b.args.target) is None
    assert not asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, {"t": b"unknown"}, 1))
    assert not asyncio.run(people_keys.handle_delivery(receiver, bindings, topic, packet, 2))


@pytest.fixture
def scheduler_clock(monkeypatch):
    clock = Namespace(now=1000.0)
    monkeypatch.setattr(people, "time", Namespace(monotonic=lambda: clock.now))
    monkeypatch.setattr(people, "account_generation", lambda: 1)
    monkeypatch.setattr(people, "read_share_key", lambda _: {"fm_id": "share-a"})
    monkeypatch.setattr(people, "mark_reauth", lambda *args, **kwargs: None)
    return clock


def test_hint_during_successful_fetch_is_due_as_soon_as_fetch_finishes(monkeypatch, scheduler_clock):
    target = people.PollTarget(Namespace(target="a@example.invalid"), refresh_requested=True)

    async def receive_hint_while_fetching(*args, **kwargs):
        assert not target.refresh_requested
        target.refresh_requested = True
        scheduler_clock.now += 3
        return True

    monkeypatch.setattr(people, "collect_once", receive_hint_while_fetching)
    asyncio.run(people.poll_target(target, 60, shared_keys=True))
    assert target.refresh_requested
    assert target.next_poll <= scheduler_clock.now < target.due
    monkeypatch.setattr(people, "collect_once", AsyncMock(return_value=True))
    asyncio.run(people.poll_target(target, 60, shared_keys=True))
    assert not target.refresh_requested
    assert target.next_poll == scheduler_clock.now + 60
    target.refresh_requested = True
    assert target.next_poll <= scheduler_clock.now


@pytest.mark.parametrize(("error", "result"), [
    (people.AppleRequestError("unauthorized", 401), -1),
    (people.AppleRequestError("unavailable", 503), 0),
    (OSError("offline"), 0),
])
def test_hint_does_not_shorten_error_retry(monkeypatch, scheduler_clock, error, result):
    target = people.PollTarget(Namespace(target="a@example.invalid"))
    monkeypatch.setattr(people, "collect_once", AsyncMock(side_effect=error))
    assert asyncio.run(people.poll_target(target, 60, shared_keys=True)) == result
    target.refresh_requested = True
    assert target.next_poll == scheduler_clock.now + 300


def test_rate_limit_defers_other_contacts_even_with_pending_hints(monkeypatch, scheduler_clock, tmp_path, caplog):
    monkeypatch.setattr(settings, "environment", settings.Environment.for_core(tmp_path))
    targets = [people.PollTarget(Namespace(target=handle), refresh_requested=True)
               for handle in ("a@example.invalid", "b@example.invalid")]
    collect = AsyncMock(side_effect=people.AppleRequestError("rate limited", 429))
    monkeypatch.setattr(people, "collect_once", collect)

    async def run_until_suspended():
        wake = asyncio.Event()
        wake.wait = AsyncMock(side_effect=asyncio.CancelledError)
        with pytest.raises(asyncio.CancelledError):
            await people.run(Namespace(poll_interval=60), targets=targets, shared_keys=True, wake=wake)

    asyncio.run(run_until_suspended())
    collect.assert_awaited_once()
    warnings = [json.loads(r.getMessage()) for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [{"stage": "people_poll", "result": "rate_limited", "http_status": 429, "retry_seconds": 2700}]
    for target in targets:
        target.refresh_requested = True
        assert target.next_poll == scheduler_clock.now + 2700


def test_household_hint_wakes_scheduler_and_publishes_fetched_report(monkeypatch, tmp_path, scheduler_clock, caplog):
    monkeypatch.setattr(settings, "environment", settings.Environment.for_core(tmp_path))
    snapshot = tmp_path / "position.json"
    (tmp_path / "account.json").write_text('{"account":{"username":"self@example.invalid"}}')
    monkeypatch.setattr(people, "NATIVE", tmp_path)
    monkeypatch.setattr(people_keys, "account_generation", lambda: 1)
    monkeypatch.setattr(people_keys, "VerifiedHttpSession", lambda *args, **kwargs: AsyncMock())
    target = people.PollTarget(Namespace(target="a@example.invalid", relationship_id="share-a", keys=True,
                                        self_uri="mailto:self@example.invalid", snapshot=snapshot),
                               due=scheduler_clock.now + 60)

    async def exercise():
        received = asyncio.Event()
        connected = asyncio.get_running_loop().create_future()
        timestamp_ms = int(datetime.now(timezone.utc).timestamp() * 1000) - 2000
        report = {"locationTs": timestamp_ms, "plaintext": {"latitude": 25, "longitude": 121, "accuracy": 20}}
        newer = {"locationTs": timestamp_ms + 1000, "plaintext": {**report["plaintext"], "latitude": 25.001}}

        class ReportClient(people.PeopleClient):
            def __init__(self, handle):
                self.target = handle
                self.selected = "share-a"

            friends = AsyncMock()
            fetch = AsyncMock(side_effect=([report], [report], [report, newer], [report]))
            close = AsyncMock(side_effect=received.set)

        def receiver(*args, on_searchparty_notification):
            async def next_notification(timeout):
                connected.set_result(on_searchparty_notification)
                await asyncio.Future()  # Connection stays open until household shutdown.

            fake = AsyncMock()
            fake.next_notification = next_notification
            return fake

        monkeypatch.setattr(people_keys, "Receiver", receiver)
        monkeypatch.setattr(people, "PeopleClient", ReportClient)
        task = asyncio.create_task(people_keys.run_household(Namespace(poll_interval=60), [target]))
        try:
            notify = await asyncio.wait_for(connected, 1)
            notify()
            notify()
            await asyncio.wait_for(received.wait(), 1)
            ReportClient.fetch.assert_awaited_once_with({"fm_id": "share-a"})
            saved, = json.loads(snapshot.read_text())["positions"]
            assert saved["target_id"] == "friend:a@example.invalid"
            assert saved["latitude"] == 25
            assert saved["longitude"] == 121
            assert saved["timestamp"] == datetime.fromtimestamp(timestamp_ms / 1000, timezone.utc).isoformat()
            assert target.next_poll == scheduler_clock.now + 60
            received.clear()
            notify()
            await asyncio.wait_for(received.wait(), 1)
            assert ReportClient.fetch.await_count == 2
            assert json.loads(snapshot.read_text())["positions"] == [saved]
            for expected_count in (3, 4):
                received.clear()
                notify()
                await asyncio.wait_for(received.wait(), 1)
                assert ReportClient.fetch.await_count == expected_count
                latest, = json.loads(snapshot.read_text())["positions"]
                assert latest["latitude"] == newer["plaintext"]["latitude"]
                assert latest["timestamp"] == datetime.fromtimestamp(newer["locationTs"] / 1000, timezone.utc).isoformat()
            assert target.next_poll == scheduler_clock.now + 60
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    with caplog.at_level(logging.DEBUG, logger="custom_components.apple_find"):
        asyncio.run(exercise())
    events = [json.loads(r.getMessage()) for r in caplog.records if r.levelno == logging.DEBUG
              and r.name.startswith("custom_components.apple_find")]
    hints = [e["newly_requested"] for e in events if e.get("result") == "searchparty_hint"]
    assert hints == [1, 0, 1, 1, 1]
    polls = [e for e in events if e.get("result") == "completed"]
    assert len(polls) == 4
    assert all(e["trigger"] == "push" and e["elapsed_ms"] == 0 and e["share_slot"] == 1 for e in polls)
    snapshots = [e for e in events if e["stage"] == "snapshot"]
    assert [e["result"] for e in snapshots] == ["updated", "already_current", "updated", "already_current"]
    assert all("report_age_seconds" in e and e["fresh"] for e in snapshots)
    assert all(value not in caplog.text for value in (target.args.target, "self@example.invalid", "share-a",
                                                       "latitude", "longitude"))


def test_receiver_logs_one_warning_until_the_connection_recovers(monkeypatch, tmp_path, caplog):
    (tmp_path / "account.json").write_text('{"account":{"username":"self@example.invalid"}}')
    monkeypatch.setattr(people, "NATIVE", tmp_path)
    monkeypatch.setattr(settings, "environment", settings.Environment.for_core(tmp_path))
    monkeypatch.setattr(people_keys, "account_generation", lambda: 1)
    monkeypatch.setattr(people_keys, "VerifiedHttpSession", lambda *args, **kwargs: AsyncMock())
    receiver = AsyncMock()
    receiver.start.side_effect = [OSError("private error detail"), OSError("private error detail"), None]
    receiver.next_notification.side_effect = [TimeoutError(), asyncio.CancelledError()]
    monkeypatch.setattr(people_keys, "Receiver", lambda *args, **kwargs: receiver)
    monkeypatch.setattr(people_keys.asyncio, "sleep", AsyncMock())
    with caplog.at_level(logging.DEBUG, logger="custom_components.apple_find"), pytest.raises(asyncio.CancelledError):
        asyncio.run(people_keys.watch_keys([], asyncio.Event()))
    records = [(r.levelno, json.loads(r.getMessage())) for r in caplog.records
               if r.name.startswith("custom_components.apple_find")]
    assert [(level, e["result"]) for level, e in records] == [
        (logging.WARNING, "retrying"), (logging.DEBUG, "retrying"), (logging.INFO, "recovered")]
    assert records[-1][1]["outage_seconds"] >= 0
    assert "private error detail" not in caplog.text
