from datetime import datetime, timedelta, timezone
from pathlib import Path


def test_discovery_is_stable_and_missing_locations_become_unavailable(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "scripts"))
    from native_devices import device_snapshot

    now = datetime(2026, 11, 16, tzinfo=timezone.utc)
    location = {"timeStamp": now.timestamp() * 1000, "latitude": 20.0,
                "longitude": 110.0, "horizontalAccuracy": 10.0}
    phone = {"id": "phone-id", "name": "iPhone", "locationEnabled": True, "location": location}
    tablet = {"id": "tablet-id", "name": "iPad", "locationEnabled": True, "location": None}

    first = device_snapshot([phone, tablet], [], now)["devices"]
    assert len(first) == 1 and "position" in first[0]

    second = device_snapshot([phone, phone, tablet | {"location": location}], first, now)["devices"]
    assert len(second) == 2 and second[0]["target_id"] == first[0]["target_id"]

    later = device_snapshot([phone, tablet], second, now + timedelta(minutes=16))["devices"]
    assert [device["target_id"] for device in later] == [device["target_id"] for device in second]
    assert all("position" not in device for device in later)


def test_sound_capability_survives_a_missing_location():
    from custom_components.apple_find.backend.native_devices import device_snapshot, device_target

    now = datetime(2026, 11, 16, tzinfo=timezone.utc)
    previous = [{"target_id": device_target("phone-id"), "name": "iPhone"}]
    listed = [{"id": "phone-id", "features": {"SND": True}}]
    snapshot = device_snapshot(listed, previous, now)["devices"]
    assert snapshot == [previous[0] | {"play_sound": True}]


def test_device_poll_diagnostics_distinguish_new_and_repeated_reports(monkeypatch, tmp_path):
    import asyncio
    import json
    from unittest.mock import AsyncMock

    from custom_components.apple_find.backend import native_devices

    now = datetime.now(timezone.utc)
    phone = {"id": "private-device-id", "name": "private-name", "locationEnabled": True,
             "location": {"timeStamp": now.timestamp() * 1000, "latitude": 12.345678,
                          "longitude": 90.123456, "horizontalAccuracy": 5}}
    monkeypatch.setattr(native_devices, "fetch_devices", AsyncMock(return_value=[phone]))
    monkeypatch.setattr(native_devices, "VerifiedHttpSession", lambda *args, **kwargs: AsyncMock())
    monkeypatch.setattr(native_devices, "account_generation", lambda: "test")
    monkeypatch.setattr(native_devices, "mark_reauth", lambda *args, **kwargs: None)
    monkeypatch.setattr(native_devices, "OUTPUT", tmp_path / "snapshot.json")
    messages = []
    monkeypatch.setattr(native_devices, "log_diagnostic", lambda message, **_: messages.append(message))

    for _ in range(2):
        asyncio.run(native_devices.run(None, provider=object()))
    polls = [json.loads(message) for message in messages]
    assert [poll["report_time_changed"] for poll in polls] == [1, 0]
    assert all(poll["listed"] == poll["located"] == 1 for poll in polls)
    assert all(0 <= poll["fetch_ms"] <= poll["elapsed_ms"] for poll in polls)
    assert all(private not in message for private in ("private-device-id", "private-name", "12.345678", "90.123456")
               for message in messages)


def test_play_sound_addresses_only_the_currently_supported_device(monkeypatch):
    import asyncio
    import json
    from unittest.mock import AsyncMock

    import pytest
    from findmy.util.http import HttpResponse

    from custom_components.apple_find.backend import native_devices

    async def exercise():
        other = {"id": "other-id", "name": "iPhone", "features": {"SND": True}}
        phone = {"id": "phone-id", "name": "iPhone", "features": {"SND": True}}
        init = {"statusCode": "200", "content": [other, phone], "serverContext": {"version": 3}}
        credentials = ("https://example.apple.com/fmipservice/device/123", ("123", "token"), {}, {})
        monkeypatch.setattr(native_devices, "_device_credentials", AsyncMock(return_value=credentials))
        provider = object()

        def http_with(*responses):
            http = AsyncMock()
            http.post.side_effect = [HttpResponse(200, json.dumps(response).encode()) for response in responses]
            return http

        target = native_devices.device_target(phone["id"])
        http = http_with(init, {"statusCode": "200"})
        await native_devices.play_sound(provider, http, target)
        init_call, sound_call = http.post.await_args_list
        assert init_call.args[0].endswith("/initClient")
        assert init_call.kwargs["json"]["clientContext"]["shouldLocate"] is False
        assert sound_call.args[0].endswith("/playSound")
        assert sound_call.kwargs["json"]["device"] == phone["id"]
        assert sound_call.kwargs["json"]["serverContext"] == init["serverContext"]

        http = http_with(init | {"content": [other, phone | {"features": {"SND": False}}]})
        with pytest.raises(native_devices.SoundTargetUnavailable):
            await native_devices.play_sound(provider, http, target)
        assert http.post.await_count == 1

        http = http_with(init, {"statusCode": "403"})
        with pytest.raises(native_devices.AppleRequestError) as error:
            await native_devices.play_sound(provider, http, target)
        assert error.value.status == 403
        assert http.post.await_count == 2

    asyncio.run(exercise())
