"""Read location reports from the native Find My Devices service on Linux."""
import argparse
import asyncio
import base64
from datetime import datetime, timezone
from hashlib import sha256
import json
import logging
import os
import time

from aiohttp import ClientError

from .environment import log_diagnostic
from .apple_probe import PRIVATE, PROXY, VerifiedHttpSession, account_generation, mark_reauth, save_private
from .native_people import AppleRequestError, apple_url
from .emulated_anisette import EmulatedMacAnisette
from ..protocol import Position, device_discovery_key

OUTPUT = PRIVATE / "native-devices.json"
MAX_AGE = 900


def device_target(identifier):
    return "device:" + sha256(identifier.encode()).hexdigest()


def supports_sound(device):
    features = device.get("features")
    return isinstance(features, dict) and features.get("SND") is True


def device_snapshot(devices, previous, now):
    catalog = {item["target_id"]: {"target_id": item["target_id"], "name": item["name"]}
               for item in previous}
    for device in devices:
        identifier = device.get("id")
        if not isinstance(identifier, str) or not identifier:
            continue
        target = device_target(identifier)
        sound = supports_sound(device)
        if target in catalog:
            catalog[target]["play_sound"] = sound
        location = device.get("location")
        if not device.get("locationEnabled") or not isinstance(location, dict) or location.get("isOld"):
            continue
        try:
            stamp = location["timeStamp"]
            if type(stamp) not in (int, float):
                continue
            report_time = datetime.fromtimestamp(stamp / 1000, tz=timezone.utc)
            position = {"target_id": target, "latitude": location["latitude"],
                        "longitude": location["longitude"], "accuracy": location["horizontalAccuracy"],
                        "timestamp": report_time.isoformat()}
            floor = location.get("floorLevel")
            if type(floor) is int:
                position["floor"] = floor
            Position.from_snapshot(position, target_id=target, now=now, max_age=MAX_AGE)
        except (KeyError, ValueError, TypeError, OSError, OverflowError):
            continue
        name = device.get("name") or device.get("deviceDisplayName") or "Apple device"
        catalog[target] = {"target_id": target, "name": name, "position": position, "play_sound": sound}
        if device.get("fmlyShare") is False and (discovery_key := device_discovery_key(device.get("deviceDiscoveryId"))):
            catalog[target]["discovery_key"] = discovery_key
    return {"schema_version": 1, "devices": list(catalog.values())}


async def _device_credentials(provider):
    state = json.loads((PRIVATE / "account.json").read_text())
    login = state["login"]["data"]
    mobileme = login["mobileme_data"]
    dsid = str(int(login["dsid"]))
    push = json.loads((PRIVATE / "apns-identity.json").read_text())
    host = mobileme["com.apple.Dataclass.DeviceLocator"]["appHostname"]
    url = apple_url(f"https://{host}/fmipservice/device/{dsid}")
    headers = await provider.get_headers(state["ids"]["uid"], push["device_id"])
    headers.update({"X-MMe-Client-Info": provider.client, "X-Apple-Realm-Support": "1.0",
                    "X-Apple-Find-API-Ver": "3.0", "X-Apple-AuthScheme": "Forever",
                    "User-Agent": "FindMy/310.3.1 CFNetwork/1408.0.4 Darwin/22.5.0",
                    "Accept": "application/json"})
    context = {"appName": "FindMy", "appVersion": "7.0", "deviceClass": "Mac",
               "productType": provider._model, "osVersion": provider._os,
               "deviceUDID": push["device_id"].upper(),
               "apsToken": base64.b64decode(push["token"], validate=True).hex().upper(),
               "fmly": True, "push": False, "shouldLocate": True, "selectedDevice": "all"}
    return url, (dsid, mobileme["tokens"]["mmeFMIPAppToken"]), headers, context


async def _request(http, credentials, route, body):
    url, auth, headers, _ = credentials
    reply = await http.post(f"{url}/{route}", auth=auth, headers=headers, json=body)
    if not reply.ok:
        raise AppleRequestError("Native Devices request rejected", reply.status_code)
    payload = reply.json() if reply._content else {}
    if not isinstance(payload, dict):
        raise ValueError("Invalid native Devices response")
    for result in (payload, payload.get("commandResponse")):
        if not isinstance(result, dict):
            continue
        status = result.get("statusCode", result.get("status"))
        if status is not None and str(status) != "200":
            code = int(status) if str(status).isdecimal() else None
            raise AppleRequestError("Native Devices request rejected", code)
    return payload


async def _init_client(http, credentials, *, locate):
    context = credentials[3] | {"shouldLocate": locate}
    payload = await _request(http, credentials, "initClient", {
        "clientContext": context, "serverContext": {},
    })
    if not isinstance(payload.get("content"), list):
        raise ValueError("Invalid native Devices response")
    return payload


async def fetch_devices(provider, http):
    credentials = await _device_credentials(provider)
    return (await _init_client(http, credentials, locate=True))["content"]


class SoundTargetUnavailable(RuntimeError):
    """The current account did not advertise sound for the selected device."""


async def play_sound(provider, http, target):
    credentials = await _device_credentials(provider)
    devices = await _init_client(http, credentials, locate=False)
    matches = [
        device for device in devices["content"] if isinstance(device.get("id"), str)
        and device_target(device["id"]) == target
    ]
    if len(matches) != 1 or not supports_sound(matches[0]):
        raise SoundTargetUnavailable
    identifier = matches[0]["id"]
    await _request(http, credentials, "playSound", {
        "device": identifier,
        "subject": "Find My",
        "clientContext": credentials[3] | {"shouldLocate": False, "selectedDevice": identifier},
        "serverContext": devices.get("serverContext") or {},
    })


async def run(interval, *, provider=None):
    owns_provider = provider is None
    provider = provider or EmulatedMacAnisette.from_json()
    http = VerifiedHttpSession(PROXY, persist_cookies=False)
    try:
        previous = json.loads(OUTPUT.read_text())["devices"] if OUTPUT.is_file() else []
        failures = 0
        while True:
            started = time.monotonic()
            generation = account_generation()
            try:
                devices = await fetch_devices(provider, http)
                fetched = time.monotonic()
                snapshot = device_snapshot(devices, previous, datetime.now(timezone.utc))
                save_private(OUTPUT, snapshot)
                prior_stamps = {
                    row["target_id"]: row["position"].get("timestamp")
                    for row in previous if isinstance(row.get("position"), dict)
                }
                previous = snapshot["devices"]
                located = [row for row in previous if "position" in row]
                mark_reauth("devices", generation, required=False)
                log_diagnostic(json.dumps({
                    "stage": "device_poll", "listed": len(devices), "discovered": len(previous),
                    "located": len(located),
                    "report_time_changed": sum(prior_stamps.get(row["target_id"]) != row["position"]["timestamp"]
                                               for row in located),
                    "play_sound_available": sum(row.get("play_sound") is True for row in previous),
                    "fetch_ms": round((fetched - started) * 1000),
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                }), flush=True)
                if failures:
                    log_diagnostic(json.dumps({"stage": "device_poll", "result": "recovered",
                                               "previous_failures": failures}), level=logging.INFO)
                    failures = 0
                delay = interval
            except (AppleRequestError, ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
                if interval is None:
                    raise
                failures += 1
                status = getattr(error, "status", None)
                if status == 401:
                    mark_reauth("devices", generation, required=True)
                delay = max(interval, 1800 if status in (401, 429) else 300)
                log_diagnostic(json.dumps({
                    "stage": "device_poll", "error_type": type(error).__name__,
                    "http_status": status, "retry_seconds": delay, "consecutive_failures": failures,
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                }), flush=True, level=logging.DEBUG if status == 401 else logging.WARNING)
            if interval is None:
                return
            while (remaining := started + delay - time.monotonic()) > 0:
                await asyncio.sleep(min(15, remaining))
                if generation != account_generation():
                    break
    finally:
        await http.close()
        if owns_provider:
            await provider.close()


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--poll-interval", type=int, choices=range(60, 3601), metavar="60..3600")
    asyncio.run(run(parser.parse_args().poll_interval))
