"""Native Find My People protocol probe, limited to one accepted share.

The Linux CoreADI emulator supplies authentication headers. Existing IDS/APNs keys are reused;
unselected relationships and location reports are never persisted or printed.
"""
import argparse
import asyncio
import base64
from contextlib import AsyncExitStack
from dataclasses import dataclass
import hashlib
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import plistlib
import re
import sys
import time
from urllib.parse import urlsplit

from aiohttp import ClientError

from .environment import log_diagnostic, environment, module_command
from .apple_probe import PRIVATE, PROXY, VerifiedHttpSession, account_generation, mark_reauth, save_private
from .emulated_anisette import EmulatedMacAnisette
from .ids_receiver import CourierDisconnected, Receiver, TOPICS_BY_HASH
from .ids_register import message_identity
from .location_pipeline import decrypt_selected_message, selected_key
from cryptography.exceptions import InvalidSignature, InvalidTag
from ..protocol import device_discovery_key, fetch_body, decrypt_report, decode_share_key, position_from_report
from findmy.util.http import HttpResponse

NATIVE = PRIVATE
FRESH_LOCATION_SECONDS = 300


def normalize_target(handle):
    return handle.strip().lower().removeprefix("mailto:")


@dataclass(frozen=True)
class SharedContact:
    relationship_id: str
    handles: tuple[str, ...]
    name: str

    @property
    def target(self):
        return "contact:" + hashlib.sha256(self.relationship_id.encode()).hexdigest()

    @property
    def snapshot_name(self):
        handle_hash = hashlib.sha256(self.handles[0].encode()).hexdigest()[:20]
        return f"{self.target.removeprefix('contact:')}-{handle_hash}.json"


def shared_contacts(payload):
    """Return accepted incoming shares. Followers are people who can see us."""
    following = payload.get("following")
    if not isinstance(following, list):
        raise ValueError("Missing Find My following list")
    ids, names = {}, {}
    for row in following:
        if not isinstance(row, dict) or row.get("onlyInEvent") is True:
            continue
        relationship_id = row.get("id")
        aliases = row.get("invitationAcceptedHandles")
        if not isinstance(relationship_id, str) or not relationship_id or not isinstance(aliases, list):
            continue
        for alias in aliases:
            if not isinstance(alias, str):
                continue
            handle = normalize_target(alias)
            if handle.startswith("+"):
                handle = "tel:" + handle
            if re.fullmatch(r"tel:\+[1-9]\d{6,14}|[^\s:@]+@[^\s:@]+\.[^\s:@]+", handle):
                ids.setdefault(relationship_id, set()).add(handle)
                for field in ("displayName", "name"):
                    if isinstance(name := row.get(field), str) and name.strip():
                        names[relationship_id] = name.strip()
                        break
    contacts = []
    for relationship_id, aliases in sorted(ids.items()):
        handles = tuple(sorted(aliases, key=lambda h: (h.startswith("tel:"), h)))
        contacts.append(SharedContact(relationship_id, handles, names.get(relationship_id, handles[0].removeprefix("tel:"))))
    return tuple(contacts)


def own_location_device(payload):
    """Read the device selected by Apple for sharing our location."""
    me = payload.get("myInfo")
    me_id = me.get("meDeviceId") if isinstance(me, dict) else None
    devices = payload.get("devices")
    if not isinstance(me_id, str) or not me_id or not isinstance(devices, list):
        return None
    matches = [
        device_discovery_key(device.get("idsDeviceId"))
        for device in devices if isinstance(device, dict) and device.get("id") == me_id
    ]
    return matches[0] if len(matches) == 1 else None


def contact_position_ttl(payload):
    """The Friends response supplies the last-known location TTL in milliseconds."""
    config = payload.get("config")
    ttl = config.get("locationTTL") if isinstance(config, dict) else None
    if type(ttl) is int and ttl >= 1000:
        return min(7200, ttl // 1000)
    return FRESH_LOCATION_SECONDS


@dataclass
class PollTarget:
    args: argparse.Namespace
    due: float = 0.0
    next_key_refresh: float = 0.0
    needs_refresh: bool = False
    refresh_requested: bool = False
    not_before: float = 0.0
    share_slot: int | None = None

    @property
    def next_poll(self):
        return self.not_before if self.refresh_requested else self.due

    def defer_until(self, deadline):
        self.not_before = max(self.not_before, deadline)
        self.due = max(self.due, deadline)


class AppleRequestError(RuntimeError):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def apple_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.port not in (None, 443) or not parsed.hostname or parsed.username or not any(
            parsed.hostname.endswith("." + host) for host in ("icloud.com", "icloud.com.cn", "apple.com")):
        raise ValueError("Unexpected Apple endpoint")
    return value


class PeopleClient:
    def __init__(self, target, *, provider=None):
        self.target = normalize_target(target) if target is not None else None
        self.relationship_id = None
        account_path = NATIVE / "account.json"
        settings_path = NATIVE / "findmy-settings.json"
        self.state = json.loads(account_path.read_text())
        self.settings = json.loads(settings_path.read_text())
        self.dsid = str(self.state["login"]["data"]["dsid"])
        if str(self.settings["dsid"]) != self.dsid:
            raise ValueError("Find My service settings belong to another account")
        self.tokens = dict(self.state["login"]["data"]["mobileme_data"]["tokens"])
        if settings_path.stat().st_mtime_ns >= account_path.stat().st_mtime_ns:
            self.tokens.update(self.settings.get("tokens", {}))
        self.push = json.loads((PRIVATE / "apns-identity.json").read_text())
        self.owns_provider = provider is None
        self.provider = provider or EmulatedMacAnisette.from_json()
        self.http = VerifiedHttpSession(PROXY, persist_cookies=target is not None)
        self.context = {"authToken": base64.b64encode(self.tokens["mmeFMFAppToken"].encode()).decode(),
                        "clientId": base64.b64encode(f"friends/fmfd~~{self.dsid}~~{int(time.time() * 1000)}".encode()).decode(),
                        "prsId": self.dsid}
        self.data_context = {}
        self.model = "1"
        self.selected = None
        config = self.settings["config"]
        people_url = config.get("com.apple.Dataclass.FindMyLocate", {}).get("people_url")
        if not people_url:
            people_url = "https://" + config["com.apple.Dataclass.ShareLocation"]["appHostname"]
        host = urlsplit(apple_url(people_url)).netloc
        self.base = apple_url(f"https://{host}/fmipservice/friends/fmfd/{self.dsid}/{self.push['device_id'].upper()}/")

    async def headers(self):
        headers = await self.provider.get_headers(self.state["ids"]["uid"], self.push["device_id"])
        headers.update({"User-Agent": "FMFD/1.0 CFNetwork/1408.0.4 Darwin/22.5.0",
                        "X-Mme-Client-Info": self.provider.client,
                        "X-Apple-Realm-Support": "1.0", "X-Apple-AuthScheme": "Forever",
                        "X-Apple-Find-API-Ver": "2.0", "X-FMF-Model-Version": self.model,
                        "Accept": "application/json", "Accept-Language": "en-US,en;q=0.9",
                        "Content-Type": "application/json"})
        return headers

    async def _friends_request(self, route):
        account = self.state["account"]["username"]
        now_ms = int(time.time() * 1000)
        context = {"appName": "findmylocated", "appVersion": "7.0",
                   "apsToken": base64.b64decode(self.push["token"]).hex().upper(),
                   "callerIdHandle": account, "signedInAs": account,
                   "contextBundleApp": "com.apple.findmy.findmylocated",
                   "currentTime": now_ms, "deviceClass": "Mac",
                   "deviceUDID": self.push["device_id"].upper(),
                   "osVersion": self.provider._os, "productType": self.provider._model,
                   "platform": "macosx", "deviceHasPasscode": True,
                   "fencingEnabled": False, "isFMFAppRemoved": False}
        if "selFriend" in route and self.selected:
            # The native request maps Handle.identifier to its tracking timestamp.
            # The relationship ID is sent separately in the SearchParty fetch.
            context["selectedHandlesMap"] = {self.target.removeprefix("tel:"): now_ms}
        response = await self.http.post(self.base + route,
            auth=(self.dsid, self.tokens["mmeFMFAppToken"]), headers=await self.headers(),
            json={"clientContext": context, "serverContext": self.context, "dataContext": self.data_context})
        diagnostic = {"stage": route, "http_status": response.status_code}
        if not response.ok:
            save_private(NATIVE / "people-status.json", diagnostic)
            log_diagnostic(json.dumps(diagnostic), flush=True)
            raise AppleRequestError("Friends request rejected", response.status_code)
        data = response.json()
        status = str(data.get("statusCode"))
        if status in ("401", "429"):
            raise AppleRequestError("Friends request rejected", int(status))
        self.context.update(data.get("serverContext") or {})
        self.data_context = data.get("dataContext", self.data_context)
        # Some versions carry the version in their context rather than headers.
        self.model = str(getattr(self.http, "model_version", None) or data.get("modelVersion", self.model))
        return data, diagnostic

    async def friends(self, route):
        data, diagnostic = await self._friends_request(route)
        relationship_id = getattr(self, "relationship_id", None)
        target = self.target.removeprefix("tel:")
        matches = [
            row for row in data.get("following", [])
            if (relationship_id is None or row.get("id") == relationship_id)
            and any(normalize_target(alias).removeprefix("tel:") == target
                    for alias in (row.get("invitationAcceptedHandles") or []) if isinstance(alias, str))
        ]
        if route == "initClient":
            self.selected = None
        if matches:
            if len(matches) != 1:
                raise ValueError("Ambiguous selected share")
            self.selected = matches[0]["id"]
            save_private(NATIVE / "selected-share.json", matches[0])
        selected_locations = [p for p in data.get("locations", []) if self.selected and p.get("id") == self.selected]
        if selected_locations:
            save_private(NATIVE / "selected-legacy-location.json", {"locations": selected_locations})
        diagnostic.update(response_fields=sorted(data), selected_share_found=bool(self.selected),
                          selected_location_count=len(selected_locations),
                          selected_location_fields=[sorted(p.get("location") or {}) for p in selected_locations])
        save_private(NATIVE / "people-status.json", diagnostic)
        save_private(NATIVE / "people-context.json", {"serverContext": self.context, "dataContext": self.data_context})
        log_diagnostic(json.dumps({
            "stage": route, "http_status": diagnostic.get("http_status"),
            "selected_share_found": bool(self.selected), "selected_location_count": len(selected_locations),
        }), flush=True)
        return selected_locations

    async def close(self):
        await self.http.close()
        if self.owns_provider:
            await self.provider.close()

    async def fetch(self, key=None):
        service = self.settings["config"]["com.apple.Dataclass.SearchParty"]
        base = apple_url(service["findmyservice_gateway_url"])
        advertised = base64.b64encode(key["advertised"]).decode() if key else None
        body = fetch_body(self.selected, base64.b64decode(self.push["token"]).hex().upper(), self.push["device_id"].upper(), advertised)
        headers = await self.headers()
        headers["Accept-Version"] = "1"
        started = time.monotonic()
        response = await self.http.post(base.rstrip("/") + "/fetch", auth=(self.dsid, self.tokens["searchPartyToken"]),
                                        headers=headers, json=body)
        elapsed_ms = round((time.monotonic() - started) * 1000)
        diagnostic = {"stage": "fetch_location" if key else "distribute_keys", "http_status": response.status_code,
                      "response_bytes": len(response._content)}
        data = response.json() if response.ok and response._content else {}
        diagnostic["response_fields"] = sorted(data)
        diagnostic["status_code"] = data.get("statusCode")
        save_private(NATIVE / "fetch-status.json", diagnostic)
        status = str(data.get("statusCode", "200"))
        log_diagnostic(json.dumps({
            "stage": diagnostic["stage"], "http_status": response.status_code,
            "status_code": diagnostic["status_code"] if type(diagnostic["status_code"]) is int else None,
            "accepted": response.ok and status == "200", "elapsed_ms": elapsed_ms,
        }), flush=True)
        if not response.ok or status != "200":
            effective_status = int(status) if response.ok and status.isdecimal() else response.status_code
            raise AppleRequestError("SearchParty request rejected", effective_status)
        reports = []
        if key:
            private_key = decode_share_key(key["private_key"])
            for package in data.get("locationPayload", []):
                if package.get("id") != advertised:
                    continue
                for report in package.get("locationInfo", []):
                    try:
                        plain = decrypt_report(base64.b64decode(report["location"], validate=True), private_key)
                    except (InvalidTag, ValueError, KeyError, TypeError):
                        continue
                    if isinstance(plain, dict) and plain.get("findMyId", self.selected) != self.selected:
                        continue
                    reports.append({"locationTs": report.get("locationTs"), "plaintext": plain})
            diagnostic.update(decrypted_count=len(reports),
                              plaintext_fields=[sorted(p["plaintext"]) for p in reports
                                                if isinstance(p["plaintext"], dict)])
            save_private(NATIVE / "fetch-status.json", diagnostic)
            log_diagnostic(json.dumps({"stage": "decrypt_locations", "report_count": len(reports)}), flush=True)
        return reports

    async def position(self, key, output, *, max_age=FRESH_LOCATION_SECONDS, on_snapshot_changed=None):
        target_id = f"friend:{self.target}"
        positions = []
        reports = await self.fetch(key)
        now = datetime.now(timezone.utc)
        for report in reports:
            try:
                positions.append(position_from_report(report, target_id=target_id, now=now, max_age=max_age))
            except (ValueError, TypeError, KeyError):
                continue
        if not positions:
            log_diagnostic(json.dumps({"stage": "snapshot", "result": "no_fresh_supported_report",
                                       "report_count": len(reports)}), flush=True)
            return False
        best = max(positions, key=lambda position: position.timestamp)
        age_seconds = (now - best.timestamp).total_seconds()
        fresh = age_seconds <= FRESH_LOCATION_SECONDS
        diagnostic = {"stage": "snapshot", "report_age_seconds": round(age_seconds, 1), "fresh": fresh}
        previous = None
        if output.is_file():
            previous = json.loads(output.read_text())["positions"][0]
        if previous:
            if previous["target_id"] != target_id:
                raise ValueError("Snapshot output belongs to another target")
            if best.timestamp <= datetime.fromisoformat(previous["timestamp"]):
                log_diagnostic(json.dumps({**diagnostic, "result": "already_current"}))
                return fresh
        save_private(output, {"schema_version": 1, "positions": [{
            "target_id": target_id, "latitude": best.latitude, "longitude": best.longitude,
            "accuracy": best.accuracy, "timestamp": best.timestamp.isoformat(), "floor": best.floor,
        }]})
        if on_snapshot_changed is not None:
            on_snapshot_changed(output)
        log_diagnostic(json.dumps({**diagnostic, "result": "updated"}), flush=True)
        return fresh


async def discover_contacts(provider):
    client = PeopleClient(None, provider=provider)
    try:
        data, _ = await client._friends_request("initClient")
        return shared_contacts(data), own_location_device(data), contact_position_ttl(data)
    finally:
        await client.close()


def share_key_path(handle):
    return NATIVE / f"share-{hashlib.sha256(handle.encode()).hexdigest()[:20]}.plist"


def read_share_key(handle):
    path = share_key_path(handle)
    try:
        key = plistlib.loads(path.read_bytes())
    except (FileNotFoundError, plistlib.InvalidFileException):
        return None
    return key if isinstance(key, dict) else None


def save_share_key(handle, key):
    path = share_key_path(handle)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(plistlib.dumps(key))
    tmp.chmod(0o600)
    tmp.replace(path)
    (NATIVE / path.name.replace("share-", "pending-envelope-")).unlink(missing_ok=True)


async def collect_once(args, *, refresh_key=False):
    provider = getattr(args, "provider", None)
    client = PeopleClient(args.target, provider=provider) if provider else PeopleClient(args.target)
    client.relationship_id = getattr(args, "relationship_id", None)
    target_uri = client.target if client.target.startswith("tel:") else f"mailto:{client.target}"
    sender_uri = args.self_uri or f"mailto:{client.state['account']['username'].lower()}"
    target_hash = hashlib.sha256(client.target.encode()).hexdigest()[:20]
    output = args.snapshot or NATIVE / f"position-{target_hash}.json"
    receiver = None
    directory = None

    async def start_receiver():
        nonlocal receiver, directory
        receiver = Receiver(client.http, target_uri, sender_uri)
        await receiver.start()
        client.push = receiver.push
        if args.check_receiver:
            await receiver.lookup_selected("com.apple.private.alloy.fmd", self_lookup=True)
        directory = await receiver.lookup_selected("com.apple.private.alloy.fmd")

    try:
        key = read_share_key(client.target)
        # The native missing-key flow introduces an already connected courier
        # to Friends before refreshing the relationship and requesting a key.
        if args.keys and (not key or refresh_key):
            await start_receiver()
        await client.friends("initClient")
        if not client.selected:
            raise RuntimeError("Selected accepted share not found")
        if key and key.get("fm_id") != client.selected:
            key = None
        if args.keys and not key and receiver is None:
            await start_receiver()
            await client.friends("initClient")
            if not client.selected:
                raise RuntimeError("Selected accepted share not found")
        await client.friends("minCallback/refreshClient")
        await client.friends("minCallback/selFriend/refreshClient")
        if receiver is not None:
            await client.fetch()
            deadline = asyncio.get_running_loop().time() + args.wait
            while asyncio.get_running_loop().time() < deadline:
                try:
                    topic_hash, packet = await receiver.next_notification(max(0.01, deadline - asyncio.get_running_loop().time()))
                except (TimeoutError, CourierDisconnected) as error:
                    result = "courier_disconnected" if isinstance(error, CourierDisconnected) else "no_selected_key_received"
                    diagnostic = {"stage": "key_delivery", "result": result, "counters": receiver.counters,
                                  "unsolicited_commands": receiver.unsolicited}
                    log_diagnostic(json.dumps(diagnostic), flush=True)
                    save_private(NATIVE / "key-delivery-status.json", diagnostic)
                    break
                if packet.get("c") != 242 or packet.get("E") != "pair-ec":
                    continue
                topic = TOPICS_BY_HASH.get(topic_hash)
                if topic not in ("com.apple.private.alloy.fmd", "com.apple.private.alloy.fmf"):
                    continue
                validation = {"stage": "selected_message_validation"}
                try:
                    envelopes = decrypt_selected_message(packet, directory, message_identity(), validation)
                    validation["step"] = "share_key"
                    candidate = selected_key(envelopes, client.selected)
                except (InvalidSignature, ValueError, KeyError, TypeError, plistlib.InvalidFileException) as error:
                    validation["error_type"] = type(error).__name__
                    log_diagnostic(json.dumps(validation), flush=True)
                    # Keep one encrypted message from the matched directory
                    # device so parser changes can be checked without another push.
                    if packet.get("t") in receiver.selected_push_tokens:
                        spool = NATIVE / f"pending-envelope-{target_hash}.plist"
                        temp = spool.with_suffix(".tmp")
                        temp.write_bytes(plistlib.dumps(packet, fmt=plistlib.FMT_BINARY))
                        temp.chmod(0o600)
                        temp.replace(spool)
                    continue
                save_share_key(client.target, candidate)
                key = candidate
                log_diagnostic(json.dumps({"stage": "key_delivery", "signature_verified": True, "selected_share_matched": True}), flush=True)
                try:
                    await receiver.acknowledge_verified(packet, directory, topic)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    log_diagnostic(json.dumps({"stage": "key_delivery_ack", "error_type": type(error).__name__}), flush=True)
                break
        if key:
            return await client.position(
                key, output, max_age=getattr(args, "max_age", FRESH_LOCATION_SECONDS),
                on_snapshot_changed=getattr(args, "on_snapshot_changed", None),
            )
        return False
    finally:
        if receiver:
            await receiver.close()
        await client.close()


def poll_targets(args):
    if args.targets_file is None:
        return [PollTarget(args)]
    handles = json.loads(args.targets_file.read_text())
    if not isinstance(handles, list) or not handles or not all(isinstance(handle, str) for handle in handles):
        raise ValueError("Targets file must contain an array of sharing handles")
    targets = [normalize_target(handle) for handle in handles]
    if not all(targets) or len(set(targets)) != len(targets):
        raise ValueError("Empty or duplicate sharing handles")
    if args.snapshot is not None:
        raise ValueError("With multiple targets, each snapshot uses its default path")
    return [PollTarget(argparse.Namespace(**(vars(args) | {"target": handle}))) for handle in targets]


async def poll_target(target, interval, *, shared_keys=False):
    delay = interval
    now = time.monotonic()
    trigger = "push" if target.refresh_requested else "scheduled"
    diagnostic = {"stage": "people_poll", "trigger": trigger}
    if target.share_slot is not None:
        diagnostic["share_slot"] = target.share_slot
    log_diagnostic(json.dumps({**diagnostic, "result": f"{trigger}_refresh",
                               "seconds_early": round(max(0, target.due - now), 1)}))
    # Consume only hints received before this fetch. A hint during I/O stays pending.
    target.refresh_requested = False
    refresh = not shared_keys and target.needs_refresh and now >= target.next_key_refresh
    if refresh:
        target.next_key_refresh = now + 1800
    generation = account_generation()
    try:
        opts = argparse.Namespace(**(vars(target.args) | {"keys": False})) if shared_keys else target.args
        key = read_share_key(opts.target) if shared_keys else None
        relationship_id = getattr(opts, "relationship_id", None)
        if shared_keys and (not key or relationship_id is not None and key.get("fm_id") != relationship_id):
            log_diagnostic(json.dumps({**diagnostic, "result": "waiting_for_share_key"}))
            target.needs_refresh = True
            target.due = now + interval
            target.not_before = now
            return 0
        target.needs_refresh = not await collect_once(opts, refresh_key=refresh)
        mark_reauth("people", generation, required=False)
        if target.needs_refresh and not shared_keys:
            delay = max(delay, 300)
    except AppleRequestError as error:
        retry_seconds = 2700 if error.status == 429 else max(delay, 300)
        log_diagnostic(json.dumps({**diagnostic, "result": "request_error", "http_status": error.status,
                                   "elapsed_ms": round((time.monotonic() - now) * 1000),
                                   "retry_seconds": retry_seconds}), flush=True)
        if error.status == 429:
            return retry_seconds
        target.defer_until(time.monotonic() + retry_seconds)
        return -1 if error.status == 401 else 0
    except (ClientError, OSError, ValueError, KeyError, RuntimeError) as error:
        retry_seconds = max(delay, 300)
        log_diagnostic(json.dumps({**diagnostic, "result": "request_error", "error_type": type(error).__name__,
                                   "elapsed_ms": round((time.monotonic() - now) * 1000),
                                   "retry_seconds": retry_seconds}), flush=True)
        target.defer_until(time.monotonic() + retry_seconds)
        return 0
    finished = time.monotonic()
    target.due = finished + delay
    target.not_before = finished
    log_diagnostic(json.dumps({**diagnostic, "result": "completed", "fresh": not target.needs_refresh,
                               "elapsed_ms": round((finished - now) * 1000)}))
    return 0


async def run(args, *, targets=None, shared_keys=False, wake=None):
    if targets is None:
        targets = poll_targets(args)
    if args.poll_interval is None:
        for target in targets:
            await collect_once(target.args)
        return
    for slot, target in enumerate(targets, start=1):
        target.share_slot = slot
    next_token_refresh = 0.0
    wake = wake or asyncio.Event()
    generation = account_generation()
    while True:
        wake.clear()
        current_generation = account_generation()
        if generation != current_generation:
            generation = current_generation
            next_token_refresh = 0.0
            for item in targets:
                item.due = item.not_before = 0.0
                item.refresh_requested = False
        target = min(targets, key=lambda item: item.next_poll)
        remaining = target.next_poll - time.monotonic()
        if remaining > 0:
            try:
                await asyncio.wait_for(wake.wait(), min(remaining, 15))
            except TimeoutError:
                pass
            continue
        result = await poll_target(target, getattr(target.args, "poll_interval", args.poll_interval),
                                   shared_keys=shared_keys)
        if result > 0:
            until = time.monotonic() + result
            for item in targets:
                item.defer_until(until)
            log_diagnostic(json.dumps({"stage": "people_poll", "result": "rate_limited", "http_status": 429,
                                       "retry_seconds": result}), level=logging.WARNING)
        elif result == -1 and time.monotonic() < next_token_refresh:
            mark_reauth("people", generation, required=True)
        elif result == -1:
            next_token_refresh = time.monotonic() + 2700
            async with AsyncExitStack() as locks:
                provider = getattr(target.args, "provider", None)
                if provider is not None:
                    await locks.enter_async_context(provider._lock)
                process = await asyncio.create_subprocess_exec(
                    *module_command("account_settings"), env=environment.subprocess_env(),
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    returned = await process.wait()
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
            if returned == 0:
                log_diagnostic(json.dumps({"stage": "people_token_refresh", "status": "settings_reloaded"}), flush=True)
            else:
                log_diagnostic(json.dumps({"stage": "people_token_refresh", "status": "failed", "exit_code": returned}))
                mark_reauth("people", generation, required=True)


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument("--target", help="Exact email or tel: handle of an existing Find My share")
    targets.add_argument("--targets-file", type=Path, help="Private JSON array of active sharing handles")
    parser.add_argument("--self-uri", help="Override the registered IDS handle for this Apple Account")
    parser.add_argument("--snapshot", type=Path, help="Output path for this member's Home Assistant snapshot")
    parser.add_argument("--poll-interval", type=int, choices=range(60, 3601), metavar="60..3600")
    parser.add_argument("--keys", action="store_true")
    parser.add_argument("--check-receiver", action="store_true", help="Check this receiver in the IDS directory")
    parser.add_argument("--wait", type=int, default=120, choices=range(1, 301), metavar="1..300")
    try:
        asyncio.run(run(parser.parse_args()))
    except Exception as exc:
        safe = str(exc) if str(exc) in ("IDS directory rejected selected lookup", "Courier disconnected: IncompleteReadError", "SearchParty request rejected", "Selected accepted share not found") else None
        log_diagnostic(json.dumps({"stage": "native_people", "error_type": type(exc).__name__, "reason": safe}), flush=True)
        raise SystemExit(1)
