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
from ..protocol import fetch_body, decrypt_report, decode_share_key, position_from_report
from findmy.util.http import HttpResponse

NATIVE = PRIVATE


def normalize_target(handle):
    return handle.strip().lower().removeprefix("mailto:")


@dataclass
class PollTarget:
    args: argparse.Namespace
    due: float = 0.0
    next_key_refresh: float = 0.0
    needs_refresh: bool = False


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
        self.target = normalize_target(target)
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
        self.http = VerifiedHttpSession(PROXY)
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

    async def friends(self, route):
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
        matches = [f for f in data.get("following", []) if self.target in
                   [str(h).removeprefix("mailto:").lower() for h in f.get("invitationAcceptedHandles", [])]]
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
        log_diagnostic(json.dumps(diagnostic), flush=True)
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
        response = await self.http.post(base.rstrip("/") + "/fetch", auth=(self.dsid, self.tokens["searchPartyToken"]),
                                        headers=headers, json=body)
        diagnostic = {"stage": "fetch_location" if key else "distribute_keys", "http_status": response.status_code,
                      "response_bytes": len(response._content)}
        data = response.json() if response.ok and response._content else {}
        diagnostic["response_fields"] = sorted(data)
        diagnostic["status_code"] = data.get("statusCode")
        log_diagnostic(json.dumps(diagnostic), flush=True)
        save_private(NATIVE / "fetch-status.json", diagnostic)
        status = str(data.get("statusCode", "200"))
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
            log_diagnostic(json.dumps(diagnostic), flush=True)
        return reports

    async def position(self, key, output):
        target_id = f"friend:{self.target}"
        positions = []
        now = datetime.now(timezone.utc)
        for report in await self.fetch(key):
            try:
                positions.append(position_from_report(report, target_id=target_id, now=now, max_age=300))
            except (ValueError, TypeError, KeyError):
                continue
        if not positions:
            log_diagnostic(json.dumps({"stage": "snapshot", "result": "no_fresh_supported_report"}), flush=True)
            return False
        best = max(positions, key=lambda position: position.timestamp)
        previous = None
        if output.is_file():
            previous = json.loads(output.read_text())["positions"][0]
        if previous:
            if previous["target_id"] != target_id:
                raise ValueError("Snapshot output belongs to another target")
            if best.timestamp <= datetime.fromisoformat(previous["timestamp"]):
                return True
        save_private(output, {"schema_version": 1, "positions": [{
            "target_id": target_id, "latitude": best.latitude, "longitude": best.longitude,
            "accuracy": best.accuracy, "timestamp": best.timestamp.isoformat(), "floor": best.floor,
        }]})
        log_diagnostic(json.dumps({"stage": "snapshot", "result": "updated"}), flush=True)
        return True


async def collect_once(args, *, refresh_key=False):
    provider = getattr(args, "provider", None)
    client = PeopleClient(args.target, provider=provider) if provider else PeopleClient(args.target)
    target_uri = client.target if client.target.startswith("tel:") else f"mailto:{client.target}"
    sender_uri = args.self_uri or f"mailto:{client.state['account']['username'].lower()}"
    target_hash = hashlib.sha256(client.target.encode()).hexdigest()[:20]
    path = NATIVE / f"share-{target_hash}.plist"
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
        key = plistlib.loads(path.read_bytes()) if path.is_file() else None
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
                    if isinstance(error, CourierDisconnected):
                        diagnostic["reason"] = str(error)
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
                tmp = path.with_suffix(".tmp")
                tmp.write_bytes(plistlib.dumps(candidate))
                tmp.chmod(0o600)
                tmp.replace(path)
                key = candidate
                (NATIVE / f"pending-envelope-{target_hash}.plist").unlink(missing_ok=True)
                log_diagnostic(json.dumps({"stage": "key_delivery", "signature_verified": True, "selected_share_matched": True}), flush=True)
                try:
                    await receiver.acknowledge_verified(packet, directory, topic)
                except (OSError, ValueError, KeyError, TypeError) as error:
                    log_diagnostic(json.dumps({"stage": "key_delivery_ack", "error_type": type(error).__name__}), flush=True)
                break
        if key:
            return await client.position(key, output)
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


async def poll_target(target, interval):
    delay = interval
    now = time.monotonic()
    refresh = target.needs_refresh and now >= target.next_key_refresh
    if refresh:
        target.next_key_refresh = now + 1800
    generation = account_generation()
    try:
        target.needs_refresh = not await collect_once(target.args, refresh_key=refresh)
        mark_reauth("people", generation, required=False)
        if target.needs_refresh:
            delay = max(delay, 300)
    except AppleRequestError as error:
        log_diagnostic(json.dumps({"stage": "people_poll", "http_status": error.status}), flush=True)
        if error.status == 429:
            return 2700
        if error.status == 401:
            target.due = time.monotonic() + max(delay, 300)
            return -1
        delay = max(delay, 300)
    except (ClientError, OSError, ValueError, KeyError, RuntimeError) as error:
        log_diagnostic(json.dumps({"stage": "people_poll", "error_type": type(error).__name__}), flush=True)
        delay = max(delay, 300)
    target.due = time.monotonic() + delay
    return 0


async def run(args, *, targets=None):
    if targets is None:
        targets = poll_targets(args)
    if args.poll_interval is None:
        for target in targets:
            await collect_once(target.args)
        return
    next_token_refresh = 0.0
    generation = account_generation()
    while True:
        target = min(targets, key=lambda item: item.due)
        remaining = target.due - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(min(remaining, 15))
            if generation != account_generation():
                generation = account_generation()
                next_token_refresh = 0.0
                for item in targets:
                    item.due = 0.0
            continue
        result = await poll_target(target, getattr(target.args, "poll_interval", args.poll_interval))
        if result > 0:
            until = time.monotonic() + result
            for item in targets:
                item.due = max(item.due, until)
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
