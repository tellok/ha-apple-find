"""Keep one APNs connection open for all of this account's active People shares."""

import asyncio
import json
import logging
import plistlib
from time import monotonic

from aiohttp import ClientError
from cryptography.exceptions import InvalidSignature

from . import native_people as people
from .apple_probe import PROXY, VerifiedHttpSession, account_generation, mark_reauth, save_private
from .environment import log_diagnostic
from .ids_receiver import CourierDisconnected, Receiver, TOPICS_BY_HASH
from .ids_register import message_identity
from .location_pipeline import decrypt_selected_message, selected_key


async def run_household(settings, targets):
    wake = asyncio.Event()
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(people.run(settings, targets=targets, shared_keys=True, wake=wake))
        tasks.create_task(watch_keys(targets, wake))


async def request_keys(receiver, targets, bindings, generation):
    topic = "com.apple.private.alloy.fmd"
    while generation == account_generation():
        for target in targets:
            if generation != account_generation():
                return
            args = target.args
            key = people.read_share_key(args.target)
            relationship_id = getattr(args, "relationship_id", None)
            has_key = key is not None and (relationship_id is None or key.get("fm_id") == relationship_id)
            if monotonic() < target.next_key_refresh or (has_key and not target.needs_refresh):
                continue
            target.next_key_refresh = monotonic() + (1800 if has_key else 300)
            uri = args.target if args.target.startswith("tel:") else f"mailto:{args.target}"
            client = people.PeopleClient(args.target, provider=args.provider)
            client.relationship_id = relationship_id
            try:
                client.push = receiver.push
                directory = await receiver.lookup_selected(topic, target_uri=uri)
                await client.friends("initClient")
                if not client.selected:
                    bindings.pop(args.target, None)
                    log_diagnostic(json.dumps({"stage": "people_key_request", "result": "share_not_found"}))
                    continue
                bindings[args.target] = (target, uri, client.selected, directory)
                await client.friends("minCallback/refreshClient")
                await client.friends("minCallback/selFriend/refreshClient")
                await client.fetch()
                log_diagnostic(json.dumps({
                    "stage": "people_key_request", "result": "accepted", "replacing_key": has_key,
                    "directory_identities": len(directory.get("identities", [])),
                }))
            except people.AppleRequestError as error:
                if error.status == 429:
                    log_diagnostic(json.dumps({"stage": "people_key_request", "result": "rate_limited",
                                               "http_status": 429, "retry_seconds": 2700}), level=logging.WARNING)
                else:
                    log_diagnostic(json.dumps({"stage": "people_key_request", "http_status": error.status}))
                if error.status == 401:
                    mark_reauth("people", generation, required=True)
                if error.status in (401, 429):
                    for candidate in targets:
                        candidate.next_key_refresh = max(candidate.next_key_refresh, monotonic() + 2700)
                    break
            except (ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
                log_diagnostic(json.dumps({"stage": "people_key_request", "error_type": type(error).__name__}))
            finally:
                await client.close()
        await asyncio.sleep(15)


async def handle_delivery(receiver, bindings, topic, packet, generation):
    if topic not in ("com.apple.private.alloy.fmd", "com.apple.private.alloy.fmf"):
        return False
    accepted = []
    for target, uri, relationship_id, directory in bindings.values():
        if not any(identity.get("push-token") == packet.get("t")
                   for identity in directory.get("identities", [])):
            continue
        try:
            envelopes = decrypt_selected_message(packet, directory, message_identity())
            key = selected_key(envelopes, relationship_id)
        except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError, plistlib.InvalidFileException):
            continue
        if generation != account_generation():
            return False
        people.save_share_key(target.args.target, key)
        target.needs_refresh = False
        target.refresh_requested = True
        accepted.append((uri, directory))
    if accepted:
        log_diagnostic(json.dumps({"stage": "key_delivery", "result": "verified", "share_count": len(accepted)}))
        uri, directory = accepted[0]
        try:
            await receiver.acknowledge_verified(packet, directory, topic, target_uri=uri)
        except (OSError, ValueError, KeyError, TypeError) as error:
            log_diagnostic(json.dumps({"stage": "people_key_ack", "error_type": type(error).__name__}))
        save_private(people.NATIVE / "key-delivery-status.json",
                     {"stage": "key_delivery", "result": "verified", "share_count": len(accepted)})
    return bool(accepted)


async def watch_keys(targets, wake):
    bindings = {}
    previous_generation = None
    outage_started = None

    def searchparty_notification():
        # The topic is account-wide. Only recheck shares already configured here.
        wake.set()
        newly_requested = sum(not target.refresh_requested for target in targets)
        for target in targets:
            target.refresh_requested = True
        log_diagnostic(json.dumps({"stage": "people_poll", "result": "searchparty_hint",
                                   "newly_requested": newly_requested, "already_pending": len(targets) - newly_requested}))

    while True:
        generation = account_generation()
        if generation != previous_generation:
            bindings.clear()
            for target in targets:
                target.next_key_refresh = 0.0
            previous_generation = generation
        http = VerifiedHttpSession(PROXY, persist_cookies=False)
        receiver = requests = None
        try:
            account = json.loads((people.NATIVE / "account.json").read_text())["account"]["username"]
            self_uri = f"mailto:{account.lower()}"
            receiver = Receiver(http, None, self_uri, on_searchparty_notification=searchparty_notification)
            await receiver.start()
            await receiver.lookup_selected("com.apple.private.alloy.fmd", self_lookup=True)
            if outage_started is None:
                log_diagnostic(json.dumps({"stage": "people_key_receiver", "result": "connected"}), level=logging.INFO)
            requests = asyncio.create_task(request_keys(receiver, targets, bindings, generation))
            while generation == account_generation():
                if requests.done():
                    await requests
                    break
                try:
                    hash_, packet = await receiver.next_notification(15)
                except TimeoutError:
                    pass  # An idle receive window also confirms the connection stayed open.
                else:
                    if await handle_delivery(receiver, bindings, TOPICS_BY_HASH.get(hash_), packet, generation):
                        wake.set()
                if outage_started is not None:
                    log_diagnostic(json.dumps({"stage": "people_key_receiver", "result": "recovered",
                                               "outage_seconds": round(monotonic() - outage_started, 1)}),
                                   level=logging.INFO)
                    outage_started = None
        except (ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError) as error:
            stage = "people_key_reconnect" if isinstance(error, CourierDisconnected) else "people_key_receiver"
            level = logging.DEBUG
            if outage_started is None:
                outage_started = monotonic()
                level = logging.WARNING
            log_diagnostic(json.dumps({"stage": stage, "result": "retrying", "error_type": type(error).__name__,
                                       "retry_seconds": 30}), level=level)
        finally:
            if requests is not None:
                requests.cancel()
                await asyncio.gather(requests, return_exceptions=True)
            if receiver is not None:
                await receiver.close()
            await http.close()
        if generation == account_generation():
            await asyncio.sleep(30)
