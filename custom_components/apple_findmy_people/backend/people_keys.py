"""Keep one APNs connection open for all of this account's active People shares."""

import asyncio
import json
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
    async with asyncio.TaskGroup() as tasks:
        tasks.create_task(people.run(settings, targets=targets, shared_keys=True))
        tasks.create_task(watch_keys(targets))


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
                    continue
                bindings[args.target] = (target, uri, client.selected, directory)
                await client.friends("minCallback/refreshClient")
                await client.friends("minCallback/selFriend/refreshClient")
                await client.fetch()
            except people.AppleRequestError as error:
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
        target.due = 0.0
        accepted.append((uri, directory))
    if accepted:
        uri, directory = accepted[0]
        try:
            await receiver.acknowledge_verified(packet, directory, topic, target_uri=uri)
        except (OSError, ValueError, KeyError, TypeError) as error:
            log_diagnostic(json.dumps({"stage": "people_key_ack", "error_type": type(error).__name__}))
        save_private(people.NATIVE / "key-delivery-status.json",
                     {"stage": "key_delivery", "result": "verified", "share_count": len(accepted)})
    return bool(accepted)


async def watch_keys(targets):
    bindings = {}
    previous_generation = None
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
            receiver = Receiver(http, None, self_uri)
            await receiver.start()
            await receiver.lookup_selected("com.apple.private.alloy.fmd", self_lookup=True)
            requests = asyncio.create_task(request_keys(receiver, targets, bindings, generation))
            while generation == account_generation():
                if requests.done():
                    await requests
                    break
                try:
                    hash_, packet = await receiver.next_notification(15)
                except TimeoutError:
                    continue
                await handle_delivery(receiver, bindings, TOPICS_BY_HASH.get(hash_), packet, generation)
        except (ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError, TimeoutError) as error:
            stage = "people_key_reconnect" if isinstance(error, CourierDisconnected) else "people_key_receiver"
            log_diagnostic(json.dumps({"stage": stage, "error_type": type(error).__name__}))
        finally:
            if requests is not None:
                requests.cancel()
                await asyncio.gather(requests, return_exceptions=True)
            if receiver is not None:
                await receiver.close()
            await http.close()
        if generation == account_generation():
            await asyncio.sleep(30)
