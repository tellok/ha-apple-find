"""Private APNs receiver with a directory probe scoped to the selected friend."""
import argparse
import asyncio
import base64
import gzip
import hashlib
import json
import logging
import os
import plistlib
import secrets
import uuid
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature

from .environment import log_diagnostic
from .apple_probe import PROXY, PRIVATE, VerifiedHttpSession, save_private
from .apns_probe import connect, frame, read_frame
from .ids_register import TOPICS, message_identity
from .ids_wire import signing_headers
from .location_pipeline import verified_directory_keys

INTERESTS = TOPICS + ["com.apple.private.ids", "com.apple.icloud.searchparty"]
TOPICS_BY_HASH = {hashlib.sha1(topic.encode()).digest(): topic for topic in INTERESTS}
PING_INTERVAL = 60
PONG_TIMEOUT = 20


class CourierDisconnected(RuntimeError):
    """The APNs connection ended before the key-delivery deadline."""


class Receiver:
    def __init__(self, http, target_uri, self_uri, *, on_searchparty_notification=None):
        self.http = http
        self.on_searchparty_notification = on_searchparty_notification
        self.target_uri = target_uri.lower() if target_uri else None
        self.self_uri = self_uri.lower()
        self.push = json.loads((PRIVATE / "apns-identity.json").read_text())
        self.registration = json.loads((PRIVATE / "ids-registration.json").read_text())
        self.pending = {}
        self.notifications = asyncio.Queue(maxsize=100)
        self.selected_push_tokens = set()
        self.writer = self.reader = self.task = None
        self.heartbeat = None
        self.pong = asyncio.Event()
        self.courier_error = None
        self.counters = {"notifications": 0, "pair_ec_messages": 0, "selected_sender": 0,
                         "selected_token": 0, "selected_pair_ec": 0, "pongs": 0,
                         "undecoded_notifications": 0}
        self.unsolicited = {}

    async def start(self):
        self.reader, self.writer = await connect(self.http, self.push, keep_open=True, signed=True)
        fields = [(1, base64.b64decode(self.push["token"]))]
        fields += [(2, topic_hash) for topic_hash in TOPICS_BY_HASH]
        self.writer.write(frame(0x14, [(1, b"\x01"), (2, b"\x7f\xff\xff\xff")]))
        self.writer.write(frame(9, fields))
        await self.writer.drain()
        self.task = asyncio.create_task(self.read_loop())
        self.heartbeat = asyncio.create_task(self.keep_alive())

    async def keep_alive(self):
        while True:
            await asyncio.sleep(PING_INTERVAL)
            self.pong.clear()
            try:
                self.writer.write(frame(0x0c, []))
                await self.writer.drain()
                await asyncio.wait_for(self.pong.wait(), PONG_TIMEOUT)
            except (TimeoutError, OSError, RuntimeError):
                self.courier_error = "HeartbeatFailed"
                self.writer.close()
                return

    async def next_notification(self, timeout):
        receiving = asyncio.create_task(self.notifications.get())
        try:
            done, _ = await asyncio.wait((receiving, self.task), timeout=timeout,
                                         return_when=asyncio.FIRST_COMPLETED)
            if receiving in done:
                return receiving.result()
            if self.task in done:
                raise CourierDisconnected(self.courier_error or "CourierClosed")
            raise TimeoutError
        finally:
            if not receiving.done():
                receiving.cancel()
                await asyncio.gather(receiving, return_exceptions=True)

    async def read_loop(self):
        try:
            while True:
                command, fields = await read_frame(self.reader)
                values = dict(fields)
                if command == 0x0a:
                    self.counters["notifications"] += 1
                    # Transport ACK carries no application message or sharing
                    # change. Never persist unrelated notification payloads.
                    self.writer.write(frame(0x0b, [(1, base64.b64decode(self.push["token"])),
                        (4, values[4]), (8, b"\x00")]))
                    await self.writer.drain()
                    topic = TOPICS_BY_HASH.get(values.get(2), "unknown")
                    if topic == "com.apple.icloud.searchparty" and self.on_searchparty_notification is not None:
                        # The topic is an account-level hint. Only a separate verified
                        # location report can identify a contact or supply a position.
                        self.on_searchparty_notification()
                        continue
                    try:
                        packet = plistlib.loads(values[3])
                    except (KeyError, ValueError, TypeError):
                        self.counters["undecoded_notifications"] += 1
                        continue
                    if not isinstance(packet, dict):
                        self.counters["undecoded_notifications"] += 1
                        continue
                    future = self.pending.get(packet.get("U"))
                    if future and not future.done():
                        future.set_result(packet)
                    else:
                        expected_uri = str(packet.get("sP", "")).lower() == self.target_uri
                        sender_token = packet.get("t")
                        expected_token = isinstance(sender_token, bytes) and sender_token in self.selected_push_tokens
                        is_pair_ec = packet.get("E") == "pair-ec" and packet.get("c") == 242
                        # Count wire commands without logging any sender or payload data.
                        wire_command = packet.get("c")
                        command_label = wire_command if type(wire_command) is int and 0 <= wire_command <= 255 else "other"
                        signature = f"{topic}:{command_label}"
                        self.unsolicited[signature] = self.unsolicited.get(signature, 0) + 1
                        self.counters["pair_ec_messages"] += int(is_pair_ec)
                        self.counters["selected_sender"] += int(expected_uri)
                        self.counters["selected_token"] += int(expected_token)
                        account_delivery = self.target_uri is None and topic in (
                            "com.apple.private.alloy.fmd", "com.apple.private.alloy.fmf",
                        )
                        if is_pair_ec and (expected_uri or expected_token or account_delivery):
                            self.counters["selected_pair_ec"] += 1
                            if not self.notifications.full():
                                self.notifications.put_nowait((values.get(2), packet))
                elif command == 0x0c:
                    self.writer.write(frame(0x0d, []))
                    await self.writer.drain()
                elif command == 0x0d:
                    self.counters["pongs"] += 1
                    self.pong.set()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.courier_error = self.courier_error or type(exc).__name__
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(CourierDisconnected(self.courier_error))

    async def lookup_selected(self, topic="com.apple.private.alloy.fmf", *, self_lookup=False, target_uri=None):
        if self.self_uri not in [u["uri"].lower() for u in self.registration["uris"]]:
            raise ValueError("Configured self handle not registered")
        response = await self.http.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")
        bag = plistlib.loads(response.plist()["bag"])
        endpoint = bag["id-query"]
        url = urlparse(endpoint)
        if url.scheme != "https" or not url.hostname.endswith(".apple.com"):
            raise ValueError("Unexpected IDS directory endpoint")
        requested_uri = self.self_uri if self_lookup else (target_uri or self.target_uri)
        if requested_uri is None:
            raise ValueError("A friend handle is required for IDS lookup")
        body = gzip.compress(plistlib.dumps({"uris": [requested_uri]}), mtime=0)
        signatures = signing_headers(bag_key="id-query", query=url.query, body=body,
            token=self.push["token"], auth=self.registration, push=self.push)
        headers = {k.replace("x-auth-", "x-id-"): v for k, v in signatures.items() if k.startswith("x-auth-")}
        headers.update({"x-push-token": self.push["token"], "x-id-self-uri": self.self_uri,
                        "x-protocol-version": "1660", "Content-Encoding": "gzip",
                        "x-id-sub-service": topic,
                        "user-agent": "com.apple.madrid-lookup [macOS,12.7.6,21H1320,Macmini7,1]"})
        identifier = secrets.token_bytes(16)
        request = {"cT": "application/x-apple-plist", "U": identifier, "c": 96,
                   "u": endpoint, "h": headers, "v": 2, "b": body}
        future = asyncio.get_running_loop().create_future()
        self.pending[identifier] = future
        try:
            self.writer.write(frame(0x0a, [(4, secrets.token_bytes(4)),
                (1, hashlib.sha1(topic.encode()).digest()),
                (2, base64.b64decode(self.push["token"])),
                (3, plistlib.dumps(request, fmt=plistlib.FMT_BINARY))]))
            await self.writer.drain()
            packet = await asyncio.wait_for(future, 30)
            payload = packet["b"]
            if payload.startswith(b"\x1f\x8b"):
                payload = gzip.decompress(payload)
            data = plistlib.loads(payload)
            if data.get("status") != 0:
                status = data.get("status")
                log_diagnostic(json.dumps({
                    "stage": "selected_friend_directory", "result": "rejected",
                    "status": status if type(status) is int else None,
                }), flush=True)
                raise RuntimeError("IDS directory rejected selected lookup")
            selected = data.get("results", {}).get(requested_uri, {})
            if self_lookup:
                courier_token = base64.b64decode(self.push["token"], validate=True)
                local_identities = [identity for identity in selected.get("identities", [])
                                    if identity.get("push-token") == courier_token]
                flags = local_identities[0].get("client-data", {}) if len(local_identities) == 1 else {}
                keys_match = False
                if len(local_identities) == 1:
                    try:
                        device, prekey = verified_directory_keys(local_identities[0])
                        keys = message_identity()
                        keys_match = (device.public_numbers() == keys["device"].public_key().public_numbers()
                                      and prekey.public_numbers() == keys["prekey"].public_key().public_numbers())
                    except (InvalidSignature, KeyError, TypeError, ValueError):
                        pass
                log_diagnostic(json.dumps({"stage": "receiver_directory", "token_matched": len(local_identities) == 1,
                                  "secure_location": flags.get("supports-secure-loc-v1") is True,
                                  "key_sharing": flags.get("supports-key-sharing") is True,
                                  "encryption_keys_matched": keys_match}), flush=True)
                return selected
            if target_uri is not None:
                return selected
            self.selected_push_tokens = {identity["push-token"] for identity in selected.get("identities", [])
                                         if isinstance(identity.get("push-token"), bytes)}
            diagnostic = {"stage": "selected_friend_directory", "status": data.get("status"),
                "selected_fields": sorted(selected), "identity_count": len(selected.get("identities", [])),
                "identity_fields": [sorted(i) for i in selected.get("identities", [])]}
            log_diagnostic(json.dumps(diagnostic), flush=True)
            save_private(PRIVATE / "selected-directory-diagnostics.json", diagnostic)
            # plist preserves binary key values. Only the configured friend is
            # persisted, even if the server adds other result entries.
            fd = os.open(PRIVATE / "selected-directory.plist", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                plistlib.dump(selected, stream)
            return selected
        finally:
            self.pending.pop(identifier, None)

    async def acknowledge_verified(self, packet, directory, topic, *, target_uri=None):
        """Application ACK only after caller has verified sender and selected key."""
        identities = [d for d in directory.get("identities", []) if d["push-token"] == packet.get("t")]
        if len(identities) != 1 or topic not in TOPICS:
            raise ValueError("ACK is not bound to selected sender")
        identifier = packet.get("U")
        if not isinstance(identifier, bytes) or len(identifier) != 16:
            raise ValueError("Invalid acknowledged UUID")
        message = {"c": 244, "rI": identifier, "sP": self.self_uri,
                   "U": uuid.uuid4().bytes, "i": secrets.randbits(32), "v": 8, "fcn": 1,
                   "dtl": [{"tP": target_uri or self.target_uri, "D": False, "t": packet["t"], "sT": identities[0]["session-token"]}]}
        self.writer.write(frame(0x0a, [(4, secrets.token_bytes(4)),
            (1, hashlib.sha1(topic.encode()).digest()), (2, base64.b64decode(self.push["token"])),
            (3, plistlib.dumps(message, fmt=plistlib.FMT_BINARY))]))
        await self.writer.drain()

    async def close(self):
        tasks = [task for task in (self.task, self.heartbeat) if task is not None]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def main(args):
    http = VerifiedHttpSession(PROXY)
    receiver = Receiver(http, args.target_uri, args.self_uri)
    try:
        await receiver.start()
        await receiver.lookup_selected()
    finally:
        await receiver.close()
        await http.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-uri", required=True)
    parser.add_argument("--self-uri", required=True)
    try:
        asyncio.run(main(parser.parse_args()))
    except Exception as exc:
        log_diagnostic(json.dumps({"stage": "ids_receiver", "error_type": type(exc).__name__}))
        raise SystemExit(1)
