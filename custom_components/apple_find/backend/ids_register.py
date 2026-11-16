"""Register this receiver for the six Find My IDS subservices only."""
import asyncio
import gzip
import json
import logging
import os
import plistlib
import re
import time
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from .apple_probe import PROXY, PRIVATE, VerifiedHttpSession, save_private
from .ids_wire import compact_key, kt_data, prekey_data, signing_headers

TOPICS = ["com.apple.private.alloy.fmf", "com.apple.private.alloy.fmd",
          "com.apple.private.alloy.status.keysharing", "com.apple.private.alloy.status.personal",
          "com.apple.private.alloy.findmy.itemsharing-crossaccount", "com.apple.private.alloy.kcsharing.invite"]


def pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def message_identity():
    path = PRIVATE / "ids-message-keys.json"
    if path.exists():
        state = json.loads(path.read_text())
    else:
        state = {"device": pem(compact_key()), "prekey": pem(compact_key()),
                 "legacy_sign": pem(ec.generate_private_key(ec.SECP256R1())),
                 "legacy_encrypt": pem(rsa.generate_private_key(public_exponent=65537, key_size=1280))}
        save_private(path, state)
    return {k: serialization.load_pem_private_key(v.encode(), password=None) for k, v in state.items()}


def legacy_identity(keys):
    point = keys["legacy_sign"].public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    modulus = keys["legacy_encrypt"].public_key().public_numbers().n.to_bytes(161, "big")
    return (b"\x30\x81\xf6\x81\x43\x00\x41" + point
            + b"\x82\x81\xae\x00\xac\x30\x81\xa9\x02\x81\xa1" + modulus
            + b"\x02\x03\x01\x00\x01")


async def main():
    auth = json.loads((PRIVATE / "ids-auth.json").read_text())
    push = json.loads((PRIVATE / "apns-identity.json").read_text())
    http = VerifiedHttpSession(PROXY)
    try:
        response = await http.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")
        bag = plistlib.loads(response.plist()["bag"])
        async def request(bag_key, body=None, indexed=False):
            endpoint = bag[bag_key]
            url = urlparse(endpoint)
            if url.scheme != "https" or not url.hostname.endswith(".apple.com"):
                raise ValueError("Unexpected IDS service host")
            headers = signing_headers(bag_key=bag_key, query=url.query, body=body,
                token=push["token"], auth=auth, push=push, auth_number=0 if indexed else None)
            headers.update({"x-protocol-version": "1660", "Content-Type": "application/x-apple-plist",
                "User-Agent": "com.apple.invitation-registration [macOS,12.7.6,21H1320,Macmini7,1]",
                "x-auth-user-id" + ("-0" if indexed else ""): auth["profile_id"]})
            if body:
                headers["Content-Encoding"] = "gzip"
            response = await http.request("POST" if body else "GET", endpoint, headers=headers, data=body)
            data = response.plist()
            summary = {"stage": bag_key, "http_status": response.status_code,
                       "status": data.get("status"), "fields": sorted(data)}
            if data.get("message"):
                message = str(data["message"])
                for sensitive in (auth["profile_id"], push["token"]):
                    message = message.replace(sensitive, "<redacted>")
                message = re.sub(r"[A-Za-z0-9+/=_-]{24,}", "<opaque>", message)
                summary["message"] = message[:500]
            print(json.dumps(summary), flush=True)
            save_private(PRIVATE / (bag_key + "-diagnostics.json"), summary)
            if not response.ok or data.get("status") != 0:
                raise RuntimeError("IDS request rejected")
            return data
        handles = await request("id-get-handles")
        uris = [{"uri": h["uri"]} for h in handles["handles"]]
        save_private(PRIVATE / "ids-handles.json", {"handles": uris})
        keys = message_identity()
        capabilities = {"public-message-identity-key": legacy_identity(keys),
            "public-message-identity-version": 2, "ec-version": 1,
            "public-message-identity-ngm-version": 13,
            "public-message-ngm-device-prekey-data-key": prekey_data(keys["device"], keys["prekey"]),
            "kt-version": 5, **{k: True for k in ("supports-fmd-v2", "supports-incoming-fmd-v1",
                "supports-findmy-plugin-messages", "supports-beacon-sharing-v3", "supports-beacon-sharing-v2",
                "supports-secure-loc-v1", "supports-key-sharing")}}
        payload = {"device-name": "Home Assistant Find My receiver", "hardware-version": "Macmini7,1",
            "language": "en-US", "os-version": "macOS,12.7.6,21H1320", "software-version": "21H1320",
            "private-device-data": {"ap": "0", "d": f"{time.time() - 978307200:.6f}",
                "dt": 1, "gt": "0", "h": "1", "p": "0", "pb": "21H1320",
                "pn": "macOS", "pv": "12.7.6", "m": "1", "s": "1", "t": "0",
                "u": push["device_id"].upper(), "v": "1"},
            "validation-data": (PRIVATE / "nac.bin").read_bytes(),
            "services": [{"capabilities": [{"flags": 1, "name": "com.apple.private.alloy", "version": 1}],
                "service": "com.apple.private.alloy.multiplex1", "sub-services": TOPICS,
                "users": [{"user-id": auth["profile_id"], "uris": uris,
                           "client-data": capabilities, "kt-loggable-data": kt_data(keys["device"])}]}]}
        data = await request("id-register", gzip.compress(plistlib.dumps(payload), mtime=0), indexed=True)
        statuses = [{"status": service.get("status"), "user_statuses": [u.get("status") for u in service.get("users", [])]}
                    for service in data.get("services", [])]
        print(json.dumps({"stage": "registration_status", "services": statuses}), flush=True)
        users = data["services"][0]["users"]
        if any(u.get("status") != 0 for u in users):
            raise RuntimeError("Find My registration user rejected")
        cert = x509.load_der_x509_certificate(users[0]["cert"])
        authkey = serialization.load_pem_private_key(auth["key"].encode(), password=None)
        if cert.public_key().public_numbers() != authkey.public_key().public_numbers():
            raise ValueError("Registration certificate key mismatch")
        save_private(PRIVATE / "ids-registration.json", {"profile_id": auth["profile_id"],
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode(), "key": auth["key"],
            "uris": uris, "topics": TOPICS})
    finally:
        await http.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        print(json.dumps({"stage": "ids_register", "error_type": type(exc).__name__}))
        raise SystemExit(1)
