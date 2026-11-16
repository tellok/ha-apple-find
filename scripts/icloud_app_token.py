"""Probe the documented GSA iCloud app-token exchange, without passwords."""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import plistlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from findmy.util.parsers import decode_plist

from apple_probe import PROXY, PRIVATE, ResearchAccount, ResearchAnisetteProvider, VerifiedHttpSession


async def main():
    spd = plistlib.loads((PRIVATE / "gsa-session.plist").read_bytes())
    if spd.get("status-code") != 200:
        raise RuntimeError("An authenticated GSA session is required")
    provider = ResearchAnisetteProvider.from_json(PRIVATE / "anisette-state.json", libs_path=PRIVATE / "anisette-libs.bin")
    account = ResearchAccount(provider, state_info=json.loads((PRIVATE / "account.json").read_text()))
    account._http = VerifiedHttpSession(PROXY)
    apps = ["com.apple.gs.icloud.auth"]
    try:
        checksum = hmac.new(spd["sk"], ("apptokens" + str(spd["adsid"]) + "".join(apps)).encode(), hashlib.sha256).digest()
        response = await account._gsa_request({"o": "apptokens", "u": str(spd["adsid"]), "app": apps,
            "c": spd["c"], "t": spd["GsIdmsToken"], "checksum": checksum})
        if response.get("Status", {}).get("ec") != 0:
            raise RuntimeError("App token exchange rejected")
        envelope = response["et"]
        if len(envelope) < 35:
            raise ValueError("Truncated encrypted app token")
        plain = AESGCM(spd["sk"]).decrypt(envelope[3:19], envelope[19:], envelope[:3])
        payload = decode_plist(plain)
        fd = os.open(PRIVATE / "icloud-app-token.plist", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            plistlib.dump(payload, stream)
        print(json.dumps({"stage": "icloud_app_token", "fields": sorted(payload),
                          "token_names": sorted(payload.get("t", {}))}), flush=True)
    finally:
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        print(json.dumps({"stage": "icloud_app_token", "error_type": type(exc).__name__}))
        raise SystemExit(1)
