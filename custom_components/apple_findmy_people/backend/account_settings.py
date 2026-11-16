"""Fetch service configuration with the existing iCloud account token.

No Find My relationship or location is requested. Persist only the credentials
and configuration needed by Find My Friends and SearchParty.
"""
import asyncio
import argparse
import json
import logging
import os
import plistlib

from .apple_probe import PROXY, PRIVATE, ResearchAccount, ResearchAnisetteProvider, VerifiedHttpSession, save_private


async def main(args):
    account_path = PRIVATE / "account.json"
    state = json.loads(account_path.read_text())
    login = state["login"]["data"]
    dsid, token = str(login["dsid"]), login["mobileme_data"]["tokens"]["mmeAuthToken"]
    settings_path = PRIVATE / "findmy-settings.json"
    if settings_path.is_file() and settings_path.stat().st_mtime_ns >= account_path.stat().st_mtime_ns:
        previous = json.loads(settings_path.read_text())
        if str(previous.get("dsid")) == dsid:
            token = previous.get("tokens", {}).get("mmeAuthToken") or token
    bootstrap = json.loads((PRIVATE / "ids-bootstrap.json").read_text())
    provider = ResearchAnisetteProvider.from_json(PRIVATE / "anisette-state.json", libs_path=PRIVATE / "anisette-libs.bin")
    account = ResearchAccount(provider, state_info=state)
    account._http = VerifiedHttpSession(PROXY)
    try:
        headers = await account.get_anisette_headers()
        headers.update({"X-Apple-ADSID": str(bootstrap["adsid"]),
                        "X-MMe-Client-Info": args.client or provider.client,
                        "User-Agent": args.user_agent or "accountsd/113 CFNetwork/1408.0.4 Darwin/22.5.0"})
        for host in ("setup.icloud.com", "setup.icloud.com.cn"):
            credentials = (account._username, bootstrap["idms_pet"]) if args.pet else (dsid, token)
            if args.post:
                headers["Content-Type"] = "application/x-apple-plist"
            response = await account._http.request("POST" if args.post else "GET",
                "https://" + host + "/setup/get_account_settings", auth=credentials, headers=headers,
                data=b"" if args.post else None)
            summary = {"stage": "get_account_settings", "host": host, "http_status": response.status_code,
                       "method": "POST" if args.post else "GET", "auth_kind": "PET" if args.pet else "mmeAuthToken"}
            try:
                data = response.plist()
                summary["fields"] = sorted(data)
                summary["token_names"] = sorted(data.get("tokens", {}))
                config = data.get("com.apple.mobileme", {})
                summary["config_names"] = sorted(config)
            except Exception:
                data = {}
                summary["response_bytes"] = len(response._content)
            print(json.dumps(summary), flush=True)
            if response.status_code == 429:
                raise RuntimeError("Apple rate-limited the service configuration request")
            if response.ok and data:
                tokens = {k: v for k, v in data.get("tokens", {}).items()
                          if k in ("mmeAuthToken", "mmeFMFAppToken", "searchPartyToken")}
                config = {k: v for k, v in data.get("com.apple.mobileme", {}).items()
                          if k in ("com.apple.Dataclass.FindMyLocate",
                                   "com.apple.Dataclass.ShareLocation",
                                   "com.apple.Dataclass.SearchParty")}
                people_url = config.get("com.apple.Dataclass.FindMyLocate", {}).get("people_url")
                app_host = config.get("com.apple.Dataclass.ShareLocation", {}).get("appHostname")
                if not ((people_url or app_host)
                        and config.get("com.apple.Dataclass.SearchParty", {}).get("findmyservice_gateway_url")):
                    continue
                save_private(settings_path, {"dsid": dsid, "tokens": tokens, "config": config})
                return
        raise RuntimeError("Apple did not provide both Find My People service endpoints")
    finally:
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--post", action="store_true")
    parser.add_argument("--pet", action="store_true")
    parser.add_argument("--client", default=None)
    parser.add_argument("--user-agent", default=None)
    try:
        asyncio.run(main(parser.parse_args()))
    except Exception as exc:
        print(json.dumps({"stage": "account_settings", "error_type": type(exc).__name__}))
        raise SystemExit(1)
