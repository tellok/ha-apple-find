"""Acquire scoped MobileMe/IDS delegates; never requests a location."""
import argparse
import asyncio
import base64
import json
import logging
import os
import plistlib
import re

from findmy import LoginState

from .apple_probe import PROXY, PRIVATE, ASSETS, ResearchAccount, ResearchAnisetteProvider, VerifiedHttpSession, save_private


async def main(args):
    state = json.loads((PRIVATE / "account.json").read_text())
    bootstrap = json.loads((PRIVATE / "ids-bootstrap.json").read_text())
    if args.use_cloud_app_token:
        app_tokens = plistlib.loads((PRIVATE / "icloud-app-token.plist").read_bytes())
        bootstrap["idms_pet"] = app_tokens["t"]["com.apple.gs.icloud.auth"]["token"]
    session = plistlib.loads((PRIVATE / "gsa-session.plist").read_bytes())
    if session.get("status-code") == 409:
        raise RuntimeError("Two-factor authentication remains pending; refusing delegate exchange")
    if not bootstrap.get("idms_pet"):
        raise RuntimeError("No PET; refusing an unauthorized delegate request")
    provider = ResearchAnisetteProvider.from_json(PRIVATE / "anisette-state.json", libs_path=PRIVATE / "anisette-libs.bin")
    account = ResearchAccount(provider, state_info=state)
    account._http = VerifiedHttpSession(PROXY)
    try:
        headers = await account.get_anisette_headers()
        headers.update({"X-Apple-ADSID": str(bootstrap["adsid"]),
                        "X-Mme-Client-Info": args.client or provider.client,
                        "X-Mme-Nas-Qualify": base64.b64encode((PRIVATE / "nac.bin").read_bytes()).decode(),
                        "Content-Type": "application/x-apple-plist",
                        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0"})
        if args.nac_profile:
            hardware = plistlib.loads((ASSETS
                / "research/vendor/pypush-full/emulated/data.plist").read_bytes())["iokit"]
            headers.update({"X-Apple-I-SRL-NO": hardware["IOPlatformSerialNumber"],
                            "X-Apple-I-MLB": hardware["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"].decode(),
                            "X-Apple-I-ROM": hardware["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"].hex(),
                            "X-Mme-Client-Info": "<Macmini7,1> <macOS;12.7.6;21H1320> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
                            "X-MMe-Country": "CN"})
        delegates = {"com.apple.private.ids": {"protocol-version": "4"}}
        if not args.ids_only:
            delegates["com.apple.mobileme"] = {}
        payload = {"delegates": delegates,
                   "protocolVersion": "1.0", "userInfo": {"client-id": account._uid.upper(),
                   "language": "en-US", "timezone": "Asia/Taipei"}}
        host = "setup.icloud.com.cn" if args.region == "cn" else "setup.icloud.com"
        url = "https://" + host + "/setup/signin/v2/login"
        if args.endpoint in ("prefpane", "iosbuddy"):
            url = "https://" + host + "/setup/" + args.endpoint + "/loginDelegates"
            payload = {"apple-id": account._username, "password": bootstrap["idms_pet"],
                       "client-id": account._uid.upper(), "delegates": delegates}
        elif args.endpoint == "profile":
            url = "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateUser"
            payload = {"username": account._username, "password": bootstrap["idms_pet"]}
        response = await account._http.post(url,
                                           auth=(account._username, bootstrap["idms_pet"]),
                                           headers=headers, data=plistlib.dumps(payload))
        try:
            data = response.plist()
        except Exception:
            text = response.text()
            import re as _re
            summary = {"stage": "signin_v2", "http_status": response.status_code,
                       "region": args.region, "response_bytes": len(response._content),
                       "html_title": _re.findall(r"<title>([^<]{0,120})</title>", text, _re.I)}
            save_private(PRIVATE / "delegate-diagnostics.json", summary)
            print(json.dumps(summary), flush=True)
            raise RuntimeError("Delegate response is not a property list") from None
        summary = {"stage": args.endpoint, "http_status": response.status_code, "status": data.get("status"),
                   "response_fields": sorted(data), "delegates": {}, "region": args.region}
        for field in ("ErrorID", "localizedError", "Header", "Body", "description"):
            if field in data:
                value = str(data[field])
                for sensitive in (account._username, str(bootstrap["adsid"]), bootstrap["idms_pet"]):
                    if sensitive:
                        value = value.replace(sensitive, "<redacted>")
                value = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<email>", value)
                value = re.sub(r"[A-Za-z0-9+/=_-]{32,}", "<opaque>", value)
                summary[field] = value[:500]
        for name, delegate in data.get("delegates", {}).items():
            summary["delegates"][name] = {"status": delegate.get("status"),
                "service_fields": sorted(delegate.get("service-data", {}))}
        save_private(PRIVATE / "delegate-diagnostics.json", summary)
        print(json.dumps(summary, indent=2), flush=True)
        if response.ok and data.get("status") == 0:
            if args.endpoint == "profile":
                save_private(PRIVATE / "ids-profile.json", data)
                return
            save_private(PRIVATE / "delegates-v2.json", data)
            mobileme = data.get("delegates", {}).get("com.apple.mobileme", {})
            if mobileme.get("status") == 0:
                service = mobileme["service-data"]
                dsid = data.get("dsid") or service.get("dsid")
                if dsid is not None:
                    account._set_login_state(LoginState.LOGGED_IN, {"dsid": dsid, "mobileme_data": service})
                    updated = account.to_json()
                    updated["account"]["password"] = None
                    save_private(PRIVATE / "account.json", updated)
    finally:
        save_private(PRIVATE / "anisette-state.json", provider.to_json())
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", default=None)
    parser.add_argument("--use-cloud-app-token", action="store_true", help="Compare the iCloud settings app credential with the normal PET")
    parser.add_argument("--endpoint", choices=["signin_v2", "prefpane", "iosbuddy", "profile"], default="signin_v2")
    parser.add_argument("--region", choices=["global", "cn"], default="global")
    parser.add_argument("--ids-only", action="store_true")
    parser.add_argument("--nac-profile", action="store_true", help="Match serial/ROM/MLB and a compatible OS to the NAC emulated hardware")
    try:
        asyncio.run(main(parser.parse_args()))
    except Exception as exc:
        print(json.dumps({"stage": "signin_v2", "error_type": type(exc).__name__}))
        raise SystemExit(1)
