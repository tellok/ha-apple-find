"""Bounded service-token comparisons using existing account credentials.

No relationship, location, device inventory, or share-changing requests.
Print only status codes and credential/configuration field names.
"""
import asyncio
import json
import logging
import os

from apple_probe import PRIVATE, PROXY, ResearchAccount, ResearchAnisetteProvider, VerifiedHttpSession, save_private

CLIENTS = {
    "windows_control": "<PC> <Windows;10.0;19045> <com.apple.AuthKitWin/1 (com.apple.iCloud/15.2)>",
    "preferences_reference": "<iPhone6,1> <iPhone OS;9.3.2;13F69> <com.apple.AppleAccount/1.0 (com.apple.Preferences/1.0)>",
    "cloudkit_reference": "<iPhone5,3> <iPhone OS;9.0.1;13A404> <com.apple.cloudkit.CloudKitDaemon/479 (com.apple.cloudd/479)>",
    "aoskit_reference": "<Macmini7,1> <macOS;12.7.6;21H1320> <com.apple.AOSKit/282 (com.apple.accountsd/113)>",
}


async def main():
    state = json.loads((PRIVATE / "account.json").read_text())
    login = state["login"]["data"]
    token = login["mobileme_data"]["tokens"]["mmeAuthToken"]
    dsid = str(login["dsid"])
    provider = ResearchAnisetteProvider.from_json(PRIVATE / "anisette-state.json", libs_path=PRIVATE / "anisette-libs.bin")
    account = ResearchAccount(provider, state_info=state)
    account._http = VerifiedHttpSession(PROXY)
    results = []
    try:
        for name, client in CLIENTS.items():
            # Legacy primary references use no Anisette for this token-broker
            # GET. Keep the successful control's identity headers unchanged.
            headers = await account.get_anisette_headers() if name == "windows_control" else {}
            headers.update({"X-Mme-Client-Info": client, "Accept": "application/xml",
                            "User-Agent": "CloudKit/479 (13A404)" if name == "cloudkit_reference" else "accountsd/113 CFNetwork/1408.0.4 Darwin/22.5.0"})
            response = await account._http.get("https://setup.icloud.com/setup/get_account_settings",
                auth=(dsid, token), headers=headers)
            result = {"stage": "settings_scope", "client": name, "http_status": response.status_code}
            try:
                data = response.plist()
                tokens = data.get("tokens", {})
                config = data.get("com.apple.mobileme", {})
                result.update(token_names=sorted(tokens), service_names=sorted(config),
                              status=data.get("status"), error_id=data.get("ErrorID"))
                if "mmeFMFAppToken" in tokens or "searchPartyToken" in tokens:
                    needed = {k: v for k, v in tokens.items() if k in ("mmeAuthToken", "mmeFMFAppToken", "searchPartyToken")}
                    service = {k: v for k, v in config.items() if any(w in k.lower() for w in ("find", "fmf", "searchparty"))}
                    save_private(PRIVATE / "findmy-settings.json", {"dsid": dsid, "tokens": needed, "config": service})
            except (ValueError, TypeError):
                result["response_bytes"] = len(response._content)
            results.append(result)
            print(json.dumps(result), flush=True)
    finally:
        save_private(PRIVATE / "token-scope-results.json", {"results": results})
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        print(json.dumps({"stage": "settings_scope", "error_type": type(exc).__name__}))
        raise SystemExit(1)
