"""Enroll the authorized Linux identity and fetch service settings without requesting a location."""

import argparse
import json
import os
import subprocess

from .apple_probe import PRIVATE
from .environment import module_command


def step(script, *arguments):
    subprocess.run(module_command(script, *arguments), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", choices=("global", "cn"), default="global")
    args = parser.parse_args()
    login = json.loads((PRIVATE / "account.json").read_text())["login"]["data"]
    if not login.get("dsid") or not login.get("mobileme_data"):
        raise ValueError("Complete Apple login first")

    # Use the PET promptly after 2FA and get a fresh validation blob for each registration request.
    step("nac_probe")
    step("people_bootstrap", "--ids-only", "--region", args.region)
    delegates = json.loads((PRIVATE / "delegates-v2.json").read_text())["delegates"]
    if delegates.get("com.apple.private.ids", {}).get("status") != 0:
        raise ValueError("Apple did not issue the IDS delegate")
    step("account_settings")
    settings = json.loads((PRIVATE / "findmy-settings.json").read_text())
    if str(settings.get("dsid")) != str(login["dsid"]):
        raise ValueError("Find My service settings belong to another account")
    tokens = settings.get("tokens", {}) | login["mobileme_data"]["tokens"]
    if not tokens.get("mmeFMFAppToken") or not tokens.get("searchPartyToken"):
        raise ValueError("Apple did not issue both Find My People tokens")
    step("ids_enroll")
    step("apns_probe")
    step("nac_probe")
    step("ids_register")
    print(json.dumps({"stage": "people_enrollment", "status": "ready_for_selected_share"}))


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"stage": "people_enrollment", "status": "failed", "error": type(error).__name__}))
        raise SystemExit(1) from None
