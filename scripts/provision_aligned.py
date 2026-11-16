"""Provision an isolated ADI identity matching the unmodified NAC fixture.

Run in Linux with FINDMY_STATE_DIR pointing to a new research directory.
Never changes an existing provisioned identity or asks for account credentials.
"""
import json
import logging
import os
import plistlib
import secrets

import urllib3
from anisette import Anisette
from anisette._device import AnisetteDeviceConfig

from apple_probe import PRIVATE, PROXY, ASSETS, CLIENT_PROFILES, VerifiedHttpSession, save_private
from findmy import LocalAnisetteProvider


def main():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    state_path = PRIVATE / "anisette-state.json"
    if state_path.exists():
        raise RuntimeError("Refusing to replace an existing provisioned identity")
    hardware = plistlib.loads((ASSETS / "research/vendor/pypush-full/emulated/data.plist").read_bytes())["iokit"]
    config = AnisetteDeviceConfig(
        server_friendly_description=CLIENT_PROFILES["mac_hardware"],
        unique_device_id=hardware["IOPlatformUUID"],
        adi_id=secrets.token_hex(8),
        local_user_uuid=secrets.token_hex(32).upper(),
    )
    ani = Anisette.load(PRIVATE / "anisette-libs.bin", default_device_config=config)
    session = ani._ani_provider.provisioning_session
    # Use the same pinned roots and verified proxy path as account HTTP.
    http = VerifiedHttpSession(PROXY)
    session._http.clear()
    session._http = urllib3.ProxyManager(PROXY, ssl_context=http.tls_context)
    ani.provision()
    headers = ani.get_data()
    if headers["X-Mme-Device-Id"] != hardware["IOPlatformUUID"]:
        raise RuntimeError("Provisioned identity does not match the NAC fixture")
    provider = LocalAnisetteProvider(libs_path=PRIVATE / "anisette-libs.bin")
    provider._ani = ani
    save_private(state_path, provider.to_json())
    save_private(PRIVATE / "debug-profile.json", {"profile": "mac_hardware"})
    result = {"stage": "aligned_adi_provisioning", "provisioned": ani.is_provisioned,
              "matches_nac_fixture_uuid": True, "password_sent": False}
    save_private(PRIVATE / "aligned-provisioning-result.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        main()
    except Exception as exc:
        print(json.dumps({"stage": "aligned_adi_provisioning", "error_type": type(exc).__name__}))
        raise SystemExit(1)
