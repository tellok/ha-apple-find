"""Run the article's NAC emulator with verified TLS and no account credentials."""
import base64
import logging
import os
from pathlib import Path
import plistlib
import sys

import certifi
import requests

from .environment import environment

ASSETS, PRIVATE = environment.assets, environment.state
VENDOR = ASSETS / "research/vendor/pypush-full"


def main():
    logging.disable(logging.CRITICAL)
    os.chdir(VENDOR)
    sys.path.insert(0, str(VENDOR))
    from emulated import nac

    bundle = PRIVATE / "apple-ca-bundle.pem"
    from .apple_probe import VerifiedHttpSession
    VerifiedHttpSession()  # Verify the fingerprint-pinned root files before using them.
    bundle.write_bytes(Path(certifi.where()).read_bytes() + (ASSETS / "research/apple-root-ca.pem").read_bytes()
                       + (ASSETS / "research/apple-root-ca-g3.pem").read_bytes())
    session = requests.Session()
    session.verify = str(bundle)
    proxy = os.environ.get("FINDMY_PROXY")
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    def get_cert():
        response = session.get("https://static.ess.apple.com/identity/validation/cert-1.0.plist", timeout=20)
        response.raise_for_status()
        return plistlib.loads(response.content)["cert"]

    def get_session_info(request):
        response = session.post("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation",
                                data=plistlib.dumps({"session-info-request": bytes(request)}), timeout=20)
        response.raise_for_status()
        return plistlib.loads(response.content)["session-info"]

    nac.get_cert = get_cert
    nac.get_session_info = get_session_info
    # Preserve the source fixture's hardware bundle. Its opaque registry
    # properties may be bound to the original UUID; change no single field.
    value = nac.generate_validation_data()
    path = PRIVATE / "nac.bin"
    path.write_bytes(value)
    path.chmod(0o600)
    print(__import__("json").dumps({"nac_ready": True, "bytes": len(value)}))


if __name__ == "__main__":
    os.umask(0o077)
    try:
        main()
    except Exception as exc:
        diagnostic = {"nac_ready": False, "error_type": type(exc).__name__}
        if isinstance(exc, requests.exceptions.SSLError):
            diagnostic["ssl_error"] = str(exc)
        print(__import__("json").dumps(diagnostic))
        raise SystemExit(1)
