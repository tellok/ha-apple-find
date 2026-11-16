"""Exchange the scoped IDS delegate for its authentication certificate."""
import asyncio
import json
import logging
import os
import plistlib
import sys
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .apple_probe import PROXY, PRIVATE, VerifiedHttpSession, save_private

from ..enrollment import authenticate_body


async def main():
    delegates = json.loads((PRIVATE / "delegates-v2.json").read_text())
    delegate = delegates["delegates"]["com.apple.private.ids"]
    if delegate.get("status") != 0:
        raise RuntimeError("No successful IDS delegate")
    service = delegate["service-data"]
    profile = service["realm-user-id"]
    http = VerifiedHttpSession(PROXY)
    try:
        response = await http.get("https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3")
        if not response.ok:
            raise RuntimeError("IDS bag rejected")
        bag = plistlib.loads(response.plist()["bag"])
        endpoint = bag["id-authenticate-ds-id"]
        url = urlparse(endpoint)
        if url.scheme != "https" or not url.hostname.endswith(".apple.com"):
            raise ValueError("Unexpected IDS enrollment host")
        keypath = PRIVATE / "ids-auth-key.pem"
        if keypath.exists():
            key = serialization.load_pem_private_key(keypath.read_bytes(), password=None)
        else:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            fd = os.open(keypath, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        response = await http.post(endpoint,
            data=authenticate_body(key, profile, service["auth-token"]),
            headers={"x-protocol-version": "1660", "Content-Type": "application/x-apple-plist",
                     "Content-Encoding": "gzip", "User-Agent": "com.apple.invitation-registration"})
        data = response.plist()
        diagnostic = {"stage": "ids_authenticate_ds", "http_status": response.status_code,
                      "status": data.get("status"), "fields": sorted(data)}
        save_private(PRIVATE / "ids-enrollment-diagnostics.json", diagnostic)
        print(json.dumps(diagnostic), flush=True)
        if not response.ok or data.get("status") != 0:
            raise RuntimeError("IDS enrollment rejected")
        cert = x509.load_der_x509_certificate(data["cert"])
        if cert.public_key().public_numbers() != key.public_key().public_numbers():
            raise ValueError("IDS certificate public key mismatch")
        save_private(PRIVATE / "ids-auth.json", {"profile_id": profile,
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "key": keypath.read_text()})
    finally:
        await http.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        print(json.dumps({"stage": "ids_enroll", "error_type": type(exc).__name__}))
        raise SystemExit(1)
