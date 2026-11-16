"""Activate a persistent emulated APNs receiver and verify its courier connection.

No Apple account password or location request is used here. Activation constants
come from the MIT-licensed, pinned pypush research checkout.
"""
import asyncio
import base64
import json
import logging
import os
import plistlib
import re
import secrets
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from .environment import log_diagnostic
from .apple_probe import PROXY, PRIVATE, ASSETS, VerifiedHttpSession, save_private


def frame(command, fields):
    payload = b"".join(bytes([tag]) + len(value).to_bytes(2, "big") + value
                       for tag, value in fields)
    return bytes([command]) + len(payload).to_bytes(4, "big") + payload


async def read_frame(reader):
    header = await reader.readexactly(5)
    size = int.from_bytes(header[1:], "big")
    if size > 1024 * 1024:
        raise ValueError("Oversized APNs frame")
    payload = await reader.readexactly(size)
    fields = []
    while payload:
        if len(payload) < 3:
            raise ValueError("Truncated APNs field")
        length = int.from_bytes(payload[1:3], "big")
        if len(payload) < 3 + length:
            raise ValueError("Truncated APNs field value")
        fields.append((payload[0], payload[3:3 + length]))
        payload = payload[3 + length:]
    return header[0], fields


async def activate(http):
    path = PRIVATE / "apns-identity.json"
    if path.exists():
        return json.loads(path.read_text())
    sys.path.insert(0, str(ASSETS / "research/vendor/pypush-full"))
    from ..enrollment import _der
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Client Push Certificate")]).public_bytes()
    public = key.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    request = _der(0x30, b"\x02\x01\x00" + subject + public + b"\xa0\x00")
    csr = _der(0x30, request + bytes.fromhex("300d06092a864886f70d0101050500")
               + _der(0x03, b"\x00" + key.sign(request, padding.PKCS1v15(), hashes.SHA1())))
    csr_pem = x509.load_der_x509_csr(csr).public_bytes(serialization.Encoding.PEM)
    device_id = json.loads((PRIVATE / "client-identity.json").read_text())["devid"]
    hardware = plistlib.loads((ASSETS / "research/vendor/pypush-full/emulated/data.plist").read_bytes())["iokit"]
    info = plistlib.dumps({
        "ActivationRandomness": str(uuid.uuid4()), "ActivationState": "Unactivated",
        "BuildVersion": "21H1320", "DeviceCertRequest": csr_pem,
        "DeviceClass": "MacOS", "ProductType": "Macmini7,1", "ProductVersion": "12.7.6",
        "SerialNumber": hardware["IOPlatformSerialNumber"], "UniqueDeviceID": device_id.upper(),
    })
    legacy = ASSETS / "research/vendor/rustpush/certs/legacy-fairplay"
    keybytes = (legacy / "fairplay.pem").read_bytes()
    loader = serialization.load_pem_private_key if keybytes.startswith(b"-----") else serialization.load_der_private_key
    fairplay = loader(keybytes, password=None)
    activation = plistlib.dumps({"ActivationInfoComplete": True, "ActivationInfoXML": info,
        "FairPlayCertChain": (legacy / "fairplay.crt").read_bytes(),
        "FairPlaySignature": fairplay.sign(info, padding.PKCS1v15(), hashes.SHA1())})
    response = await http.post(
        "https://albert.apple.com/deviceservices/deviceActivation?device=MacOS",
        data={"activation-info": activation},
        headers={"User-Agent": "ApplePushService/4.0 CFNetwork/1408.0.4 Darwin/22.5.0"})
    log_diagnostic(json.dumps({"stage": "apns_activation", "http_status": response.status_code}), flush=True)
    if not response.ok:
        raise RuntimeError("APNs activation rejected")
    match = re.search(r"<Protocol>(.*?)</Protocol>", response.text(), re.S)
    if not match:
        raise RuntimeError("Missing activation protocol")
    result = plistlib.loads(match.group(1).encode())
    if "device-activation" not in result:
        log_diagnostic(json.dumps({"stage": "activation_protocol", "fields": sorted(result),
                          "nested_fields": {k: sorted(v) for k, v in result.items() if isinstance(v, dict)}}), flush=True)
        raise RuntimeError("Activation did not return a device record")
    pem = result["device-activation"]["activation-record"]["DeviceCertificate"]
    cert = x509.load_pem_x509_certificate(pem)
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError("APNs certificate public key mismatch")
    identity = {"key": key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(),
        "cert": pem.decode(), "device_id": device_id}
    save_private(path, identity)
    return identity


def courier_connect_fields(identity, *, signed):
    fields = [(2, b"\x01"), (5, (0x41 if signed else 0x45).to_bytes(4, "big"))]
    if identity.get("token"):
        fields.insert(0, (1, base64.b64decode(identity["token"])))
    if signed:
        nonce = b"\x00" + (int(time.time()) * 1000).to_bytes(8, "big") + secrets.token_bytes(8)
        certificate = x509.load_pem_x509_certificate(identity["cert"].encode())
        key = serialization.load_pem_private_key(identity["key"].encode(), password=None)
        signature = b"\x01\x01" + key.sign(nonce, padding.PKCS1v15(), hashes.SHA1())
        fields.extend([(12, certificate.public_bytes(serialization.Encoding.DER)), (13, nonce),
                       (14, signature), (16, (9).to_bytes(2, "big"))])
    return fields


async def connect(http, identity, *, keep_open=False, signed=False):
    response = await http.get("https://init.push.apple.com/bag")
    if not response.ok:
        raise RuntimeError("APNs bag rejected")
    bag = response.plist()
    if "bag" in bag:
        bag = plistlib.loads(bag["bag"])
    suffix = bag["APNSCourierHostname"]
    if not suffix.endswith(".push.apple.com"):
        raise ValueError("Unexpected courier host")
    host = f"{secrets.randbelow(int(bag['APNSCourierHostcount'])) + 1}-{suffix}"
    context = VerifiedHttpSession().tls_context
    alpn = "apns-security-v3" if signed else "apns-security-v2"
    if not signed:
        certfile, keyfile = PRIVATE / "apns-cert.pem", PRIVATE / "apns-key.pem"
        for path, content in ((certfile, identity["cert"]), (keyfile, identity["key"])):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(content)
        # The legacy 1024-bit client certificate needs a lower TLS security level.
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
        context.load_cert_chain(certfile, keyfile)
    context.set_alpn_protocols([alpn])
    writer = None
    retained = False
    try:
        # The numbered address is a routing endpoint. Apple's bag advertises
        # the base courier service identity used by its TLS certificate.
        if PROXY:
            proxy = urlparse(PROXY)
            if proxy.scheme != "http" or not proxy.hostname or proxy.username:
                raise ValueError("Courier requires an HTTP CONNECT proxy without embedded credentials")
            reader, writer = await asyncio.wait_for(asyncio.open_connection(proxy.hostname, proxy.port or 80), 15)
            writer.write(f"CONNECT {host}:5223 HTTP/1.1\r\nHost: {host}:5223\r\n\r\n".encode())
            await writer.drain()
            reply = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 20)
            if reply.split(b" ", 2)[1] != b"200":
                raise RuntimeError("Proxy courier tunnel rejected")
            await asyncio.wait_for(writer.start_tls(context, server_hostname=suffix), 20)
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 5223, ssl=context, server_hostname=suffix), 20
            )
        negotiated = writer.get_extra_info("ssl_object").selected_alpn_protocol()
        if signed and negotiated not in (None, alpn):
            raise RuntimeError("Courier negotiated an unsupported protocol")
        writer.write(frame(7, courier_connect_fields(identity, signed=signed)))
        await writer.drain()
        command, fields = await asyncio.wait_for(read_frame(reader), 20)
        values = dict(fields)
        if command != 8 or values.get(1) != b"\x00":
            raise RuntimeError("Courier connect rejected")
        token = values.get(3) or base64.b64decode(identity.get("token", ""))
        if not token:
            raise RuntimeError("Courier did not issue a token")
        if signed and identity.get("token") and token != base64.b64decode(identity["token"]):
            raise RuntimeError("Signed courier did not retain the registered token")
        identity["token"] = base64.b64encode(token).decode()
        save_private(PRIVATE / "apns-identity.json", identity)
        log_diagnostic(json.dumps({"stage": "apns_courier", "tls_verified": True, "protocol": negotiated,
                          "token_bytes": len(token)}), flush=True)
        if keep_open:
            retained = True
            return reader, writer
    finally:
        if writer is not None and not retained:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


async def main():
    http = VerifiedHttpSession(PROXY)
    try:
        identity = await activate(http)
        await connect(http, identity)
    finally:
        await http.close()


if __name__ == "__main__":

    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        log_diagnostic(json.dumps({"stage": "apns", "error_type": type(exc).__name__,
                          "ssl_reason": getattr(exc, "reason", None),
                          "verify_message": getattr(exc, "verify_message", None)}), flush=True)
        raise SystemExit(1)
