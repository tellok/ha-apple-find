"""Windows ADI v3 research adapter; never sends account credentials to ADI.

Protocol reference: nab138/isideload remote_v3 at the pinned vendor commit.
Only provisioning blobs and the random per-install identifier reach the server.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import plistlib
import secrets
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

import aiohttp
from findmy.reports.anisette import BaseAnisetteProvider

from .apple_probe import PRIVATE, PROXY, VerifiedHttpSession, save_private, ResearchAccount

SERVER = "https://ani.jkcoxson.com"


class WindowsV3Anisette(BaseAnisetteProvider):
    def to_json(self, dst=None):
        value = {"type": "researchWindowsV3", "server": SERVER,
                 "client_override": self.client_override}
        if dst is not None:
            from pathlib import Path
            save_private(Path(dst), value)
        return value

    @classmethod
    def from_json(cls, value):
        if value.get("server") != SERVER:
            raise ValueError("Unexpected Windows ADI server")
        return cls(client_override=value.get("client_override"))

    def __init__(self, *, client_override=None):
        super().__init__()
        self.path = PRIVATE / "windows-adi-v3.json"
        self.state = json.loads(self.path.read_text()) if self.path.exists() else {"identifier": base64.b64encode(secrets.token_bytes(16)).decode()}
        if self.state.get("server", SERVER) != SERVER:
            raise ValueError("ADI provisioning belongs to a different server")
        self.state["server"] = SERVER
        self.http = VerifiedHttpSession(PROXY)
        self.client_override = client_override
        self.info = self.state.get("client_info")
        self.data = None
        self.expires = 0

    @property
    def client(self):
        if not self.info:
            raise RuntimeError("ADI metadata must be initialized first")
        return self.client_override or self.info["client_info"]

    @property
    def otp(self):
        return self.data["X-Apple-I-MD"]

    @property
    def machine(self):
        return self.data["X-Apple-I-MD-M"]

    @property
    def device_id(self):
        return str(uuid.UUID(bytes=base64.b64decode(self.state["identifier"], validate=True)))

    @property
    def local_user_id(self):
        return hashlib.sha256(base64.b64decode(self.state["identifier"], validate=True)).hexdigest()

    async def plist_request(self, endpoint, request):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname.endswith(".apple.com"):
            raise ValueError("Unexpected provisioning endpoint")
        response = await self.http.post(endpoint, headers={
            "Content-Type": "text/x-xml-plist", "X-Mme-Client-Info": self.info["client_info"],
            "User-Agent": self.info["user_agent"], "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-MD-LU": self.local_user_id,
        }, data=plistlib.dumps({"Header": {"Version": "1.0.1"}, "Request": request}))
        if not response.ok:
            raise RuntimeError("ADI provisioning HTTP failure")
        return response.plist()["Response"]

    async def initialize(self):
        response = await self.http.get(SERVER + "/v3/client_info")
        self.info = response.json()
        if not response.ok or set(self.info) != {"client_info", "user_agent"}:
            raise RuntimeError("Invalid Windows ADI metadata")
        self.state["client_info"] = self.info
        save_private(self.path, self.state)
        if self.state.get("adi_pb"):
            return
        lookup = await self.http.get("https://gsa.apple.com/grandslam/GsService2/lookup", headers={
            "User-Agent": self.info["user_agent"], "X-Mme-Client-Info": self.info["client_info"]})
        urls = lookup.plist()["urls"]
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=40)) as session:
            async with session.ws_connect(SERVER.replace("https:", "wss:") + "/v3/provisioning_session",
                ssl=self.http.tls_context, proxy=PROXY, max_msg_size=1024*1024) as ws:
                for _ in range(8):
                    msg = await asyncio.wait_for(ws.receive_json(), 30)
                    stage = msg.get("result")
                    if stage == "GiveIdentifier":
                        await ws.send_json({"identifier": self.state["identifier"]})
                    elif stage == "GiveStartProvisioningData":
                        response = await self.plist_request(urls["midStartProvisioning"], {})
                        await ws.send_json({"spim": response["spim"]})
                    elif stage == "GiveEndProvisioningData":
                        response = await self.plist_request(urls["midFinishProvisioning"], {"cpim": msg["cpim"]})
                        await ws.send_json({"ptm": response["ptm"], "tk": response["tk"]})
                    elif stage == "ProvisioningSuccess":
                        self.state["adi_pb"] = msg["adi_pb"]
                        save_private(self.path, self.state)
                        return
                    else:
                        raise RuntimeError("ADI provisioning failed at " + str(stage))
        raise RuntimeError("ADI provisioning did not complete")

    async def get_headers(self, user_id, device_id, serial="0", with_client_info=False):
        if not self.info or not self.state.get("adi_pb"):
            await self.initialize()
        now = asyncio.get_running_loop().time()
        if self.data is None or now >= self.expires:
            response = await self.http.post(SERVER + "/v3/get_headers", json={
                "identifier": self.state["identifier"], "adi_pb": self.state["adi_pb"]})
            data = response.json()
            if not response.ok or not all(isinstance(data.get(k), str) and data[k] for k in ("X-Apple-I-MD", "X-Apple-I-MD-M")):
                raise RuntimeError("Windows ADI headers unavailable")
            self.data, self.expires = data, now + 30
        headers = {"X-Apple-I-MD": self.otp, "X-Apple-I-MD-M": self.machine,
            "X-Mme-Device-Id": self.device_id, "X-Apple-I-MD-LU": self.local_user_id,
            "X-Apple-I-MD-RINFO": str(self.data.get("X-Apple-I-MD-RINFO", "50660608")),
            "X-Apple-I-Client-Time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "X-Apple-I-TimeZone": "UTC", "X-Apple-Locale": "en_US"}
        if with_client_info:
            headers["X-Mme-Client-Info"] = self.client
        return headers

    async def resync(self, sim):
        if isinstance(sim, bytes):
            sim = base64.b64encode(sim).decode()
        if not isinstance(sim, str) or len(sim) > 1024*1024:
            raise ValueError("Invalid ADI synchronization challenge")
        response = await self.http.post(SERVER + "/v3/get_headers", json={
            "identifier": self.state["identifier"], "adi_pb": self.state["adi_pb"],
            "sim": sim, "device_id": self.device_id, "md_lu": self.local_user_id})
        data = response.json()
        if not response.ok or not all(isinstance(data.get(k), str) and data[k] for k in ("X-Apple-I-MD", "X-Apple-I-MD-M")):
            raise RuntimeError("Windows ADI synchronization failed")
        self.data, self.expires = data, asyncio.get_running_loop().time() + 30

    async def close(self):
        await self.http.close()


async def main():
    PRIVATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    username = os.environ["FINDMY_APPLE_ACCOUNT"]
    provider = WindowsV3Anisette()
    account = ResearchAccount(provider)
    account._http = VerifiedHttpSession(PROXY)
    try:
        headers = await provider.get_headers(account._uid, account._devid)
        print(json.dumps({"stage": "windows_v3_preflight", "ready": True,
            "client_info": provider.client, "header_names": sorted(headers), "password_sent": False}), flush=True)
        import srp._pysrp as srp
        profiles = {"server_windows": None, "mac_reference": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"}
        results = []
        for label, client in profiles.items():
            provider.client_override = client
            user = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            _, a2k = user.start_authentication()
            response = await account._gsa_request({"A2k": a2k, "u": username, "ps": ["s2k", "s2k_fo"], "o": "init"})
            result = {"profile": label, "ec": response.get("Status", {}).get("ec"),
                "hsc": response.get("Status", {}).get("hsc"), "status_fields": sorted(response.get("Status", {})), "password_sent": False}
            results.append(result)
            print(json.dumps(result), flush=True)
        save_private(PRIVATE / "windows-v3-challenge-results.json", {"results": results})
    finally:
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except Exception as exc:
        print(json.dumps({"stage": "windows_v3", "error_type": type(exc).__name__}))
        raise SystemExit(1)
