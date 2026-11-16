"""Credential bootstrap. Never requests any friend's or device's location."""
from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import hashlib
from http.cookies import SimpleCookie
import json
import logging
import os
import plistlib
import re
import ssl
import time
from pathlib import Path
from yarl import URL

from findmy import AsyncAppleAccount, LocalAnisetteProvider, LoginState
from findmy import util
from findmy.util.http import HttpResponse, HttpSession
import aiohttp
import certifi
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .environment import environment

ASSETS, PRIVATE, PROXY = environment.assets, environment.state, environment.proxy
ANDROID_CLIENT = "<Pixel 7> <Android;14;UQ1A.240205.002> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
CLIENT_PROFILES = {
    "mac_modern": "<MacBookPro18,3> <macOS;27.0;26A300> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "ios": "<iPhone6,1> <iPhone OS;9.3.2;13F69> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "mac": "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "mac_hardware": "<Macmini7,1> <macOS;12.7.6;21H1320> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
    "android": ANDROID_CLIENT,
    "windows": "<PC> <Windows;6.2(0,0);9200> <com.apple.AuthKitWin/1 (com.apple.iCloud/7.21)>",
    "windows_modern": "<PC> <Windows;10.0;19045> <com.apple.AuthKitWin/1 (com.apple.iCloud/15.2)>",
}


class ResearchAnisetteProvider(LocalAnisetteProvider):
    def select_profile(self):
        path = PRIVATE / "debug-profile.json"
        profile = json.loads(path.read_text()).get("profile", "android") if path.exists() else "android"
        if profile not in CLIENT_PROFILES:
            raise ValueError("Unknown authentication client profile")
        self._selected_profile = profile
        settings = json.loads(path.read_text()) if path.exists() else {}
        backend = "emulated_mac" if os.environ.get("FINDMY_MAC_ADI_CLI") else settings.get("backend", "local_android")
        if backend not in ("local_android", "windows_v3", "emulated_mac"):
            raise ValueError("Unknown anisette backend")
        self._selected_backend = backend
        if backend == "windows_v3" and not getattr(self, "_windows_provider", None):
            from .windows_anisette import WindowsV3Anisette
            self._windows_provider = WindowsV3Anisette()
        if backend == "emulated_mac" and not getattr(self, "_mac_provider", None):
            from .emulated_anisette import EmulatedMacAnisette
            self._mac_provider = EmulatedMacAnisette.from_json()
        return profile

    @property
    def client(self):
        # The default local backend emulates Android ADI. The Windows research
        # backend must use the metadata supplied by its own generating library.
        profile = getattr(self, "_selected_profile", None) or self.select_profile()
        if getattr(self, "_selected_backend", "local_android") == "windows_v3":
            return self._windows_provider.client
        if self._selected_backend == "emulated_mac":
            return self._mac_provider.client
        return CLIENT_PROFILES[profile]

    async def get_headers(self, user_id, device_id, serial="0", with_client_info=False):
        if not getattr(self, "_selected_profile", None):
            self.select_profile()
        if getattr(self, "_selected_backend", "local_android") == "windows_v3":
            return await self._windows_provider.get_headers(user_id, device_id, serial, with_client_info)
        if self._selected_backend == "emulated_mac":
            return await self._mac_provider.get_headers(user_id, device_id, serial, with_client_info)
        headers = await super().get_headers(user_id, device_id, serial, with_client_info)
        # Keep the identifiers used in ADI provisioning, rather than replacing
        # them with unrelated account UUIDs as the upstream wrapper does.
        for key in ("X-Apple-I-MD-LU", "X-Mme-Device-Id"):
            headers[key] = self._ani_data[key]
        profile = getattr(self, "_selected_profile", None) or self.select_profile()
        if profile == "mac_hardware":
            hardware = plistlib.loads((ASSETS / "research/vendor/pypush-full/emulated/data.plist").read_bytes())["iokit"]
            headers.update({"X-Apple-I-SRL-NO": hardware["IOPlatformSerialNumber"],
                "X-Apple-I-ROM": hardware["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:ROM"].hex().upper(),
                "X-Apple-I-MLB": hardware["4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14:MLB"].decode()})
        return headers

    @property
    def supports_resync(self):
        return getattr(self, "_selected_backend", "local_android") in ("windows_v3", "emulated_mac")

    async def resync(self, sim):
        if not self.supports_resync:
            raise RuntimeError("Current anisette backend does not support resynchronization")
        provider = self._mac_provider if self._selected_backend == "emulated_mac" else self._windows_provider
        await provider.resync(sim)

    async def close(self):
        if getattr(self, "_windows_provider", None):
            await self._windows_provider.close()
        if getattr(self, "_mac_provider", None):
            await self._mac_provider.close()
        await super().close()


class VerifiedHttpSession(HttpSession):
    """Use verified TLS; the pinned upstream's HTTP wrapper disables it."""

    def __init__(self, proxy=None, *, persist_cookies=True):
        super().__init__()
        self.proxy = proxy
        self.persist_cookies = persist_cookies
        self.cookie_generation = account_generation()
        self.tls_context = ssl.create_default_context(cafile=certifi.where())
        roots = {
            "apple-root-ca.pem": "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",
            "apple-root-ca-g3.pem": "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
        }
        for filename, expected in roots.items():
            root_path = ASSETS / "research" / filename
            certificate = x509.load_pem_x509_certificate(root_path.read_bytes())
            fingerprint = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
            if fingerprint != expected:
                raise ValueError("Apple root certificate fingerprint mismatch")
            self.tls_context.load_verify_locations(cafile=str(root_path))

    async def _get_session(self):
        if self._closed:
            raise RuntimeError("HttpSession has been closed and cannot be used")
        if self._session is None or self._session.closed:
            # Keep the cookie jar, but never reuse a TCP/TLS connection between
            # GrandSlam requests (AltSign #52 and xtool GrandSlamClient).
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(force_close=True))
        return self._session

    async def request(self, method, url, **kwargs):
        if not url.startswith("https://"):
            raise ValueError("Apple authentication requires HTTPS")
        session = await self._get_session()
        cookie_path = PRIVATE / "auth-cookies.json"
        if self.persist_cookies and not getattr(self, "cookies_loaded", False):
            if cookie_path.exists():
                for value in json.loads(cookie_path.read_text()).get("cookies", []):
                    cookie = SimpleCookie()
                    cookie[value["name"]] = value["value"]
                    for key in ("domain", "path", "expires", "secure", "httponly"):
                        cookie[value["name"]][key] = value.get(key, "")
                    session.cookie_jar.update_cookies(cookie,
                        response_url=URL("https://" + value["domain"].lstrip(".") + (value.get("path") or "/")))
            self.cookies_loaded = True
        auth = kwargs.pop("auth", None)
        if isinstance(auth, tuple):
            headers = dict(kwargs.pop("headers", {}))
            headers["Authorization"] = "Basic " + base64.b64encode((auth[0] + ":" + auth[1]).encode()).decode()
            kwargs["headers"] = headers
            auth = None
        kwargs.pop("auto_retry", None)
        async with session.request(method, url, auth=auth, ssl=self.tls_context,
                                   proxy=self.proxy, timeout=aiohttp.ClientTimeout(total=30),
                                   allow_redirects=False,
                                   **kwargs) as response:
            self.last_token_headers = {name: response.headers.getall(name, [])
                for name in ("X-Apple-GS-Token", "X-Apple-HB-Token", "X-Apple-PE-Token")}
            self.last_response_status = response.status
            self.last_response_metadata = {
                "content_type": response.headers.get("Content-Type", "").split(";")[0],
                "server_time": response.headers.get("Date"),
                "has_retry_uuid": "X-Apple-I-Retry-Request-UUID" in response.headers,
                "has_auth_challenge": "WWW-Authenticate" in response.headers,
            }
            cookies = [{"name": cookie.key, "value": cookie.value,
                        **{key: cookie[key] for key in ("domain", "path", "expires", "secure", "httponly")}}
                       for cookie in session.cookie_jar]
            if self.persist_cookies and self.cookie_generation == account_generation():
                save_private(cookie_path, {"cookies": cookies})
            return HttpResponse(response.status, await response.read())


def save_private(path: Path, data: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, ensure_ascii=False)
    os.replace(tmp, path)
    path.chmod(0o600)


def account_generation():
    try:
        return (PRIVATE / "account.json").stat().st_mtime_ns
    except OSError:
        return None


def mark_reauth(source, generation, *, required):
    if generation is None or generation != account_generation():
        return
    path = PRIVATE / f"reauth-{source}.json"
    if required:
        save_private(path, {"generation": generation})
    else:
        path.unlink(missing_ok=True)


class VerificationCodeRejected(RuntimeError):
    """Apple rejected the code while the trusted-device challenge was open."""


class ResearchAccount(AsyncAppleAccount):
    """Keep the PET for later IDS delegation; upstream discards it after login."""

    async def _gsa_authenticate(self, username=None, password=None):
        if hasattr(self._anisette, "select_profile"):
            self._anisette.select_profile()
        if self.login_state == LoginState.AUTHENTICATED:
            self._set_login_state(LoginState.LOGGED_OUT)
        self.header_tokens = {}
        original = util.crypto.decrypt_spd_aes_cbc

        def capture_spd(key, encrypted):
            plaintext = original(key, encrypted)
            spd = util.parsers.decode_plist(plaintext)
            self.session_payload = spd
            path = PRIVATE / "gsa-session.plist"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                plistlib.dump(spd, stream)
            print(json.dumps({"stage": "gsa_session", "payload_fields": sorted(spd),
                              "service_token_names": sorted(spd.get("t", {})),
                              "pet_in_headers": bool(getattr(self, "header_tokens", {}).get("com.apple.gs.idms.pet"))}), flush=True)
            return plaintext

        # Upstream exposes no session-payload hook. Scope this synchronous capture
        # to this single CLI account and restore the function even after errors.
        util.crypto.decrypt_spd_aes_cbc = capture_spd
        try:
            state = await super()._gsa_authenticate(username, password)
            spd = getattr(self, "session_payload", {})
            if state == LoginState.AUTHENTICATED and spd.get("status-code") == 409:
                self._account_info["trusted_device_2fa"] = True
                return self._set_login_state(LoginState.REQUIRE_2FA,
                    {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]})
            return state
        finally:
            util.crypto.decrypt_spd_aes_cbc = original

    def _set_login_state(self, state, data=None):
        data = dict(data or {})
        if state == LoginState.AUTHENTICATED and not data.get("idms_pet"):
            data["idms_pet"] = getattr(self, "header_tokens", {}).get("com.apple.gs.idms.pet", "")
        return super()._set_login_state(state, data)

    async def twofactor_headers(self):
        headers = await self.get_anisette_headers(with_client_info=True)
        # xtool's GrandSlamClient also sets its client descriptor before the
        # dedicated request adds anisette, application and identity headers.
        for key in ("X-Apple-I-SRL-NO", "loc"):
            headers.pop(key, None)
        headers["X-Xcode-Version"] = "26.5 (17F42)"
        headers.update({"User-Agent": "Xcode", "Accept-Language": "en-us",
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Apple-Identity-Token": base64.b64encode(
            (str(self._login_state_data["adsid"]) + ":" + self._login_state_data["idms_token"]).encode()).decode(),
            "Accept": "application/x-buddyml", "Content-Type": "application/x-plist"})
        return headers

    async def td_2fa_request(self):
        self.last_stage = "request_trusted_device_2fa"
        lookup_path = PRIVATE / "gsa-lookup.plist"
        url = self._ENDPOINT_2FA_TD_REQUEST
        if lookup_path.exists():
            lookup = plistlib.loads(lookup_path.read_bytes())
            url = lookup["urls"]["trustedDeviceSecondaryAuth"]
        if URL(url).scheme != "https" or URL(url).host not in ("gsa.apple.com", "gsd.apple.com"):
            raise ValueError("Unexpected authentication endpoint")
        response = await self._http.get(url, headers=await self.twofactor_headers())
        diagnostic = {"stage": self.last_stage, "http_status": response.status_code}
        save_private(PRIVATE / "twofactor-request.json", diagnostic)
        print(json.dumps(diagnostic), flush=True)
        if not response.ok:
            raise RuntimeError("Trusted device request rejected")

    async def td_2fa_submit(self, code):
        self.last_stage = "submit_trusted_device_2fa"
        code = re.sub(r"[\s-]", "", code)
        if re.fullmatch(r"[0-9]{6}", code) is None:
            raise ValueError("Verification code must contain exactly six digits")
        self._pending_code = code
        headers = await self.twofactor_headers()
        headers["security-code"] = code
        response = await self._http.get(self._ENDPOINT_2FA_TD_SUBMIT, headers=headers)
        try:
            data = response.plist()
        except (Exception,):
            data = {}
        root = data.get("Response", data)
        error = root.get("Status", root).get("ec")
        diagnostic = {"stage": self.last_stage, "http_status": response.status_code,
                      "ec": error if isinstance(error, int) else None,
                      "response_bytes": len(response._content),
                      "response_fields": sorted(data),
                      **getattr(self._http, "last_response_metadata", {})}
        save_private(PRIVATE / "twofactor-validation.json", diagnostic)
        print(json.dumps(diagnostic), flush=True)
        if not response.ok:
            raise RuntimeError("Two-factor validation endpoint rejected the request")
        if error == -21669:
            raise VerificationCodeRejected("Apple did not accept this verification code")
        if error is not None and error != 0:
            raise RuntimeError("Two-factor code not accepted")
        self.harvest_header_tokens()
        if not self._password:
            raise RuntimeError("Two-factor accepted; SRP replay requires the in-memory password")
        state = await self._gsa_authenticate()
        if state != LoginState.AUTHENTICATED or not self._login_state_data.get("idms_pet"):
            raise RuntimeError("Two-factor verification did not complete authentication")
        return await self._login_mobileme()

    def harvest_header_tokens(self):
        for name, values in getattr(self._http, "last_token_headers", {}).items():
            for value in values:
                fields = base64.b64decode(value, validate=True).decode().split(":")
                if len(fields) >= 2:
                    token_name = "com.apple.gs.idms.pet" if name == "X-Apple-PE-Token" else fields[0]
                    if not hasattr(self, "header_tokens"):
                        self.header_tokens = {}
                    self.header_tokens[token_name] = fields[1]
        if getattr(self, "header_tokens", {}):
            save_private(PRIVATE / "gsa-header-tokens.json", {"tokens": self.header_tokens})

    async def _gsa_request(self, parameters):
        lookup_path = PRIVATE / "gsa-lookup.plist"
        if lookup_path.exists():
            endpoint = plistlib.loads(lookup_path.read_bytes())["urls"]["gsService"]
            if URL(endpoint).scheme != "https" or URL(endpoint).host not in ("gsa.apple.com", "gsd.apple.com"):
                raise ValueError("Unexpected GrandSlam service endpoint")
            self._ENDPOINT_GSA = endpoint
        self.last_stage = "grandslam_" + str(parameters.get("o", "unknown"))
        try:
            if getattr(self._anisette, "_selected_profile", None) == "mac_modern":
                body = {"Header": {"Version": "1.0.1"}, "Request": {
                    "cpd": await self._anisette.get_cpd(self._uid, self._devid), **parameters}}
                response = await self._http.post(self._ENDPOINT_GSA, data=plistlib.dumps(body), headers={
                    "Content-Type": "text/x-xml-plist", "Accept": "*/*",
                    "User-Agent": "AuthKit/1 (Macintosh; OS X 27.0) (com.apple.dt.Xcode/26.5)",
                    "X-MMe-Client-Info": self._anisette.client})
                if not response.ok:
                    raise RuntimeError("Modern client GSA transport rejected")
                result = response.plist()["Response"]
            else:
                result = await super()._gsa_request(parameters)
        except Exception as exc:
            match = re.fullmatch(r"Error response for GSA request: (\d{3})", str(exc))
            if match:
                self.diagnostics = [{"stage": self.last_stage, "http_status": int(match[1])}]
            raise
        status = result.get("Status", {})
        self.harvest_header_tokens()
        diag = {"stage": self.last_stage, "ec": status.get("ec"),
                "auth_mode": status.get("au"), "password_protocol": result.get("sp")}
        self.diagnostics = getattr(self, "diagnostics", []) + [diag]
        print(json.dumps(diag), flush=True)
        save_private(PRIVATE / "login-diagnostics.json", {"steps": self.diagnostics})
        # Windows ADI can require one hsc=434 challenge/resynchronization.
        # Match isideload's bounded retry, reusing the same SRP public value.
        if (parameters.get("o") == "init" and status.get("hsc") == 434
                and status.get("X-Apple-I-MD-DATA") is not None
                and getattr(self._anisette, "supports_resync", hasattr(self._anisette, "resync"))
                and not getattr(self, "_adi_resync_active", False)):
            self._adi_resync_active = True
            try:
                await self._anisette.resync(status["X-Apple-I-MD-DATA"])
                return await self._gsa_request(parameters)
            finally:
                self._adi_resync_active = False
        return result

    async def _login_mobileme(self):
        if getattr(self, "session_payload", {}).get("status-code") == 409:
            raise RuntimeError("Two-factor authentication remains pending; refusing delegate exchange")
        expiry = getattr(self, "session_payload", {}).get("t", {}).get("com.apple.gs.idms.pet", {}).get("expiry")
        if expiry and time.time() >= float(expiry) / 1000 - 10 and self._password:
            self._set_login_state(LoginState.LOGGED_OUT)
            state = await self._gsa_authenticate()
            if state != LoginState.AUTHENTICATED:
                raise RuntimeError("Expired PET refresh requires another verification")
        self.last_stage = "mobileme_delegate"
        self.ids_bootstrap = dict(self._login_state_data)
        save_private(PRIVATE / "ids-bootstrap.json", self.ids_bootstrap)
        checkpoint = self.to_json()
        checkpoint["account"]["password"] = None
        save_private(PRIVATE / "account.json", checkpoint)
        if not self.ids_bootstrap.get("idms_pet"):
            raise RuntimeError("Missing PET: authentication proof passed but no usable session token was issued")
        body = plistlib.dumps({"apple-id": self._username,
                               "delegates": {"com.apple.mobileme": {}},
                               "password": self.ids_bootstrap["idms_pet"], "client-id": self._uid})
        headers = await self.get_anisette_headers()
        headers.update({"X-Apple-ADSID": str(self.ids_bootstrap["adsid"]),
                        "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
                        "X-Mme-Client-Info": self._anisette.client,
                        "Content-Type": "application/x-apple-plist"})
        response = await self._http.post(self._ENDPOINT_LOGIN_MOBILEME,
                                        auth=(self._username, self.ids_bootstrap["idms_pet"]),
                                        data=body, headers=headers)
        data = response.plist()
        delegate = data.get("delegates", {}).get("com.apple.mobileme", {})
        diagnostic = {"stage": self.last_stage, "http_status": response.status_code,
                      "outer_status": data.get("status"), "delegate_status": delegate.get("status"),
                      "has_service_data": "service-data" in delegate,
                      "has_dsid": "dsid" in data}
        self.diagnostics = getattr(self, "diagnostics", []) + [diagnostic]
        save_private(PRIVATE / "login-diagnostics.json", {"steps": self.diagnostics})
        print(json.dumps(diagnostic), flush=True)
        status = delegate.get("status", data.get("status"))
        if not response.ok or status != 0:
            raise RuntimeError("MobileMe delegate rejected")
        return self._set_login_state(LoginState.LOGGED_IN,
                                     {"dsid": data["dsid"], "mobileme_data": delegate["service-data"]})


async def run(args):
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    provider = (
        ResearchAnisetteProvider.from_json(PRIVATE / "anisette-state.json", libs_path=PRIVATE / "anisette-libs.bin")
        if (PRIVATE / "anisette-state.json").exists()
        else ResearchAnisetteProvider(libs_path=PRIVATE / "anisette-libs.bin")
    )
    account = ResearchAccount(provider, state_info=json.loads((PRIVATE / "account.json").read_text())
                              if args.command in ("delegate", "resume-2fa", "request-2fa") else None)
    identity_path = PRIVATE / "client-identity.json"
    if identity_path.exists():
        identity = json.loads(identity_path.read_text())
        account._uid, account._devid = identity["uid"], identity["devid"]
    else:
        save_private(identity_path, {"uid": account._uid, "devid": account._devid})
    account._http = VerifiedHttpSession(args.proxy)
    try:
        canonical = await provider.get_headers(account._uid, account._devid)
        account._devid = canonical["X-Mme-Device-Id"]
        if getattr(provider, "_mac_provider", None):
            account._uid = provider._mac_provider.identity["local_user_uuid"]
        save_private(identity_path, {"uid": account._uid, "devid": account._devid})
        if args.command == "preflight":
            headers = await asyncio.wait_for(account.get_anisette_headers(), 180)
            ready = all(headers.get(k) for k in ("X-Apple-I-MD", "X-Apple-I-MD-M"))
            print(json.dumps({"local_anisette_ready": ready, "apple_account_login": "not_attempted"}))
            save_private(PRIVATE / "preflight.json", {"local_anisette_ready": ready})
            return
        if args.command == "challenge":
            import srp._pysrp as srp
            user = srp.User(args.account, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
            _, a2k = user.start_authentication()
            response = await account._gsa_request({"A2k": a2k, "u": args.account, "ps": ["s2k", "s2k_fo"], "o": "init"})
            if response.get("Status", {}).get("ec") != 0:
                raise RuntimeError("Authentication challenge rejected")
            return
        if args.command in ("resume-2fa", "request-2fa"):
            spd = plistlib.loads((PRIVATE / "gsa-session.plist").read_bytes())
            account._account_info["trusted_device_2fa"] = True
            account._set_login_state(LoginState.REQUIRE_2FA, {"adsid": spd["adsid"], "idms_token": spd["GsIdmsToken"]})
            if args.command == "request-2fa":
                await account.td_2fa_request()
                return
            state = await account.td_2fa_submit(getpass.getpass("手机上新收到的验证码（输入不显示）: "))
        elif args.command == "delegate":
            account._login_state_data = json.loads((PRIVATE / "ids-bootstrap.json").read_text())
            state = await account._login_mobileme()
        else:
            print("仅验证账户登录；不读取好友或设备位置。密码和验证码不会保存。", flush=True)
            password = getpass.getpass("Apple 账户密码（输入不显示）: ")
            state = await account.login(args.account, password)
        if state == LoginState.REQUIRE_2FA:
            state = await complete_trusted_device_challenge(account)
        if state != LoginState.LOGGED_IN:
            raise RuntimeError("Login incomplete")
        data = account.to_json()
        data["account"]["password"] = None
        save_private(PRIVATE / "account.json", data)
        save_private(PRIVATE / "ids-bootstrap.json", getattr(account, "ids_bootstrap", {}))
        tokens = data["login"]["data"]["mobileme_data"].get("tokens", {})
        summary = {"account_login": "passed", "available_token_names": sorted(tokens),
                   "people_location": "not_attempted", "device_location": "not_attempted"}
        save_private(PRIVATE / "auth-result.json", summary)
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    except Exception as exc:
        # Recognize upstream public error labels without printing its dynamic data.
        labels = {
            "This implementation only supports": "unsupported_password_protocol",
            "Failed to process challenge": "srp_challenge_rejected",
            "Failed to verify session": "srp_server_proof_failed",
            "Unknown auth value": "unsupported_auth_mode",
            "com.apple.mobileme login failed": "mobileme_delegate_rejected",
        }
        text = str(exc)
        reason = next((v for k, v in labels.items() if text.startswith(k)), "unclassified")
        diagnostic = {"error_type": type(exc).__name__, "stage": getattr(account, "last_stage", "local_anisette"),
                      "reason": reason, "steps": getattr(account, "diagnostics", []),
                      "last_http_status": getattr(account._http, "last_response_status", None)}
        save_private(PRIVATE / "login-diagnostics.json", diagnostic)
        print(json.dumps(diagnostic, ensure_ascii=False, indent=2), flush=True)
        raise
    finally:
        save_private(PRIVATE / "anisette-state.json", provider.to_json())
        await account.close()


async def complete_trusted_device_challenge(account):
    await account.td_2fa_request()
    print("已向 Apple 请求新的登录提示。请点「允许」并输入这次显示的验证码。", flush=True)
    for attempt in range(2):
        code = getpass.getpass("手机验证码（输入不显示）: ")
        try:
            return await account.td_2fa_submit(code)
        except VerificationCodeRejected:
            if attempt:
                raise
            print("Apple 未接受这次验证码。按回车在当前会话重新请求，或按 Control-C 退出。", flush=True)
            input()
            await account.td_2fa_request()


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["preflight", "challenge", "login", "delegate", "resume-2fa", "request-2fa"])
    parser.add_argument("--account", help="Apple Account identifier; login prompts if omitted")
    parser.add_argument("--proxy", default=None, help="Explicit proxy for Apple requests (TLS remains verified)")
    arguments = parser.parse_args()
    if not arguments.account and arguments.command == "login":
        arguments.account = input("Apple Account: ").strip()
    if not arguments.account and arguments.command in ("challenge", "login"):
        parser.error("provide the Apple Account identifier")
    try:
        asyncio.run(run(arguments))
    except (Exception, KeyboardInterrupt) as exc:
        # Don't print upstream exception bodies: they can contain account or token data.
        print(f"测试未完成：{type(exc).__name__}。没有读取位置。")
        raise SystemExit(1)
