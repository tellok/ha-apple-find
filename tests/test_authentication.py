import asyncio
import base64
import json
import pytest
from types import SimpleNamespace

from findmy import AsyncAppleAccount, LocalAnisetteProvider, LoginState

from custom_components.apple_find.backend import emulated_anisette

import scripts.apple_probe as probe


@pytest.mark.parametrize("os_label", ["macOS", "Mac OS X"])
def test_emulated_adi_sends_compatible_client_info_without_rewriting_identity(
    monkeypatch, tmp_path, os_label,
):
    client = f"<MacBookPro13,2> <{os_label};13.1;22C65> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
    identity = {"device_id": "test-device", "client_info": client}
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity))

    async def headers(*args):
        return json.dumps({
            "X-Mme-Device-Id": identity["device_id"],
            "X-MMe-Client-Info": client,
            "X-Apple-Locale": "en_US",
        })

    monkeypatch.setattr(emulated_anisette, "_run", headers)
    provider = emulated_anisette.EmulatedMacAnisette(tmp_path, tmp_path / "mac_anisette.py")

    async def check_headers():
        expected = client.replace("> <macOS;", "> <Mac OS X;")
        assert provider.client == expected
        result = await provider.get_headers("user", "device", with_client_info=True)
        assert result["X-Mme-Client-Info"] == expected
        result = await provider.get_headers("user", "device")
        assert all(key.lower() != "x-mme-client-info" for key in result)

    asyncio.run(check_headers())
    assert json.loads(identity_path.read_text()) == identity


def test_trusted_challenge_requests_a_new_prompt_before_reading_a_code(monkeypatch):
    actions = []
    first_code, second_code = object(), object()
    codes = iter((first_code, second_code))

    async def request():
        actions.append("request")

    async def submit(code):
        actions.append("submit")
        if code is first_code:
            raise probe.VerificationCodeRejected()
        assert code is second_code
        return LoginState.LOGGED_IN

    def read_code(_):
        actions.append("read_code")
        return next(codes)

    monkeypatch.setattr(probe.getpass, "getpass", read_code)
    monkeypatch.setattr("builtins.input", lambda: actions.append("confirmed_retry"))
    account = SimpleNamespace(td_2fa_request=request, td_2fa_submit=submit)
    assert asyncio.run(probe.complete_trusted_device_challenge(account)) == LoginState.LOGGED_IN
    assert actions == ["request", "read_code", "submit", "confirmed_retry", "request", "read_code", "submit"]


@pytest.mark.parametrize("pet", ["", "synthetic-pet"])
def test_pending_twofactor_inside_spd_is_not_a_completed_login(monkeypatch, pet):
    async def authenticated_but_pending(self, username=None, password=None):
        self._account_info = {"trusted_device_2fa": False}
        self._login_state_data = {"idms_pet": pet, "adsid": "synthetic-adsid"}
        self.session_payload = {"status-code": 409, "adsid": "synthetic-adsid", "GsIdmsToken": "synthetic-idms"}
        return LoginState.AUTHENTICATED

    monkeypatch.setattr(AsyncAppleAccount, "_gsa_authenticate", authenticated_but_pending)
    account = probe.ResearchAccount(LocalAnisetteProvider())
    assert asyncio.run(account._gsa_authenticate()) == LoginState.REQUIRE_2FA
    assert account._login_state_data["idms_token"] == "synthetic-idms"
    asyncio.run(account.close())


def test_repeated_service_headers_and_pet_identifier_are_preserved(monkeypatch, tmp_path):
    monkeypatch.setattr(probe, "PRIVATE", tmp_path)
    encode = lambda text: base64.b64encode(text.encode()).decode()
    account = probe.ResearchAccount(LocalAnisetteProvider())
    original_http = account._http
    account._http = SimpleNamespace(last_token_headers={
        "X-Apple-GS-Token": [encode("service.a:token-a:300"), encode("service.b:token-b:300")],
        "X-Apple-PE-Token": [encode("account-identifier:pet-token")],
    })
    account.harvest_header_tokens()
    assert account.header_tokens == {"service.a": "token-a", "service.b": "token-b", "com.apple.gs.idms.pet": "pet-token"}
    account._http = original_http
    asyncio.run(account.close())


def test_delegate_exchange_is_blocked_while_twofactor_is_pending():
    account = probe.ResearchAccount(LocalAnisetteProvider())
    account.session_payload = {"status-code": 409}
    account._login_state_data = {"idms_pet": "synthetic-pet"}
    with pytest.raises(RuntimeError, match="remains pending"):
        asyncio.run(account._login_mobileme())
    asyncio.run(account.close())


def test_twofactor_request_has_native_user_agent_and_identity(monkeypatch):
    async def headers(self, **kwargs):
        return {"X-Mme-Client-Info": "synthetic-client", "loc": "en_US",
                "X-Apple-I-SRL-NO": "0", "X-Apple-App-Info": "com.apple.gs.xcode.auth"}
    monkeypatch.setattr(probe.ResearchAccount, "get_anisette_headers", headers)
    account = probe.ResearchAccount(LocalAnisetteProvider())
    account._login_state_data = {"adsid": "synthetic-adsid", "idms_token": "synthetic-idms"}
    result = asyncio.run(account.twofactor_headers())
    assert result["User-Agent"] == "Xcode"
    assert result["Accept"] == "application/x-buddyml"
    assert base64.b64decode(result["X-Apple-Identity-Token"]) == b"synthetic-adsid:synthetic-idms"
    assert result["X-Mme-Client-Info"] == "synthetic-client"
    asyncio.run(account.close())


@pytest.mark.parametrize("second_status", [{"ec": 0}, {"ec": -22421, "hsc": 434, "X-Apple-I-MD-DATA": b"synthetic-sim"}])
def test_windows_adi_resync_reuses_srp_value_and_retries_only_once(monkeypatch, tmp_path, second_status):
    monkeypatch.setattr(probe, "PRIVATE", tmp_path)
    requests, challenges = [], []

    async def request(self, parameters):
        requests.append(parameters)
        return {"Status": ({"ec": -22421, "hsc": 434, "X-Apple-I-MD-DATA": b"synthetic-sim"}
                           if len(requests) == 1 else second_status)}

    async def resync(challenge):
        challenges.append(challenge)

    monkeypatch.setattr(AsyncAppleAccount, "_gsa_request", request)
    provider = LocalAnisetteProvider()
    provider.supports_resync = True
    provider.resync = resync
    account = probe.ResearchAccount(provider)
    parameters = {"o": "init", "A2k": b"synthetic-public-srp-value"}
    result = asyncio.run(account._gsa_request(parameters))
    assert result["Status"] == second_status
    assert requests == [parameters, parameters]
    assert challenges == [b"synthetic-sim"]
    assert account._adi_resync_active is False
    asyncio.run(account.close())
