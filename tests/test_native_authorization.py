"""An invalid challenge cannot activate a different account or replace a live session."""
import asyncio
import json

import pytest


def test_failure_origin_identifies_worker_frame_without_private_path(tmp_path):
    from custom_components.apple_find.backend.environment import failure_origin
    from custom_components.apple_find.backend.native_authorization import account_dsid

    not_a_directory = tmp_path / "synthetic-private-account"
    not_a_directory.touch()
    with pytest.raises(NotADirectoryError) as failure:
        account_dsid(not_a_directory)
    origin = failure_origin(ExceptionGroup("private worker detail", [failure.value]))
    assert origin.startswith("NotADirectoryError at custom_components.apple_find.backend.native_authorization.account_dsid:")
    assert origin.rsplit(":", 1)[1].isdecimal()


def test_challenge_keeps_live_credentials_until_verified(monkeypatch, tmp_path):
    monkeypatch.setenv("FINDMY_STATE_DIR", str(tmp_path))
    from scripts import native_authorization as auth

    monkeypatch.setattr(auth, "STATE", tmp_path)
    adi = tmp_path / "adi"
    adi.mkdir()
    monkeypatch.setenv("FINDMY_MAC_ADI_STATE", str(adi))
    active = tmp_path / "account.json"

    def record(dsid, token):
        return {"login": {"data": {"dsid": dsid, "token": token}}}

    active.write_text(json.dumps(record("1", "old")))
    for name in ("apns-identity.json", "ids-registration.json", "ids-message-keys.json"):
        (tmp_path / name).write_text("{}")
    marker = tmp_path / "reauth-people.json"
    marker.write_text("{}")

    async def run():
        bridge = auth.AuthorizationBridge()
        stage = tmp_path / "stage"
        stage.mkdir()
        (stage / "adi").mkdir()
        transitions = iter(["verification_required", "invalid_code", "authenticated"])

        class StagedDirectory:
            name = str(stage)

            def cleanup(self):
                pass

        async def start():
            bridge.directory = StagedDirectory()
            bridge.session = "test-session"
            (stage / "account.json").write_text(json.dumps(record("1", "new")))

        async def exchange(_):
            return next(transitions)

        monkeypatch.setattr(bridge, "start", start)
        monkeypatch.setattr(bridge, "exchange", exchange)
        assert (await bridge.handle({"action": "login", "username": "example", "password": "test"}))["status"] == "verification_required"
        assert (await bridge.handle({"action": "verify", "session": "unrelated"}))["status"] == "session_expired"
        verify = {"action": "verify", "session": "test-session", "code": "123456"}
        assert (await bridge.handle(verify))["status"] == "invalid_code"
        assert json.loads(active.read_text()) == record("1", "old")
        assert marker.exists()
        assert (await bridge.handle(verify))["status"] == "authorized"
        assert json.loads(active.read_text()) == record("1", "new")
        assert not marker.exists()

    asyncio.run(run())
