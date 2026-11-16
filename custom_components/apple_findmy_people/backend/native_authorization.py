"""HA's private Unix-socket bridge for native Apple sign-in."""
import asyncio
from contextlib import suppress
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile

from .environment import Environment, environment, module_command

STATE = environment.state
SOCKET = STATE / "authorization.sock"
SESSION_FILES = ("account.json", "ids-bootstrap.json", "gsa-session.plist",
                 "gsa-header-tokens.json", "auth-cookies.json", "anisette-state.json",
                 "client-identity.json")
REGISTRATION_FILES = ("findmy-settings.json", "apns-identity.json", "ids-registration.json",
                      "ids-message-keys.json", "ids-auth.json", "ids-auth-key.pem", "ids-handles.json")


def account_dsid(directory):
    try:
        return str(json.loads((directory / "account.json").read_text())["login"]["data"]["dsid"])
    except (FileNotFoundError, KeyError, TypeError, ValueError):
        return None


async def worker():
    """One staged login, with the password kept in this process through 2FA."""
    from findmy import LoginState
    from .apple_probe import (PRIVATE, PROXY, ResearchAccount, ResearchAnisetteProvider,
                             VerificationCodeRejected, VerifiedHttpSession, save_private)

    def reply(status):
        print(json.dumps({"status": status}), file=responses, flush=True)

    responses = os.fdopen(os.dup(sys.stdout.fileno()), "w")
    # Research routines print diagnostics. Keep them out of the IPC channel.
    with open(os.devnull, "w") as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
    logging.disable(logging.CRITICAL)
    provider = ResearchAnisetteProvider(libs_path=PRIVATE / "anisette-libs.bin")
    account = ResearchAccount(provider)
    account._http = VerifiedHttpSession(PROXY)
    try:
        identity = await provider.get_headers(account._uid, account._devid)
        account._devid = identity["X-Mme-Device-Id"]
        account._uid = provider._mac_provider.identity["local_user_uuid"]
        save_private(PRIVATE / "client-identity.json", {"uid": account._uid, "devid": account._devid})
        request = json.loads(sys.stdin.readline())
        result = await account.login(request["username"], request.pop("password"))
        if result == LoginState.REQUIRE_2FA:
            await account.td_2fa_request()
            reply("verification_required")
            while result == LoginState.REQUIRE_2FA:
                line = await asyncio.to_thread(sys.stdin.readline)
                if not line:
                    return
                request = json.loads(line)
                if request["action"] == "resend":
                    await account.td_2fa_request()
                    reply("verification_required")
                    continue
                try:
                    result = await account.td_2fa_submit(request.pop("code"))
                except VerificationCodeRejected:
                    reply("invalid_code")
        if result != LoginState.LOGGED_IN:
            reply("invalid_auth")
            return
        data = account.to_json()
        data["account"]["password"] = None
        save_private(PRIVATE / "account.json", data)
        save_private(PRIVATE / "ids-bootstrap.json", account.ids_bootstrap)
        save_private(PRIVATE / "anisette-state.json", provider.to_json())
        tokens = data["login"]["data"]["mobileme_data"]["tokens"]
        if not all(tokens.get(name) for name in ("mmeFMIPAppToken", "mmeFMFAppToken", "searchPartyToken")):
            reply("authorization_failed")
            return
        reply("authenticated")
    except Exception as error:
        print(type(error).__name__, file=sys.stderr, flush=True)
        reply("invalid_auth" if getattr(account._http, "last_response_status", None) in (401, 403)
              else "authorization_failed")
    finally:
        await account.close()
        responses.close()


class AuthorizationBridge:
    def __init__(self, *, workspace=None, provider=None):
        self.environment = workspace
        self.provider = provider
        self.lock = asyncio.Lock()
        self.process = self.directory = self.session = self.expiry = None

    async def discard(self):
        if self.expiry:
            self.expiry.cancel()
            self.expiry = None
        if self.process is not None:
            if self.process.returncode is None:
                with suppress(ProcessLookupError):
                    self.process.kill()
            await self.process.wait()
            self.process = None
        if self.directory is not None:
            self.directory.cleanup()
            self.directory = None
        self.session = None

    async def expire(self, session):
        async with self.lock:
            if self.session == session:
                await self.discard()

    @property
    def state(self):
        return self.environment.state if self.environment else STATE

    @property
    def settings(self):
        return self.environment or Environment.from_shell()

    async def start(self):
        await self.discard()
        # Keep checkpoints and failed attempts separate from the active collectors.
        self.directory = tempfile.TemporaryDirectory(dir=self.state, prefix="pending-auth-")
        stage = Path(self.directory.name)
        adi = stage / "adi"
        if self.provider is None:
            shutil.copytree(self.settings.adi, adi)
        else:
            async with self.provider._lock:
                shutil.copytree(self.settings.adi, adi)
        self.session = secrets.token_urlsafe(24)
        session = self.session
        self.expiry = asyncio.get_running_loop().call_later(
            480, lambda: asyncio.create_task(self.expire(session))
        )
        self.process = await asyncio.create_subprocess_exec(
            *module_command("native_authorization", "--worker"),
            env=self.settings.subprocess_env(staged_state=stage),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        )

    async def exchange(self, request):
        self.process.stdin.write(json.dumps(request).encode() + b"\n")
        await self.process.stdin.drain()
        raw = await asyncio.wait_for(self.process.stdout.readline(), 180)
        return json.loads(raw)["status"]

    async def commit(self):
        stage = Path(self.directory.name)
        current = account_dsid(self.state)
        candidate = account_dsid(stage)
        if candidate is None or current and current != candidate:
            return "account_mismatch"
        existing_registration = current and all((self.state / name).is_file() for name in
                                                ("apns-identity.json", "ids-registration.json", "ids-message-keys.json"))
        if not existing_registration:
            command = await asyncio.create_subprocess_exec(
                *module_command("prepare_people"),
                env=self.settings.subprocess_env(staged_state=stage),
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                if await asyncio.wait_for(command.wait(), 210) != 0:
                    return "enrollment_failed"
            finally:
                if command.returncode is None:
                    with suppress(ProcessLookupError):
                        command.kill()
                    await command.wait()
            for name in REGISTRATION_FILES:
                (stage / name).replace(self.state / name)
        # Copy a successful ADI resync from the staged area before publishing the session.
        if self.provider is None:
            self.publish(stage)
        else:
            async with self.provider._lock:
                self.publish(stage)
                await self.provider.close()
        return "authorized"

    def publish(self, stage):
        adi = self.settings.adi
        for path in (stage / "adi").rglob("*"):
            if path.is_file():
                destination = adi / path.relative_to(stage / "adi")
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.is_file() or destination.read_bytes() != path.read_bytes():
                    path.replace(destination)
        for name in SESSION_FILES:
            if name != "account.json" and (stage / name).is_file():
                (stage / name).replace(self.state / name)
        (stage / "account.json").replace(self.state / "account.json")
        for source in ("people", "devices"):
            (self.state / f"reauth-{source}.json").unlink(missing_ok=True)

    async def handle(self, request):
        action = request.get("action")
        async with self.lock:
            if action == "status":
                return {"status": "authorized" if account_dsid(self.state) else "login_required"}
            if action == "login":
                if not isinstance(request.get("username"), str) or not isinstance(request.get("password"), str):
                    return {"status": "invalid_auth"}
                await self.start()
            elif action not in ("verify", "resend") or self.session is None or request.get("session") != self.session:
                return {"status": "session_expired"}
            try:
                status = await self.exchange(request)
                if status in ("verification_required", "invalid_code"):
                    return {"status": status, "session": self.session}
                if status == "authenticated":
                    status = await self.commit()
                return {"status": status}
            finally:
                if "status" not in locals() or status not in ("verification_required", "invalid_code"):
                    await self.discard()

    async def serve(self, reader, writer):
        try:
            raw = await asyncio.wait_for(reader.readline(), 5)
            result = await self.handle(json.loads(raw))
        except Exception as error:
            print(type(error).__name__, flush=True)
            result = {"status": "authorization_failed"}
        try:
            writer.write(json.dumps(result).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


async def main():
    bridge = AuthorizationBridge()
    SOCKET.unlink(missing_ok=True)
    server = await asyncio.start_unix_server(bridge.serve, path=SOCKET, limit=16384)
    SOCKET.chmod(0o600)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    os.umask(0o077)
    asyncio.run(worker() if "--worker" in sys.argv else main())
