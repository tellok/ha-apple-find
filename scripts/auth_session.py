"""Local, temporary authentication debugger. Password stays in memory only.

The private Unix socket accepts a small allowlist of actions and never returns
credentials. Stop the process to clear its in-memory password.
"""
import asyncio
import getpass
import importlib
import json
import logging
import os
import sys

import apple_probe as probe
from findmy import LoginState


async def main():
    username = os.environ.get("FINDMY_APPLE_ACCOUNT") or input("Apple Account: ").strip()
    provider = probe.ResearchAnisetteProvider.from_json(probe.PRIVATE / "anisette-state.json", libs_path=probe.PRIVATE / "anisette-libs.bin")
    account = probe.ResearchAccount(provider)
    identity = json.loads((probe.PRIVATE / "client-identity.json").read_text())
    account._uid, account._devid = identity["uid"], identity["devid"]
    account._http = probe.VerifiedHttpSession(probe.PROXY)
    socket_path = probe.PRIVATE / "auth.sock"
    if socket_path.exists():
        socket_path.unlink()
    stopped = asyncio.Event()
    lock = asyncio.Lock()
    current = {"phase": "waiting_for_password"}
    password = None

    def persist():
        probe.save_private(probe.PRIVATE / "auth-status.json", current)
        probe.save_private(probe.PRIVATE / "anisette-state.json", provider.to_json())

    async def action(name):
        nonlocal current
        async with lock:
            importlib.reload(probe)
            account.__class__ = probe.ResearchAccount
            provider.__class__ = probe.ResearchAnisetteProvider
            account._http.__class__ = probe.VerifiedHttpSession
            try:
                if name == "login":
                    if not password:
                        raise RuntimeError("Password not provided")
                    account._set_login_state(LoginState.LOGGED_OUT)
                    account._pending_code = None
                    current = {"phase": "authenticating"}
                    persist()
                    state = await account.login(username, password)
                    if state == LoginState.REQUIRE_2FA:
                        current = {"phase": "waiting_for_code"}
                        persist()
                        print("苹果已发送验证码，请允许手机登录提示。", flush=True)
                        code = await asyncio.to_thread(getpass.getpass, "手机上新收到的验证码（输入不显示）: ")
                        state = await account.td_2fa_submit(code)
                    current = {"phase": "logged_in" if state == LoginState.LOGGED_IN else state.name}
                elif name == "request-code":
                    await account.td_2fa_request()
                    current = {"phase": "code_requested"}
                elif name == "verify":
                    current = {"phase": "waiting_for_code"}
                    persist()
                    code = await asyncio.to_thread(getpass.getpass, "手机验证码（输入不显示）: ")
                    await account.td_2fa_submit(code)
                    current = {"phase": "logged_in"}
                elif name == "replay-code":
                    if not getattr(account, "_pending_code", None):
                        raise RuntimeError("No in-memory verification code")
                    await account.td_2fa_submit(account._pending_code)
                    current = {"phase": "logged_in"}
                elif name == "delegate":
                    await account._login_mobileme()
                    current = {"phase": "logged_in"}
                elif name == "refresh":
                    state = await account._gsa_authenticate(username, password)
                    if account._login_state_data.get("idms_pet"):
                        probe.save_private(probe.PRIVATE / "ids-bootstrap.json", account._login_state_data)
                    current = {"phase": "session_refreshed", "login_state": state.name,
                               "pet_present": bool(account._login_state_data.get("idms_pet")),
                               "payload_status": getattr(account, "session_payload", {}).get("status-code")}
                else:
                    raise ValueError("Unsupported action")
            except Exception as exc:
                current = {"phase": "error", "error_type": type(exc).__name__,
                           "stage": getattr(account, "last_stage", "unknown"),
                           "http_status": getattr(account._http, "last_response_status", None),
                           "pet_present": bool(account._login_state_data.get("idms_pet")),
                           "login_state": account.login_state.name}
                print(json.dumps(current), flush=True)
                print("认证调试会话保持打开，后续重试无需再次输入密码。", flush=True)
            state = account.to_json()
            state["account"]["password"] = None
            probe.save_private(probe.PRIVATE / "account.json", state)
            persist()
            return current

    async def handle(reader, writer):
        try:
            request = json.loads(await reader.readline())
            name = request.get("action")
            if name == "status":
                result = current
            elif name == "stop":
                stopped.set()
                result = {"phase": "stopping"}
            else:
                result = await action(name)
            writer.write((json.dumps(result) + "\n").encode())
            await writer.drain()
        except Exception as exc:
            writer.write((json.dumps({"error_type": type(exc).__name__}) + "\n").encode())
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, path=str(socket_path), limit=8192)
    socket_path.chmod(0o600)
    persist()
    try:
        print("临时认证调试：密码只留在此进程内存中，关闭窗口即清除。", flush=True)
        password = await asyncio.to_thread(getpass.getpass, "Apple 账户密码（输入不显示）: ")
        await action("login")
        await stopped.wait()
    finally:
        password = None
        account._password = None
        server.close()
        await server.wait_closed()
        socket_path.unlink(missing_ok=True)
        await account.close()


if __name__ == "__main__":
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    try:
        asyncio.run(main())
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps({"error_type": type(exc).__name__}))
        raise SystemExit(1)
