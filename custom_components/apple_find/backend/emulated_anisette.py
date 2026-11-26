"""Get macOS-provenance anisette from a CoreADI emulator running on Linux."""

import asyncio
import base64
import json
import tempfile
from pathlib import Path
import sys
import time

from findmy.reports.anisette import BaseAnisetteProvider

from .environment import environment


async def _run(*args, data=None, timeout=75):
    child = await asyncio.create_subprocess_exec(
        sys.executable, *map(str, args), env=environment.subprocess_env(),
        stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        output, _ = await asyncio.wait_for(child.communicate(data), timeout=timeout)
    except BaseException:
        if child.returncode is None:
            child.kill()
            await child.wait()
        raise
    if child.returncode:
        raise RuntimeError("CoreADI provider command failed")
    return output


class EmulatedMacAnisette(BaseAnisetteProvider):
    def __init__(self, state: Path, script: Path):
        super().__init__()
        self.state = state
        self.script = script
        self.identity = json.loads((state / "identity.json").read_text())
        self._model, os_info, *_ = self.identity["client_info"].strip("<>").split("> <")
        _, self._os, *_ = os_info.split(";")
        self._headers = {}
        self._window = None
        self._lock = asyncio.Lock()

    @property
    def client(self):
        # GrandSlam rejects the macOS label stored by older installations.
        return self.identity["client_info"].replace("> <macOS;", "> <Mac OS X;", 1)

    @property
    def otp(self):
        return self._headers["X-Apple-I-MD"]

    @property
    def machine(self):
        return self._headers["X-Apple-I-MD-M"]

    @property
    def router(self):
        return self._headers["X-Apple-I-MD-RINFO"]


    async def get_headers(self, user_id, device_id, serial="0", with_client_info=False):
        async with self._lock:
            window = time.time_ns() // 30_000_000_000
            if self._window != window:
                raw = await _run(self.script, "headers", "--state", self.state)
                headers = json.loads(raw)
                if headers["X-Mme-Device-Id"] != self.identity["device_id"]:
                    raise RuntimeError("CoreADI installation identity changed")
                self._headers = headers
                self._window = window
            result = dict(self._headers)
            result["loc"] = result["X-Apple-Locale"]
            if not with_client_info:
                result.pop("X-MMe-Client-Info", None)
            else:
                result.pop("X-MMe-Client-Info", None)
                result["X-Mme-Client-Info"] = self.client
                result["X-Apple-App-Info"] = "com.apple.gs.xcode.auth"
                result["X-Xcode-Version"] = "11.2 (11B41)"
            return result

    async def resync(self, sim):
        if isinstance(sim, str):
            data = base64.b64decode(sim, validate=True)
        else:
            data = bytes(sim)
        async with self._lock:
            await _run(Path(__file__).with_name("sync_emulated_adi.py"), self.script, self.state, data=data)
            self._headers = {}
            self._window = None

    def to_json(self, *args, **kwargs):
        return {"type": "emulatedMacCoreADI"}

    @classmethod
    async def provision(cls):
        directory = environment.adi
        with tempfile.TemporaryDirectory(dir=directory.parent, prefix="pending-adi-") as tmp:
            stage = Path(tmp) / "adi"
            await _run(environment.adi_cli, "provision", "--state", stage, timeout=150)
            await _run(environment.adi_cli, "headers", "--state", stage)
            stage.replace(directory)
        return cls.from_json()

    @classmethod
    def from_json(cls, *args, **kwargs):
        return cls(environment.adi, environment.adi_cli)

    async def close(self):
        self._headers = {}
        self._window = None
