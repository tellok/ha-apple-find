"""Answer a CoreADI synchronization challenge supplied on private standard input."""

import base64
import json
from pathlib import Path
import sys
import tempfile


def main():
    cli, state = map(Path, sys.argv[1:])
    sys.path.insert(0, str(cli.resolve().parent))
    from mac_anisette import DS_ID, MacAnisette
    from gsa import Device, GSA

    sim = sys.stdin.buffer.read(4097)
    if not 0 < len(sim) <= 4096:
        raise RuntimeError("Invalid CoreADI challenge length")
    machine = MacAnisette(state)
    identity = machine.identity
    if not machine.is_provisioned():
        raise RuntimeError("CoreADI state is unprovisioned")
    reply = machine.adi.synchronize(DS_ID, sim)
    if reply.ret != 0:
        raise RuntimeError("CoreADI did not accept the challenge")
    server = GSA(Device(identity["device_id"], identity["client_info"],
                        identity["local_user_uuid"], identity["serial"]))
    server.load_urlbag()
    mid, srm = (base64.b64encode(reply.outputs[key]).decode() for key in ("mid", "srm"))
    result = server.sync_machine(mid, srm, int(identity["routing"]))
    if (result.get("Status") or {}).get("ec") != 0:
        raise RuntimeError("CoreADI synchronization rejected")
    routing = result.get("X-Apple-I-MD-RINFO")
    if routing is not None:
        machine.adi.set_routing(DS_ID, int(routing))
        machine.identity["routing"] = int(routing)
        with tempfile.NamedTemporaryFile(mode="w", dir=state, delete=False) as file:
            json.dump(machine.identity, file)
        Path(file.name).replace(state / "identity.json")
    machine._save_store()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
