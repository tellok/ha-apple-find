"""Paths and environment shared by the Core backend and its command-line tools."""
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import sys

PACKAGE_ROOT = Path(__file__).resolve().parents[3]
PACKAGE_ASSETS = Path(__file__).resolve().parents[1] / "assets"
LOGGER = logging.getLogger(__package__)


@dataclass(frozen=True)
class Environment:
    workspace: Path
    state: Path
    assets: Path
    adi: Path | None
    adi_cli: Path | None
    coreadi: Path | None
    proxy: str | None = None
    in_core: bool = False

    @classmethod
    def from_shell(cls):
        root = Path(os.environ.get("FINDMY_WORKSPACE", str(PACKAGE_ROOT)))
        return cls(root, Path(os.environ.get("FINDMY_STATE_DIR", str(root / ".private"))),
                   _env_path("FINDMY_ASSETS") or PACKAGE_ASSETS,
                   _env_path("FINDMY_MAC_ADI_STATE"), _env_path("FINDMY_MAC_ADI_CLI"),
                   _env_path("COREADI_PATH"), os.environ.get("FINDMY_PROXY") or None)

    @classmethod
    def for_core(cls, workspace):
        return cls(workspace, workspace / "state", PACKAGE_ASSETS, workspace / "state" / "adi",
                   PACKAGE_ASSETS / "external/adi/tools/machoadi/mac_anisette.py",
                   PACKAGE_ASSETS / "external/CoreADI.x86_64", in_core=True)

    def subprocess_env(self, *, staged_state=None):
        env = os.environ.copy()
        env["FINDMY_WORKSPACE"] = str(self.workspace)
        env["FINDMY_ASSETS"] = str(self.assets)
        env["FINDMY_STATE_DIR"] = str(staged_state or self.state)
        for key, value in (
            ("FINDMY_MAC_ADI_STATE", staged_state / "adi" if staged_state else self.adi),
            ("FINDMY_MAC_ADI_CLI", self.adi_cli),
            ("COREADI_PATH", self.coreadi),
            ("FINDMY_PROXY", self.proxy),
        ):
            if value is None:
                env.pop(key, None)
            else:
                env[key] = str(value)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, (str(PACKAGE_ROOT), env.get("PYTHONPATH"))))
        return env


def _env_path(key):
    value = os.environ.get(key)
    return Path(value) if value else None


environment = Environment.from_shell()


def module_command(module, *args):
    return (sys.executable, "-m", f"{__package__}.{module}", *args)


def log_diagnostic(message, *, flush=False):
    if environment.in_core:
        LOGGER.debug("%s", message)
    else:
        print(message, flush=flush)
