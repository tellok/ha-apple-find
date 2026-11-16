"""Run or import the native backend's native_devices module."""
from pathlib import Path
import sys

if __name__ == "__main__" or not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from runpy import run_module

    run_module("custom_components.apple_find.backend.native_devices", run_name="__main__")
else:
    from custom_components.apple_find.backend import native_devices

    sys.modules[__name__] = native_devices
