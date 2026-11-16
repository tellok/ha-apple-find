"""Run or import the native backend's people_bootstrap module."""
from pathlib import Path
import sys

if __name__ == "__main__" or not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from runpy import run_module

    run_module("custom_components.apple_findmy_people.backend.people_bootstrap", run_name="__main__")
else:
    from custom_components.apple_findmy_people.backend import people_bootstrap

    sys.modules[__name__] = people_bootstrap
