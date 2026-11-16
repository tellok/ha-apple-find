"""Run or import the native backend's location_pipeline module."""
from pathlib import Path
import sys

if __name__ == "__main__" or not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

if __name__ == "__main__":
    from runpy import run_module

    run_module("custom_components.apple_findmy_people.backend.location_pipeline", run_name="__main__")
else:
    from custom_components.apple_findmy_people.backend import location_pipeline

    sys.modules[__name__] = location_pipeline
