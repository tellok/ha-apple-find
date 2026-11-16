"""Shared Home Assistant discovery for native devices."""

from dataclasses import dataclass
from datetime import timedelta
import json
import logging

from homeassistant.core import callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from . import DOMAIN, workspace_path
from .protocol import Position

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class NativeDevice:
    name: str
    position: Position | None
    play_sound: bool
    discovery_key: str | None = None

    def device_info(self, target):
        return DeviceInfo(identifiers={(DOMAIN, target)}, name=self.name, manufacturer="Apple")


class DevicesCoordinator(DataUpdateCoordinator[dict[str, NativeDevice]]):
    def __init__(self, hass, entry):
        super().__init__(hass, LOGGER, config_entry=entry, name="Apple Find Devices",
                         update_interval=timedelta(seconds=30), always_update=False)
        self.path = workspace_path(hass) / "state" / "native-devices.json"

    def read_snapshot(self):
        snapshot = json.loads(self.path.read_text())
        if snapshot.get("schema_version") != 1:
            raise ValueError("Unsupported device snapshot")
        now = dt_util.utcnow()
        devices = {}
        for row in snapshot["devices"]:
            target = row["target_id"]
            position = None
            if isinstance(report := row.get("position"), dict):
                try:
                    position = Position.from_snapshot(report, target_id=target, now=now, max_age=900)
                except (TypeError, ValueError, KeyError):
                    pass
            devices[target] = NativeDevice(row["name"], position, row.get("play_sound") is True,
                                           row.get("discovery_key"))
        return devices

    async def _async_update_data(self):
        try:
            return await self.hass.async_add_executor_job(self.read_snapshot)
        except (OSError, ValueError, KeyError, TypeError):
            raise UpdateFailed("Native device snapshot unavailable") from None

    @callback
    def async_discover(self, entry, async_add_entities, build_entity):
        registered = set()

        @callback
        def discover():
            entities = []
            for target, device in (self.data or {}).items():
                if target not in registered and (entity := build_entity(target, device)) is not None:
                    registered.add(target)
                    entities.append(entity)
            if entities:
                async_add_entities(entities)

        entry.async_on_unload(self.async_add_listener(discover))
        discover()
