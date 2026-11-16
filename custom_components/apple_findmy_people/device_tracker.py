"""Expose verified Apple Find My People location snapshots as GPS trackers.

HA's Recorder can retain position attributes whenever the tracker state updates.
Only normalized snapshots for explicitly configured targets are accepted.
"""
from datetime import timedelta
import json
import logging
from pathlib import Path

from homeassistant.components.device_tracker import TrackerEntity, SourceType
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity, DataUpdateCoordinator, UpdateFailed,
)
from homeassistant.util import dt as dt_util

from . import DEVICES_ID
from .protocol import Position

LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry, async_add_entities):
    config = entry.data
    if config.get("kind") == "devices":
        coordinator = entry.runtime_data
        coordinator.async_discover(
            entry, async_add_entities, lambda target, device: NativeDeviceTracker(coordinator, target, device)
        )
        return
    path = Path(config["snapshot_path"])
    if not path.is_absolute():
        raise ValueError("snapshot_path must be absolute")
    targets = {config["target_id"]: config["name"]}
    if not targets:
        raise ValueError("At least one explicit target is required")

    def read_snapshot():
        with path.open("rb") as stream:
            content = stream.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("Snapshot too large")
        snapshot = json.loads(content)
        if snapshot.get("schema_version") != 1:
            raise ValueError("Unsupported snapshot schema")
        result = {}
        for value in snapshot["positions"]:
            target = value["target_id"]
            if target not in targets or target in result:
                raise ValueError("Unselected or duplicate target")
            result[target] = Position.from_snapshot(
                value, target_id=target, now=dt_util.utcnow(), max_age=config["max_age"],
            )
        return result

    async def update():
        try:
            result = await hass.async_add_executor_job(read_snapshot)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Avoid leaking file content or coordinates in logs.
            raise UpdateFailed("Location snapshot missing, stale, or invalid") from None
        previous = coordinator.data or {}
        if any(k in previous and p.timestamp < previous[k].timestamp for k, p in result.items()):
            raise UpdateFailed("Location timestamp moved backwards")
        return result

    coordinator = DataUpdateCoordinator(
        hass, LOGGER, name="Apple Find My selected targets", update_method=update,
        update_interval=timedelta(seconds=config["poll_seconds"]), always_update=False,
        config_entry=entry,
    )
    await coordinator.async_refresh()
    async_add_entities([SelectedTracker(coordinator, target, name) for target, name in targets.items()])


class SelectedTracker(CoordinatorEntity, TrackerEntity):
    def __init__(self, coordinator, target, name):
        super().__init__(coordinator)
        self.target = target
        self._attr_name = name
        self._attr_unique_id = "apple_findmy_people:" + target

    @property
    def available(self):
        return super().available and self._position is not None

    @property
    def _position(self):
        return (self.coordinator.data or {}).get(self.target)

    @property
    def source_type(self):
        return SourceType.GPS

    @property
    def latitude(self):
        position = self._position
        return position.latitude if position else None

    @property
    def longitude(self):
        position = self._position
        return position.longitude if position else None

    @property
    def location_accuracy(self):
        position = self._position
        return int(round(position.accuracy)) if position else 0

    @property
    def extra_state_attributes(self):
        position = self._position
        if position is None:
            return {}
        attributes = {"last_seen": position.timestamp.isoformat()}
        if position.floor is not None:
            attributes["floor"] = position.floor
        return attributes


class NativeDeviceTracker(SelectedTracker):
    def __init__(self, coordinator, target, device):
        super().__init__(coordinator, target, f"{device.name} (查找设备)")
        self._attr_unique_id = DEVICES_ID + ":" + target
        self._attr_device_info = device.device_info(target)

    @property
    def _position(self):
        device = (self.coordinator.data or {}).get(self.target)
        return device.position if device else None
