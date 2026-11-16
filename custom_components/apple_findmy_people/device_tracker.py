"""Expose verified Apple Find My People location snapshots as GPS trackers.

HA's Recorder can retain position attributes whenever the tracker state updates.
Locations are loaded from verified snapshots for the corresponding share.
"""
from datetime import timedelta
import json
import logging
from pathlib import Path

from homeassistant.components.device_tracker import TrackerEntity, SourceType
from homeassistant.core import callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.update_coordinator import (
    CoordinatorEntity, DataUpdateCoordinator, UpdateFailed,
)
from homeassistant.util import dt as dt_util, slugify

from . import DEVICES_ID, DOMAIN, workspace_path
from .groups import CONTACTS, DEVICES, group_id
from .protocol import Position
from .runtime import async_get_runtime

LOGGER = logging.getLogger(__name__)
OWN_LOCATION = "me"


def read_positions(path, targets, max_age):
    with path.open("rb") as stream:
        content = stream.read(1024 * 1024 + 1)
    if len(content) > 1024 * 1024:
        raise ValueError("Snapshot too large")
    snapshot = json.loads(content)
    if snapshot.get("schema_version") != 1:
        raise ValueError("Unsupported snapshot schema")
    positions = {}
    for value in snapshot["positions"]:
        target = value["target_id"]
        if target not in targets or target in positions:
            raise ValueError("Unexpected or duplicate target")
        positions[target] = Position.from_snapshot(
            value, target_id=target, now=dt_util.utcnow(), max_age=max_age,
        )
    return positions


async def async_setup_contacts(hass, entry, async_add_entities):
    runtime = await async_get_runtime(hass)
    subentry_id = group_id(entry, CONTACTS)
    registry = dr.async_get(hass)
    directory = workspace_path(hass) / "state" / "contacts"
    registered = set()

    def read_contacts(contacts, max_age):
        data = {}
        for contact in contacts:
            target_id = "friend:" + contact.handles[0]
            try:
                position = read_positions(directory / contact.snapshot_name, {target_id}, max_age).get(target_id)
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                position = None
            data[contact.target] = (contact.name, position, contact.handles[0])
        return data

    async def update():
        manual = {
            candidate.data["target_id"].removeprefix("friend:")
            for candidate in hass.config_entries.async_entries(DOMAIN)
            if candidate.data.get("kind") != "devices" and "target_id" in candidate.data
        }
        contacts, own_device, max_age = await runtime.async_contacts()
        data = await hass.async_add_executor_job(
            read_contacts, [contact for contact in contacts if manual.isdisjoint(contact.handles)], max_age,
        )
        devices = entry.runtime_data
        matches = [
            device.position for device in (devices.data or {}).values()
            if own_device and devices.last_update_success and device.discovery_key == own_device
        ]
        data[OWN_LOCATION] = (None, matches[0] if len(matches) == 1 else None, None)
        return data

    coordinator = DataUpdateCoordinator(
        hass, LOGGER, name="Apple Find shared contacts", update_method=update,
        update_interval=timedelta(seconds=30), always_update=False, config_entry=entry,
    )

    @callback
    def discover():
        entities = []
        for target, (name, _, handle) in (coordinator.data or {}).items():
            if target not in registered:
                registered.add(target)
                tracker = OwnLocationTracker if target == OWN_LOCATION else SharedContactTracker
                entities.append(tracker(coordinator, target, name, handle))
            elif name:
                device = registry.async_get_device_by_identifier((DOMAIN, target), entry.entry_id)
                if device is not None and device.name != name:
                    registry.async_update_device(device.id, name=name)
        if entities:
            async_add_entities(entities, config_subentry_id=subentry_id)

    await coordinator.async_refresh()
    entry.async_on_unload(coordinator.async_add_listener(discover))
    discover()


async def async_setup_entry(hass, entry, async_add_entities):
    config = entry.data
    if config.get("kind") == "devices":
        coordinator = entry.runtime_data
        coordinator.async_discover(
            entry, async_add_entities, lambda target, device: NativeDeviceTracker(coordinator, target, device),
            subentry_id=group_id(entry, DEVICES),
        )
        await async_setup_contacts(hass, entry, async_add_entities)
        return
    path = Path(config["snapshot_path"])
    if not path.is_absolute():
        raise ValueError("snapshot_path must be absolute")
    targets = {config["target_id"]: config["name"]}
    if not targets:
        raise ValueError("At least one explicit target is required")

    async def update():
        try:
            result = await hass.async_add_executor_job(read_positions, path, targets, config["max_age"])
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
        if name is not None:
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


class SharedContactTracker(SelectedTracker):
    def __init__(self, coordinator, target, name, handle=None):
        super().__init__(coordinator, target, name)
        if handle and (object_id := slugify(handle.removeprefix("tel:"))):
            # HA uses this suggestion for new entries and restores existing IDs by unique ID.
            self.entity_id = f"device_tracker.{object_id}"
        # The integration page expands registry rows, so give each contact a
        # logical service row alongside its existing tracker.
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, target)},
            entry_type=DeviceEntryType.SERVICE,
            name=name or "Me",
            translation_key="me" if target == OWN_LOCATION else None,
        )

    @callback
    def _handle_coordinator_update(self):
        if contact := (self.coordinator.data or {}).get(self.target):
            if contact[0] is not None:
                self._attr_name = contact[0]
        super()._handle_coordinator_update()

    @property
    def _position(self):
        contact = (self.coordinator.data or {}).get(self.target)
        return contact[1] if contact else None


class OwnLocationTracker(SharedContactTracker):
    _attr_has_entity_name = True
    _attr_translation_key = "me"
    _attr_suggested_object_id = "apple_find_me"


class NativeDeviceTracker(SelectedTracker):
    _attr_has_entity_name = True
    _attr_name = None

    def __init__(self, coordinator, target, device):
        super().__init__(coordinator, target, None)
        self._attr_unique_id = DEVICES_ID + ":" + target
        self._attr_device_info = device.device_info(target)

    @property
    def _position(self):
        device = (self.coordinator.data or {}).get(self.target)
        return device.position if device else None
