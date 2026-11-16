"""Organize an Apple account's existing trackers and controls on its integration page."""

from types import MappingProxyType

from homeassistant.config_entries import ConfigSubentry
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.translation import async_get_translations

from . import DOMAIN

CONTACTS = "contacts"
DEVICES = "devices"


def group_id(entry, group):
    """Return the ID of a group created during account setup."""
    return next(subentry.subentry_id for subentry in entry.subentries.values()
                if subentry.unique_id == group)


async def async_setup_groups(hass, entry):
    """Create the two groups and move existing hardware into the Devices group."""
    existing = {subentry.unique_id for subentry in entry.subentries.values()}
    if not {CONTACTS, DEVICES}.issubset(existing):
        translations = await async_get_translations(hass, hass.config.language, "common", [DOMAIN])
        for group, fallback in ((CONTACTS, "Contacts"), (DEVICES, "Devices")):
            if group not in existing:
                hass.config_entries.async_add_subentry(
                    entry,
                    ConfigSubentry(
                        data=MappingProxyType({}),
                        subentry_type=group,
                        title=translations.get(f"component.{DOMAIN}.common.{group}", fallback),
                        unique_id=group,
                    ),
                )

    devices_id = group_id(entry, DEVICES)
    registry = dr.async_get(hass)
    for device in dr.async_entries_for_config_entry(registry, entry.entry_id):
        if device.config_subentry_id != devices_id and any(
            domain == DOMAIN and target.startswith("device:")
            for domain, target in device.identifiers
        ):
            registry.async_update_device(device.id, new_config_subentry_id=devices_id)
