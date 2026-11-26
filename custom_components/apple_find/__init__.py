"""Native Apple Find My for Home Assistant."""

import logging
from pathlib import Path
from time import monotonic

DOMAIN = "apple_find"
DEVICES_ID = "apple_findmy_native_devices"
LOGGER = logging.getLogger(__name__)


def workspace_path(hass):
    return Path(hass.config.path(".findmy-people-headless"))


def _platforms(entry):
    from homeassistant.const import Platform

    if entry.data.get("kind") == "devices":
        return [Platform.DEVICE_TRACKER, Platform.BUTTON]
    return [Platform.DEVICE_TRACKER]


async def async_setup_entry(hass, entry):
    from homeassistant.exceptions import ConfigEntryNotReady

    from .authorization import setup_authorization_monitor
    from .runtime import async_get_runtime

    started = monotonic()
    kind = "account" if entry.data.get("kind") == "devices" else "manual contact"
    LOGGER.debug("Setting up Apple Find %s entry", kind)
    try:
        runtime = await async_get_runtime(hass)
    except RuntimeError as error:
        raise ConfigEntryNotReady(str(error)) from None

    if entry.data.get("kind") == "devices":
        from .devices import DevicesCoordinator
        from .groups import async_setup_groups

        await async_setup_groups(hass, entry)
        entry.runtime_data = DevicesCoordinator(hass, entry)
        await entry.runtime_data.async_refresh()
    await hass.config_entries.async_forward_entry_setups(entry, _platforms(entry))
    await runtime.async_entry_changed(entry.entry_id, dict(entry.data), entry.options)
    await setup_authorization_monitor(hass, entry)
    LOGGER.info("Apple Find %s entry ready in %.2fs", kind, monotonic() - started)
    return True


async def async_unload_entry(hass, entry):
    from .runtime import async_get_runtime

    if not await hass.config_entries.async_unload_platforms(entry, _platforms(entry)):
        LOGGER.warning("Apple Find platform unload failed")
        return False
    runtime = await async_get_runtime(hass)
    await runtime.async_entry_changed(entry.entry_id, None)
    LOGGER.debug("Apple Find entry unloaded")
    return True
