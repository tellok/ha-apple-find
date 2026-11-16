"""Play a sound using the native Find My Devices service."""

from homeassistant.components.button import ButtonDeviceClass, ButtonEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DEVICES_ID
from .groups import DEVICES, group_id
from .runtime import async_get_runtime


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = entry.runtime_data
    runtime = await async_get_runtime(hass)
    coordinator.async_discover(
        entry, async_add_entities,
        lambda target, device: PlaySoundButton(coordinator, runtime, target, device) if device.play_sound else None,
        subentry_id=group_id(entry, DEVICES),
    )


class PlaySoundButton(CoordinatorEntity, ButtonEntity):
    _attr_has_entity_name = True
    _attr_translation_key = "play_sound"
    _attr_device_class = ButtonDeviceClass.IDENTIFY

    def __init__(self, coordinator, runtime, target, device):
        super().__init__(coordinator)
        self.runtime = runtime
        self.target = target
        self._attr_unique_id = f"{DEVICES_ID}:{target}:play_sound"
        self._attr_device_info = device.device_info(target)

    @property
    def available(self):
        device = (self.coordinator.data or {}).get(self.target)
        return super().available and device is not None and device.play_sound

    async def async_press(self):
        await self.runtime.async_play_sound(self.target)
