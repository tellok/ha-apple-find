"""Set up native Find My contacts and devices using one Apple account."""

from homeassistant import config_entries

from . import DEVICES_ID, DOMAIN
from .authorization import AppleAuthorizationFlow, authorization_request


class FindMyConfigFlow(AppleAuthorizationFlow, config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        await self.async_set_unique_id(DEVICES_ID)
        self._abort_if_unique_id_configured()
        status = (await authorization_request(self.hass, "status"))["status"]
        if status != "authorized":
            return await self.async_step_apple_login()
        return await self._authorized_setup()

    async def _authorized_setup(self):
        self._abort_if_unique_id_configured()
        return self.async_create_entry(title="Apple Find", data={"kind": "devices"})
