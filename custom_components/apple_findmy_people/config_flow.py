"""Set up native Find My contacts and devices using one Apple account."""

import hashlib
import re

import voluptuous as vol
from homeassistant import config_entries

from . import DEVICES_ID, DOMAIN, workspace_path
from .authorization import AppleAuthorizationFlow, authorization_request


class FindMyConfigFlow(AppleAuthorizationFlow, config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        status = (await authorization_request(self.hass, "status"))["status"]
        if status != "authorized":
            return await self.async_step_apple_login()
        return await self._authorized_setup()

    async def _authorized_setup(self):
        return self.async_show_menu(step_id="user", menu_options=["devices", "tracker"])

    async def async_step_devices(self, user_input=None):
        await self.async_set_unique_id(DEVICES_ID)
        self._abort_if_unique_id_configured()
        if user_input is None:
            return self.async_show_form(step_id="devices")
        return self.async_create_entry(title="Apple Find Devices", data={"kind": "devices"})

    async def async_step_tracker(self, user_input=None):
        errors = {}
        if user_input is not None:
            handle = user_input["handle"].strip().lower().removeprefix("mailto:")
            if handle.startswith("+"):
                handle = "tel:" + handle
            if not re.fullmatch(r"tel:\+[1-9]\d{6,14}|[^\s:@]+@[^\s:@]+\.[^\s:@]+", handle):
                errors["handle"] = "invalid_handle"
            else:
                target_id = "friend:" + handle
                await self.async_set_unique_id(target_id)
                self._abort_if_unique_id_configured()
                digest = hashlib.sha256(handle.encode()).hexdigest()[:20]
                snapshot = workspace_path(self.hass) / "state" / f"position-{digest}.json"
                return self.async_create_entry(title=user_input["name"], data={
                    "kind": "person",
                    "target_id": target_id,
                    "name": user_input["name"],
                    "snapshot_path": str(snapshot),
                    "max_age": 300,
                    "poll_seconds": 60,
                })
        return self.async_show_form(step_id="tracker", data_schema=vol.Schema({
            vol.Required("handle"): str,
            vol.Required("name"): str,
        }), errors=errors)
