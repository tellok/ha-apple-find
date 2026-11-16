"""Set up native Find My contacts and devices using one Apple account."""

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import callback

from . import DEVICES_ID, DOMAIN
from .authorization import SECRET, AppleAuthorizationFlow, authorization_request
from .backend.icloud_contacts import CONF_CONTACTS_PASSWORD
from .runtime import async_get_runtime

PASSWORD_GUIDE_URL = (
    "https://github.com/tellok/ha-apple-find/blob/main/docs/icloud-app-specific-password.md"
)


class ContactsForm:
    async def _contacts_form_result(self, user_input):
        password = user_input.get(CONF_CONTACTS_PASSWORD, "").strip()
        if not password:
            return {}, {}
        try:
            runtime = await async_get_runtime(self.hass)
            error = await runtime.async_validate_contacts_password(password)
        except RuntimeError:
            error = "contacts_unavailable"
        if error:
            return {}, {"base": error}
        return {CONF_CONTACTS_PASSWORD: password}, {}

    def _show_contacts_form(self, step_id, errors):
        return self.async_show_form(
            step_id=step_id,
            errors=errors,
            data_schema=vol.Schema({vol.Optional(CONF_CONTACTS_PASSWORD): SECRET}),
            description_placeholders={"password_guide_url": PASSWORD_GUIDE_URL},
        )


class FindMyConfigFlow(AppleAuthorizationFlow, ContactsForm, config_entries.ConfigFlow, domain=DOMAIN):
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
        return await self.async_step_icloud_contacts()

    async def async_step_icloud_contacts(self, user_input=None):
        errors = {}
        if user_input is not None:
            options, errors = await self._contacts_form_result(user_input)
            if not errors:
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title="Apple Find",
                    data={"kind": "devices"},
                    options=options,
                    description="contacts_matching_saved" if options else None,
                )
        return self._show_contacts_form("icloud_contacts", errors)

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        return ContactsOptionsFlow()


class ContactsOptionsFlow(ContactsForm, config_entries.OptionsFlowWithReload):
    async def async_step_init(self, user_input=None):
        errors = {}
        if user_input is not None:
            options, errors = await self._contacts_form_result(user_input)
            if not errors:
                current = dict(self.config_entry.options)
                current.pop(CONF_CONTACTS_PASSWORD, None)
                if not options:
                    return self.async_create_entry(title="", data=current)
                # HA's options success screen has fixed text. Save first, then
                # finish with a localized message, as in a reconfigure flow.
                entry = self.config_entry
                if self.hass.config_entries.async_update_entry(entry, options={**current, **options}):
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_abort(reason="contacts_matching_saved")
        return self._show_contacts_form("init", errors)
