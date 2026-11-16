"""Shared Home Assistant setup and reauthentication for the native collectors."""
from datetime import timedelta
import json

import voluptuous as vol
from homeassistant.components import persistent_notification
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from . import DOMAIN, workspace_path
from .runtime import async_get_runtime

NOTIFICATION = "apple_findmy_native_reauth"
SECRET = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


def state_path(hass):
    return workspace_path(hass) / "state"


async def authorization_request(hass, action, **fields):
    try:
        runtime = await async_get_runtime(hass)
        return await runtime.async_authorize({"action": action, **fields})
    except RuntimeError:
        return {"status": "collector_unavailable"}


def authorization_required(directory):
    try:
        generation = (directory / "account.json").stat().st_mtime_ns
    except OSError:
        generation = None
    for source in ("people", "devices"):
        try:
            marker = json.loads((directory / f"reauth-{source}.json").read_text())
            if marker["generation"] == generation:
                return True
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return False


async def setup_authorization_monitor(hass, entry):
    async def check(_now=None):
        entries = sorted(hass.config_entries.async_entries(DOMAIN), key=lambda candidate: candidate.data.get("kind") != "devices")
        primary = next((candidate for candidate in entries if not candidate.disabled_by), None)
        if primary is not entry:
            return
        if await hass.async_add_executor_job(authorization_required, state_path(hass)):
            persistent_notification.async_create(
                hass,
                "Apple 要求重新验证「查找」账号。请在 [修复面板](/config/repairs) 打开重新验证流程。",
                title="Apple Find 需要重新验证",
                notification_id=NOTIFICATION,
            )
            entry.async_start_reauth(hass)
        else:
            persistent_notification.async_dismiss(hass, NOTIFICATION)

    entry.async_on_unload(async_track_time_interval(hass, check, timedelta(seconds=30)))
    await check()


class AppleAuthorizationFlow:
    """HA config flow for the shared native Apple session."""

    authorization_session = None

    async def async_step_reauth(self, entry_data):
        return await self.async_step_apple_login()

    async def async_step_reconfigure(self, user_input=None):
        return await self.async_step_apple_login(user_input)

    async def async_step_apple_login(self, user_input=None):
        errors = {}
        if user_input is not None:
            result = await authorization_request(
                self.hass, "login", username=user_input["username"].strip().lower(),
                password=user_input["password"],
            )
            status = result["status"]
            if status == "authorized":
                return await self._authorization_finished()
            if status == "verification_required":
                self.authorization_session = result["session"]
                return await self.async_step_apple_verification()
            errors["base"] = status
        return self.async_show_form(step_id="apple_login", errors=errors, data_schema=vol.Schema({
            vol.Required("username"): str,
            vol.Required("password"): SECRET,
        }))

    async def async_step_apple_verification(self, user_input=None):
        errors = {}
        if user_input is not None:
            resend = user_input.get("resend", False)
            code = user_input.get("code", "").strip()
            if not resend and not (len(code) == 6 and code.isascii() and code.isdigit()):
                errors["base"] = "code_format"
            else:
                result = await authorization_request(
                    self.hass, "resend" if resend else "verify",
                    session=self.authorization_session, **({} if resend else {"code": code}),
                )
                status = result["status"]
                if status == "authorized":
                    return await self._authorization_finished()
                if status == "session_expired":
                    return self.async_abort(reason="session_expired")
                if status != "verification_required":
                    errors["base"] = status
        return self.async_show_form(step_id="apple_verification", errors=errors, data_schema=vol.Schema({
            vol.Optional("code"): SECRET,
            vol.Optional("resend", default=False): bool,
        }))

    async def _authorization_finished(self):
        self.authorization_session = None
        persistent_notification.async_dismiss(self.hass, NOTIFICATION)
        if self.source == "reauth":
            return self.async_update_reload_and_abort(self._get_reauth_entry())
        if self.source == "reconfigure":
            return self.async_update_reload_and_abort(self._get_reconfigure_entry())
        return await self._authorized_setup()
