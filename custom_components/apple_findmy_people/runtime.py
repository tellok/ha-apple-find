"""Own the native Find My clients for every entry in this HA instance."""

import argparse
import asyncio
from contextlib import suppress
from dataclasses import replace
import logging
from pathlib import Path
from time import monotonic

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.exceptions import HomeAssistantError

from . import DOMAIN, workspace_path
from .backend import environment as backend_environment

LOGGER = logging.getLogger(__name__)
PEOPLE_POLL_SECONDS = 60
DEVICE_POLL_SECONDS = 120
CONTACT_DISCOVERY_SECONDS = 300
ADDRESS_BOOK_REFRESH_SECONDS = 1800


class NativeRuntime:
    """Run the native clients on one Core thread with their own asyncio loop.

    The existing protocol code uses synchronous filesystem operations for
    session, key, and snapshot files. Keeping it off HA's loop also allows one
    provider and one APNs key-delivery flow to be shared by all entries.
    """

    def __init__(self, hass):
        self.hass = hass
        self.workspace = workspace_path(hass)
        self.ready = hass.loop.create_future()
        self.entries = {}
        self.contacts = ()
        self.own_device = None
        self.contact_position_ttl = 300
        self.contact_generation = None
        self.collectors = {}
        self.authorization_tasks = set()

    async def async_start(self):
        self.future = self.hass.loop.run_in_executor(None, self._run)
        unsubscribe = self.hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, self.async_stop)
        try:
            await asyncio.shield(self.ready)
        except RuntimeError:
            unsubscribe()
            raise

    def _run(self):
        try:
            asyncio.run(self._main())
        except Exception as error:
            self.hass.loop.call_soon_threadsafe(self._failed, type(error).__name__)

    def _failed(self, error_type):
        if not self.ready.done():
            self.ready.set_exception(RuntimeError(f"Find My runtime setup failed ({error_type})"))
        else:
            LOGGER.error("Find My runtime stopped (%s)", error_type)

    async def _main(self):
        backend_environment.environment = backend_environment.Environment.for_core(self.workspace)
        from .backend import native_devices, native_people, people_keys
        from .backend.emulated_anisette import EmulatedMacAnisette
        from .backend.native_authorization import AuthorizationBridge

        self.native_people = native_people
        self.people_keys = people_keys
        self.native_devices = native_devices
        self.loop = asyncio.get_running_loop()
        self.stop = asyncio.Event()
        self.entry_lock = asyncio.Lock()
        self.state = backend_environment.environment.state
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.provider = EmulatedMacAnisette.from_json() if (
            backend_environment.environment.adi / "identity.json"
        ).is_file() else None
        self.provision_lock = asyncio.Lock()
        self.authorization = AuthorizationBridge(workspace=backend_environment.environment, provider=self.provider)
        self.hass.loop.call_soon_threadsafe(self.ready.set_result, None)
        await self.stop.wait()

        tasks = [task for _, task in self.collectors.values()] + list(self.authorization_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.authorization.discard()
        if self.provider is not None:
            await self.provider.close()

    async def async_stop(self, _event):
        try:
            await asyncio.shield(self.ready)
        except RuntimeError:
            return
        if not self.future.done():
            self.loop.call_soon_threadsafe(self.stop.set)
            await self.future

    async def _call(self, method, *args):
        await asyncio.shield(self.ready)
        if self.future.done():
            raise RuntimeError("Find My runtime has stopped")
        return await asyncio.wrap_future(
            asyncio.run_coroutine_threadsafe(method(*args), self.loop)
        )

    async def async_entry_changed(self, entry_id, data, options=None):
        await self._call(self._entry_changed, entry_id, data, options)

    async def _entry_changed(self, entry_id, data, options):
        from .backend.icloud_contacts import CONF_CONTACTS_PASSWORD

        async with self.entry_lock:
            if data is None:
                self.entries.pop(entry_id, None)
            else:
                self.entries[entry_id] = {**data, CONF_CONTACTS_PASSWORD: (options or {}).get(CONF_CONTACTS_PASSWORD)}

            if self.provider is None:
                return

            device_entry = next((entry for entry in self.entries.values() if entry.get("kind") == "devices"), None)
            devices = device_entry is not None
            settings = (device_entry.get(CONF_CONTACTS_PASSWORD), self.hass.config.country) if devices else None
            await self._set_collector("contacts", settings, lambda: self._discover_contacts(*settings))
            if not devices:
                self.contacts = ()
                self.own_device = None
            await self._sync_people()
            await self._set_collector(
                "devices", devices,
                lambda: self.native_devices.run(DEVICE_POLL_SECONDS, provider=self.provider),
            )

    async def _sync_people(self):
        people = [
            (entry["target_id"].removeprefix("friend:"), entry["snapshot_path"], entry["poll_seconds"], None, 300)
            for entry in self.entries.values() if entry.get("kind") != "devices"
        ]
        manual = {handle for handle, *_ in people}
        people.extend(
            (contact.handles[0], str(self.state / "contacts" / contact.snapshot_name),
             PEOPLE_POLL_SECONDS, contact.relationship_id, self.contact_position_ttl)
            for contact in self.contacts if manual.isdisjoint(contact.handles)
        )
        settings = tuple(sorted(people, key=lambda item: item[:2]))
        await self._set_collector("people", settings, lambda: self._collect_people(settings))

    async def async_contacts(self):
        return await self._call(self._contacts)

    async def _contacts(self):
        from .backend.apple_probe import account_generation

        if self.contact_generation != account_generation():
            return (), None, self.contact_position_ttl
        return self.contacts, self.own_device, self.contact_position_ttl

    async def async_validate_contacts_password(self, password):
        """Validate the app-specific password using the same read as discovery."""
        _, error = await self._call(self._read_address_book, password, self.hass.config.country)
        return error

    async def _read_address_book(self, password, region):
        from aiohttp import ClientError
        from defusedxml.common import DefusedXmlException
        from xml.etree.ElementTree import ParseError

        from .backend.icloud_contacts import ContactsAuthError, fetch_index

        try:
            return await fetch_index(self.state / "account.json", password, region), None
        except ContactsAuthError:
            return None, "contacts_invalid_auth"
        except (ClientError, DefusedXmlException, OSError, ParseError, ValueError, KeyError, TypeError):
            return None, "contacts_unavailable"

    async def _discover_contacts(self, password, region):
        from aiohttp import ClientError

        from .backend.apple_probe import account_generation, mark_reauth
        from .backend.icloud_contacts import match_name
        from .backend.native_people import AppleRequestError

        address_book = {}
        address_book_generation = None
        next_refresh = 0
        while True:
            generation = account_generation()
            delay = CONTACT_DISCOVERY_SECONDS
            try:
                contacts, own_device, position_ttl = await self.native_people.discover_contacts(self.provider)
            except AppleRequestError as error:
                if error.status == 401:
                    mark_reauth("contacts", generation, required=True)
                if error.status == 429:
                    delay = 2700
                LOGGER.debug("Find My contact discovery was rejected (%s)", error.status)
            except (ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
                LOGGER.debug("Find My contact discovery will retry (%s)", type(error).__name__)
            else:
                if generation != address_book_generation:
                    address_book, next_refresh = {}, 0
                    address_book_generation = generation
                if password and monotonic() >= next_refresh:
                    index, error = await self._read_address_book(password, region)
                    if error:
                        LOGGER.warning("iCloud Contacts could not refresh (%s)", error)
                    else:
                        address_book = index
                    next_refresh = monotonic() + ADDRESS_BOOK_REFRESH_SECONDS
                if address_book:
                    contacts = tuple(
                        replace(contact, name=match_name(contact.handles, address_book, region) or contact.name)
                        for contact in contacts
                    )
                async with self.entry_lock:
                    if generation == account_generation():
                        self.contacts = contacts
                        self.own_device = own_device
                        self.contact_position_ttl = position_ttl
                        self.contact_generation = generation
                        await self._sync_people()
                mark_reauth("contacts", generation, required=False)
            for remaining in range(0, delay, 15):
                await asyncio.sleep(min(15, delay - remaining))
                if account_generation() != generation:
                    break

    async def _set_collector(self, name, settings, collect):
        current = self.collectors.get(name)
        if current is not None:
            previous, task = current
            if previous == settings:
                return
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            self.collectors.pop(name, None)
        if settings:
            self.collectors[name] = settings, asyncio.create_task(self._retry(name, collect))

    async def _retry(self, name, collect):
        while True:
            try:
                await collect()
            except Exception as error:
                LOGGER.warning("Find My %s client will retry (%s)", name, type(error).__name__)
            await asyncio.sleep(60)

    async def _collect_people(self, entries):
        settings = argparse.Namespace(poll_interval=PEOPLE_POLL_SECONDS)
        targets = [
            self.native_people.PollTarget(argparse.Namespace(
                target=handle, snapshot=Path(path), self_uri=None, keys=True,
                provider=self.provider,
                poll_interval=interval, relationship_id=relationship_id, max_age=max_age,
            ))
            for handle, path, interval, relationship_id, max_age in entries
        ]
        await self.people_keys.run_household(settings, targets)

    async def async_play_sound(self, target):
        error = await self._call(self._play_sound, target)
        if error:
            raise HomeAssistantError(translation_domain=DOMAIN, translation_key=error)

    async def _play_sound(self, target):
        from aiohttp import ClientError

        from .backend.apple_probe import PROXY, VerifiedHttpSession, account_generation, mark_reauth
        from .backend.native_people import AppleRequestError

        if self.provider is None:
            return "sound_reauth"
        generation = account_generation()
        http = None
        try:
            http = VerifiedHttpSession(PROXY, persist_cookies=False)
            await self.native_devices.play_sound(self.provider, http, target)
        except self.native_devices.SoundTargetUnavailable:
            return "sound_target_unavailable"
        except AppleRequestError as error:
            if error.status == 401:
                mark_reauth("devices", generation, required=True)
                return "sound_reauth"
            return "sound_rejected"
        except (ClientError, OSError, ValueError, KeyError, TypeError, RuntimeError):
            return "sound_request_failed"
        finally:
            if http is not None:
                await http.close()
        return None

    async def async_authorize(self, request):
        return await self._call(self._authorize, request)

    async def _authorize(self, request):
        task = asyncio.current_task()
        self.authorization_tasks.add(task)
        try:
            if self.provider is None:
                if request.get("action") == "status":
                    return {"status": "login_required"}
                if request.get("action") == "login":
                    from .backend.emulated_anisette import EmulatedMacAnisette

                    async with self.provision_lock:
                        if self.provider is None:
                            self.provider = await EmulatedMacAnisette.provision()
                            self.authorization.provider = self.provider
            return await self.authorization.handle(request)
        except Exception as error:
            LOGGER.warning("Find My authorization failed (%s)", type(error).__name__)
            return {"status": "authorization_failed"}
        finally:
            self.authorization_tasks.discard(task)


async def async_get_runtime(hass):
    key = (DOMAIN, "runtime")
    runtime = hass.data.get(key)
    if runtime is None:
        runtime = hass.data[key] = NativeRuntime(hass)
        try:
            await runtime.async_start()
        except RuntimeError:
            hass.data.pop(key, None)
            raise
    else:
        await asyncio.shield(runtime.ready)
    return runtime
