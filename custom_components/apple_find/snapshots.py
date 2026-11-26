"""Refresh Home Assistant entities when the background collector publishes data."""

from datetime import timedelta

from homeassistant.core import callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect, async_dispatcher_send
from homeassistant.helpers.event import async_track_point_in_utc_time
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from . import DOMAIN

SIGNAL_SNAPSHOT_CHANGED = f"{DOMAIN}_snapshot_changed"


def notify_snapshot_changed(hass, path=None):
    """Hand off a completed snapshot write or contact discovery to the HA loop."""
    hass.loop.call_soon_threadsafe(async_dispatcher_send, hass, SIGNAL_SNAPSHOT_CHANGED, path)


class SnapshotCoordinator(DataUpdateCoordinator):
    def __init__(self, hass, logger, *, config_entry, accepts_snapshot, **kwargs):
        super().__init__(hass, logger, config_entry=config_entry, always_update=False, **kwargs)
        self._refresh_task = None
        self._refresh_pending = False
        self._cancel_expiry = None
        self._accepts_snapshot = accepts_snapshot
        self._unsubscribe = async_dispatcher_connect(hass, SIGNAL_SNAPSHOT_CHANGED, self._snapshot_changed)
        config_entry.async_on_unload(self._stop_watching)

    @callback
    def _snapshot_changed(self, path):
        if self._accepts_snapshot(path):
            self.async_snapshot_changed()

    @callback
    def async_snapshot_changed(self):
        self._refresh_pending = True
        if self._refresh_task is None:
            self._refresh_task = self.hass.async_create_task(
                self._refresh_pending_snapshots(), name=f"Refresh {self.name} snapshots", eager_start=False,
            )

    async def _refresh_pending_snapshots(self):
        try:
            while self._refresh_pending:
                self._refresh_pending = False
                await self.async_refresh()
        finally:
            self._refresh_task = None

    @callback
    def async_schedule_position_expiry(self, positions, max_age):
        if self._cancel_expiry is not None:
            self._cancel_expiry()
            self._cancel_expiry = None
        oldest = min((position.timestamp for position in positions if position is not None), default=None)
        if oldest is not None:
            expires = oldest + timedelta(seconds=max_age, microseconds=1)
            self._cancel_expiry = async_track_point_in_utc_time(self.hass, self._positions_expired, expires)

    @callback
    def _positions_expired(self, _now):
        self._cancel_expiry = None
        self.async_snapshot_changed()

    @callback
    def _stop_watching(self):
        self._unsubscribe()
        self._refresh_pending = False
        if self._refresh_task is not None:
            self._refresh_task.cancel()
        if self._cancel_expiry is not None:
            self._cancel_expiry()
            self._cancel_expiry = None
