"""Match Find My sharing handles against the account's iCloud CardDAV address book."""

from collections import defaultdict
import json
import re
from urllib.parse import urlsplit

import aiohttp
from defusedxml import ElementTree
import phonenumbers
import vobject
from vobject.base import ParseError

CONF_CONTACTS_PASSWORD = "contacts_password"
MAX_RESPONSE = 8 * 1024 * 1024
ADDRESS_DATA = "{urn:ietf:params:xml:ns:carddav}address-data"
QUERY = """<c:addressbook-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:carddav">
  <d:prop><c:address-data>
    <c:prop name="VERSION"/><c:prop name="FN"/><c:prop name="N"/>
    <c:prop name="EMAIL"/><c:prop name="TEL"/>
  </c:address-data></d:prop>
  <c:filter/>
</c:addressbook-query>"""


class ContactsAuthError(Exception):
    """Apple rejected the address-book credentials."""


def account_endpoint(account_path):
    """Only send the credential to the Apple CardDAV service for this account."""
    state = json.loads(account_path.read_text())
    login = state["login"]["data"]
    endpoint = urlsplit(login["mobileme_data"]["com.apple.Dataclass.Contacts"]["url"])
    dsid = str(login["dsid"])
    if (
        endpoint.scheme != "https"
        or endpoint.port not in (None, 443)
        or endpoint.username is not None
        or not re.fullmatch(r"(?:p[0-9]+-)?contacts\.icloud\.com(?:\.cn)?", endpoint.hostname or "")
        or not dsid.isascii()
        or not dsid.isdecimal()
    ):
        raise ValueError("Unexpected iCloud Contacts endpoint")
    return state["account"]["username"], f"https://{endpoint.hostname}/{dsid}/carddavhome/card/"


async def fetch_index(account_path, password, region):
    """Read names and handles, without storing the address book on disk."""
    username, url = account_endpoint(account_path)
    headers = {
        "Authorization": aiohttp.encode_basic_auth(username, password),
        "Content-Type": "application/xml; charset=utf-8",
        "Depth": "1",
    }
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=20)) as session:
        async with session.request("REPORT", url, data=QUERY, headers=headers, allow_redirects=False) as response:
            if response.status in (401, 403):
                raise ContactsAuthError
            if response.status != 207:
                raise ValueError("Unexpected iCloud Contacts response")
            body = bytearray()
            async for chunk in response.content.iter_chunked(64 * 1024):
                body.extend(chunk)
                if len(body) > MAX_RESPONSE:
                    raise ValueError("iCloud Contacts response too large")
    return index_cards(ElementTree.fromstring(bytes(body)), region)


def normalize_handle(handle, region):
    value = handle.strip().casefold().removeprefix("mailto:").removeprefix("tel:")
    if "@" in value:
        return value
    try:
        phone = phonenumbers.parse(value, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_possible_number(phone):
        return None
    return phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.E164)


def index_cards(multistatus, region):
    names = defaultdict(set)
    for element in multistatus.iter(ADDRESS_DATA):
        if not element.text:
            continue
        try:
            card = vobject.readOne(element.text)
        except (ParseError, ValueError):
            continue
        if not (name := getattr(getattr(card, "fn", None), "value", "").strip()):
            continue
        for field in ("email", "tel"):
            for item in card.contents.get(field, ()):
                if key := normalize_handle(str(item.value), region):
                    names[key].add(name)
    return names


def match_name(handles, index, region):
    """Leave a share unnamed when multiple address-book names match."""
    names = set()
    for handle in handles:
        names.update(index.get(normalize_handle(handle, region), ()))
    return next(iter(names)) if len(names) == 1 else None
