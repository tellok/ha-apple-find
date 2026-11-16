"""Check matching across CardDAV and Find My handle formats."""

from xml.etree import ElementTree

from custom_components.apple_findmy_people.backend.icloud_contacts import (
    ADDRESS_DATA,
    index_cards,
    match_name,
)


def test_matches_email_and_local_phone_without_guessing_conflicts():
    multistatus = ElementTree.Element("{DAV:}multistatus")
    for lines in (
        ["FN:王小明", "item1.EMAIL:User@Example.com", "TEL:138 0013 8000"],
        ["FN:另一位联系人", "EMAIL:other@example.com"],
        ["FN:同地址的另一张名片", "EMAIL:duplicate@example.com"],
        ["FN:共享地址", "EMAIL:duplicate@example.com"],
    ):
        ElementTree.SubElement(multistatus, ADDRESS_DATA).text = "\r\n".join(
            ["BEGIN:VCARD", "VERSION:3.0", *lines, "END:VCARD", ""]
        )

    index = index_cards(multistatus, "CN")
    assert match_name(("mailto:user@example.com",), index, "CN") == "王小明"
    assert match_name(("tel:+8613800138000",), index, "CN") == "王小明"
    assert match_name(("user@example.com", "tel:+8613800138000"), index, "CN") == "王小明"
    assert match_name(("user@example.com", "other@example.com"), index, "CN") is None
    assert match_name(("duplicate@example.com",), index, "CN") is None
    assert match_name(("missing@example.com",), index, "CN") is None
