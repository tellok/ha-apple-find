import json
from pathlib import Path
from string import Formatter
from unicodedata import name

import pytest


COMPONENT = Path(__file__).resolve().parents[1] / "custom_components" / "apple_find"
TRANSLATIONS = COMPONENT / "translations"


def strings_by_key(data, prefix=""):
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            yield from strings_by_key(value, f"{path}.")
        else:
            yield path, value


def placeholders(value):
    return {field for _, field, _, _ in Formatter().parse(value) if field is not None}


def test_english_fallback_uses_english():
    english = json.loads((TRANSLATIONS / "en.json").read_text())
    assert english == json.loads((COMPONENT / "strings.json").read_text())
    for key, value in strings_by_key(english):
        assert not any(name(char, "").startswith("CJK UNIFIED IDEOGRAPH") for char in value), key


@pytest.mark.parametrize("path", sorted(TRANSLATIONS.glob("*.json")), ids=lambda path: path.stem)
def test_locale_covers_english_keys_and_placeholders(path):
    english = dict(strings_by_key(json.loads((TRANSLATIONS / "en.json").read_text())))
    locale = dict(strings_by_key(json.loads(path.read_text())))
    assert locale.keys() == english.keys()
    for key, value in locale.items():
        assert isinstance(value, str) and value.strip(), key
        assert placeholders(value) == placeholders(english[key]), key
    assert "](/config/repairs)" in locale["common.reauth_notification_message"]
