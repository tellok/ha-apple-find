import json
import sys

import pytest

from scripts import migrate_ha_registry as migration


@pytest.mark.parametrize("devices_domain", [migration.PEOPLE, migration.DEVICES])
def test_domain_migration_preserves_registrations_and_restores_backup(
    tmp_path, monkeypatch, capsys, devices_domain
):
    storage = tmp_path / ".storage"
    storage.mkdir()
    backup = tmp_path / "backup"
    entry = {
        "domain": devices_domain,
        "entry_id": "apple-entry",
        "unique_id": migration.DEVICES,
        "title": "Apple Find",
        "data": {"kind": "devices"} if devices_domain == migration.PEOPLE else {},
    }
    tracker = {
        "platform": devices_domain,
        "entity_id": "device_tracker.my_phone",
        "unique_id": f"{migration.DEVICES}:phone",
        "config_entry_id": entry["entry_id"],
        "device_id": "apple-device",
    }
    device = {
        "id": tracker["device_id"],
        "identifiers": [[devices_domain, "phone"]],
        "name_by_user": "My phone",
    }
    other_device = {"id": "other-device", "identifiers": [["other", "key", "value"]]}
    repository = {
        "full_name": "tellok/ha-apple-find",
        "domain": migration.PEOPLE,
        "repository_manifest": {"filename": f"{migration.PEOPLE}.zip"},
        "version_installed": "v0.5.4",
    }
    documents = [
        {"data": {"entries": [entry]}},
        {"data": {"entities": [tracker], "deleted_entities": []}},
        {"data": {"devices": [device, other_device]}},
        {"data": {"123": repository}},
    ]
    paths = [storage / name for name in migration.FILES]
    originals = [json.dumps(document) for document in documents]
    for path, original in zip(paths, originals, strict=True):
        path.write_text(original)

    args = ["migrate_ha_registry.py", str(tmp_path), str(backup)]
    monkeypatch.setattr(sys, "argv", args)
    migration.main()
    assert json.loads(capsys.readouterr().out)["needs_migration"]
    assert not backup.exists()
    assert [path.read_text() for path in paths] == originals

    monkeypatch.setattr(sys, "argv", [*args, "--apply"])
    migration.main()
    assert json.loads(capsys.readouterr().out)["applied"]
    assert [json.loads(path.read_text()) for path in paths] == [
        {"data": {"entries": [dict(entry, domain="apple_find", data={"kind": "devices"})]}},
        {"data": {"entities": [dict(tracker, platform="apple_find")], "deleted_entities": []}},
        {"data": {"devices": [dict(device, identifiers=[["apple_find", "phone"]]), other_device]}},
        {"data": {"123": dict(repository, domain="apple_find", repository_manifest={"filename": "apple_find.zip"})}},
    ]

    migration.main()
    assert not json.loads(capsys.readouterr().out)["needs_migration"]

    monkeypatch.setattr(sys, "argv", [*args, "--restore"])
    migration.main()
    assert [path.read_text() for path in paths] == originals
