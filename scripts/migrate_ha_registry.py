"""Merge the native Devices config entry into Apple Find while HA is stopped."""

import argparse
import json
import os
from pathlib import Path
import tempfile

PEOPLE = "apple_findmy_people"
DEVICES = "apple_findmy_native_devices"
FILES = ("core.config_entries", "core.entity_registry")


def migrate(config_entries, entity_registry):
    entries = config_entries["data"]["entries"]
    devices_entries = [entry for entry in entries if entry["domain"] == DEVICES]
    if not devices_entries:
        return []
    if len(devices_entries) != 1 or any(
        entry["domain"] == PEOPLE and entry["unique_id"] == DEVICES for entry in entries
    ):
        raise ValueError("Expected one legacy devices entry and no merged devices entry")

    devices_entry = devices_entries[0]
    entry_id = devices_entry["entry_id"]
    registry = entity_registry["data"]
    rows = registry["entities"] + registry.get("deleted_entities", [])
    moved = []
    for row in rows:
        if row["platform"] != DEVICES:
            continue
        if row.get("config_entry_id") != entry_id and row in registry["entities"]:
            raise ValueError("Legacy tracker does not belong to the devices config entry")
        moved.append(row)
    if not any(row.get("config_entry_id") == entry_id for row in moved):
        raise ValueError("No registered trackers belong to the legacy devices entry")

    new_keys = {(row["entity_id"].split(".", 1)[0], row["unique_id"]) for row in moved}
    if any(row["platform"] == PEOPLE and (
        row["entity_id"].split(".", 1)[0], row["unique_id"]
    ) in new_keys for row in rows):
        raise ValueError("A tracker already has the merged registry key")

    devices_entry["domain"] = PEOPLE
    devices_entry["data"]["kind"] = "devices"
    if devices_entry["title"] == "Apple Find My Native Devices":
        devices_entry["title"] = "Apple Find Devices"
    for row in moved:
        row["platform"] = PEOPLE
    return [row["entity_id"] for row in moved if row in registry["entities"]]


def replace_file(path, contents, metadata=None):
    metadata = metadata or path.stat()
    fd, name = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + "-")
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), metadata.st_mode & 0o777)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("backup", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="Write the migration with HA stopped")
    group.add_argument("--restore", action="store_true", help="Restore the backup with HA stopped")
    args = parser.parse_args()
    paths = [args.config / ".storage" / name for name in FILES]
    if args.restore:
        backups = [args.backup / name for name in FILES]
        originals = [path.read_bytes() for path in backups]
        for path, original in zip(paths, originals, strict=True):
            replace_file(path, original)
        return

    originals = [path.read_bytes() for path in paths]
    entries, registry = (json.loads(original) for original in originals)
    moved = migrate(entries, registry)
    if moved and args.apply:
        args.backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        for path, original in zip(paths, originals, strict=True):
            replace_file(args.backup / path.name, original, metadata=path.stat())
        changed = []
        try:
            for path, document in zip(paths, (entries, registry), strict=True):
                replace_file(path, (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode())
                changed.append(path)
        except BaseException:
            for path in changed:
                replace_file(path, originals[paths.index(path)])
            raise
    print(json.dumps({"moved": moved, "applied": bool(moved and args.apply)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
