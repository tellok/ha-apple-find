"""Migrate older Apple Find installations to the apple_find domain while HA is stopped."""

import argparse
import json
import os
from pathlib import Path
import tempfile

DOMAIN = "apple_find"
PEOPLE = "apple_findmy_people"
DEVICES = "apple_findmy_native_devices"
LEGACY_DOMAINS = {PEOPLE, DEVICES}
REPOSITORY = "tellok/ha-apple-find"
FILES = (
    "core.config_entries",
    "core.entity_registry",
    "core.device_registry",
    "marketplace.repositories",
)


def migrate(config_entries, entity_registry, device_registry=None):
    entries = config_entries["data"]["entries"]
    entry_keys = set()
    for entry in entries:
        if entry["domain"] not in LEGACY_DOMAINS | {DOMAIN}:
            continue
        if (key := entry.get("unique_id")) is not None:
            if key in entry_keys:
                raise ValueError("Two config entries would have the same unique ID")
            entry_keys.add(key)

    registry = entity_registry["data"]
    rows = registry["entities"] + registry.get("deleted_entities", [])
    entity_keys = set()
    for row in rows:
        if row["platform"] in LEGACY_DOMAINS | {DOMAIN}:
            key = (row["entity_id"].split(".", 1)[0], row["unique_id"])
            if key in entity_keys:
                raise ValueError("Two entities would have the same registry key")
            entity_keys.add(key)

    for entry in entries:
        if entry["domain"] == DEVICES:
            entry["data"]["kind"] = "devices"
            if entry["title"] == "Apple Find My Native Devices":
                entry["title"] = "Apple Find Devices"
        if entry["domain"] in LEGACY_DOMAINS:
            entry["domain"] = DOMAIN

    moved = [row["entity_id"] for row in registry["entities"] if row["platform"] in LEGACY_DOMAINS]
    for row in rows:
        if row["platform"] in LEGACY_DOMAINS:
            row["platform"] = DOMAIN

    if device_registry is not None:
        devices = device_registry["data"]
        for key in ("devices", "child_devices", "deleted_devices"):
            for device in devices.get(key, []):
                identifiers = device.get("identifiers", [])
                if any(identifier[0] in LEGACY_DOMAINS for identifier in identifiers):
                    device["identifiers"] = [
                        list(identifier)
                        for identifier in dict.fromkeys(
                            (DOMAIN, *identifier[1:])
                            if identifier[0] in LEGACY_DOMAINS else tuple(identifier)
                            for identifier in identifiers
                        )
                    ]
                if device.get("domain") in LEGACY_DOMAINS:
                    device["domain"] = DOMAIN
    return moved


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


def migrate_marketplace(document):
    for repository in document["data"].values():
        if (
            repository.get("full_name", "").lower() == REPOSITORY
            and repository.get("domain") in LEGACY_DOMAINS
        ):
            repository["domain"] = DOMAIN
            manifest = repository.get("repository_manifest")
            if manifest and manifest.get("filename") == f"{PEOPLE}.zip":
                manifest["filename"] = f"{DOMAIN}.zip"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("backup", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--apply", action="store_true", help="Write the migration with HA stopped")
    group.add_argument("--restore", action="store_true", help="Restore the backup with HA stopped")
    args = parser.parse_args()
    if args.restore:
        # Older backups only contain the first two registries.
        backups = [args.backup / name for name in FILES[:2]]
        backups.extend(path for name in FILES[2:] if (path := args.backup / name).exists())
        originals = [path.read_bytes() for path in backups]
        for backup, original in zip(backups, originals, strict=True):
            path = args.config / ".storage" / backup.name
            replace_file(path, original, metadata=backup.stat())
        return

    storage = args.config / ".storage"
    paths = [storage / name for name in FILES[:2]]
    paths.extend(path for name in FILES[2:] if (path := storage / name).exists())
    originals = {path: path.read_bytes() for path in paths}
    documents = {path: json.loads(original) for path, original in originals.items()}
    moved = migrate(
        documents[storage / FILES[0]],
        documents[storage / FILES[1]],
        documents.get(storage / FILES[2]),
    )
    if (marketplace := documents.get(storage / FILES[3])) is not None:
        migrate_marketplace(marketplace)
    updates = {path: document for path, document in documents.items()
               if document != json.loads(originals[path])}
    applied = bool(updates and args.apply)
    if applied:
        args.backup.mkdir(mode=0o700, parents=True, exist_ok=False)
        for path, original in originals.items():
            replace_file(args.backup / path.name, original, metadata=path.stat())
        changed = []
        try:
            for path, document in updates.items():
                replace_file(path, (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode())
                changed.append(path)
        except BaseException:
            for path in changed:
                replace_file(path, originals[path])
            raise
    print(json.dumps({"moved": moved, "needs_migration": bool(updates), "applied": applied}, ensure_ascii=False))


if __name__ == "__main__":
    main()
