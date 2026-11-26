"""Prepare, verify and package the single Home Assistant release unit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from zipfile import ZIP_STORED, ZipFile, ZipInfo

PACKAGE = "ha-apple-find"
INTEGRATION = Path("custom_components/apple_find")
MANIFEST = INTEGRATION / "manifest.json"
EVIDENCE = Path(".changeset/release.json")
NOTES = Path(".version-pr-notes.md")
VERSION_FILES = {"package.json", "package-lock.json", str(MANIFEST), "CHANGELOG.md", str(EVIDENCE)}
LEVELS = ("major", "minor", "patch")


def git(*args):
    return subprocess.check_output(["git", *args]).decode().rstrip("\n")


def read_json(path):
    return json.loads(Path(path).read_text())


def at(ref, path):
    return git("show", f"{ref}:{path}")


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


def output(**fields):
    with open(os.environ["GITHUB_OUTPUT"], "a") as target:
        for key, value in fields.items():
            target.write(f"{key}={value}\n")


def stable_version(value):
    if not re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}", value, re.ASCII):
        raise ValueError(f"Expected a stable semantic version, got {value!r}")
    return tuple(map(int, value.split(".")))


def planned_release():
    with TemporaryDirectory() as temp:
        path = Path(temp) / "plan.json"
        subprocess.run(["node_modules/.bin/changeset", "status", f"--output={path}"], check=True)
        plan = read_json(path)
    if not plan["releases"]:
        return None
    release, = plan["releases"]
    if release["name"] != PACKAGE or release["oldVersion"] != read_json(MANIFEST)["version"]:
        raise ValueError("Changesets plan does not match the release unit and manifest")
    if stable_version(release["newVersion"]) <= stable_version(release["oldVersion"]):
        raise ValueError("The version must advance")
    return release


def sections(changelog, version):
    headings = list(re.finditer(r"^## (.+)$", changelog, re.M))
    matches = [i for i, heading in enumerate(headings) if heading[1] == version]
    if len(matches) != 1:
        raise ValueError(f"Expected one CHANGELOG section for {version}")
    index, = matches
    end = headings[index + 1].start() if index + 1 < len(headings) else len(changelog)
    section = changelog[headings[index].end():end]
    blocks = re.split(r"^### (Major|Minor|Patch) Changes\s*$", section, flags=re.M)
    if blocks[0].strip() or len(blocks) < 3:
        raise ValueError(f"Unrecognized CHANGELOG section for {version}")
    result = {}
    for level, body in zip(blocks[1::2], blocks[2::2]):
        body = body.strip()
        if level.lower() in result or not body.startswith("- "):
            raise ValueError(f"Invalid {level} entries for {version}")
        result[level.lower()] = body
    return result


def notes(changelog, old, new, source, pending=False):
    parts = []
    if pending:
        parts.extend([f"Pending release. Base commit: `{source}`.", f"# {PACKAGE}: `{old} -> {new}`"])
    anchor = new.replace(".", "")
    url = "https://github.com/tellok/ha-apple-find"
    parts.append(f"[CHANGELOG {new}]({url}/blob/{'release/version-update' if pending else source}/CHANGELOG.md#{anchor})")
    groups = sections(changelog, new)
    for level in LEVELS:
        if level not in groups:
            continue
        body = re.sub(
            r"^[ \t]*(?:[-*][ \t]+)?(?:linked[ \t]+)?(?:openspec|spec(?:ification)?s?)[ \t]*:[^\n]*\n?",
            "",
            groups[level],
            flags=re.I | re.M,
        )
        if body.strip():
            parts.append(f"## {level}\n\n{body.strip()}")
    return "\n\n".join(parts) + "\n"


def candidate(path):
    return path.lower() != ".changeset/readme.md" and re.fullmatch(r"\.changeset/(?!\.)[^/]+\.md", path)


def prepare():
    release = planned_release()
    if release is None:
        return
    base = git("rev-parse", "HEAD")
    old, new = release["oldVersion"], release["newVersion"]
    subprocess.run(["node_modules/.bin/changeset", "version"], check=True)
    if read_json("package.json")["version"] != new:
        raise ValueError("Prepared version disagrees with the Changesets plan")
    manifest = read_json(MANIFEST)
    manifest["version"] = new
    write_json(MANIFEST, manifest)
    subprocess.run(["npm", "install", "--package-lock-only", "--offline", "--ignore-scripts", "--no-audit"], check=True)

    removed = git("diff", "--diff-filter=D", "--name-only", "-z", base)
    consumed = {path: git("rev-parse", f"{base}:{path}") for path in removed.split("\0") if candidate(path)}
    planned = [str(Path(".changeset") / f"{item}.md") for item in release["changesets"]]
    if not planned or not set(planned) <= consumed.keys():
        raise ValueError("Changesets CLI did not consume the planned entries")

    changelog = Path("CHANGELOG.md").read_text()
    write_json(EVIDENCE, {
        "unit": PACKAGE, "base": base, "old": old, "new": new, "bump": release["type"],
        "tag": f"v{new}", "asset": read_json("hacs.json")["filename"],
        "changesets": consumed,
    })
    subprocess.run(["node_modules/.bin/prettier", "--write", MANIFEST, EVIDENCE], check=True)
    NOTES.write_text(notes(changelog, old, new, base, pending=True))


def verify(base, head, result):
    if git("rev-list", "--parents", "-n", "1", head).split() != [head, base]:
        raise ValueError("The managed PR must have one version commit on the current base")
    if git("rev-parse", f"{head}^{{tree}}") != git("rev-parse", f"{result}^{{tree}}"):
        raise ValueError("The resulting tree does not match the prepared version")
    evidence = json.loads(at(result, EVIDENCE))
    if evidence["unit"] != PACKAGE or evidence["base"] != base:
        raise ValueError("The version record does not match the release unit or base")

    old, new = evidence["old"], evidence["new"]
    major, minor, patch = stable_version(old)
    increments = {
        "major": (major + 1, 0, 0),
        "minor": (major, minor + 1, 0),
        "patch": (major, minor, patch + 1),
    }
    if stable_version(new) != increments[evidence["bump"]] or evidence["tag"] != f"v{new}":
        raise ValueError("The recorded bump or tag does not match the actual version")
    for ref, version in [(base, old), (result, new)]:
        lock = json.loads(at(ref, "package-lock.json"))
        if any(value != version for value in [
            json.loads(at(ref, MANIFEST))["version"], json.loads(at(ref, "package.json"))["version"],
            lock["version"], lock["packages"][""]["version"],
        ]):
            raise ValueError(f"Manifest, package and lock versions disagree at {ref}")

    consumed = evidence["changesets"]
    if not consumed or any(not candidate(path) for path in consumed):
        raise ValueError("The release must consume recorded Changesets")
    diff = git("diff", "--no-renames", "--name-status", "-z", base, result).split("\0")
    changes = dict(zip(diff[1::2], diff[::2]))
    if changes.keys() != VERSION_FILES | consumed.keys():
        raise ValueError("The version commit changes files outside the recorded release scope")
    for path, blob in consumed.items():
        if changes[path] != "D" or git("rev-parse", f"{base}:{path}") != blob:
            raise ValueError(f"Invalid consumption record for {path}")

    # The version commit can only change the version fields of the integration
    # and npm metadata. Product changes must already be on the base.
    for path in ("package.json", "package-lock.json", MANIFEST):
        before, after = (json.loads(at(ref, path)) for ref in (base, result))
        after["version"] = old
        if path == "package-lock.json":
            after["packages"][""]["version"] = old
        if before != after:
            raise ValueError(f"Unexpected changes in {path}")
    changelog = at(result, "CHANGELOG.md")
    sections(changelog, new)
    old_changelog = at(base, "CHANGELOG.md")
    if not changelog.endswith(old_changelog.split("\n", 1)[1].lstrip("\n")):
        raise ValueError("Version preparation changed historical CHANGELOG entries")
    return evidence


def pack(source, directory):
    if git("rev-parse", "HEAD") != source:
        raise ValueError("Packaging checkout does not match the verified release source")
    evidence = read_json(EVIDENCE)
    config = read_json("hacs.json")
    name = evidence["asset"]
    if config["zip_release"] is not True or config["filename"] != name or name != "apple_find.zip":
        raise ValueError("Unexpected HACS ZIP configuration")

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    files = {}
    entries = git("ls-tree", "-r", "-z", source, "--", str(INTEGRATION)).rstrip("\0")
    for entry in entries.split("\0"):
        mode_type_hash, filename = entry.split("\t", 1)
        mode, kind, blob = mode_type_hash.split()
        if kind != "blob" or mode != "100644":
            raise ValueError(f"Unexpected file mode for {filename}")
        files[str(Path(filename).relative_to(INTEGRATION))] = subprocess.check_output(["git", "cat-file", "blob", blob])
    if json.loads(files["manifest.json"])["version"] != evidence["new"]:
        raise ValueError("ZIP manifest version mismatch")
    with ZipFile(path, "w", compression=ZIP_STORED) as archive:
        for filename, data in files.items():
            archive.writestr(ZipInfo(filename), data)
    with ZipFile(path) as archive:
        if archive.namelist() != list(files) or any(archive.read(file) != data for file, data in files.items()):
            raise ValueError("ZIP verification failed")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(directory / "assets.json", [{"name": name, "path": str(path), "hash": f"sha256:{digest}"}])
    (directory / "notes.md").write_text(
        notes(at(source, "CHANGELOG.md"), evidence["old"], evidence["new"], source)
    )


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan")
    commands.add_parser("prepare")
    check = commands.add_parser("verify")
    check.add_argument("base")
    check.add_argument("head")
    check.add_argument("result")
    build = commands.add_parser("pack")
    build.add_argument("source")
    build.add_argument("directory", type=Path)
    args = parser.parse_args()
    if args.command == "plan":
        release = planned_release()
        if release:
            output(title=f"release: version update {release['oldVersion']} -> {release['newVersion']}")
    elif args.command == "prepare":
        prepare()
    elif args.command == "verify":
        record = verify(args.base, args.head, args.result)
        output(version=record["new"], tag=record["tag"])
    else:
        pack(args.source, args.directory)


if __name__ == "__main__":
    main()
