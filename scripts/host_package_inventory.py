#!/usr/bin/env python3
"""Fresh read-only distribution metadata snapshot for an offline OS scanner.

Only os-release, Debian package status/version, or one installed RPM database
root are copied. This is metadata evidence, not a signature or loaded-kernel
attestation. A package transaction or uncertain filesystem identity fails closed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from host_kernel_security import parse_os_release

MAX_FILE_BYTES = 64 * 1024**2
MAX_TOTAL_BYTES = 128 * 1024**2
MAX_FILES = 128
MAX_ENTRIES = 256
MAX_DEPTH = 8
SAFE_NAME = re.compile(r"[A-Za-z0-9_.+-]{1,200}")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def stable(info):
    # A legitimate read may advance atime; it cannot change these identities.
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def trusted_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "untrusted-package-metadata-directory")
    return stable(info)


def ancestors(path, boundary):
    require(path.is_absolute() and boundary.is_absolute() and path.is_relative_to(boundary),
            "package-metadata-path-outside-boundary")
    current = boundary
    values = {str(current): trusted_directory(current)}
    for part in path.relative_to(boundary).parts:
        current /= part
        values[str(current)] = trusted_directory(current)
    return values


def ordinary_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022 and 0 <= info.st_size <= MAX_FILE_BYTES,
            "untrusted-package-metadata-file")
    return stable(info)


def read_file(path, expected, *, copy_to=None, testing=False):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    require(testing or hasattr(os, "O_NOFOLLOW"), "package-metadata-platform-unavailable")
    output = None
    try:
        with os.fdopen(os.open(path, flags), "rb") as source:
            require(stable(os.fstat(source.fileno())) == expected, "package-metadata-file-replaced")
            if copy_to is not None:
                output = os.fdopen(os.open(copy_to, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                          | getattr(os, "O_NOFOLLOW", 0), 0o600), "wb")
            digest, size, chunks = hashlib.sha256(), 0, []
            while True:
                raw = source.read(65536)
                if not raw:
                    break
                size += len(raw)
                require(size <= MAX_FILE_BYTES and size <= expected[6], "package-metadata-file-grew")
                digest.update(raw)
                if output is not None:
                    output.write(raw)
                # Only the small fixed OS-release file is decoded by the caller.
                if path.name == "os-release":
                    require(size <= 16384, "package-os-release-size-limit")
                    chunks.append(raw)
            require(size == expected[6] and stable(os.fstat(source.fileno())) == expected
                    and stable(path.lstat()) == expected, "package-metadata-file-changed")
            if output is not None:
                output.flush(); os.fsync(output.fileno()); output.close(); output = None
                os.chmod(copy_to, 0o400)
                copied = ordinary_file(copy_to)
                require(copied[6] == size, "package-inventory-copy-changed")
            return dict(sha256=digest.hexdigest(), bytes=size), b"".join(chunks)
    finally:
        if output is not None:
            output.close()


def link_target(path, allowed, root):
    info = path.lstat()
    require(stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1,
            "untrusted-package-metadata-link")
    raw = os.readlink(path)
    target = Path(os.path.normpath(str(path.parent / raw))) if not Path(raw).is_absolute() else Path(raw)
    # Absolute links in test trees are logical host paths, never real host reads.
    if root != Path(root.anchor) and Path(raw).is_absolute():
        target = root / str(Path(raw)).lstrip("/")
    require(target == allowed and allowed.resolve(strict=True) == allowed,
            "unexpected-package-metadata-link")
    return stable(info), raw


def metadata_sources(root):
    directories, links, files = {}, {}, {}
    def include(relative, output=None):
        path = root / relative
        directories.update(ancestors(path.parent, root))
        files[output or relative] = (path, ordinary_file(path))
        return path
    os_path = root / "etc/os-release"
    directories.update(ancestors(os_path.parent, root))
    if os_path.is_symlink():
        target = root / "usr/lib/os-release"
        links[str(os_path)] = link_target(os_path, target, root)
        os_path = include("usr/lib/os-release", "etc/os-release")
    else:
        os_path = include("etc/os-release")
    os_record, os_raw = read_file(os_path, files["etc/os-release"][1], testing=root != Path(root.anchor))
    distribution = parse_os_release(os_raw.decode("utf-8", errors="strict"))
    rpm_root = None
    if distribution["family"] == "debian":
        include("etc/debian_version")
        include("var/lib/dpkg/status")
    else:
        legacy, modern = root / "var/lib/rpm", root / "usr/lib/sysimage/rpm"
        present = []
        for candidate in (legacy, modern):
            if not os.path.lexists(candidate):
                continue
            directories.update(ancestors(candidate.parent, root))
            if candidate.is_symlink():
                require(candidate == legacy, "unexpected-package-metadata-link")
                links[str(candidate)] = link_target(candidate, modern, root)
            else:
                trusted_directory(candidate)
                present.append(candidate)
        require(len(present) == 1, "missing-or-ambiguous-rpm-database-root")
        rpm_path = present[0]; rpm_root = rpm_path.relative_to(root).as_posix()
        entries = 0
        def walk(directory, depth=0):
            nonlocal entries
            require(depth <= MAX_DEPTH, "package-metadata-depth-limit")
            directories[str(directory)] = trusted_directory(directory)
            with os.scandir(directory) as listing:
                names = sorted(item.name for item in listing)
            entries += len(names)
            require(entries <= MAX_ENTRIES, "package-metadata-entry-limit")
            for name in names:
                require(SAFE_NAME.fullmatch(name) and name not in {".", ".."}, "invalid-package-metadata-name")
                path = directory / name; info = path.lstat()
                if stat.S_ISDIR(info.st_mode):
                    walk(path, depth + 1)
                else:
                    include(path.relative_to(root).as_posix())
        walk(rpm_path)
        # Rocky 9/10 use RPM's SQLite database. Do not call a stale/BDB directory covered.
        require(rpm_root + "/rpmdb.sqlite" in files, "supported-rpm-database-missing")
        # A stable committed WAL can contain packages absent from the main file.
        # Copying it does not establish that this scanner replays transactions.
        for name in ("rpmdb.sqlite-wal", "rpmdb.sqlite-journal"):
            pending = files.get(rpm_root + "/" + name)
            require(pending is None or pending[1][6] == 0, "rpm-transaction-journal-replay-unavailable")
    require(0 < len(files) <= MAX_FILES, "package-metadata-file-count-limit")
    require(sum(value[1][6] for value in files.values()) <= MAX_TOTAL_BYTES, "package-metadata-total-size-limit")
    return dict(distribution=distribution, rpmRoot=rpm_root, files=files,
                directories=directories, links=links, osReleaseRecord=os_record)


def snapshot_host_packages(destination, *, _test_root=None, _before_finish=None):
    """Copy fixed metadata into an existing fresh protected empty directory.

    Private test hooks are not production configuration. The production caller
    passes only its newly-created encrypted TemporaryDirectory destination.
    An unsuccessful snapshot must never be used as scanner input.
    """
    require(_test_root is not None or os.name == "posix", "package-metadata-platform-unavailable")
    root = Path(_test_root) if _test_root is not None else Path("/")
    destination = Path(destination)
    require(root.is_absolute() and root.resolve(strict=True) == root
            and destination.is_absolute() and destination.resolve(strict=True) == destination,
            "noncanonical-package-inventory-root")
    destination_identity = trusted_directory(destination)
    destination_boundary = root.parent if _test_root is not None else Path(destination.anchor)
    ancestors(destination.parent, destination_boundary)
    require(not any(destination.iterdir()), "package-inventory-not-fresh")
    before = metadata_sources(root)
    for path, _ in before["files"].values():
        require(destination != path and not destination.is_relative_to(path.parent),
                "package-inventory-overlaps-source")
    records = {}
    for relative, (source, identity) in sorted(before["files"].items()):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        records[relative], _ = read_file(source, identity, copy_to=target, testing=_test_root is not None)
    if _before_finish is not None:
        require(_test_root is not None, "test-hook-not-production-configuration")
        _before_finish()
    after = metadata_sources(root)
    require(after == before, "package-metadata-inventory-changed")
    for relative, (source, identity) in sorted(after["files"].items()):
        record, _ = read_file(source, identity, testing=_test_root is not None)
        require(record == records[relative], "package-metadata-bytes-changed")
        copy_record, _ = read_file(destination / relative, ordinary_file(destination / relative), testing=_test_root is not None)
        require(copy_record == record, "package-inventory-copy-changed")
    # Directory size/mtime naturally changes during our copy; pin its ownership,
    # permissions and immutable inode instead of comparing those changing fields.
    end = trusted_directory(destination)
    require(end[:5] == destination_identity[:5], "package-inventory-root-changed")
    copied_files = set()
    for path in destination.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            trusted_directory(path)
        else:
            ordinary_file(path)
            copied_files.add(path.relative_to(destination).as_posix())
    require(copied_files == set(records), "package-inventory-membership-changed")
    return dict(distribution=before["distribution"], rpmRoot=before["rpmRoot"], files=records,
                fileCount=len(records), totalBytes=sum(item["bytes"] for item in records.values()))
