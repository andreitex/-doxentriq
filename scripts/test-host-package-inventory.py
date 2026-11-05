#!/usr/bin/env python3
"""Synthetic temp-tree snapshots and trust/race boundaries; no host inventory."""
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("host_package_inventory", HERE / "host_package_inventory.py")
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class Snapshot(unittest.TestCase):
    def setUp(self):
        location = HERE.parent / ".local" if os.name == "nt" else None
        self.temporary = tempfile.TemporaryDirectory(dir=location)
        self.folder = Path(self.temporary.name).resolve()
        self.root = self.folder / "source"; self.root.mkdir(mode=0o700)
        self.destination = self.folder / "inventory"; self.destination.mkdir(mode=0o700)
        self.overrides = {}
        self.lstat = Path.lstat; self.fstat = os.fstat
        def normalize(info, path=None):
            # Portable unit fixtures model Unix root ownership explicitly. Live
            # Linux ownership/open-no-follow behavior requires the native probe.
            fields = {name: getattr(info, name) for name in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns", "st_atime_ns")}
            fields.update(st_uid=0, st_gid=0)
            if os.name == "nt":
                # Windows creation-time semantics differ between lstat/fstat;
                # synthetic Unix ctime follows this fixture's write clock.
                fields["st_ctime_ns"] = fields["st_mtime_ns"]
                if stat.S_ISDIR(info.st_mode):
                    fields["st_mode"] = stat.S_IFDIR | 0o700
            if path is not None:
                fields.update(self.overrides.get(str(path), {}))
            return SimpleNamespace(**fields)
        self.patches = [patch.object(Path, "lstat", lambda path: normalize(self.lstat(path), path)),
                        patch.object(os, "fstat", lambda fd: normalize(self.fstat(fd)))]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        for path in self.folder.rglob("*"):
            if path.is_file(): path.chmod(0o600)
        self.temporary.cleanup()

    def file(self, relative, raw=b"synthetic package metadata"):
        path = self.root / relative; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw); path.chmod(0o400)
        return path

    def debian(self):
        self.file("etc/os-release", b'ID=debian\nVERSION_ID="12"\n')
        self.file("etc/debian_version", b"12.13\n")
        self.file("var/lib/dpkg/status", b"Package: fixture\nStatus: install ok installed\nVersion: 1\n\n")

    def rocky(self, relative="usr/lib/sysimage/rpm"):
        self.file("etc/os-release", b'ID=rocky\nVERSION_ID="10.2"\n')
        self.file(relative + "/rpmdb.sqlite", b"synthetic SQLite package database")
        self.file(relative + "/rpmdb.sqlite-wal", b"")
        self.file(relative + "/rpmdb.sqlite-shm", b"synthetic SQLite SHM")

    def snapshot(self, **kwargs):
        return M.snapshot_host_packages(self.destination, _test_root=self.root, **kwargs)

    def test_debian_fresh_exact_metadata_copy_and_hashes_preserve_sources(self):
        self.debian()
        before = {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        result = self.snapshot()
        self.assertEqual(result["distribution"], {"family": "debian", "version": "12"})
        self.assertIsNone(result["rpmRoot"])
        self.assertEqual(set(result["files"]), {"etc/os-release", "etc/debian_version", "var/lib/dpkg/status"})
        self.assertEqual(result["fileCount"], 3)
        for name, metadata in result["files"].items():
            raw = (self.destination / name).read_bytes()
            self.assertEqual(metadata, {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
        self.assertEqual(before, {str(path): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

    def test_rocky_one_exact_root_includes_present_sqlite_sidecars(self):
        for relative in ("usr/lib/sysimage/rpm", "var/lib/rpm"):
            with self.subTest(relative=relative):
                if relative != "usr/lib/sysimage/rpm":
                    self.tearDown(); self.setUp()
                self.rocky(relative)
                result = self.snapshot()
                self.assertEqual(result["rpmRoot"], relative)
                self.assertEqual(set(result["files"]), {"etc/os-release", *(relative + "/" + name for name in ("rpmdb.sqlite", "rpmdb.sqlite-wal", "rpmdb.sqlite-shm"))})

    def test_known_os_release_link_only_resolves_to_fixed_vendor_file(self):
        self.debian(); logical = self.root / "etc/os-release"
        self.file("usr/lib/os-release", b'ID=debian\nVERSION_ID="12"\n')
        self.overrides[str(logical)] = {"st_mode": stat.S_IFLNK | 0o777}
        with patch.object(Path, "is_symlink", lambda path: path == logical), patch.object(os, "readlink", return_value="../usr/lib/os-release"):
            result = self.snapshot()
        self.assertIn("etc/os-release", result["files"])
        self.assertNotIn("usr/lib/os-release", result["files"])

    def test_nonempty_wal_or_journal_does_not_claim_main_database_is_complete(self):
        for name in ("rpmdb.sqlite-wal", "rpmdb.sqlite-journal"):
            with self.subTest(name=name):
                if name != "rpmdb.sqlite-wal": self.tearDown(); self.setUp()
                self.rocky()
                path = self.root / "usr/lib/sysimage/rpm" / name
                if path.exists(): path.chmod(0o600)
                path.write_bytes(b"stable committed transaction"); path.chmod(0o400)
                with self.assertRaisesRegex(ValueError, "rpm-transaction-journal-replay-unavailable"):
                    self.snapshot()
                self.assertFalse(any(self.destination.iterdir()))

    def test_empty_journal_is_retained_with_hash_and_shm_remains_ordinary_metadata(self):
        self.rocky(); self.file("usr/lib/sysimage/rpm/rpmdb.sqlite-journal", b"")
        result = self.snapshot()
        self.assertEqual(result["files"]["usr/lib/sysimage/rpm/rpmdb.sqlite-journal"],
                         {"sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0})
        self.assertIn("usr/lib/sysimage/rpm/rpmdb.sqlite-shm", result["files"])

    def test_known_legacy_rpm_link_only_maps_to_one_modern_root(self):
        self.rocky(); logical = self.file("var/lib/rpm", b"link fixture")
        self.overrides[str(logical)] = {"st_mode": stat.S_IFLNK | 0o777}
        with patch.object(Path, "is_symlink", lambda path: path == logical), patch.object(os, "readlink", return_value="../../usr/lib/sysimage/rpm"):
            result = self.snapshot()
        self.assertEqual(result["rpmRoot"], "usr/lib/sysimage/rpm")
        self.assertFalse(any(name.startswith("var/lib/rpm/") for name in result["files"]))

    def test_foreign_or_chained_os_release_link_fails_before_copy(self):
        self.debian(); logical = self.root / "etc/os-release"
        self.file("usr/lib/os-release", b'ID=debian\nVERSION_ID="12"\n')
        self.overrides[str(logical)] = {"st_mode": stat.S_IFLNK | 0o777}
        for link in ("../../etc/shadow", "../usr/lib/foreign-os-release"):
            with self.subTest(link=link), patch.object(Path, "is_symlink", lambda path: path == logical), patch.object(os, "readlink", return_value=link), self.assertRaisesRegex(ValueError, "unexpected-package-metadata-link"):
                self.snapshot()
        self.assertFalse(any(self.destination.iterdir()))

    def test_both_real_rpm_roots_are_ambiguous_and_bdb_is_unavailable(self):
        self.rocky(); self.file("var/lib/rpm/rpmdb.sqlite")
        with self.assertRaisesRegex(ValueError, "ambiguous-rpm"): self.snapshot()
        self.tearDown(); self.setUp(); self.rocky()
        database = self.root / "usr/lib/sysimage/rpm/rpmdb.sqlite"; database.chmod(0o600); database.unlink()
        self.file("usr/lib/sysimage/rpm/Packages")
        with self.assertRaisesRegex(ValueError, "supported-rpm-database-missing"): self.snapshot()

    def test_nonroot_writable_multilink_or_special_source_is_rejected(self):
        self.debian(); source = self.root / "var/lib/dpkg/status"
        for fields in ({"st_uid": 99}, {"st_mode": stat.S_IFREG | 0o666}, {"st_nlink": 2},
                       {"st_mode": stat.S_IFIFO | 0o600}, {"st_mode": stat.S_IFLNK | 0o777}):
            self.overrides[str(source)] = fields
            with self.subTest(fields=fields), self.assertRaisesRegex(ValueError, "untrusted-package-metadata-file"):
                self.snapshot()
        self.assertFalse(any(self.destination.iterdir()))

    def test_untrusted_source_ancestor_and_destination_are_rejected(self):
        self.debian()
        for path in (self.root / "var", self.destination):
            for fields in ({"st_uid": 99}, {"st_mode": stat.S_IFDIR | 0o777}, {"st_mode": stat.S_IFLNK | 0o777}):
                self.overrides[str(path)] = fields
                with self.subTest(path=path, fields=fields), self.assertRaises(ValueError): self.snapshot()
                self.overrides.clear()

    def test_nested_rpm_links_are_never_followed(self):
        self.rocky(); path = self.file("usr/lib/sysimage/rpm/nested/foreign", b"no credentials")
        self.overrides[str(path)] = {"st_mode": stat.S_IFLNK | 0o777}
        with self.assertRaisesRegex(ValueError, "untrusted-package-metadata-file"): self.snapshot()

    def test_existing_destination_never_reuses_or_overwrites_stale_inventory(self):
        self.debian(); stale = self.destination / "old-status"; stale.write_text("preserve old inventory")
        with self.assertRaisesRegex(ValueError, "package-inventory-not-fresh"): self.snapshot()
        self.assertEqual(stale.read_text(), "preserve old inventory")

    def test_mid_copy_package_transaction_or_membership_change_is_unavailable(self):
        for action in ("replace", "new-sidecar", "removed-sidecar"):
            with self.subTest(action=action):
                if action != "replace": self.tearDown(); self.setUp()
                self.rocky()
                def mutate():
                    source = self.root / "usr/lib/sysimage/rpm/rpmdb.sqlite-wal"
                    if action == "new-sidecar": self.file("usr/lib/sysimage/rpm/new-db-sidecar")
                    elif action == "removed-sidecar": source.chmod(0o600); source.unlink()
                    else:
                        source = self.root / "usr/lib/sysimage/rpm/rpmdb.sqlite"
                        source.chmod(0o600); source.write_bytes(b"different database transaction"); source.chmod(0o400)
                with self.assertRaisesRegex(ValueError, "package-metadata-inventory-changed"):
                    self.snapshot(_before_finish=mutate)

    def test_boundary_size_count_entries_and_depth_are_bounded(self):
        self.rocky()
        for name, value, reason in (("MAX_FILE_BYTES", 8, "untrusted-package-metadata-file"),
                                    ("MAX_TOTAL_BYTES", 8, "total-size-limit"),
                                    ("MAX_FILES", 1, "file-count-limit"),
                                    ("MAX_ENTRIES", 1, "entry-limit"),
                                    ("MAX_DEPTH", -1, "depth-limit")):
            with self.subTest(name=name), patch.object(M, name, value), self.assertRaisesRegex(ValueError, reason): self.snapshot()
        self.assertFalse(any(self.destination.iterdir()))

    def test_destination_added_or_replaced_copy_cannot_complete(self):
        self.debian()
        def mutate():
            (self.destination / "unexpected").write_text("not source metadata")
            (self.destination / "unexpected").chmod(0o400)
        with self.assertRaisesRegex(ValueError, "package-inventory-membership-changed"):
            self.snapshot(_before_finish=mutate)

    def test_copied_bytes_are_rehashed_and_cannot_be_changed_in_place(self):
        self.debian()
        def mutate():
            target = self.destination / "var/lib/dpkg/status"
            raw = target.read_bytes()
            target.chmod(0o600); target.write_bytes(b"x" * len(raw)); target.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "package-inventory-copy-changed"):
            self.snapshot(_before_finish=mutate)

    def test_unexpected_distribution_does_not_copy_arbitrary_host_metadata(self):
        self.file("etc/os-release", b"ID=ubuntu\nVERSION_ID=24.04\n")
        with self.assertRaises(ValueError): self.snapshot()
        self.assertFalse(any(self.destination.iterdir()))


if __name__ == "__main__": unittest.main()
