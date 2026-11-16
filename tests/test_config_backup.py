# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import datetime as dt
import hashlib
import json
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import zipfile

from scripts.config_backup import (
    BackupError, create_configuration_backup, create_factory_restore_backup,
    import_configuration_backup,
    inspect_configuration_backup,
)


class ConfigurationBackupTest(unittest.TestCase):
    def test_factory_restore_backup_works_when_local_backup_settings_are_broken(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            local = config / "local"
            local.mkdir(parents=True)
            (config / "backups.yaml").write_text(
                "schema_version: 1\nbackups:\n"
                "  directory: output/config-backups\n"
                "  source_directory: config/local\n"
                "  include: [reports.yaml, backups.yaml]\n"
                "  archive_prefix: restore-safety\n"
                "  checksum: sha256\n",
                encoding="utf-8",
            )
            (local / "reports.yaml").write_text("schema_version: 1\n", encoding="utf-8")
            (local / "backups.yaml").write_text("invalid: [yaml\n", encoding="utf-8")

            result = create_factory_restore_backup(root)

            with zipfile.ZipFile(result["archive"]) as bundle:
                self.assertIn("config/local/backups.yaml", bundle.namelist())

    @staticmethod
    def _project(root: Path) -> Path:
        config = root / "config"
        config.mkdir()
        (config / "projects.local.yaml").write_text(
            "schema_version: 1\nvalue: original\n", encoding="utf-8",
        )
        (config / "reports.yaml").write_text("schema_version: 1\n", encoding="utf-8")
        (config / "backups.yaml").write_text(
            "schema_version: 1\nbackups:\n"
            "  directory: output/config-backups\n"
            "  include: [projects.local.yaml, reports.yaml]\n"
            "  archive_prefix: test-config\n"
            "  checksum: sha256\n",
            encoding="utf-8",
        )
        return config

    def test_private_verified_backup_contains_only_configured_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            (config / "projects.local.yaml").write_text(
                "schema_version: 1\nprivate: true\n", encoding="utf-8",
            )
            (config / "reports.yaml").write_text("schema_version: 1\n", encoding="utf-8")
            (config / "not-included.yaml").write_text("secret: no\n", encoding="utf-8")
            (config / "backups.yaml").write_text(
                "schema_version: 1\nbackups:\n"
                "  directory: output/config-backups\n"
                "  include: [projects.local.yaml, reports.yaml]\n"
                "  archive_prefix: test-config\n"
                "  checksum: sha256\n",
                encoding="utf-8",
            )

            result = create_configuration_backup(
                root, now=dt.datetime(2026, 11, 16, 12, 30, tzinfo=dt.timezone.utc),
            )

            archive = result["archive"]
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(archive.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(result["checksum_file"].stat().st_mode), 0o600)
            with zipfile.ZipFile(archive) as bundle:
                self.assertIsNone(bundle.testzip())
                self.assertEqual(
                    set(bundle.namelist()),
                    {"config/projects.local.yaml", "config/reports.yaml", "backup-manifest.json"},
                )
                manifest = json.loads(bundle.read("backup-manifest.json"))
                self.assertEqual(manifest["created_at"], "2026-11-16T12:30:00Z")
                self.assertEqual(len(manifest["files"]), 2)
            self.assertIn(result["sha256"], result["checksum_file"].read_text(encoding="ascii"))

    def test_destination_outside_output_is_rejected(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            config.mkdir()
            (config / "reports.yaml").write_text("schema_version: 1\n", encoding="utf-8")
            (config / "backups.yaml").write_text(
                "schema_version: 1\nbackups:\n"
                "  directory: backups\n"
                "  include: [reports.yaml]\n",
                encoding="utf-8",
            )
            with self.assertRaises(BackupError):
                create_configuration_backup(root)

    def test_local_directory_layout_is_preserved_in_backup(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config"
            local = config / "local"
            local.mkdir(parents=True)
            (local / "projects.yaml").write_text(
                "schema_version: 1\nproject_roots: []\n", encoding="utf-8",
            )
            (local / "reports.yaml").write_text(
                "schema_version: 1\nreports: {}\n", encoding="utf-8",
            )
            (config / "backups.yaml").write_text(
                "schema_version: 1\nbackups:\n"
                "  directory: output/config-backups\n"
                "  source_directory: config/local\n"
                "  include: [projects.yaml, reports.yaml]\n"
                "  archive_prefix: test-local\n"
                "  checksum: sha256\n",
                encoding="utf-8",
            )

            result = create_configuration_backup(root)

            with zipfile.ZipFile(result["archive"]) as bundle:
                self.assertEqual(set(bundle.namelist()), {
                    "config/local/projects.yaml",
                    "config/local/reports.yaml",
                    "backup-manifest.json",
                })

    def test_import_verifies_and_restores_after_creating_safety_backup(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config = self._project(root)
            backup = create_configuration_backup(
                root, now=dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.timezone.utc),
            )
            inspected = inspect_configuration_backup(root, backup["archive"])
            self.assertTrue(inspected["sidecar_verified"])
            (config / "projects.local.yaml").write_text(
                "schema_version: 1\nvalue: changed\n", encoding="utf-8",
            )

            restored = import_configuration_backup(root, backup["archive"])

            self.assertIn("value: original", (config / "projects.local.yaml").read_text(encoding="utf-8"))
            self.assertTrue(restored["safety_backup"].is_file())
            with zipfile.ZipFile(restored["safety_backup"]) as bundle:
                self.assertIn("value: changed", bundle.read("config/projects.local.yaml").decode("utf-8"))

    def test_import_rejects_archive_members_outside_config(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            self._project(root)
            archive = root / "malicious.zip"
            content = b"schema_version: 1\n"
            manifest = {
                "schema_version": 1,
                "created_at": "2026-11-16T00:00:00Z",
                "files": [{
                    "path": "../outside.yaml", "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }],
            }
            with zipfile.ZipFile(archive, "w") as bundle:
                bundle.writestr("../outside.yaml", content)
                bundle.writestr("backup-manifest.json", json.dumps(manifest))

            with self.assertRaises(BackupError):
                inspect_configuration_backup(root, archive)


if __name__ == "__main__":
    unittest.main()
