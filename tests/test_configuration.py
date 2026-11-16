# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.configuration import (
    effective_config_path, initialize_local_overrides, restore_local_override,
)


class LocalConfigurationOverrideTest(unittest.TestCase):
    FACTORIES = (
        "projects.example.yaml", "advisory-sources.yaml", "reports.yaml",
        "ai-agents.yaml", "backups.yaml", "application.yaml",
    )

    def create_factories(self, config: Path) -> None:
        config.mkdir()
        for name in self.FACTORIES:
            (config / name).write_text("schema_version: 1\n", encoding="utf-8")

    def test_factory_is_used_until_local_override_exists(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            self.create_factories(config)
            self.assertEqual(
                effective_config_path(config, "reports.yaml"), config / "reports.yaml",
            )
            (config / "local").mkdir()
            override = config / "local/reports.yaml"
            override.write_text("schema_version: 1\nreports: {}\n", encoding="utf-8")
            self.assertEqual(effective_config_path(config, "reports.yaml"), override)

    def test_initializer_creates_all_overrides_in_ignored_directory(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            self.create_factories(config)
            created = initialize_local_overrides(config)
            self.assertEqual(len(created), 6)
            self.assertTrue(all(path.parent == config / "local" for path in created))
            self.assertEqual(initialize_local_overrides(config), [])

    def test_legacy_projects_file_is_migrated_without_deleting_it(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            self.create_factories(config)
            legacy = config / "projects.local.yaml"
            legacy.write_text("schema_version: 1\nlegacy: true\n", encoding="utf-8")
            self.assertEqual(
                effective_config_path(config, "projects.example.yaml"), legacy,
            )
            initialize_local_overrides(config)
            migrated = config / "local/projects.yaml"
            self.assertIn("legacy: true", migrated.read_text(encoding="utf-8"))
            self.assertTrue(legacy.is_file())

    def test_factory_restore_atomically_replaces_only_selected_override(self) -> None:
        with TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            self.create_factories(config)
            (config / "reports.yaml").write_text(
                "schema_version: 1\nreports:\n  timezone: UTC\n", encoding="utf-8",
            )
            initialize_local_overrides(config)
            selected = config / "local/reports.yaml"
            untouched = config / "local/ai-agents.yaml"
            selected.write_text("schema_version: 1\nlocal: true\n", encoding="utf-8")
            untouched_before = untouched.read_bytes()

            factory, destination = restore_local_override(config, "reports.yaml")

            self.assertEqual(factory, config / "reports.yaml")
            self.assertEqual(destination, selected)
            self.assertEqual(selected.read_bytes(), factory.read_bytes())
            self.assertEqual(untouched.read_bytes(), untouched_before)
            self.assertEqual(selected.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(selected.parent.glob(".reports.yaml.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
