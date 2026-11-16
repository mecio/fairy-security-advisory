# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.desktop_integration import (
    desktop_entry_installed, install_linux_desktop_entry, remove_linux_desktop_entry,
)


class DesktopIntegrationTest(unittest.TestCase):
    @patch("scripts.desktop_integration.refresh_desktop_database")
    def test_install_and_remove_user_desktop_entry(self, _refresh) -> None:
        with TemporaryDirectory() as directory:
            data_home = Path(directory) / "share"

            desktop_path, icon_path = install_linux_desktop_entry(data_home)

            entry = desktop_path.read_text(encoding="utf-8")
            self.assertTrue(desktop_entry_installed(data_home))
            self.assertIn("Name=fAIry Security Advisory", entry)
            self.assertIn(" --gui", entry)
            self.assertIn(f"Icon={icon_path}", entry)
            self.assertEqual(stat.S_IMODE(desktop_path.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(icon_path.stat().st_mode), 0o644)

            remove_linux_desktop_entry(data_home)
            self.assertFalse(desktop_entry_installed(data_home))
