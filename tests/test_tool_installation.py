# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

from types import SimpleNamespace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.tool_installation import (
    go_toolchain_status, installation_plan, resolve_agent_executable,
)


class ToolInstallationTest(unittest.TestCase):
    @patch("scripts.tool_installation.shutil.which")
    def test_codex_uses_official_standalone_installer_without_npm(self, which) -> None:
        which.side_effect = lambda name: "/usr/bin/curl" if name == "curl" else None

        plan = installation_plan("codex")

        self.assertNotIn("blocked", plan)
        self.assertIn("openai/codex/releases/latest/download/install.sh", plan["command"])
        self.assertIn("CODEX_NON_INTERACTIVE=1", plan["command"])
        self.assertIn('"$HOME/.local/bin/codex" --version', plan["command"])
        self.assertNotIn("npm", plan["command"])
        self.assertIn("IDE-managed", plan["note"])

    @patch("scripts.tool_installation.Path.home")
    @patch("scripts.tool_installation.shutil.which", return_value="/ide/bin/codex")
    def test_user_codex_is_preferred_over_ide_path(self, _which, home) -> None:
        with TemporaryDirectory() as directory:
            home.return_value = Path(directory)
            candidate = Path(directory) / ".local/bin/codex"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("#!/bin/sh\n", encoding="utf-8")
            candidate.chmod(0o700)

            self.assertEqual(resolve_agent_executable("codex"), str(candidate))

    @patch("scripts.tool_installation.shutil.which", return_value=None)
    def test_codex_install_is_blocked_without_download_tool(self, _which) -> None:
        plan = installation_plan("codex")

        self.assertIn("blocked", plan)
        self.assertIn("Neither curl nor wget", plan["blocked"])

    @patch("scripts.tool_installation.platform.machine", return_value="x86_64")
    @patch("scripts.tool_installation.shutil.which")
    @patch("scripts.tool_installation.linux_distribution", return_value=("ubuntu", {"debian"}))
    def test_osv_uses_checksummed_official_binary_without_go(
        self, _distribution, which, _machine,
    ) -> None:
        which.side_effect = lambda name: None if name == "go" else f"/usr/bin/{name}"

        plan = installation_plan("osv-scanner")

        self.assertIsNotNone(plan)
        self.assertNotIn("blocked", plan)
        self.assertIn("osv-scanner_linux_amd64", plan["command"])
        self.assertIn("sha256sum --check", plan["command"])
        self.assertIn('"$HOME/.local/bin/osv-scanner"', plan["command"])
        self.assertNotIn("go install", plan["command"])

    @patch("scripts.tool_installation.platform.machine", return_value="riscv64")
    @patch("scripts.tool_installation.shutil.which", return_value=None)
    @patch("scripts.tool_installation.linux_distribution", return_value=("ubuntu", {"debian"}))
    def test_osv_blocks_unsupported_architecture_without_go(
        self, _distribution, _which, _machine,
    ) -> None:
        plan = installation_plan("osv-scanner")

        self.assertIn("blocked", plan)
        self.assertIn("Go is not installed", plan["blocked"])

    @patch("scripts.tool_installation.shutil.which", return_value="/usr/bin/go")
    @patch("scripts.tool_installation.subprocess.run")
    def test_old_go_toolchain_is_rejected(self, run, _which) -> None:
        run.return_value = SimpleNamespace(
            returncode=0, stdout="go version go1.25.4 linux/amd64", stderr="",
        )

        compatible, detail = go_toolchain_status()

        self.assertFalse(compatible)
        self.assertIn("requires Go 1.26.2 or newer", detail)


if __name__ == "__main__":
    unittest.main()
