# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest
from unittest.mock import patch

from scripts.sandbox_preflight import (
    claude_sandbox_settings, sandbox_preflight, sandbox_setup_command,
    sandbox_setup_plan,
)


class SandboxPreflightTest(unittest.TestCase):
    @patch("scripts.sandbox_preflight._probe_bwrap", return_value=(True, "ok"))
    @patch("scripts.sandbox_preflight._restriction_value", return_value="1")
    @patch("scripts.sandbox_preflight.shutil.which")
    def test_ready_probe_wins_even_when_ubuntu_restriction_is_enabled(
        self, which, _restriction, _probe,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"
        result = sandbox_preflight(("codex", "claude"))
        self.assertTrue(result["ready"])
        self.assertEqual(result["state"], "Ready")

    @patch(
        "scripts.sandbox_preflight._probe_bwrap",
        return_value=(False, "bwrap: setting up uid map: Permission denied"),
    )
    @patch("scripts.sandbox_preflight._restriction_value", return_value="1")
    @patch("scripts.sandbox_preflight.shutil.which")
    def test_apparmor_block_is_reported_with_targeted_guidance(
        self, which, _restriction, _probe,
    ) -> None:
        which.side_effect = lambda name: f"/usr/bin/{name}"
        result = sandbox_preflight(("codex", "claude"))
        self.assertFalse(result["ready"])
        self.assertEqual(result["state"], "Action required")
        self.assertIn("AppArmor", result["details"])
        self.assertIn("Keep the system-wide user-namespace restriction enabled", result["guidance"])

    @patch("scripts.sandbox_preflight._probe_bwrap", return_value=(True, "ok"))
    @patch("scripts.sandbox_preflight._restriction_value", return_value="0")
    @patch("scripts.sandbox_preflight.shutil.which")
    def test_socat_is_required_for_claude_but_not_codex(
        self, which, _restriction, _probe,
    ) -> None:
        which.side_effect = lambda name: "/usr/bin/bwrap" if name == "bwrap" else None
        self.assertTrue(sandbox_preflight(("codex",))["ready"])
        self.assertEqual(sandbox_preflight(("claude",))["state"], "Missing")

    def test_reviewed_setup_keeps_global_apparmor_restriction_enabled(self) -> None:
        with patch("scripts.sandbox_preflight.linux_distribution", return_value=("ubuntu", {"debian"})), patch(
            "scripts.sandbox_preflight.platform.freedesktop_os_release",
            return_value={"VERSION_ID": "24.04"},
        ):
            command = sandbox_setup_command(apparmor_required=True)
        self.assertIn("/etc/apparmor.d/bwrap-userns-restrict", command)
        self.assertIn("sudo apt-get install bubblewrap socat", command)
        self.assertIn("apt-get download apparmor-profiles", command)
        self.assertIn("dpkg-deb -x apparmor-profiles_*.deb", command)
        self.assertNotIn("sudo apt-get install bubblewrap socat apparmor-profiles", command)
        self.assertIn("sudo apparmor_parser -r", command)
        self.assertNotIn("flags=(unconfined)", command)
        self.assertNotIn("sudo systemctl reload apparmor", command)
        self.assertNotIn("apparmor_restrict_unprivileged_userns=0", command)

    def test_unknown_apparmor_repair_has_no_executable_command(self) -> None:
        with patch("scripts.sandbox_preflight.linux_distribution", return_value=("fedora", set())), patch(
            "scripts.sandbox_preflight.platform.freedesktop_os_release",
            return_value={"VERSION_ID": "42"},
        ):
            plan = sandbox_setup_plan(apparmor_required=True)
        self.assertFalse(plan["supported"])
        self.assertEqual(plan["command"], "")

    def test_claude_settings_fail_closed_without_unsandboxed_retry(self) -> None:
        settings = claude_sandbox_settings()
        self.assertIn('"enabled":true', settings)
        self.assertIn('"allowUnsandboxedCommands":false', settings)
        self.assertIn('"failIfUnavailable":true', settings)


if __name__ == "__main__":
    unittest.main()
