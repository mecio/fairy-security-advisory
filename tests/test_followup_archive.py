# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import stat
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.followup_archive import archive_closed_followups


HEADER = (
    "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | "
    "Last updated | Next action | Due date | Completion evidence |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
)


class FollowupArchiveTest(unittest.TestCase):
    def test_closed_rows_move_to_year_month_archives_and_open_rows_remain(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            followup = root / "output/followup.md"
            archive = root / "output/followup-archive"
            followup.parent.mkdir()
            followup.write_text(
                "# Follow-up\n\n" + HEADER
                + "| A-1 | CVE-1 | api | Open | High | Dev | Open | 2026-10-01 | 2026-11-01 | Patch | — | — |\n"
                + "| A-2 | CVE-2 | api | Done | High | Dev | Completed | 2026-10-01 | 2026-10-31 | None | — | Tests |\n"
                + "| A-3 | CVE-3 | web | Closed | Critical | Ops | Externally closed | 2026-11-01 | 2026-11-16 | Monitor | — | Admin evidence |\n"
                + "\n## Notes\n\nKeep this note.\n",
                encoding="utf-8",
            )

            result = archive_closed_followups(
                root, followup_path=followup, archive_directory=archive,
            )

            active = followup.read_text(encoding="utf-8")
            self.assertEqual(result["archived"], 2)
            self.assertIn("| A-1 |", active)
            self.assertNotIn("| A-2 |", active)
            self.assertNotIn("| A-3 |", active)
            self.assertIn("Keep this note.", active)
            self.assertIn("| A-2 |", (archive / "2026/10.md").read_text(encoding="utf-8"))
            self.assertIn("| A-3 |", (archive / "2026/11.md").read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE((archive / "2026/11.md").stat().st_mode), 0o600)

            second = archive_closed_followups(
                root, followup_path=followup, archive_directory=archive,
            )
            self.assertEqual(second["archived"], 0)


if __name__ == "__main__":
    unittest.main()
