# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QUrl
    from PySide6.QtWidgets import QApplication, QPushButton
    from desktop import services
    from desktop.main_window import BarChartCard, MainWindow
except ImportError:
    QApplication = None
    BarChartCard = None
    MainWindow = None
    QPushButton = None
    QUrl = None


@unittest.skipUnless(QApplication is not None, "optional PySide6 dependency is not installed")
class DesktopWindowTest(unittest.TestCase):
    def test_chart_entries_receive_distinct_colors(self) -> None:
        application = QApplication.instance() or QApplication([])
        chart = BarChartCard("Test")
        chart.set_data({"First": 3, "Second": 2, "Third": 1})

        styles = [bar.styleSheet() for bar in chart.bars]
        self.assertEqual(len(styles), 3)
        self.assertEqual(len(set(styles)), 3)
        chart.deleteLater()
        application.processEvents()

    def test_main_window_loads_all_local_views(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.show()
        application.processEvents()

        self.assertEqual(window.pages.count(), 9)
        self.assertEqual(
            [window.config_tabs.tabText(index) for index in range(window.config_tabs.count())],
            [
                "Local projects", "Advisory sources", "Reports", "Backups",
                "AI agents", "AI Codex", "AI Claude",
            ],
        )
        self.assertGreater(window.inventory_tree.topLevelItemCount(), 0)
        self.assertGreater(window.report_list.count(), 0)
        self.assertEqual(window.status_table.columnCount(), 4)
        optional_rows = {
            window.status_table.item(row, 0).text(): row
            for row in range(window.status_table.rowCount())
        }
        self.assertIsNotNone(window.status_table.cellWidget(optional_rows["osv-scanner"], 3))
        self.assertIsNotNone(window.status_table.cellWidget(optional_rows["trivy"], 3))
        self.assertIsNotNone(window.status_table.cellWidget(optional_rows["Configuration backup"], 3))
        self.assertIn("Version: 0.1.2", window.about_metadata.text())
        self.assertEqual(
            window.footer_identity.text(),
            "Version 0.1.2  ·  License AGPL-3.0-or-later",
        )
        buttons = {button.text(): button for button in window.findChildren(QPushButton)}
        self.assertEqual(buttons["Save settings"].property("variant"), "success")
        self.assertEqual(buttons["Restore factory defaults…"].property("variant"), "danger")
        self.assertEqual(buttons["Import backup…"].property("variant"), "danger")
        self.assertEqual(buttons["Stop"].property("variant"), "danger")
        self.assertEqual(buttons["Send to AI"].property("variant"), "ai")
        self.assertFalse(buttons["Initialize local configuration"].isHidden())
        self.assertTrue(buttons["Back up configurations"].isHidden())
        self.assertTrue(buttons["Import backup…"].isHidden())
        window.config_tabs.setCurrentIndex(3)
        application.processEvents()
        self.assertTrue(buttons["Initialize local configuration"].isHidden())
        self.assertFalse(buttons["Back up configurations"].isHidden())
        self.assertFalse(buttons["Import backup…"].isHidden())
        self.assertIn("Desktop user guide", window.guide_viewer.toPlainText())
        window.guide_search.setText("Configuration backups")
        window.search_guide_next()
        self.assertIn(
            "configuration backups",
            window.guide_viewer.textCursor().selectedText().casefold(),
        )
        window.navigation.setCurrentRow(7)
        application.processEvents()
        window.open_guide_link(QUrl("#configuration-backups"))
        application.processEvents()
        self.assertIn(
            "configuration backups",
            window.guide_viewer.textCursor().selectedText().casefold(),
        )
        self.assertGreater(window.guide_viewer.verticalScrollBar().value(), 0)
        self.assertIn("Opened section", window.guide_search_status.text())

        local_editor = window.config_editors[next(iter(window.config_editors))]
        local_editor.appendPlainText("# unsaved test marker")
        window.refresh_all()
        self.assertIn("# unsaved test marker", local_editor.toPlainText())
        window.close()
        window.deleteLater()
        application.processEvents()
        application.quit()

    def test_ai_account_tabs_offer_login_or_install_contextually(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with patch(
            "desktop.main_window.services.agent_component_status",
            return_value=("codex", "Login required", "/usr/bin/codex; account authentication required"),
        ):
            window.refresh_agent_account("codex")
        widgets = window.agent_account_widgets["codex"]
        self.assertEqual(widgets["state"].text(), "Not authenticated")
        self.assertFalse(widgets["login"].isHidden())
        self.assertTrue(widgets["install"].isHidden())
        with patch(
            "desktop.main_window.services.agent_component_status",
            return_value=("codex", "Missing", "not installed"),
        ):
            window.refresh_agent_account("codex")
        self.assertTrue(widgets["login"].isHidden())
        self.assertFalse(widgets["install"].isHidden())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_developer_tools_flag_controls_prepublication_button(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.developer_tools_active = False
        window.prepublish_button.setVisible(False)
        with patch("desktop.main_window.services.set_developer_tools_enabled") as save:
            window.set_developer_tools(True)
        save.assert_called_once_with(True)
        self.assertTrue(window.developer_tools_active)
        self.assertFalse(window.prepublish_button.isHidden())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_guided_project_form_preserves_unknown_yaml_fields(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        path = services.LOCAL_CONFIG
        editor = window.config_editors[path]
        editor.setPlainText(
            "schema_version: 1\n"
            "custom_top_level: keep-me\n"
            "project_roots:\n"
            "  - path: /example/project\n"
            "    label: example\n"
            "    enabled: true\n"
            "    custom_root_setting: keep-this-too\n"
            "    exclude: []\n"
            "inventory:\n"
            "  generated_at: null\n"
            "  projects: []\n"
        )
        form = window.config_simple_forms[path]
        form.load_data(services.validate_config_text(editor.toPlainText()))
        form.table.item(0, 0).setText("renamed")
        browse = form.table.cellWidget(0, 4)
        remove = form.table.cellWidget(0, 5)
        self.assertEqual(browse.text(), "Browse")
        self.assertGreaterEqual(browse.minimumWidth(), 100)
        self.assertTrue(browse.toolTip())
        self.assertGreaterEqual(remove.minimumWidth(), 90)
        self.assertTrue(remove.toolTip())

        window.sync_simple_configuration(path)
        updated = services.validate_config_text(editor.toPlainText())

        self.assertEqual(updated["custom_top_level"], "keep-me")
        self.assertEqual(updated["project_roots"][0]["custom_root_setting"], "keep-this-too")
        self.assertEqual(updated["project_roots"][0]["label"], "renamed")
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_guided_advisory_form_preserves_unknown_source_fields(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        path = services.LOCAL_CONFIG_DIR / "advisory-sources.yaml"
        editor = window.config_editors[path]
        editor.setPlainText(
            "schema_version: 1\n"
            "custom_top_level: keep-me\n"
            "advisory_sources:\n"
            "  - id: vendor\n"
            "    name: Vendor\n"
            "    url: https://vendor.example/advisory\n"
            "    type: html\n"
            "    priority: high\n"
            "    active: true\n"
            "    technologies: [python]\n"
            "    custom_auth_mode: public-read-only\n"
        )
        form = window.config_simple_forms[path]
        form.load_data(services.validate_config_text(editor.toPlainText()))

        window.sync_simple_configuration(path)
        updated = services.validate_config_text(editor.toPlainText())

        self.assertEqual(updated["custom_top_level"], "keep-me")
        self.assertEqual(
            updated["advisory_sources"][0]["custom_auth_mode"], "public-read-only",
        )
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_remaining_guided_forms_preserve_unknown_fields(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        cases = (
            (
                services.LOCAL_CONFIG_DIR / "reports.yaml",
                "schema_version: 1\ncustom: keep\nreports:\n"
                "  daily_directory: output/daily\n  daily_filename: '%Y-%m-%d.md'\n"
                "  summary_file: output/summary.md\n  followup_file: output/followup.md\n"
                "  followup_archive_directory: output/archive\n  timezone: UTC\n"
                "  language: en\n  include_open_followups: true\n"
                "  preserve_existing_evidence: true\n"
                "  risk_levels: [high]\n  classifications: [follow-up]\n"
                "  custom_report_setting: keep-report\n",
                lambda updated: updated["reports"]["custom_report_setting"],
                "keep-report",
            ),
            (
                services.LOCAL_CONFIG_DIR / "ai-agents.yaml",
                "schema_version: 1\ncustom: keep\ndefault_profile: economical\n"
                "default_execution_mode: economical\nprofiles:\n  economical:\n"
                "    description: Economy\n    custom_profile_setting: keep-profile\n"
                "    agents:\n      codex: {model: luna}\n      claude: {model: haiku}\n"
                "execution_modes:\n  economical:\n    description: Sequential\n"
                "    max_parallel_sources: 1\n    use_subagents: false\n    max_subagents: 0\n",
                lambda updated: updated["profiles"]["economical"]["custom_profile_setting"],
                "keep-profile",
            ),
            (
                services.LOCAL_CONFIG_DIR / "backups.yaml",
                "schema_version: 1\ncustom: keep\nbackups:\n"
                "  directory: output/config-backups\n  include: [reports.yaml]\n"
                "  archive_prefix: fairy\n  checksum: sha256\n"
                "  custom_backup_setting: keep-backup\n",
                lambda updated: updated["backups"]["custom_backup_setting"],
                "keep-backup",
            ),
        )
        for path, text, extract, expected in cases:
            editor = window.config_editors[path]
            editor.setPlainText(text)
            window.config_simple_forms[path].load_data(services.validate_config_text(text))
            window.sync_simple_configuration(path)
            updated = services.validate_config_text(editor.toPlainText())
            self.assertEqual(updated["custom"], "keep")
            self.assertEqual(extract(updated), expected)
        reports_form = window.config_simple_forms[services.LOCAL_CONFIG_DIR / "reports.yaml"]
        self.assertTrue(reports_form.timezone.isReadOnly())
        self.assertEqual(reports_form.timezone.text(), "UTC")
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_login_action_is_shown_for_installed_unauthenticated_agent(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with patch("desktop.main_window.services.component_status", return_value=[
            ("codex", "Login required", "/usr/bin/codex; account authentication required"),
        ]):
            window.load_status()
        action_cell = window.status_table.cellWidget(0, 3)
        labels = [button.text() for button in action_cell.findChildren(type(window.assistant_send_button))]
        self.assertIn("Log in", labels)
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_linux_desktop_launcher_action_switches_between_install_and_remove(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with patch("desktop.main_window.services.component_status", return_value=[
            ("Linux desktop launcher", "Not created", "not installed for the current user"),
        ]):
            window.load_status()
        action_cell = window.status_table.cellWidget(0, 3)
        self.assertEqual(
            [button.text() for button in action_cell.findChildren(QPushButton)], ["Install"],
        )
        with patch("desktop.main_window.services.component_status", return_value=[
            ("Linux desktop launcher", "Ready", "/tmp/fairy-security-advisory.desktop"),
        ]):
            window.load_status()
        action_cell = window.status_table.cellWidget(0, 3)
        self.assertEqual(
            [button.text() for button in action_cell.findChildren(QPushButton)], ["Remove"],
        )
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_followup_table_has_solve_and_ai_chat_actions_for_open_issue(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with TemporaryDirectory() as directory:
            followup = Path(directory) / "followup.md"
            followup.write_text(
                "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
                "| A-1 | CVE-2026-1234 | api | Patch | High | Dev | Open | 2026-11-01 | 2026-11-01 | Upgrade | — | — |\n"
                "| A-2 | CVE-2 | web | Done | Low | Dev | Completed | 2026-11-01 | 2026-11-02 | None | — | Test |\n",
                encoding="utf-8",
            )
            window.load_followup_table(followup)

            activity_cell = window.followup_table.cellWidget(0, 0)
            open_buttons = window.followup_table.cellWidget(0, 6).findChildren(QPushButton)
            closed_buttons = window.followup_table.cellWidget(1, 6).findChildren(QPushButton)
            self.assertEqual([button.text() for button in open_buttons], ["Set as solved", "AI chat"])
            self.assertIn(
                "https://www.cve.org/CVERecord?id=CVE-2026-1234",
                activity_cell.text(),
            )
            self.assertTrue(activity_cell.openExternalLinks())
            self.assertTrue(all(button.isEnabled() for button in open_buttons))
            self.assertEqual(open_buttons[0].property("variant"), "success")
            self.assertEqual(open_buttons[1].property("variant"), "ai")
            self.assertTrue(all(not button.isEnabled() for button in closed_buttons))
        window.close()
        window.deleteLater()
        application.processEvents()


if __name__ == "__main__":
    unittest.main()
