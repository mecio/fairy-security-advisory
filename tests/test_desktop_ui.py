# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QProcess, QUrl
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QComboBox, QLabel, QMessageBox, QPushButton
    from desktop import services
    from desktop.eula_dialog import EulaDialog
    from desktop.inventory_technologies_dialog import InventoryTechnologiesDialog
    from desktop.main_window import BarChartCard, MainWindow, PAGE_RUN
    from desktop.run_visualization import RunJourneyWidget
except ImportError:
    QApplication = None
    BarChartCard = None
    MainWindow = None
    PAGE_RUN = None
    QLabel = None
    QPushButton = None
    QUrl = None
    QProcess = None
    Qt = None
    EulaDialog = None
    InventoryTechnologiesDialog = None
    RunJourneyWidget = None


@unittest.skipUnless(QApplication is not None, "optional PySide6 dependency is not installed")
class DesktopWindowTest(unittest.TestCase):
    def test_stop_assistant_terminates_active_request_without_saving_partial_reply(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.show()
        window.assistant_issue_combo.clear()
        window.assistant_issue_combo.addItem("Example issue", {
            "ID": "ISSUE-1", "Project": "Example project",
        })
        window.chat_process.setProperty("issue_id", "ISSUE-1")
        with patch("desktop.main_window.services.assistant_history", return_value=[
            {"role": "user", "content": "What next?"},
        ]), patch("desktop.main_window.services.append_assistant_history") as save_reply:
            window._set_chat_busy("ISSUE-1")
            window.assistant_send_button.setEnabled(False)
            window.assistant_stop_button.setEnabled(True)
            window.chat_process.start(sys.executable, ["-c", "import time; time.sleep(20)"])
            self.assertTrue(window.chat_process.waitForStarted(3000))
            window.chat_response = "Partial reply"
            window.stop_assistant_message()
            self.assertTrue(window.chat_process.waitForFinished(5000))
            application.processEvents()
            self.assertEqual(window.chat_process.state(), QProcess.ProcessState.NotRunning)
            self.assertFalse(window.chat_busy_timer.isActive())
            self.assertTrue(window.assistant_busy_progress.isHidden())
            self.assertFalse(window.assistant_stop_button.isEnabled())
            self.assertTrue(window.assistant_send_button.isEnabled())
            self.assertEqual(window.chat_response, "")
            save_reply.assert_not_called()
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_assistant_shows_progress_and_clears_it_after_start_failure(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.show()
        window.assistant_issue_combo.clear()
        window.assistant_issue_combo.addItem("Example issue", {
            "ID": "ISSUE-1", "Project": "Example project",
        })
        with patch("desktop.main_window.services.assistant_history", return_value=[
            {"role": "user", "content": "What next?"},
        ]), patch.object(QMessageBox, "critical"):
            window._set_chat_busy("ISSUE-1")
            window.load_assistant_conversation()
            application.processEvents()
            self.assertFalse(window.assistant_busy_progress.isHidden())
            self.assertTrue(window.chat_busy_timer.isActive())
            self.assertIn("Preparing a response", window.assistant_conversation.toPlainText())
            window._chat_error(QProcess.ProcessError.FailedToStart)
            application.processEvents()
            self.assertTrue(window.assistant_busy_progress.isHidden())
            self.assertFalse(window.chat_busy_timer.isActive())
            self.assertNotIn("Preparing a response", window.assistant_conversation.toPlainText())
            window.chat_start_failed = False
            window.chat_process.setProperty("issue_id", "ISSUE-1")
            window._set_chat_busy("ISSUE-1")
            with patch("desktop.main_window.services.extract_issue_update", return_value=("Done", None)), \
                 patch("desktop.main_window.services.append_assistant_history"), \
                 patch.object(window, "_read_chat_output"):
                window._chat_finished(0, QProcess.ExitStatus.NormalExit)
            self.assertTrue(window.assistant_busy_progress.isHidden())
            self.assertFalse(window.chat_busy_timer.isActive())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_inventory_manual_technology_dialog_adds_and_edits_an_entry(self) -> None:
        application = QApplication.instance() or QApplication([])
        dialog = InventoryTechnologiesDialog({"id": "workspace"}, ["Python"])
        self.assertEqual([dialog.tabs.tabText(index) for index in range(dialog.tabs.count())],
                         ["Inventory technologies", "Add / edit technology"])
        self.assertEqual(dialog.tabs.currentIndex(), 0)
        dialog.add_button.click()
        self.assertEqual(dialog.tabs.currentIndex(), 1)
        dialog.name.setText("PostgreSQL")
        dialog.category.setCurrentIndex(dialog.category.findData("databases"))
        dialog.note.setText("User-declared database")
        dialog._add_or_update()
        self.assertEqual(dialog.manual, [{
            "name": "PostgreSQL", "category": "databases",
            "note": "User-declared database",
        }])
        self.assertEqual(dialog.tabs.currentIndex(), 0)
        dialog.inventory_table.selectRow(0)
        dialog.edit_button.click()
        self.assertEqual(dialog.tabs.currentIndex(), 1)
        self.assertEqual(dialog.name.text(), "PostgreSQL")
        dialog.version.setText("unverified")
        dialog._add_or_update()
        self.assertEqual(dialog.manual[0]["version"], "unverified")
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_inventory_dialog_can_target_one_dependency_ecosystem(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [
            {"category": "dependencies", "name": "shared", "ecosystem": "npm", "version": "1.0.0"},
            {"category": "dependencies", "name": "shared", "ecosystem": "pypi", "version": "2.0.0"},
        ]}
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.add_button.click()
        dialog.name.setText("shared")
        dialog.category.setCurrentIndex(dialog.category.findData("dependencies"))
        dialog.ecosystem.setCurrentText("npm")
        dialog.version.setText("1.1.0")
        dialog._add_or_update()
        self.assertEqual(dialog.manual[0]["ecosystem"], "npm")
        dialog._save()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_inventory_dialog_edits_visible_version_without_recreating_other_version(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [
            {"category": "dependencies", "name": "shared", "ecosystem": "npm",
             "version": "1.0.0", "source": "resolved-lockfile"},
            {"category": "dependencies", "name": "shared", "ecosystem": "npm",
             "version": "2.0.0", "source": "resolved-lockfile"},
        ]}
        dialog = InventoryTechnologiesDialog(project, [])
        self.assertFalse(dialog.inventory_table.item(0, 3).flags() & Qt.ItemFlag.ItemIsEditable)
        self.assertFalse(dialog.inventory_table.item(0, 0).flags() & Qt.ItemFlag.ItemIsEditable)
        dialog.inventory_table.selectRow(0)
        dialog.edit_button.click()
        self.assertEqual(dialog.tabs.currentIndex(), 1)
        self.assertEqual(dialog.version.text(), "1.0.0")
        dialog.version.setText("1.1.0")
        dialog._add_or_update()
        self.assertEqual(dialog.manual, [{"name": "shared", "category": "dependencies",
            "version": "1.1.0", "ecosystem": "npm", "replaces_version": "1.0.0"}])
        self.assertEqual(sorted(dialog.inventory_table.item(row, 3).text()
                                for row in range(dialog.inventory_table.rowCount())),
                         ["1.1.0", "2.0.0"])
        dialog.inventory_table.selectRow(0)
        dialog.edit_button.click()
        dialog.version.setText("1.2.0")
        dialog._add_or_update()
        self.assertEqual(dialog.manual[0]["replaces_version"], "1.0.0")
        self.assertEqual(dialog.manual[0]["version"], "1.2.0")
        dialog._save()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_inventory_dialog_can_exclude_a_replaced_dependency(self) -> None:
        application = QApplication.instance() or QApplication([])
        dialog = InventoryTechnologiesDialog({"id": "workspace", "technology_inventory": [
            {"category": "dependencies", "name": "example.test/old",
             "ecosystem": "go", "source": "go-replaced", "version": ""},
        ]}, [])
        dialog.add_button.click()
        dialog.name.setText("example.test/old")
        dialog.category.setCurrentIndex(dialog.category.findData("dependencies"))
        dialog.ecosystem.setCurrentText("go")
        dialog.exclude.setChecked(True)
        dialog._add_or_update()
        self.assertTrue(dialog.manual[0]["exclude"])
        self.assertEqual(dialog.inventory_table.item(0, 5).text(), "Excluded by user")
        dialog.inventory_table.selectRow(0)
        dialog.edit_button.click()
        self.assertTrue(dialog.exclude.isChecked())
        self.assertEqual(dialog.name.text(), "example.test/old")
        dialog.tabs.setCurrentIndex(0)
        dialog.remove_button.click()
        self.assertEqual(dialog.manual, [])
        self.assertEqual(dialog.inventory_table.item(0, 5).text(), "Go-Replaced")
        dialog._save()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_first_run_eula_requires_explicit_checkbox_acceptance(self) -> None:
        application = QApplication.instance() or QApplication([])
        dialog = EulaDialog("# Notice\n\nProvided **as is**.", "1")
        self.assertFalse(dialog.accept_button.isEnabled())
        dialog.acceptance.setChecked(True)
        application.processEvents()
        self.assertTrue(dialog.accept_button.isEnabled())
        dialog.acceptance.setChecked(False)
        application.processEvents()
        self.assertFalse(dialog.accept_button.isEnabled())
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_ai_analysis_progress_is_visible_across_pages(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.run_journey.start("ai-check")
        window._start_analysis_activity()
        self.assertTrue(window.global_analysis_label.isVisibleTo(window.statusBar()))
        self.assertEqual(window.analysis_project_progress.maximum(), 0)

        marker = (
            '::fairy-analysis-progress::{"phase":"evidence","status":"running",'
            '"provider":"claude","completed":2,"total":5,"active_projects":3,'
            '"message":"Collecting read-only evidence"}'
        )
        self.assertTrue(window._consume_analysis_progress_line(marker))
        self.assertEqual(window.analysis_project_progress.maximum(), 5)
        self.assertEqual(window.analysis_project_progress.value(), 2)
        self.assertIn("Claude", window.analysis_activity_label.text())
        self.assertIn("3 projects", window.analysis_activity_label.text())
        self.assertEqual(window.run_journey.phase, "evidence")
        self.assertEqual(window.run_journey.agent, "Claude")
        self.assertEqual(window.run_journey.state, "running")
        self.assertNotIn(marker, window.log.toPlainText())

        window.navigation.setCurrentRow(0)
        application.processEvents()
        self.assertFalse(window.global_analysis_label.isHidden())
        window._handle_analysis_progress({
            "phase": "complete", "status": "completed", "provider": "codex",
            "completed": 5, "total": 5, "active_projects": 0,
            "message": "Analysis completed",
        })
        self.assertEqual(window.analysis_project_progress.value(), 5)
        self.assertIn("completed", window.analysis_activity_label.text().casefold())
        self.assertEqual(window.run_journey.state, "completed")
        self.assertFalse(window.run_journey.timer.isActive())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_run_check_baselines_and_log_have_separate_full_height_tabs(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.resize(980, 680)
        window.show()
        window._navigate_to_page(PAGE_RUN)
        window.run_tabs.setCurrentIndex(1)
        application.processEvents()

        self.assertEqual(
            [window.run_tabs.tabText(index) for index in range(window.run_tabs.count())],
            ["Activity", "Technology baselines", "Detailed log"],
        )
        self.assertTrue(window.run_tabs.widget(1).isAncestorOf(window.technology_scan_tree))
        self.assertGreater(window.technology_scan_tree.height(), 250)
        window.run_tabs.setCurrentIndex(2)
        application.processEvents()
        self.assertGreater(window.log.height(), 250)
        window.run_journey.start("ai-check")
        window._handle_analysis_progress({
            "phase": "consolidation", "status": "running", "provider": "codex",
            "completed": 1, "total": 2, "message": "Consolidating evidence",
        })
        self.assertEqual(window.run_tabs.currentIndex(), 2)
        self.assertEqual(window.run_journey.phase, "consolidation")
        self.assertTrue(window.run_journey.timer.isActive())
        window.run_journey.finish(True)
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_run_journey_renders_and_tracks_non_ai_checks(self) -> None:
        application = QApplication.instance() or QApplication([])
        journey = RunJourneyWidget(
            services.ROOT / "desktop/assets/fairy-security-advisory-icon.png"
        )
        journey.resize(720, 200)
        journey.start("sources")
        self.assertEqual(journey._active_edges(), {"sources"})
        self.assertEqual(journey._face_scale(), -1.0)
        self.assertFalse(journey.grab().isNull())
        journey.finish(False)
        self.assertEqual(journey.state, "failed")
        self.assertFalse(journey.timer.isActive())
        journey.close()
        journey.deleteLater()
        application.processEvents()

    def test_run_journey_turns_to_matching_and_casts_spell(self) -> None:
        application = QApplication.instance() or QApplication([])
        journey = RunJourneyWidget(
            services.ROOT / "desktop/assets/fairy-security-advisory-icon.png"
        )
        journey.resize(720, 200)
        journey.start("ai-check")
        journey.progress({"phase": "evidence", "status": "running"})
        self.assertEqual(journey._face_scale(), -1.0)
        journey.progress({"phase": "consolidation", "status": "running"})
        self.assertEqual(journey._face_scale(), -1.0)
        for _ in range(journey.TURN_FRAMES):
            journey._advance()
        self.assertEqual(journey._face_scale(), 1.0)
        self.assertNotEqual(journey._wand_angle(), 0.0)
        self.assertFalse(journey.grab().isNull())
        journey.finish(True)
        self.assertEqual(journey._wand_angle(), 0.0)
        journey.close()
        journey.deleteLater()
        application.processEvents()

    def test_sandbox_terminal_handoff_closes_gui_only_after_successful_launch(self) -> None:
        application = QApplication.instance() or QApplication([])
        plan = {
            "command": "printf ready", "supported": True, "note": "Test command.",
            "claude_documentation": "https://example.test/claude",
            "ubuntu_documentation": "https://example.test/ubuntu",
        }
        with patch("desktop.main_window.services.sandbox_configuration_plan", return_value=plan), patch(
            "desktop.main_window.SandboxSetupDialog.exec",
            return_value=1,
        ), patch(
            "desktop.main_window.shutil.which",
            return_value="/usr/bin/gnome-terminal",
        ), patch("desktop.main_window.QProcess.startDetached", return_value=(True, 123)) as launch:
            window = MainWindow()
            window.show()
            application.processEvents()
            window.configure_ai_sandbox()
            self.assertFalse(window.isVisible())
            launch.assert_called_once()
            window.deleteLater()
            application.processEvents()

        with patch("desktop.main_window.services.sandbox_configuration_plan", return_value=plan), patch(
            "desktop.main_window.SandboxSetupDialog.exec",
            return_value=1,
        ), patch(
            "desktop.main_window.shutil.which",
            return_value="/usr/bin/gnome-terminal",
        ), patch(
            "desktop.main_window.QProcess.startDetached", return_value=(False, 0),
        ), patch("desktop.main_window.QMessageBox.critical"):
            window = MainWindow()
            window.show()
            application.processEvents()
            window.configure_ai_sandbox()
            self.assertTrue(window.isVisible())
            window.close()
            window.deleteLater()
            application.processEvents()

    @patch(
        "desktop.main_window.services.report_entries",
        return_value=[("Demonstration report", Path("/tmp/fairy-demo-report.md"))],
    )
    def test_report_reset_requires_confirmation_and_refreshes_the_view(self, _entries) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with patch(
            "desktop.main_window.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ) as question, patch("desktop.main_window.services.archive_and_reset_reports") as reset:
            window.reset_reports_for_recheck()
            reset.assert_not_called()
            self.assertIn("It will not read the snapshot", question.call_args.args[2])

        with patch(
            "desktop.main_window.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ), patch(
            "desktop.main_window.services.archive_and_reset_reports",
            return_value=(Path("/tmp/report-reset-test"), 2),
        ) as reset, patch(
            "desktop.main_window.QMessageBox.information",
        ), patch.object(window, "refresh_all") as refresh:
            window.reset_reports_for_recheck()
            reset.assert_called_once()
            refresh.assert_called_once()
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_logs_page_reads_archives_and_deletes_only_selected_run(self) -> None:
        application = QApplication.instance() or QApplication([])
        with TemporaryDirectory() as directory:
            root = Path(directory) / "analysis-runs"
            run = root / "2026/11/20261116T180000Z-42"
            run.mkdir(parents=True)
            (run / "run-summary.txt").write_text(
                "Run ID: 20261116T180000Z-42\nStatus: completed\n"
                "Started UTC: 2026-11-16T18:00:00Z\nCoordinator: codex\n",
                encoding="utf-8",
            )
            (run / "run.log").write_text("START\nFINISH\n", encoding="utf-8")
            with patch("desktop.services.ANALYSIS_RUNS_DIR", root):
                window = MainWindow()
                window.navigation.setCurrentRow(4)
                application.processEvents()
                run_item = window.logs_tree.topLevelItem(0).child(0).child(0)
                window.logs_tree.setCurrentItem(run_item)
                application.processEvents()
                self.assertIn("Run ID: 20261116T180000Z-42", window.analysis_log_viewer.toPlainText())
                self.assertTrue(window.delete_log_button.isEnabled())
                with patch(
                    "desktop.main_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Yes,
                ):
                    window.delete_selected_analysis_run()
                self.assertFalse(run.exists())
                self.assertEqual(window.logs_tree.topLevelItemCount(), 0)
                window.close()
                window.deleteLater()
                application.processEvents()

    def test_complete_analysis_uses_routing_plan_and_selected_profile(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.provider_combo.setCurrentText("codex")
        window.profile_combo.setCurrentText("balanced")
        window.mode_combo.setCurrentText("economical")
        routing = {
            "summary": "Codex: 2 project(s); Claude: 1 project(s); excluded: 1",
            "groups": {"codex": 2, "claude": 1},
            "excluded": 1,
            "selected": 3,
            "required_providers": ["codex", "claude"],
        }
        with patch(
            "desktop.main_window.services.analysis_routing", return_value=routing,
        ), patch(
            "desktop.main_window.services.ai_model",
            side_effect=lambda provider, _profile: f"{provider}-model",
        ), patch(
            "desktop.main_window.services.sandbox_preflight",
            return_value={"ready": True},
        ), patch(
            "desktop.main_window.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ) as question, patch(
            "desktop.main_window.services.write_technology_selection",
            return_value=Path("/private/selection.json"),
        ), patch.object(window, "start_action") as start:
            window.run_ai_analysis()

        message = question.call_args.args[2]
        self.assertIn(routing["summary"], message)
        self.assertIn("codex: codex-model", message)
        self.assertIn("claude: claude-model", message)
        start.assert_called_once_with(
            "ai-check", provider="codex", profile="balanced", mode="economical",
            assume_yes=True, non_interactive=True,
            technology_selection_file=Path("/private/selection.json"),
        )
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_inventory_supports_project_selection_and_preferred_ai(self) -> None:
        application = QApplication.instance() or QApplication([])
        with patch("desktop.main_window.services.inventory_projects", return_value=[{
            "id": "api",
            "path": "/private/api",
            "roles": ["backend"],
            "languages": [{"name": "Python"}],
            "advisory_checks": {"enabled": False, "preferred_ai": "claude"},
        }]), patch("desktop.main_window.services.inventory_age", return_value="current"):
            window = MainWindow()
            window.load_inventory()

        self.assertEqual(window.inventory_tree.columnCount(), 6)
        item = window.inventory_tree.topLevelItem(0)
        selector = window.inventory_tree.itemWidget(item, 2)
        self.assertEqual(item.checkState(0), Qt.CheckState.Unchecked)
        self.assertIsInstance(selector, QComboBox)
        self.assertEqual(
            [selector.itemText(index) for index in range(selector.count())],
            ["-", "Codex", "Claude"],
        )
        self.assertEqual(selector.currentData(), "claude")
        self.assertEqual(item.childCount(), 0)
        self.assertIn("Python version missing", item.text(4))
        self.assertEqual(window.edit_technologies_button.text(), "Details")
        self.assertFalse(window.edit_technologies_button.isEnabled())
        window.inventory_tree.setCurrentItem(item)
        self.assertTrue(window.edit_technologies_button.isEnabled())

        item.setCheckState(0, Qt.CheckState.Checked)
        selector.setCurrentIndex(selector.findData("codex"))
        with patch("desktop.main_window.services.update_inventory_preferences") as save, patch(
            "desktop.main_window.QMessageBox.information",
            return_value=QMessageBox.StandardButton.Ok,
        ), patch("desktop.main_window.services.inventory_projects", return_value=[]):
            with patch.object(window, "load_initialization_scope") as reload_scope:
                window.save_inventory_preferences()
                reload_scope.assert_called_once_with()
        save.assert_called_once_with({
            "/private/api": {"enabled": True, "preferred_ai": "codex"},
        })
        window.close()
        window.deleteLater()
        application.processEvents()

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

        self.assertEqual(window.pages.count(), 10)
        self.assertEqual(
            [
                window.navigation.item(index).text()
                for index in range(window.navigation.count())
                if window.navigation.item(index).flags() & Qt.ItemFlag.ItemIsSelectable
            ],
            [
                "Dashboard", "Reports", "Run check", "AI issue assistant", "Logs",
                "Inventory", "Configuration", "System status", "User guide", "About",
            ],
        )
        separators = [
            window.navigation.item(index)
            for index in range(window.navigation.count())
            if not window.navigation.item(index).flags() & Qt.ItemFlag.ItemIsSelectable
        ]
        self.assertEqual(len(separators), 2)
        self.assertEqual(
            [window.config_tabs.tabText(index) for index in range(window.config_tabs.count())],
            [
                "Local projects", "Advisory sources", "Reports", "Backups",
                "AI agents", "AI Codex", "AI Claude",
            ],
        )
        self.assertGreater(window.inventory_tree.topLevelItemCount(), 0)
        if window.report_list.count():
            self.assertTrue(window.reset_reports_button.isEnabled())
        else:
            self.assertIn("No reports yet", window.report_viewer.toPlainText())
            self.assertFalse(window.reset_reports_button.isEnabled())
        self.assertEqual(window.status_table.columnCount(), 4)
        self.assertIn(
            "applies only to Inventory projects whose AI preference is ‘-’",
            window.findChild(QLabel, "routingNotice").text(),
        )
        optional_rows = {
            window.status_table.item(row, 0).text(): row
            for row in range(window.status_table.rowCount())
        }
        for component in ("osv-scanner", "trivy"):
            row = optional_rows[component]
            action = window.status_table.cellWidget(row, 3)
            if window.status_table.item(row, 1).text() == "Ready":
                self.assertIsNone(action)
            else:
                self.assertIsNotNone(action)
        self.assertIsNotNone(window.status_table.cellWidget(optional_rows["Configuration backup"], 3))
        self.assertIn("Version: 0.2.1", window.about_metadata.text())
        self.assertEqual(
            window.footer_identity.text(),
            "Version 0.2.1  ·  License AGPL-3.0-or-later",
        )
        buttons = {button.text(): button for button in window.findChildren(QPushButton)}
        self.assertEqual(buttons["Save settings"].property("variant"), "success")
        self.assertEqual(buttons["Restore factory defaults…"].property("variant"), "danger")
        self.assertEqual(buttons["Import backup…"].property("variant"), "danger")
        self.assertEqual(buttons["Clear reports and follow-up…"].property("variant"), "danger")
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
        window._navigate_to_page(8)
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
            followup.write_text(
                "| ID | Issue title | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence | Source URL |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
                "| A-1 | PHP2Shell in PHP runtime | CVE-2026-1234 | api | Patch | High | Dev | Open | 2026-11-01 | 2026-11-01 | Upgrade | — | — | https://example.com/advisory |\n",
                encoding="utf-8",
            )
            window.load_followup_table(followup)
            self.assertIn("PHP2Shell in PHP runtime", window.followup_table.cellWidget(0, 0).text())
            self.assertIn("CVE-2026-1234", window.followup_table.cellWidget(0, 0).text())
            self.assertIn("https://example.com/advisory", window.followup_table.cellWidget(0, 0).text())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_ai_assistant_emphasizes_the_affected_project(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        issue = {
            "ID": "ADV-DEMO-001",
            "Project": "payments-api",
            "Issue title": "Runtime advisory affecting payments API",
            "Advisory / CVE": "CVE-2026-1234",
            "Priority": "High",
            "Status": "Open",
            "Owner": "Security team",
            "Next action": "Verify the patched runtime",
        }
        window.assistant_issue_combo.clear()
        window.assistant_issue_combo.addItem(
            "payments-api  |  ADV-DEMO-001  |  High  |  Open", issue,
        )
        window.load_assistant_conversation()

        self.assertEqual(window.assistant_project_label.text(), "payments-api")
        self.assertGreaterEqual(window.assistant_project_label.font().pointSize(), 18)
        self.assertIn("ADV-DEMO-001", window.assistant_issue_details.text())
        self.assertIn("Runtime advisory affecting payments API", window.assistant_issue_details.text())
        self.assertIn("CVE-2026-1234", window.assistant_issue_details.text())
        self.assertTrue(window.assistant_issue_details.textInteractionFlags())
        window.close()
        window.deleteLater()
        application.processEvents()


if __name__ == "__main__":
    unittest.main()
