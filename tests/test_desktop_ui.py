# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PySide6.QtCore import QProcess, QUrl
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QKeySequence, QPalette
    from PySide6.QtWidgets import (
        QApplication, QComboBox, QDialog, QHeaderView, QLabel, QMessageBox, QPushButton,
        QToolTip, QTreeWidgetItem,
    )
    from desktop import services
    from desktop.eula_dialog import EulaDialog
    from desktop.inventory_technologies_dialog import InventoryTechnologiesDialog
    from desktop.main_window import (
        BarChartCard, MainWindow, PAGE_ASSISTANT, PAGE_REPORTS, PAGE_RUN,
    )
    from desktop.run_visualization import RunJourneyWidget
except ImportError:
    QApplication = None
    BarChartCard = None
    MainWindow = None
    PAGE_RUN = None
    PAGE_REPORTS = None
    PAGE_ASSISTANT = None
    QLabel = None
    QPushButton = None
    QUrl = None
    QProcess = None
    QDialog = None
    QHeaderView = None
    QKeySequence = None
    QPalette = None
    QToolTip = None
    QTreeWidgetItem = None
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
                         ["Inventory technologies", "Add / edit technology",
                          "Production versions", "Add / edit production"])
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
        dialog.version_status.setCurrentIndex(
            dialog.version_status.findData("hypothetical"),
        )
        dialog._add_or_update()
        self.assertEqual(dialog.manual[0]["version"], "unverified")
        self.assertEqual(dialog.manual[0]["version_status"], "hypothetical")
        self.assertEqual(dialog.inventory_table.item(0, 6).text(), "Hypothetical")
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

    def test_inventory_dialog_records_multiple_production_environments(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [{
            "category": "databases", "name": "PostgreSQL", "version": "17.2",
            "source": "verified-local",
        }]}
        dialog = InventoryTechnologiesDialog(project, [])
        self.assertEqual(dialog.inventory_table.item(0, 4).text(), "Default: 17.2")
        self.assertIn(
            "not production verified", dialog.inventory_table.item(0, 5).text(),
        )
        dialog.inventory_table.selectRow(0)
        dialog.add_production_button.click()
        self.assertEqual(dialog.tabs.currentIndex(), 3)
        dialog.production_environment.setText("production-eu")
        dialog.production_version.setText("16.4")
        dialog.production_evidence_type.setCurrentIndex(
            dialog.production_evidence_type.findData("administrator-confirmed"),
        )
        dialog.production_verified_at.setText("2026-11-19T10:30:00Z")
        dialog.production_evidence.setText("Confirmed by the system administrator")
        dialog._add_or_update_production()
        self.assertEqual(dialog.tabs.currentIndex(), 2)
        self.assertEqual(dialog.production[0]["environment"], "production-eu")
        self.assertIn("production-eu: 16.4", dialog.inventory_table.item(0, 4).text())

        dialog.add_production_button.click()
        dialog.production_environment.setText("production-us")
        dialog.production_version.setText("16.6")
        dialog.production_evidence_type.setCurrentIndex(
            dialog.production_evidence_type.findData("authorized-check"),
        )
        dialog.production_verified_at.setText("2026-11-19T10:35:00Z")
        dialog.production_evidence.setText("Authorized read-only version command")
        dialog._add_or_update_production()
        self.assertEqual(len(dialog.production), 2)
        self.assertEqual(dialog.production_table.rowCount(), 2)
        dialog._save()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_new_production_version_defaults_to_inventory_version(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [{
            "category": "databases", "name": "PostgreSQL", "version": "17.2",
            "source": "verified-local",
        }]}
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.inventory_table.selectRow(0)
        dialog.add_production_button.click()

        self.assertEqual(dialog.production_version.text(), "17.2")
        dialog.production_version.setText("16.4")
        self.assertEqual(dialog.production_version.text(), "16.4")
        self.assertEqual(dialog.production, [])

        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_inventory_rerender_does_not_retarget_pending_production_version(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {
            "id": "workspace",
            "technology_inventory": [{
                "category": "runtimes", "name": "Beta", "version": "1.0",
                "source": "declared",
            }],
            "manual_technologies": [{
                "category": "runtimes", "name": "Alpha", "version": "2.0",
            }],
        }
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.inventory_table.selectRow(0)
        dialog.add_production_button.click()
        self.assertEqual(dialog.production_technology.currentText(), "Alpha")
        self.assertEqual(dialog.production_version.text(), "2.0")
        dialog.production_evidence.setText("Pending production evidence")

        dialog.tabs.setCurrentIndex(0)
        dialog.inventory_table.selectRow(0)
        dialog._edit_selected()
        dialog.name.setText("Zulu")
        dialog._add_or_update()

        self.assertEqual(dialog.production_technology.currentIndex(), -1)
        self.assertTrue(dialog._production_form_dirty)

        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_missing_inventory_version_can_open_ai_research(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "path": "/projects/workspace", "technology_inventory": [
            {"category": "databases", "name": "PostgreSQL", "version": "",
             "source": "configuration"},
        ]}
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.inventory_table.selectRow(0)
        self.assertTrue(dialog.find_version_button.isEnabled())
        dialog.find_version_button.click()
        self.assertEqual(dialog.ai_version_request["name"], "PostgreSQL")
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)

        window = MainWindow()
        window.open_technology_version_ai(project, dialog.ai_version_request)
        context = window.selected_assistant_issue()
        self.assertEqual(window.pages.currentIndex(), PAGE_ASSISTANT)
        self.assertEqual(context["Context type"], "technology-version")
        self.assertEqual(context["Technology"], "PostgreSQL")
        self.assertIn("determine the exact version of PostgreSQL", window.assistant_input.toPlainText())
        self.assertIn("VERSION MISSING", window.assistant_issue_details.text())
        self.assertTrue(window.assistant_send_button.isEnabled())
        window.close()
        dialog.deleteLater()
        window.deleteLater()
        application.processEvents()

    def test_ai_version_research_confirms_pending_edits_and_rechecks_version(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [{
            "category": "databases", "name": "PostgreSQL", "version": "",
            "source": "configuration",
        }]}
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.inventory_table.selectRow(0)
        dialog._edit_selected()
        dialog.version.setText("17.2")
        dialog.tabs.setCurrentIndex(0)
        dialog.inventory_table.selectRow(0)

        with patch.object(
            QMessageBox, "question", return_value=QMessageBox.StandardButton.No,
        ) as question:
            dialog._find_version_with_ai()
        question.assert_called_once()
        self.assertEqual(dialog.result(), dialog.DialogCode.Rejected)
        self.assertIsNone(dialog.ai_version_request)
        self.assertEqual(dialog.version.text(), "17.2")

        with patch.object(
            QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes,
        ):
            dialog._find_version_with_ai()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        self.assertEqual(dialog.manual[0]["version"], "17.2")
        self.assertIsNone(dialog.ai_version_request)

        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_ai_version_research_saves_other_preview_changes_before_opening(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {"id": "workspace", "technology_inventory": [{
            "category": "databases", "name": "PostgreSQL", "version": "",
            "source": "configuration",
        }]}
        dialog = InventoryTechnologiesDialog(project, [])
        dialog.add_button.click()
        dialog.name.setText("Redis")
        dialog.category.setCurrentIndex(dialog.category.findData("databases"))
        dialog.version.setText("7.2.1")
        dialog._add_or_update()
        dialog.inventory_table.selectRow(0)

        with patch.object(
            QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes,
        ) as question:
            dialog._find_version_with_ai()
        question.assert_called_once()
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)
        self.assertEqual(dialog.ai_version_request["name"], "PostgreSQL")
        self.assertEqual(dialog.manual[0]["name"], "Redis")

        dialog.close()
        dialog.deleteLater()
        application.processEvents()

    def test_ai_version_research_persists_dialog_changes_before_navigation(self) -> None:
        application = QApplication.instance() or QApplication([])
        project = {
            "id": "workspace", "path": "/projects/workspace",
            "technology_inventory": [{
                "category": "databases", "name": "PostgreSQL", "version": "",
                "source": "configuration",
            }],
        }
        dialog = SimpleNamespace(
            manual=[{"category": "databases", "name": "Redis", "version": "7.2.1"}],
            production=[],
            ai_version_request={
                "category": "databases", "name": "PostgreSQL", "version": "",
                "quality": "red", "source": "configuration",
            },
            exec=lambda: QDialog.DialogCode.Accepted,
        )
        updated = {**project, "manual_technologies": dialog.manual}
        events: list[str] = []
        window = MainWindow()
        with patch.object(services, "inventory_projects", return_value=[project]):
            window.load_inventory()
        window.inventory_tree.setCurrentItem(window.inventory_tree.topLevelItem(0))

        def save(*_args: object) -> dict[str, object]:
            events.append("save")
            return updated

        def navigate(*_args: object) -> None:
            events.append("open-ai")

        with patch("desktop.main_window.InventoryTechnologiesDialog", return_value=dialog), \
             patch.object(services, "inventory_projects", return_value=[project]), \
             patch.object(services, "technology_names", return_value=[]), \
             patch.object(services, "update_project_technologies", side_effect=save), \
             patch.object(window, "load_inventory"), \
             patch.object(window, "load_initialization_scope"), \
             patch.object(window, "open_technology_version_ai", side_effect=navigate):
            window.edit_inventory_technologies()

        self.assertEqual(events, ["save", "open-ai"])
        window.close()
        window.deleteLater()
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
        self.assertFalse(dialog.find_version_button.isEnabled())
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
        self.assertEqual(dialog.inventory_table.item(0, 7).text(), "Excluded by user")
        dialog.inventory_table.selectRow(0)
        dialog.edit_button.click()
        self.assertTrue(dialog.exclude.isChecked())
        self.assertEqual(dialog.name.text(), "example.test/old")
        dialog.tabs.setCurrentIndex(0)
        dialog.remove_button.click()
        self.assertEqual(dialog.manual, [])
        self.assertEqual(dialog.inventory_table.item(0, 7).text(), "Go-Replaced")
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
        for _ in range(window.run_journey.MOVE_FRAMES * 3):
            window.run_journey._advance()
            if window.run_journey.state == "completed":
                break
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
        self.assertTrue(
            window.run_tabs.widget(1).isAncestorOf(window.technology_baseline_filter)
        )
        self.assertGreater(window.technology_scan_tree.height(), 220)
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

    def test_technology_baseline_filter_hides_rows_without_changing_selection(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window.technology_scan_tree.clear()
        for key, technology, version, checked in (
            ("php-key", "PHP", ">=7.2", True),
            ("redis-key", "Redis", "7.4", False),
        ):
            item = QTreeWidgetItem((
                "", technology, version, "Inventory", "Uncertain", "Missing", "app",
            ))
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked,
            )
            window.technology_scan_tree.addTopLevelItem(item)

        window.technology_baseline_filter.setText("php")
        application.processEvents()

        self.assertFalse(window.technology_scan_tree.topLevelItem(0).isHidden())
        self.assertTrue(window.technology_scan_tree.topLevelItem(1).isHidden())
        self.assertEqual(
            window.technology_scan_tree.topLevelItem(0).checkState(0),
            Qt.CheckState.Checked,
        )
        self.assertEqual(
            window.technology_scan_tree.topLevelItem(1).checkState(0),
            Qt.CheckState.Unchecked,
        )
        window.technology_baseline_filter.clear()
        application.processEvents()
        self.assertFalse(window.technology_scan_tree.topLevelItem(1).isHidden())
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
        self.assertEqual(journey._active_edges(), {"candidate-intake"})
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
        self.assertEqual(journey.phase, "evidence")
        self.assertEqual(len(journey.pending_events), 1)
        for _ in range(journey.MOVE_FRAMES + journey.TURN_FRAMES):
            journey._advance()
        self.assertEqual(journey._face_scale(), 1.0)
        self.assertNotEqual(journey._wand_angle(), 0.0)
        self.assertFalse(journey.grab().isNull())
        journey.finish(True)
        self.assertEqual(journey.state, "running")
        for _ in range(journey.MOVE_FRAMES * 3):
            journey._advance()
            if journey.state == "completed":
                break
        self.assertEqual(journey.state, "completed")
        self.assertEqual(journey._wand_angle(), 0.0)
        journey.close()
        journey.deleteLater()
        application.processEvents()

    def test_run_journey_uses_phase_art_and_respects_motion_modes(self) -> None:
        application = QApplication.instance() or QApplication([])
        journey = RunJourneyWidget(
            services.ROOT / "desktop/assets/fairy-security-advisory-icon.png",
            animation_mode="full",
        )
        self.assertFalse(journey.idle_sprite.isNull())
        self.assertLessEqual(journey.FAIRY_MAX_SIZE, 74.0)
        self.assertEqual(len(journey.MAIN_STATIONS), 15)
        self.assertTrue(journey.timer.isActive())
        first_source = journey._phase_pixmap()[1]
        for _ in range(8):
            journey._advance()
        self.assertNotEqual(journey._phase_pixmap()[1], first_source)

        journey.start("ai-check")
        routing_start = journey._position_ratio()
        journey.progress({
            "phase": "validation", "status": "running", "provider": "codex",
            "detail": "3 staged reports · candidate ledger · coverage receipt",
            "attempt": 1, "max_attempts": 2,
        })
        self.assertEqual(journey.phase, "validation")
        self.assertEqual(journey._active_edges(), {"validation"})
        self.assertEqual(journey._position_ratio(), routing_start)
        for _ in range(journey.MOVE_FRAMES):
            journey._advance()
        self.assertEqual(journey._position_ratio(), journey.PHASE_POSITIONS["validation"])
        self.assertFalse(journey._phase_icon().isNull())
        self.assertEqual((journey.attempt, journey.max_attempts), (1, 2))
        rectangles = journey._station_rectangles(960, 120, 245)
        self.assertEqual(len(rectangles), 16)
        self.assertIn("candidate-ledger", rectangles)
        self.assertIn("coverage-receipt", rectangles)
        self.assertIn("correction", rectangles)

        journey.progress({"phase": "validation", "status": "completed"})
        self.assertIn("validation", journey.visited_phases)
        journey.progress({"phase": "correction", "status": "rejected"})
        self.assertNotIn("correction", journey.visited_phases)

        journey.set_animation_mode("reduced")
        self.assertTrue(journey.timer.isActive())
        self.assertEqual(journey.timer.interval(), 240)
        journey.set_animation_mode("disabled")
        self.assertFalse(journey.timer.isActive())
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            journey.set_animation_mode("fast-and-dizzy")
        journey.close()
        journey.deleteLater()
        application.processEvents()

    def test_run_journey_queues_fast_real_phase_events_until_each_move_finishes(self) -> None:
        application = QApplication.instance() or QApplication([])
        journey = RunJourneyWidget(
            services.ROOT / "desktop/assets/fairy-security-advisory-icon.png",
            animation_mode="full",
        )
        journey.start("ai-check")
        journey.progress({"phase": "evidence", "status": "running"})
        journey.progress({"phase": "candidate-intake", "status": "running"})
        journey.progress({"phase": "staging", "status": "running"})
        self.assertEqual(journey.phase, "evidence")
        self.assertEqual(len(journey.pending_events), 2)
        for _ in range(journey.MOVE_FRAMES):
            journey._advance()
        self.assertEqual(journey.phase, "candidate-intake")
        self.assertEqual(len(journey.pending_events), 1)
        for _ in range(journey.MOVE_FRAMES):
            journey._advance()
        self.assertEqual(journey.phase, "staging")
        journey.progress({"phase": "coverage-receipt", "status": "failed"})
        self.assertEqual(journey.state, "failed")
        self.assertEqual(
            journey._position_ratio(), journey.PHASE_POSITIONS["coverage-receipt"],
        )
        journey.close()
        journey.deleteLater()
        application.processEvents()

    def test_animation_preference_updates_the_live_journey(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        reduced = window.work_animation_combo.findData("reduced")
        with patch("desktop.main_window.services.set_work_animation_mode") as save:
            window.work_animation_combo.setCurrentIndex(reduced)
        save.assert_called_once_with("reduced")
        self.assertEqual(window.work_animation_mode, "reduced")
        self.assertEqual(window.run_journey.animation_mode, "reduced")
        window.close()
        window.deleteLater()
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
            (run / "candidate-ledger.json").write_text(json.dumps({
                "schema_version": 1,
                "candidates": [{
                    "advisory_id": "CVE-TEST-1", "project_id": "legacy",
                    "declared_value": ">=7.2", "decision": "not-applicable",
                    "decision_reason": "Confirmed absent prerequisite",
                }],
            }), encoding="utf-8")
            with patch("desktop.services.ANALYSIS_RUNS_DIR", root):
                window = MainWindow()
                window.navigation.setCurrentRow(4)
                application.processEvents()
                run_item = window.logs_tree.topLevelItem(0).child(0).child(0)
                window.logs_tree.setCurrentItem(run_item)
                application.processEvents()
                self.assertIn("Run ID: 20261116T180000Z-42", window.analysis_log_viewer.toPlainText())
                self.assertIn(
                    "candidate-ledger.json",
                    [window.log_file_combo.itemText(index) for index in range(window.log_file_combo.count())],
                )
                self.assertIn("CVE-TEST-1", window.analysis_log_exclusions.text())
                self.assertIn("Confirmed absent prerequisite", window.analysis_log_exclusions.text())
                self.assertIn("ledger decisions 1", window.analysis_log_candidates.text())
                self.assertIn("unscored 1", window.analysis_log_candidates.text())
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
        ) as write_selection, patch.object(window, "start_action") as start:
            window.run_ai_analysis()

        message = question.call_args.args[2]
        self.assertIn(routing["summary"], message)
        self.assertIn("codex: codex-model", message)
        self.assertIn("claude: claude-model", message)
        self.assertIn("Historical baseline scan", message)
        selected_keys = [
            str(window.technology_scan_tree.topLevelItem(index).data(
                0, Qt.ItemDataRole.UserRole,
            ))
            for index in range(window.technology_scan_tree.topLevelItemCount())
            if window.technology_scan_tree.topLevelItem(index).checkState(0)
            == Qt.CheckState.Checked
        ]
        write_selection.assert_called_once_with(selected_keys)
        start.assert_called_once_with(
            "ai-check", provider="codex", profile="balanced", mode="economical",
            assume_yes=True, non_interactive=True,
            technology_selection_file=Path("/private/selection.json"),
        )
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_scan_all_technologies_ignores_baseline_checkboxes(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        self.assertEqual(window.scan_selected_button.text(), "Scan selected technologies")
        self.assertEqual(window.scan_all_button.text(), "Scan all technologies")
        window.technology_scan_tree.clear()
        for key, checked in (("php-key", False), ("shell-key", True)):
            item = QTreeWidgetItem((
                "", key, "1.0", "Inventory", "Certain", "Missing", "app",
            ))
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked,
            )
            window.technology_scan_tree.addTopLevelItem(item)
        window._sync_baseline_toggle()
        self.assertEqual(
            window.baseline_select_all.checkState(), Qt.CheckState.PartiallyChecked,
        )
        window.baseline_select_all.setCheckState(Qt.CheckState.Checked)
        self.assertTrue(all(
            window.technology_scan_tree.topLevelItem(index).checkState(0)
            == Qt.CheckState.Checked
            for index in range(window.technology_scan_tree.topLevelItemCount())
        ))
        window.baseline_select_all.setCheckState(Qt.CheckState.Unchecked)
        self.assertTrue(all(
            window.technology_scan_tree.topLevelItem(index).checkState(0)
            == Qt.CheckState.Unchecked
            for index in range(window.technology_scan_tree.topLevelItemCount())
        ))
        window.technology_scan_tree.topLevelItem(1).setCheckState(
            0, Qt.CheckState.Checked,
        )
        self.assertEqual(
            window.baseline_select_all.checkState(), Qt.CheckState.PartiallyChecked,
        )
        routing = {
            "summary": "Codex: 1 project(s); Claude: 0 project(s); excluded: 0",
            "groups": {"codex": 1, "claude": 0}, "excluded": 0, "selected": 1,
            "required_providers": ["codex"],
        }
        with patch.object(services, "analysis_routing", return_value=routing), \
             patch.object(services, "ai_model", return_value="codex-model"), \
             patch.object(services, "sandbox_preflight", return_value={"ready": True}), \
             patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes), \
             patch.object(
                 services, "write_technology_selection",
                 return_value=Path("/private/all-selection.json"),
             ) as write_selection, patch.object(window, "start_action"):
            window.run_ai_analysis(scan_all=True)

        write_selection.assert_called_once_with(["php-key", "shell-key"])
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
        self.assertEqual([
            window.inventory_actions_layout.itemAt(index).widget().text()
            for index in range(3)
        ], ["Details", "Reload from paths", "Save"])
        self.assertEqual(window.global_reload_action.text(), "Reload all views")
        self.assertFalse(window.global_reload_action.icon().isNull())
        self.assertTrue(window.global_reload_action.isEnabled())
        with patch.object(window, "reload_views") as reload_views:
            window.reload_views_from_toolbar()
        reload_views.assert_called_once_with()
        self.assertIn("were not rescanned", window.statusBar().currentMessage())
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

    def test_inventory_filters_combine_selection_ai_and_technology(self) -> None:
        application = QApplication.instance() or QApplication([])
        projects = [
            {
                "id": "api", "path": "/private/api",
                "languages": [{"name": "PHP"}],
                "advisory_checks": {"enabled": True, "preferred_ai": "codex"},
            },
            {
                "id": "worker", "path": "/private/worker",
                "languages": [{"name": "Python"}],
                "advisory_checks": {"enabled": False, "preferred_ai": "claude"},
            },
            {
                "id": "web", "path": "/private/web",
                "languages": [{"name": "PHP"}],
                "advisory_checks": {"enabled": True},
            },
        ]
        with patch("desktop.main_window.services.inventory_projects", return_value=projects), patch(
            "desktop.main_window.services.inventory_age", return_value="current",
        ):
            window = MainWindow()
            window.load_inventory()

        window.inventory_selected_filter.setChecked(True)
        self.assertFalse(window.inventory_tree.topLevelItem(0).isHidden())
        self.assertTrue(window.inventory_tree.topLevelItem(1).isHidden())
        self.assertFalse(window.inventory_tree.topLevelItem(2).isHidden())
        window.inventory_ai_filter.setCurrentIndex(window.inventory_ai_filter.findData("codex"))
        self.assertFalse(window.inventory_tree.topLevelItem(0).isHidden())
        self.assertTrue(window.inventory_tree.topLevelItem(2).isHidden())
        window.inventory_technology_filter.setText("php")
        self.assertFalse(window.inventory_tree.topLevelItem(0).isHidden())
        self.assertIn("1 shown", window.inventory_count.text())
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

        self.assertEqual(
            QToolTip.palette().color(QPalette.ColorRole.ToolTipText),
            QColor("#f2f8ff"),
        )

        self.assertEqual(window.pages.count(), 10)
        self.assertEqual(
            [
                window.navigation.item(index).text()
                for index in range(window.navigation.count())
                if window.navigation.item(index).flags() & Qt.ItemFlag.ItemIsSelectable
            ],
            [
                "Dashboard", "Reports", "Run check", "AI assistant", "Logs",
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
        self.assertEqual(reports_form.actionable_threshold.value(), 80)
        self.assertEqual(reports_form.review_threshold.value(), 50)
        reports_data = reports_form.apply_to(
            services.validate_config_text(
                window.config_editors[services.LOCAL_CONFIG_DIR / "reports.yaml"].toPlainText()
            )
        )
        self.assertEqual(reports_data["reports"]["finding_presentation"], {
            "actionable_threshold": 80,
            "review_threshold": 50,
            "collapse_below_threshold": 50,
            "notify_below_threshold": False,
            "show_weak_signals": False,
        })
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
            self.assertEqual(
                [button.text() for button in open_buttons],
                ["Solved", "Ignored", "AI chat"],
            )
            self.assertIn(
                "https://www.cve.org/CVERecord?id=CVE-2026-1234",
                activity_cell.text(),
            )
            self.assertTrue(activity_cell.openExternalLinks())
            self.assertTrue(all(button.isEnabled() for button in open_buttons))
            self.assertEqual(open_buttons[0].property("variant"), "success")
            self.assertEqual(open_buttons[1].property("variant"), "warning")
            self.assertEqual(open_buttons[2].property("variant"), "ai")
            self.assertGreaterEqual(
                open_buttons[0].minimumWidth(),
                open_buttons[0].fontMetrics().horizontalAdvance("Solved") + 32,
            )
            self.assertEqual(
                window.followup_table.horizontalHeader().sectionResizeMode(0),
                QHeaderView.ResizeMode.Interactive,
            )
            self.assertGreaterEqual(window.followup_table.columnWidth(0), 320)
            self.assertGreaterEqual(window.followup_table.columnWidth(6), 275)
            self.assertEqual(
                window.followup_table.cellWidget(0, 6).layout().spacing(), 12
            )
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
            self.assertGreaterEqual(window.followup_table.rowHeight(0), 110)
            window.report_stack.setCurrentWidget(window.followup_table)
            window.report_search.setText("PHP2Shell")
            window.search_report_next()
            self.assertEqual(window.followup_table.currentRow(), 0)
            self.assertIn("Match 1 of 1", window.report_search_status.text())

            followup.write_text(
                "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
                "| A-1 | CVE-2026-1234 | api; worker; API | Patch | High | Dev | Open | 2026-11-01 | 2026-11-01 | Upgrade | — | — |\n",
                encoding="utf-8",
            )
            window.load_followup_table(followup)
            self.assertEqual(window.followup_table.rowCount(), 1)
            self.assertEqual(window.followup_table.item(0, 1).text(), "api\nworker")
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_report_search_supports_ctrl_f_navigation_and_wrapping(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        window._navigate_to_page(PAGE_REPORTS)
        window.show()
        application.processEvents()

        with TemporaryDirectory() as directory:
            report = Path(directory) / "report.md"
            report.write_text(
                "# Example\n\nFirst security needle.\n\nSecond security needle.\n",
                encoding="utf-8",
            )
            window.report_paths[0] = report
            window.show_report(0)
            window.report_search.setText("security needle")
            window.search_report_next()
            self.assertEqual(
                window.report_viewer.textCursor().selectedText().casefold(),
                "security needle",
            )
            highlights = window.report_viewer.extraSelections()
            self.assertEqual(len(highlights), 1)
            self.assertEqual(
                highlights[0].format.background().color(), QColor("#ffd166")
            )
            self.assertEqual(
                highlights[0].format.foreground().color(), QColor("#081426")
            )
            window.search_report_next()
            self.assertIn("next match", window.report_search_status.text())
            window.report_find_shortcut.activated.emit()
            self.assertTrue(window.report_search.hasFocus())
            self.assertEqual(
                window.report_find_shortcut.key().matches(
                    QKeySequence(QKeySequence.StandardKey.Find)
                ),
                QKeySequence.SequenceMatch.ExactMatch,
            )
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_followup_confidence_badge_and_filters_are_presentation_only(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        with TemporaryDirectory() as directory:
            followup = Path(directory) / "followup.md"
            followup.write_text(
                "| ID | Advisory / CVE | Project | Description | Priority | Owner | Status | Opened | Last updated | Next action | Due date | Completion evidence |\n"
                "|---|---|---|---|---|---|---|---|---|---|---|---|\n"
                "| A-1 | CVE-2026-109618 | api | Verify | Medium | Dev | Open | 2026-11-01 | 2026-11-01 | Review | — | — |\n",
                encoding="utf-8",
            )
            candidates = [{
                "advisory_id": "AL07/261021/CSIRT-ITA",
                "identifiers": ["CVE-2026-109618"],
                "match_score": 62,
                "confidence": "review",
                "score_breakdown": {"version_relation": 20},
                "project_id": "api",
            }]
            with patch(
                "desktop.main_window.services.latest_candidate_assessments",
                return_value=candidates,
            ), patch(
                "desktop.main_window.services.reports_config",
                return_value={"finding_presentation": {"collapse_below_threshold": 50}},
            ):
                window.load_followup_table(followup)
                activity = window.followup_table.cellWidget(0, 0)
                self.assertIn("Needs review · 62%", activity.text())
                self.assertEqual(activity.property("confidence"), "review")
                self.assertFalse(window.followup_table.isRowHidden(0))

                window.followup_confidence_filter.setCurrentIndex(
                    window.followup_confidence_filter.findData("confirmed")
                )
                self.assertTrue(window.followup_table.isRowHidden(0))
                window.followup_confidence_filter.setCurrentIndex(
                    window.followup_confidence_filter.findData("review")
                )
                self.assertFalse(window.followup_table.isRowHidden(0))
                self.assertIn("never removed", window.followup_confidence_filter.toolTip())
        window.close()
        window.deleteLater()
        application.processEvents()

    def test_ignore_followup_requires_reason_and_archives_the_activity(self) -> None:
        application = QApplication.instance() or QApplication([])
        window = MainWindow()
        issue = {"ID": "A-1", "Project": "api", "Status": "Open"}
        with patch(
            "desktop.main_window.services.open_followup_activities", return_value=[issue],
        ), patch(
            "desktop.main_window.QInputDialog.getMultiLineText",
            return_value=("Duplicate of the platform activity", True),
        ), patch(
            "desktop.main_window.QMessageBox.question",
            return_value=QMessageBox.StandardButton.Yes,
        ), patch(
            "desktop.main_window.services.update_followup_activity",
        ) as update, patch(
            "desktop.main_window.services.archive_closed_followups",
        ) as archive, patch.object(
            window, "refresh_all",
        ), patch("desktop.main_window.QMessageBox.information"):
            window.set_followup_ignored("A-1")

        update.assert_called_once_with("A-1", {
            "Status": "Ignored",
            "Next action": "No further action",
            "Completion evidence": "Duplicate of the platform activity",
        })
        archive.assert_called_once_with(services.ROOT)
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
