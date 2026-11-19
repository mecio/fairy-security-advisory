# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Structured configuration forms used by the desktop interface."""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


def _readonly_item(text: str) -> QTableWidgetItem:
    item = QTableWidgetItem(text)
    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
    return item


class ProjectsConfigForm(QWidget):
    """Friendly editor for project roots and inventory scan limits."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Choose the directories to scan. Double-click Exclusions to edit ignored paths. "
            "Detected inventory data is preserved when these settings are saved."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #9fb4c8; padding: 2px 4px 8px 4px;")
        layout.addWidget(intro)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels((
            "Label", "Directory", "Enabled", "Exclusions", "Browse", "Remove",
        ))
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(44)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(4, 108)
        self.table.setColumnWidth(5, 98)
        self.table.cellDoubleClicked.connect(self._cell_double_clicked)
        layout.addWidget(self.table, 1)

        actions = QHBoxLayout()
        add = QPushButton("Add directory…")
        add.clicked.connect(self.add_directory)
        actions.addWidget(add)
        actions.addStretch()
        actions.addWidget(QLabel("Refresh inventory after (hours)"))
        self.refresh_hours = QSpinBox()
        self.refresh_hours.setRange(1, 8760)
        self.refresh_hours.setValue(168)
        actions.addWidget(self.refresh_hours)
        actions.addWidget(QLabel("Maximum files per project"))
        self.max_files = QSpinBox()
        self.max_files.setRange(100, 10_000_000)
        self.max_files.setSingleStep(1000)
        self.max_files.setValue(20_000)
        actions.addWidget(self.max_files)
        layout.addLayout(actions)

    def load_data(self, data: dict[str, Any]) -> None:
        self.table.setRowCount(0)
        for root in data.get("project_roots", []) or []:
            if isinstance(root, dict):
                self._append_root(root)
        inventory = data.get("inventory", {}) or {}
        self.refresh_hours.setValue(int(inventory.get("refresh_after_hours", 168)))
        self.max_files.setValue(int(inventory.get("max_files_per_project", 20_000)))

    def _append_root(self, root: dict[str, Any]) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        label = QTableWidgetItem(str(root.get("label", "workspace")))
        label.setData(Qt.ItemDataRole.UserRole, copy.deepcopy(root))
        self.table.setItem(row, 0, label)
        self.table.setItem(row, 1, QTableWidgetItem(str(root.get("path", ""))))
        enabled = _readonly_item("")
        enabled.setFlags(enabled.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        enabled.setCheckState(
            Qt.CheckState.Checked if root.get("enabled", True) else Qt.CheckState.Unchecked
        )
        self.table.setItem(row, 2, enabled)
        exclusions = [str(value) for value in root.get("exclude", []) or []]
        exclusion_item = _readonly_item(self._exclusion_summary(exclusions))
        exclusion_item.setData(Qt.ItemDataRole.UserRole, exclusions)
        exclusion_item.setToolTip("\n".join(exclusions) or "No exclusions")
        self.table.setItem(row, 3, exclusion_item)
        self._set_row_actions(row)

    @staticmethod
    def _exclusion_summary(exclusions: list[str]) -> str:
        if not exclusions:
            return "None"
        return f"{len(exclusions)} rules · " + ", ".join(exclusions[:2])

    def _set_row_actions(self, row: int) -> None:
        browse = QPushButton("Browse")
        browse.setMinimumWidth(100)
        browse.setToolTip("Choose a different project directory")
        browse.setAccessibleName("Browse project directory")
        browse.setProperty("table_row", row)
        browse.clicked.connect(
            lambda _checked=False, button=browse: self.browse_row(int(button.property("table_row")))
        )
        self.table.setCellWidget(row, 4, browse)
        remove = QPushButton("Remove")
        remove.setMinimumWidth(90)
        remove.setToolTip("Remove this directory from the scan configuration")
        remove.setAccessibleName("Remove project directory")
        remove.setProperty("variant", "danger")
        remove.setProperty("table_row", row)
        remove.clicked.connect(
            lambda _checked=False, button=remove: self.remove_row(int(button.property("table_row")))
        )
        self.table.setCellWidget(row, 5, remove)

    def _update_action_rows(self) -> None:
        for row in range(self.table.rowCount()):
            for column in (4, 5):
                button = self.table.cellWidget(row, column)
                if button is not None:
                    button.setProperty("table_row", row)

    def _cell_double_clicked(self, row: int, column: int) -> None:
        if column == 3:
            self.edit_exclusions(row)

    def add_directory(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Add project directory")
        if not directory:
            return
        path = Path(directory)
        self._append_root({
            "path": str(path), "enabled": True, "label": path.name or "workspace", "exclude": [],
        })

    def browse_row(self, row: int) -> None:
        if row < 0 or row >= self.table.rowCount():
            return
        current = self.table.item(row, 1).text()
        directory = QFileDialog.getExistingDirectory(self, "Select project directory", current)
        if directory:
            self.table.item(row, 1).setText(directory)

    def remove_row(self, row: int) -> None:
        if row < 0 or row >= self.table.rowCount():
            return
        label = self.table.item(row, 0).text()
        if QMessageBox.question(
            self, "Remove project root", f"Remove {label!r} from the scan configuration?",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.table.removeRow(row)
        self._update_action_rows()

    def edit_exclusions(self, row: int) -> None:
        item = self.table.item(row, 3)
        exclusions = item.data(Qt.ItemDataRole.UserRole) or []
        text, accepted = QInputDialog.getMultiLineText(
            self, "Exclusion rules", "One glob pattern per line:", "\n".join(exclusions),
        )
        if not accepted:
            return
        updated = [line.strip() for line in text.splitlines() if line.strip()]
        item.setData(Qt.ItemDataRole.UserRole, updated)
        item.setText(self._exclusion_summary(updated))
        item.setToolTip("\n".join(updated) or "No exclusions")

    def apply_to(self, original: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(original)
        roots: list[dict[str, Any]] = []
        for row in range(self.table.rowCount()):
            label_item = self.table.item(row, 0)
            path = self.table.item(row, 1).text().strip()
            if not path:
                raise ValueError(f"Project root row {row + 1} requires a directory.")
            root = copy.deepcopy(label_item.data(Qt.ItemDataRole.UserRole) or {})
            root.update({
                "path": path,
                "enabled": self.table.item(row, 2).checkState() == Qt.CheckState.Checked,
                "label": label_item.text().strip() or Path(path).name or "workspace",
                "exclude": list(self.table.item(row, 3).data(Qt.ItemDataRole.UserRole) or []),
            })
            roots.append(root)
        data["project_roots"] = roots
        inventory = copy.deepcopy(data.get("inventory", {}) or {})
        inventory["refresh_after_hours"] = self.refresh_hours.value()
        inventory["max_files_per_project"] = self.max_files.value()
        inventory.setdefault("projects", [])
        data["inventory"] = inventory
        return data


class AdvisorySourcesConfigForm(QWidget):
    """Guided editor for public advisory sources."""

    TYPES = ("html", "rss", "atom", "json", "api", "repository")
    PRIORITIES = ("critical", "high", "normal", "low")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Manage public advisory sources without editing YAML. Open checks the configured "
            "address in your browser; no source is changed remotely."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #9fb4c8; padding: 2px 4px 8px 4px;")
        layout.addWidget(intro)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels((
            "Name", "URL", "Type", "Priority", "Active", "Technologies", "Actions",
        ))
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setDefaultSectionSize(48)
        for column in (0, 1, 5):
            self.table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        for column in (2, 3, 4):
            self.table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(6, 232)
        layout.addWidget(self.table, 1)
        actions = QHBoxLayout()
        add = QPushButton("Add advisory source…")
        add.clicked.connect(self.add_source)
        actions.addWidget(add)
        actions.addStretch()
        layout.addLayout(actions)

    def load_data(self, data: dict[str, Any]) -> None:
        self.table.setRowCount(0)
        for source in data.get("advisory_sources", []) or []:
            if isinstance(source, dict):
                self._append_source(source)

    def _append_source(self, source: dict[str, Any]) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        name = _readonly_item(str(source.get("name", "Unnamed source")))
        name.setData(Qt.ItemDataRole.UserRole, copy.deepcopy(source))
        self.table.setItem(row, 0, name)
        self.table.setItem(row, 1, _readonly_item(str(source.get("url", ""))))
        self.table.setItem(row, 2, _readonly_item(str(source.get("type", "html"))))
        self.table.setItem(row, 3, _readonly_item(str(source.get("priority", "normal"))))
        active = _readonly_item("Yes" if source.get("active", True) else "No")
        active.setForeground(Qt.GlobalColor.green if source.get("active", True) else Qt.GlobalColor.gray)
        self.table.setItem(row, 4, active)
        self.table.setItem(row, 5, _readonly_item(", ".join(map(str, source.get("technologies", []) or []))))
        self._set_row_actions(row)

    def _set_row_actions(self, row: int) -> None:
        cell = QWidget()
        row_layout = QHBoxLayout(cell)
        row_layout.setContentsMargins(3, 3, 3, 3)
        row_layout.setSpacing(5)
        for label, variant, handler in (
            ("Edit", "", self.edit_source),
            ("Open", "secondary", self.open_source),
            ("Remove", "danger", self.remove_source),
        ):
            button = QPushButton(label)
            button.setMinimumWidth({"Edit": 58, "Open": 62, "Remove": 78}[label])
            button.setToolTip({
                "Edit": "Edit this advisory source",
                "Open": "Open this advisory source in the system browser",
                "Remove": "Remove this advisory source from the configuration",
            }[label])
            button.setAccessibleName(f"{label} advisory source")
            button.setProperty("table_row", row)
            if variant:
                button.setProperty("variant", variant)
            button.clicked.connect(
                lambda _checked=False, control=button, callback=handler:
                callback(int(control.property("table_row")))
            )
            row_layout.addWidget(button)
        self.table.setCellWidget(row, 6, cell)

    def _update_action_rows(self) -> None:
        for row in range(self.table.rowCount()):
            cell = self.table.cellWidget(row, 6)
            if cell is not None:
                for button in cell.findChildren(QPushButton):
                    button.setProperty("table_row", row)

    @staticmethod
    def _slug(value: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-") or "advisory-source"

    def _edit_dialog(self, source: dict[str, Any]) -> dict[str, Any] | None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Advisory source")
        dialog.setMinimumWidth(620)
        form = QFormLayout(dialog)
        name = QLineEdit(str(source.get("name", "")))
        identifier = QLineEdit(str(source.get("id", "")))
        url = QLineEdit(str(source.get("url", "")))
        source_type = QComboBox()
        source_type.addItems(self.TYPES)
        source_type.setCurrentText(str(source.get("type", "html")))
        category = QLineEdit(str(source.get("category_or_filter", "")))
        technologies = QLineEdit(", ".join(map(str, source.get("technologies", []) or [])))
        priority = QComboBox()
        priority.addItems(self.PRIORITIES)
        priority.setCurrentText(str(source.get("priority", "normal")))
        active = QCheckBox("Enabled for advisory checks")
        active.setChecked(bool(source.get("active", True)))
        form.addRow("Name", name)
        form.addRow("Stable ID", identifier)
        form.addRow("URL", url)
        form.addRow("Type", source_type)
        form.addRow("Category or filter", category)
        form.addRow("Technologies (comma separated)", technologies)
        form.addRow("Priority", priority)
        form.addRow("Status", active)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        while True:
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return None
            if not name.text().strip() or not url.text().strip():
                QMessageBox.warning(dialog, "Incomplete source", "Name and URL are required.")
                continue
            if not re.match(r"^https?://", url.text().strip(), flags=re.IGNORECASE):
                QMessageBox.warning(
                    dialog, "Invalid URL", "The source URL must start with http:// or https://.",
                )
                continue
            break
        updated = copy.deepcopy(source)
        updated.update({
            "id": identifier.text().strip() or self._slug(name.text()),
            "name": name.text().strip(),
            "url": url.text().strip(),
            "type": source_type.currentText(),
            "category_or_filter": category.text().strip(),
            "technologies": [value.strip() for value in technologies.text().split(",") if value.strip()],
            "priority": priority.currentText(),
            "active": active.isChecked(),
        })
        return updated

    def add_source(self) -> None:
        source = self._edit_dialog({"active": True, "type": "html", "priority": "normal"})
        if source is not None:
            self._append_source(source)

    def edit_source(self, row: int) -> None:
        if row < 0 or row >= self.table.rowCount():
            return
        source = self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) or {}
        updated = self._edit_dialog(source)
        if updated is None:
            return
        self.table.removeRow(row)
        self._insert_source(row, updated)
        self._update_action_rows()

    def _insert_source(self, row: int, source: dict[str, Any]) -> None:
        self.table.insertRow(row)
        name = _readonly_item(str(source.get("name", "Unnamed source")))
        name.setData(Qt.ItemDataRole.UserRole, copy.deepcopy(source))
        self.table.setItem(row, 0, name)
        self.table.setItem(row, 1, _readonly_item(str(source.get("url", ""))))
        self.table.setItem(row, 2, _readonly_item(str(source.get("type", "html"))))
        self.table.setItem(row, 3, _readonly_item(str(source.get("priority", "normal"))))
        self.table.setItem(row, 4, _readonly_item("Yes" if source.get("active", True) else "No"))
        self.table.setItem(row, 5, _readonly_item(", ".join(map(str, source.get("technologies", []) or []))))
        self._set_row_actions(row)

    def open_source(self, row: int) -> None:
        QDesktopServices.openUrl(QUrl(self.table.item(row, 1).text()))

    def remove_source(self, row: int) -> None:
        if row < 0 or row >= self.table.rowCount():
            return
        name = self.table.item(row, 0).text()
        if QMessageBox.question(
            self, "Remove advisory source", f"Remove {name!r} from the configuration?",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.table.removeRow(row)
        self._update_action_rows()

    def apply_to(self, original: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(original)
        sources = []
        identifiers: set[str] = set()
        for row in range(self.table.rowCount()):
            source = copy.deepcopy(self.table.item(row, 0).data(Qt.ItemDataRole.UserRole) or {})
            identifier = str(source.get("id", "")).strip()
            if not identifier or identifier in identifiers:
                raise ValueError(f"Advisory source row {row + 1} has a missing or duplicate stable ID.")
            identifiers.add(identifier)
            sources.append(source)
        data["advisory_sources"] = sources
        return data


class ReportsConfigForm(QWidget):
    """Guided editor for report locations, behavior, and classifications."""

    RISK_LEVELS = ("critical", "high", "medium", "low", "informational")
    CLASSIFICATIONS = ("immediate-action", "follow-up", "monitor", "not-applicable")

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Choose where local reports are written and which information each check retains. "
            "All output paths should remain below the Git-ignored output directory."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #9fb4c8; padding: 2px 4px 8px 4px;")
        layout.addWidget(intro)

        groups = QGridLayout()
        locations = QGroupBox("Report locations")
        location_form = QFormLayout(locations)
        self.daily_directory = QLineEdit()
        self.daily_filename = QLineEdit()
        self.summary_file = QLineEdit()
        self.followup_file = QLineEdit()
        self.archive_directory = QLineEdit()
        for label, field, tip in (
            ("Daily reports folder", self.daily_directory, "Directory containing one report per day"),
            ("Daily filename", self.daily_filename, "strftime pattern, for example %Y-%m-%d.md"),
            ("Current summary file", self.summary_file, "Short current status and history"),
            ("Active follow-up file", self.followup_file, "Register of open activities"),
            ("Closed-issue archive", self.archive_directory, "Year/month archive for completed work"),
        ):
            field.setToolTip(tip)
            location_form.addRow(label, field)
        groups.addWidget(locations, 0, 0)

        behavior = QGroupBox("Report behavior")
        behavior_form = QFormLayout(behavior)
        self.timezone = QLineEdit("UTC")
        self.timezone.setReadOnly(True)
        self.timezone.setToolTip("Reports always use UTC for reproducible daily checks.")
        self.language = QComboBox()
        self.language.setEditable(True)
        self.language.addItems(("en", "it"))
        self.include_open = QCheckBox("Repeat unfinished activities in later daily reports")
        self.preserve_evidence = QCheckBox("Keep existing evidence when updating a report")
        self.incremental_overlap = QSpinBox()
        self.incremental_overlap.setRange(1, 90)
        self.incremental_overlap.setSuffix(" days")
        self.incremental_overlap.setToolTip(
            "Recheck this many days before each source's last successful checkpoint."
        )
        self.actionable_threshold = QSpinBox()
        self.actionable_threshold.setRange(0, 100)
        self.actionable_threshold.setSuffix("%")
        self.review_threshold = QSpinBox()
        self.review_threshold.setRange(0, 100)
        self.review_threshold.setSuffix("%")
        self.collapse_threshold = QSpinBox()
        self.collapse_threshold.setRange(0, 100)
        self.collapse_threshold.setSuffix("%")
        self.notify_below_threshold = QCheckBox("Allow notifications below review threshold")
        self.show_weak_signals = QCheckBox("Show weak signals in the configured view")
        behavior_form.addRow("Timezone", self.timezone)
        behavior_form.addRow("Report language", self.language)
        behavior_form.addRow(self.include_open)
        behavior_form.addRow(self.preserve_evidence)
        behavior_form.addRow("Incremental overlap", self.incremental_overlap)
        behavior_form.addRow("Confirmed finding from", self.actionable_threshold)
        behavior_form.addRow("Needs review from", self.review_threshold)
        behavior_form.addRow("Collapse below", self.collapse_threshold)
        behavior_form.addRow(self.notify_below_threshold)
        behavior_form.addRow(self.show_weak_signals)
        groups.addWidget(behavior, 0, 1)

        risk_group = QGroupBox("Risk levels")
        risk_layout = QVBoxLayout(risk_group)
        self.risk_checks: dict[str, QCheckBox] = {}
        for value in self.RISK_LEVELS:
            checkbox = QCheckBox(value.replace("-", " ").title())
            self.risk_checks[value] = checkbox
            risk_layout.addWidget(checkbox)
        risk_layout.addStretch()
        groups.addWidget(risk_group, 1, 0)

        classification_group = QGroupBox("Applicability decisions")
        classification_layout = QVBoxLayout(classification_group)
        self.classification_checks: dict[str, QCheckBox] = {}
        for value in self.CLASSIFICATIONS:
            checkbox = QCheckBox(value.replace("-", " ").title())
            self.classification_checks[value] = checkbox
            classification_layout.addWidget(checkbox)
        classification_layout.addStretch()
        groups.addWidget(classification_group, 1, 1)
        groups.setColumnStretch(0, 1)
        groups.setColumnStretch(1, 1)
        layout.addLayout(groups, 1)
        self._extra_risks: list[str] = []
        self._extra_classifications: list[str] = []

    def load_data(self, data: dict[str, Any]) -> None:
        reports = data.get("reports", {}) or {}
        self.daily_directory.setText(str(reports.get("daily_directory", "output/daily-advisory-check")))
        self.daily_filename.setText(str(reports.get("daily_filename", "%Y-%m-%d.md")))
        self.summary_file.setText(str(reports.get("summary_file", "output/check-summary.md")))
        self.followup_file.setText(str(reports.get("followup_file", "output/followup.md")))
        self.archive_directory.setText(str(reports.get("followup_archive_directory", "output/followup-archive")))
        self.timezone.setText("UTC")
        self.language.setCurrentText(str(reports.get("language", "en")))
        self.include_open.setChecked(bool(reports.get("include_open_followups", True)))
        self.preserve_evidence.setChecked(bool(reports.get("preserve_existing_evidence", True)))
        self.incremental_overlap.setValue(int(reports.get("incremental_overlap_days", 10)))
        presentation = reports.get("finding_presentation", {}) or {}
        self.actionable_threshold.setValue(int(presentation.get("actionable_threshold", 80)))
        self.review_threshold.setValue(int(presentation.get("review_threshold", 50)))
        self.collapse_threshold.setValue(int(presentation.get("collapse_below_threshold", 50)))
        self.notify_below_threshold.setChecked(bool(
            presentation.get("notify_below_threshold", False)
        ))
        self.show_weak_signals.setChecked(bool(
            presentation.get("show_weak_signals", False)
        ))
        risks = [str(value) for value in reports.get("risk_levels", self.RISK_LEVELS) or []]
        classifications = [
            str(value) for value in reports.get("classifications", self.CLASSIFICATIONS) or []
        ]
        for value, checkbox in self.risk_checks.items():
            checkbox.setChecked(value in risks)
        for value, checkbox in self.classification_checks.items():
            checkbox.setChecked(value in classifications)
        self._extra_risks = [value for value in risks if value not in self.risk_checks]
        self._extra_classifications = [
            value for value in classifications if value not in self.classification_checks
        ]

    def apply_to(self, original: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(original)
        reports = copy.deepcopy(data.get("reports", {}) or {})
        locations = {
            "daily_directory": self.daily_directory.text().strip(),
            "daily_filename": self.daily_filename.text().strip(),
            "summary_file": self.summary_file.text().strip(),
            "followup_file": self.followup_file.text().strip(),
            "followup_archive_directory": self.archive_directory.text().strip(),
        }
        missing = [name for name, value in locations.items() if not value]
        if missing:
            raise ValueError(f"Report settings require: {', '.join(missing)}.")
        reports.update(locations)
        reports.update({
            "timezone": "UTC",
            "language": self.language.currentText().strip() or "en",
            "include_open_followups": self.include_open.isChecked(),
            "preserve_existing_evidence": self.preserve_evidence.isChecked(),
            "incremental_overlap_days": self.incremental_overlap.value(),
            "finding_presentation": {
                "actionable_threshold": self.actionable_threshold.value(),
                "review_threshold": self.review_threshold.value(),
                "collapse_below_threshold": self.collapse_threshold.value(),
                "notify_below_threshold": self.notify_below_threshold.isChecked(),
                "show_weak_signals": self.show_weak_signals.isChecked(),
            },
            "risk_levels": [
                value for value, checkbox in self.risk_checks.items() if checkbox.isChecked()
            ] + self._extra_risks,
            "classifications": [
                value for value, checkbox in self.classification_checks.items() if checkbox.isChecked()
            ] + self._extra_classifications,
        })
        if not reports["risk_levels"] or not reports["classifications"]:
            raise ValueError("Select at least one risk level and one applicability decision.")
        if self.review_threshold.value() > self.actionable_threshold.value():
            raise ValueError("Needs review threshold cannot exceed confirmed finding threshold.")
        data["reports"] = reports
        return data


class AIAgentsConfigForm(QWidget):
    """Structured editor for model profiles and execution modes."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Choose the default cost profile and speed mode. Model names remain editable so "
            "administrators can follow the aliases supported by their installed agents."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #9fb4c8; padding: 2px 4px 8px 4px;")
        layout.addWidget(intro)
        defaults = QHBoxLayout()
        defaults.addWidget(QLabel("Default model profile"))
        self.default_profile = QComboBox()
        defaults.addWidget(self.default_profile)
        defaults.addSpacing(24)
        defaults.addWidget(QLabel("Default speed / consumption mode"))
        self.default_mode = QComboBox()
        defaults.addWidget(self.default_mode)
        defaults.addStretch()
        layout.addLayout(defaults)

        self.profile_table = QTableWidget(0, 4)
        self.profile_table.setHorizontalHeaderLabels((
            "Profile", "Description", "Codex model", "Claude model",
        ))
        self.profile_table.verticalHeader().setDefaultSectionSize(38)
        self.profile_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.profile_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.profile_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.profile_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        profile_group = QGroupBox("AI model profiles")
        profile_layout = QVBoxLayout(profile_group)
        profile_layout.addWidget(self.profile_table)
        layout.addWidget(profile_group, 1)

        self.mode_table = QTableWidget(0, 5)
        self.mode_table.setHorizontalHeaderLabels((
            "Mode", "Description", "Parallel sources", "Use sub-agents", "Max sub-agents",
        ))
        self.mode_table.verticalHeader().setDefaultSectionSize(38)
        self.mode_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.mode_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column in (2, 3, 4):
            self.mode_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        mode_group = QGroupBox("Speed and consumption modes")
        mode_layout = QVBoxLayout(mode_group)
        mode_layout.addWidget(self.mode_table)
        layout.addWidget(mode_group, 1)

    def load_data(self, data: dict[str, Any]) -> None:
        profiles = data.get("profiles", {}) or {}
        modes = data.get("execution_modes", {}) or {}
        self.default_profile.clear()
        self.default_profile.addItems(map(str, profiles))
        self.default_profile.setCurrentText(str(data.get("default_profile", "economical")))
        self.default_mode.clear()
        self.default_mode.addItems(map(str, modes))
        self.default_mode.setCurrentText(str(data.get("default_execution_mode", "economical")))
        self.profile_table.setRowCount(0)
        for name, profile in profiles.items():
            row = self.profile_table.rowCount()
            self.profile_table.insertRow(row)
            name_item = _readonly_item(str(name))
            name_item.setData(Qt.ItemDataRole.UserRole, copy.deepcopy(profile))
            self.profile_table.setItem(row, 0, name_item)
            description = QTableWidgetItem(str(profile.get("description", "")))
            description.setToolTip(description.text())
            self.profile_table.setItem(row, 1, description)
            agents = profile.get("agents", {}) or {}
            for column, agent in ((2, "codex"), (3, "claude")):
                model = QTableWidgetItem(str((agents.get(agent, {}) or {}).get("model", "")))
                model.setToolTip(model.text())
                self.profile_table.setItem(row, column, model)
        self.mode_table.setRowCount(0)
        for name, mode in modes.items():
            row = self.mode_table.rowCount()
            self.mode_table.insertRow(row)
            name_item = _readonly_item(str(name))
            name_item.setData(Qt.ItemDataRole.UserRole, copy.deepcopy(mode))
            self.mode_table.setItem(row, 0, name_item)
            description = QTableWidgetItem(str(mode.get("description", "")))
            description.setToolTip(description.text())
            self.mode_table.setItem(row, 1, description)
            self.mode_table.setItem(row, 2, QTableWidgetItem(str(mode.get("max_parallel_sources", 1))))
            use_subagents = _readonly_item("")
            use_subagents.setFlags(use_subagents.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            use_subagents.setCheckState(
                Qt.CheckState.Checked if mode.get("use_subagents", False) else Qt.CheckState.Unchecked
            )
            self.mode_table.setItem(row, 3, use_subagents)
            self.mode_table.setItem(row, 4, QTableWidgetItem(str(mode.get("max_subagents", 0))))

    def apply_to(self, original: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(original)
        profiles: dict[str, Any] = {}
        for row in range(self.profile_table.rowCount()):
            name_item = self.profile_table.item(row, 0)
            name = name_item.text()
            profile = copy.deepcopy(name_item.data(Qt.ItemDataRole.UserRole) or {})
            profile["description"] = self.profile_table.item(row, 1).text().strip()
            agents = copy.deepcopy(profile.get("agents", {}) or {})
            for column, agent in ((2, "codex"), (3, "claude")):
                agent_config = copy.deepcopy(agents.get(agent, {}) or {})
                model = self.profile_table.item(row, column).text().strip()
                if not model:
                    raise ValueError(f"Profile {name!r} requires a model for {agent}.")
                agent_config["model"] = model
                agents[agent] = agent_config
            profile["agents"] = agents
            profiles[name] = profile
        modes: dict[str, Any] = {}
        for row in range(self.mode_table.rowCount()):
            name_item = self.mode_table.item(row, 0)
            name = name_item.text()
            mode = copy.deepcopy(name_item.data(Qt.ItemDataRole.UserRole) or {})
            try:
                parallel = int(self.mode_table.item(row, 2).text())
                maximum = int(self.mode_table.item(row, 4).text())
            except ValueError as error:
                raise ValueError(f"Execution mode {name!r} requires numeric limits.") from error
            if parallel < 1 or maximum < 0:
                raise ValueError(f"Execution mode {name!r} has invalid limits.")
            mode.update({
                "description": self.mode_table.item(row, 1).text().strip(),
                "max_parallel_sources": parallel,
                "use_subagents": self.mode_table.item(row, 3).checkState() == Qt.CheckState.Checked,
                "max_subagents": maximum,
            })
            modes[name] = mode
        if self.default_profile.currentText() not in profiles:
            raise ValueError("The default model profile does not exist.")
        if self.default_mode.currentText() not in modes:
            raise ValueError("The default execution mode does not exist.")
        data.update({
            "default_profile": self.default_profile.currentText(),
            "default_execution_mode": self.default_mode.currentText(),
            "profiles": profiles,
            "execution_modes": modes,
        })
        return data


class BackupsConfigForm(QWidget):
    """Friendly editor for private configuration-backup settings."""

    KNOWN_FILES = (
        "projects.yaml", "advisory-sources.yaml", "reports.yaml", "ai-agents.yaml",
        "backups.yaml",
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 8, 0, 0)
        intro = QLabel(
            "Backups remain local and unencrypted under the ignored output directory. "
            "An import is verified and creates a safety backup before replacing files."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #9fb4c8; padding: 2px 4px 8px 4px;")
        layout.addWidget(intro)
        settings = QGroupBox("Backup archive")
        settings_form = QFormLayout(settings)
        self.directory = QLineEdit()
        self.archive_prefix = QLineEdit()
        self.checksum = QComboBox()
        self.checksum.addItems(("sha256",))
        settings_form.addRow("Local destination", self.directory)
        settings_form.addRow("Archive filename prefix", self.archive_prefix)
        settings_form.addRow("Integrity checksum", self.checksum)
        layout.addWidget(settings)
        included = QGroupBox("Configuration files included")
        included_layout = QVBoxLayout(included)
        self.files = QListWidget()
        included_layout.addWidget(self.files)
        layout.addWidget(included, 1)

    def load_data(self, data: dict[str, Any]) -> None:
        backups = data.get("backups", {}) or {}
        self.directory.setText(str(backups.get("directory", "output/config-backups")))
        self.archive_prefix.setText(str(backups.get("archive_prefix", "fairy-config")))
        self.checksum.setCurrentText(str(backups.get("checksum", "sha256")))
        configured = [str(value) for value in backups.get("include", self.KNOWN_FILES) or []]
        names = list(dict.fromkeys((*self.KNOWN_FILES, *configured)))
        self.files.clear()
        for name in names:
            item = QListWidgetItem(name)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if name in configured else Qt.CheckState.Unchecked)
            self.files.addItem(item)

    def apply_to(self, original: dict[str, Any]) -> dict[str, Any]:
        data = copy.deepcopy(original)
        backups = copy.deepcopy(data.get("backups", {}) or {})
        directory = self.directory.text().strip()
        prefix = self.archive_prefix.text().strip()
        if not directory or not prefix:
            raise ValueError("Backup destination and archive prefix are required.")
        selected = [
            self.files.item(row).text()
            for row in range(self.files.count())
            if self.files.item(row).checkState() == Qt.CheckState.Checked
        ]
        if not selected:
            raise ValueError("Select at least one configuration file to back up.")
        backups.update({
            "directory": directory,
            "include": selected,
            "archive_prefix": prefix,
            "checksum": self.checksum.currentText(),
        })
        data["backups"] = backups
        return data
