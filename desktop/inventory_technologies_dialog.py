# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Guided editor for per-project technologies declared by the local user."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QFormLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from scripts.inventory import MANUAL_TECH_CATEGORIES, normalize_manual_technologies


CATEGORY_LABELS = {
    "languages": "Language", "runtimes": "Runtime",
    "frameworks_and_tooling": "Framework / tooling", "databases": "Database",
    "web_servers_and_proxies": "Web server / proxy", "containers": "Container",
    "operating_systems": "Operating system", "ci_cd": "CI/CD",
    "infrastructure_as_code": "Infrastructure as Code",
    "virtualization_and_services": "Virtualization / service", "other": "Other",
}


class InventoryTechnologiesDialog(QDialog):
    """Edit only manual additions; scanner-detected technologies stay read-only."""

    def __init__(
        self, project: dict[str, Any], detected: list[str], parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit project technologies")
        self.setMinimumSize(760, 570)
        self.manual = normalize_manual_technologies(project.get("manual_technologies", []))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        project_label = QLabel(f"Project: {project.get('id', 'unnamed')}")
        project_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        layout.addWidget(project_label)
        explanation = QLabel(
            "Add technologies missed by discovery. Manual entries are user-declared "
            "context, not verified installed or production versions. They stay in "
            "local configuration after an inventory refresh."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        detected_label = QLabel("Detected by scanner: " + (", ".join(detected) or "None"))
        detected_label.setWordWrap(True)
        detected_label.setStyleSheet("color: #9fb4c8; padding: 6px 0;")
        layout.addWidget(detected_label)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(("Technology", "Category", "Version", "Context / evidence"))
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setDefaultSectionSize(42)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.itemSelectionChanged.connect(self._load_selected)
        layout.addWidget(self.table, 1)

        form = QFormLayout()
        self.name = QLineEdit()
        self.name.setMaxLength(120)
        self.name.setPlaceholderText("For example, PostgreSQL")
        form.addRow("Technology", self.name)
        self.category = QComboBox()
        for key in MANUAL_TECH_CATEGORIES:
            self.category.addItem(CATEGORY_LABELS[key], key)
        self.category.setCurrentIndex(self.category.findData("other"))
        form.addRow("Category", self.category)
        self.version = QLineEdit()
        self.version.setMaxLength(120)
        self.version.setPlaceholderText("Optional; user supplied and unverified")
        form.addRow("Version", self.version)
        self.note = QLineEdit()
        self.note.setMaxLength(500)
        self.note.setPlaceholderText("Optional context or evidence to check")
        form.addRow("Context / evidence", self.note)
        layout.addLayout(form)

        actions = QHBoxLayout()
        add = QPushButton("Add or update")
        add.setProperty("variant", "info")
        add.clicked.connect(self._add_or_update)
        actions.addWidget(add)
        remove = QPushButton("Remove selected")
        remove.setProperty("variant", "danger")
        remove.clicked.connect(self._remove_selected)
        actions.addWidget(remove)
        actions.addStretch()
        cancel = QPushButton("Cancel")
        cancel.setProperty("variant", "secondary")
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)
        save = QPushButton("Save changes")
        save.setProperty("variant", "success")
        save.clicked.connect(self._save)
        actions.addWidget(save)
        layout.addLayout(actions)
        self._render()

    def _render(self) -> None:
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.manual))
        for row, item in enumerate(self.manual):
            for column, value in enumerate((
                item["name"], CATEGORY_LABELS[item["category"]],
                item.get("version", ""), item.get("note", ""),
            )):
                cell = QTableWidgetItem(value)
                cell.setFlags(cell.flags() & ~Qt.ItemFlag.ItemIsEditable)
                cell.setToolTip(value)
                self.table.setItem(row, column, cell)
        self.table.blockSignals(False)

    def _load_selected(self) -> None:
        row = self.table.currentRow()
        if not 0 <= row < len(self.manual):
            return
        item = self.manual[row]
        self.name.setText(item["name"])
        self.category.setCurrentIndex(self.category.findData(item["category"]))
        self.version.setText(item.get("version", ""))
        self.note.setText(item.get("note", ""))

    def _add_or_update(self) -> None:
        candidate = {
            "name": self.name.text(), "category": self.category.currentData(),
            "version": self.version.text(), "note": self.note.text(),
        }
        row = self.table.currentRow()
        updated = list(self.manual)
        if 0 <= row < len(updated):
            updated[row] = candidate
        else:
            updated.append(candidate)
        try:
            self.manual = normalize_manual_technologies(updated)
        except ValueError as error:
            QMessageBox.warning(self, "Invalid technology", str(error))
            return
        self._render()
        self.table.clearSelection()
        self.table.setCurrentCell(-1, -1)
        self.name.clear()
        self.category.setCurrentIndex(self.category.findData("other"))
        self.version.clear()
        self.note.clear()

    def _remove_selected(self) -> None:
        row = self.table.currentRow()
        if not 0 <= row < len(self.manual):
            return
        self.manual.pop(row)
        self._render()
        self.name.clear()
        self.category.setCurrentIndex(self.category.findData("other"))
        self.version.clear()
        self.note.clear()

    def _save(self) -> None:
        try:
            self.manual = normalize_manual_technologies(self.manual)
        except ValueError as error:
            QMessageBox.warning(self, "Invalid technology", str(error))
            return
        self.accept()
