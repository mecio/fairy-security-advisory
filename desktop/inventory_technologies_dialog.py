# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Guided editor for per-project technologies declared by the local user."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QFormLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from scripts.inventory import MANUAL_TECH_CATEGORIES, normalize_manual_technologies
from scripts.technology_state import ambiguous_manual_dependencies, project_technology_records


CATEGORY_LABELS = {
    "languages": "Language", "runtimes": "Runtime",
    "dependencies": "Dependency",
    "frameworks_and_tooling": "Framework / tooling", "databases": "Database",
    "web_servers_and_proxies": "Web server / proxy", "containers": "Container",
    "operating_systems": "Operating system", "ci_cd": "CI/CD",
    "infrastructure_as_code": "Infrastructure as Code",
    "virtualization_and_services": "Virtualization / service", "other": "Other",
}


class InventoryTechnologiesDialog(QDialog):
    """Keep inventory review separate from the add/edit form."""

    def __init__(
        self, project: dict[str, Any], detected: list[str], parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.project = project
        self.setWindowTitle("Edit project technologies")
        self.setMinimumSize(960, 680)
        self.manual = normalize_manual_technologies(project.get("manual_technologies", []))
        self._display_rows: list[dict[str, Any]] = []
        self._editing_record: dict[str, Any] | None = None
        self._editing_manual_index: int | None = None
        self._form_dirty = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        project_label = QLabel(f"Project: {project.get('id', 'unnamed')}")
        project_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        layout.addWidget(project_label)
        explanation = QLabel(
            "Select a technology and choose Edit selected, or add a new one. "
            "Review changes in the inventory tab, then save them."
        )
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        table_page = QWidget()
        table_layout = QVBoxLayout(table_page)
        table_layout.setContentsMargins(10, 12, 10, 10)
        table_layout.setSpacing(10)
        inventory_label = QLabel("Effective technology inventory and manual decisions")
        inventory_label.setStyleSheet("font-weight:700; color:#c9dded;")
        table_layout.addWidget(inventory_label)
        self.inventory_table = QTableWidget(0, 6)
        self.inventory_table.setHorizontalHeaderLabels((
            "Technology", "Category", "Ecosystem", "Version", "Quality", "Source",
        ))
        self.inventory_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.inventory_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.inventory_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.inventory_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.inventory_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.inventory_table.itemSelectionChanged.connect(self._update_table_actions)
        self.inventory_table.itemDoubleClicked.connect(lambda _item: self._edit_selected())
        table_layout.addWidget(self.inventory_table, 1)
        table_actions = QHBoxLayout()
        self.add_button = QPushButton("Add technology")
        self.add_button.setProperty("variant", "info")
        self.add_button.clicked.connect(self._new_technology)
        table_actions.addWidget(self.add_button)
        self.edit_button = QPushButton("Edit selected")
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self._edit_selected)
        table_actions.addWidget(self.edit_button)
        self.remove_button = QPushButton("Remove manual decision")
        self.remove_button.setProperty("variant", "danger")
        self.remove_button.setEnabled(False)
        self.remove_button.clicked.connect(self._remove_selected)
        table_actions.addWidget(self.remove_button)
        table_actions.addStretch()
        table_layout.addLayout(table_actions)
        self.tabs.addTab(table_page, "Inventory technologies")

        form_page = QWidget()
        form_layout = QVBoxLayout(form_page)
        form_layout.setContentsMargins(18, 18, 18, 18)
        form_layout.setSpacing(14)
        self.form_title = QLabel("Add technology")
        self.form_title.setStyleSheet("font-size:18px; font-weight:700; color:#c9dded;")
        form_layout.addWidget(self.form_title)
        form_hint = QLabel(
            "A manual version is unverified until checked against the environment. "
            "Exclude a detected dependency only after confirming it is not used."
        )
        form_hint.setWordWrap(True)
        form_layout.addWidget(form_hint)

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
        self.ecosystem = QComboBox()
        self.ecosystem.setEditable(True)
        self.ecosystem.addItem("—", "")
        detected_ecosystems = {
            str(item.get("ecosystem", "")).strip().casefold()
            for item in project.get("technology_inventory", [])
            if isinstance(item, dict) and item.get("ecosystem")
        }
        for name in sorted(detected_ecosystems | {"npm", "pypi", "composer", "cargo", "rubygems", "go"}):
            self.ecosystem.addItem(name, name)
        self.ecosystem.setCurrentIndex(0)
        form.addRow("Dependency ecosystem", self.ecosystem)
        self.category.currentIndexChanged.connect(self._update_ecosystem_enabled)
        self.version = QLineEdit()
        self.version.setMaxLength(120)
        self.version.setPlaceholderText("Optional; user supplied and unverified")
        form.addRow("Version", self.version)
        self.exclude = QCheckBox("Exclude matching detected dependency from advisory scope")
        self.exclude.toggled.connect(self._update_exclusion)
        form.addRow("Human decision", self.exclude)
        self._update_ecosystem_enabled()
        self.note = QLineEdit()
        self.note.setMaxLength(500)
        self.note.setPlaceholderText("Optional context or evidence to check")
        form.addRow("Context / evidence", self.note)
        form_layout.addLayout(form)

        form_actions = QHBoxLayout()
        apply = QPushButton("Apply change")
        apply.setProperty("variant", "info")
        apply.clicked.connect(self._add_or_update)
        form_actions.addWidget(apply)
        back = QPushButton("Back to inventory")
        back.setProperty("variant", "secondary")
        back.clicked.connect(lambda: self.tabs.setCurrentIndex(0))
        form_actions.addWidget(back)
        form_actions.addStretch()
        form_layout.addLayout(form_actions)
        form_layout.addStretch()
        self.tabs.addTab(form_page, "Add / edit technology")

        actions = QHBoxLayout()
        cancel = QPushButton("Cancel")
        cancel.setProperty("variant", "secondary")
        cancel.clicked.connect(self.reject)
        actions.addWidget(cancel)
        save = QPushButton("Save changes")
        save.setProperty("variant", "success")
        save.clicked.connect(self._save)
        actions.addWidget(save)
        layout.addLayout(actions)
        self._render_effective()
        self._connect_form_changes()

    def _manual_index_for(self, record: dict[str, str]) -> int | None:
        if record["source"] != "manual":
            return None
        return next((index for index, item in enumerate(self.manual)
            if not item.get("exclude") and item["category"] == record["category"]
            and item["name"].casefold() == record["name"].casefold()
            and item.get("version", "") == record["version"]
            and (not item.get("ecosystem") or item["ecosystem"] == record.get("ecosystem", ""))), None)

    def _render_effective(self) -> None:
        scroll = self.inventory_table.verticalScrollBar().value()
        records = project_technology_records({**self.project, "manual_technologies": self.manual})
        self._display_rows = [
            {"record": record, "manual_index": self._manual_index_for(record)}
            for record in records
        ]
        self._display_rows.extend({
            "record": {"name": item["name"], "category": item["category"],
                       "ecosystem": item.get("ecosystem", ""), "version": "",
                       "quality": "red", "source": "excluded"},
            "manual_index": index,
        } for index, item in enumerate(self.manual) if item.get("exclude"))
        self.inventory_table.blockSignals(True)
        self.inventory_table.setRowCount(len(self._display_rows))
        colors = {"green": QColor("#66d38f"), "orange": QColor("#e5a84b"), "red": QColor("#df6f6f")}
        labels = {"green": "Certain", "orange": "Uncertain", "red": "Missing"}
        for row, entry in enumerate(self._display_rows):
            record = entry["record"]
            excluded = record["source"] == "excluded"
            values = (
                record["name"], CATEGORY_LABELS.get(record["category"], record["category"]),
                record.get("ecosystem") or "—", record.get("version") or "—",
                "—" if excluded else labels[record["quality"]],
                "Excluded by user" if excluded else record["source"].title(),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setFlags(cell.flags() & ~Qt.ItemFlag.ItemIsEditable)
                cell.setForeground(QColor("#aab6c2") if excluded else colors[record["quality"]])
                cell.setToolTip(
                    "Excluded from advisory scope by a manual decision." if excluded else
                    "Version evidence quality only; this color is not a vulnerability assessment."
                )
                self.inventory_table.setItem(row, column, cell)
        self.inventory_table.blockSignals(False)
        self.inventory_table.verticalScrollBar().setValue(scroll)
        self._update_table_actions()

    def _update_table_actions(self) -> None:
        row = self.inventory_table.currentRow()
        selected = 0 <= row < len(self._display_rows) and bool(self.inventory_table.selectedItems())
        self.edit_button.setEnabled(selected)
        self.remove_button.setEnabled(selected and self._display_rows[row]["manual_index"] is not None)

    def _connect_form_changes(self) -> None:
        for field in (self.name, self.version, self.note):
            field.textChanged.connect(self._mark_form_dirty)
        self.category.currentIndexChanged.connect(self._mark_form_dirty)
        self.ecosystem.currentTextChanged.connect(self._mark_form_dirty)
        self.exclude.toggled.connect(self._mark_form_dirty)

    def _mark_form_dirty(self, *_args: object) -> None:
        self._form_dirty = True

    def _new_technology(self) -> None:
        self._editing_record = None
        self._editing_manual_index = None
        self.form_title.setText("Add technology")
        self.name.clear()
        self.category.setCurrentIndex(self.category.findData("other"))
        self.ecosystem.setCurrentIndex(0)
        self.version.clear()
        self.exclude.setChecked(False)
        self.note.clear()
        self._form_dirty = False
        self.tabs.setCurrentIndex(1)
        self.name.setFocus()

    def _edit_selected(self) -> None:
        row = self.inventory_table.currentRow()
        if not 0 <= row < len(self._display_rows):
            return
        entry = self._display_rows[row]
        record = entry["record"]
        index = entry["manual_index"]
        item = self.manual[index] if index is not None else record
        self._editing_record = record
        self._editing_manual_index = index
        self.form_title.setText(f"Edit technology: {record['name']}")
        self.name.setText(item["name"])
        self.category.setCurrentIndex(self.category.findData(item["category"]))
        self.ecosystem.setCurrentText(item.get("ecosystem", ""))
        self.version.setText(item.get("version", ""))
        self.exclude.setChecked(item.get("exclude") is True)
        self.note.setText(item.get("note", ""))
        self._form_dirty = False
        self.tabs.setCurrentIndex(1)
        self.version.setFocus()
        self.version.selectAll()

    def _add_or_update(self) -> None:
        candidate = {
            "name": self.name.text(), "category": self.category.currentData(),
            "ecosystem": self.ecosystem.currentText().replace("—", "").strip(),
            "version": "" if self.exclude.isChecked() else self.version.text(),
            "exclude": self.exclude.isChecked(), "note": self.note.text(),
        }
        updated = list(self.manual)
        if self._editing_manual_index is not None:
            previous = updated[self._editing_manual_index]
            if ("replaces_version" in previous
                and previous["category"] == candidate["category"]
                and previous["name"].casefold() == candidate["name"].strip().casefold()
                and previous.get("ecosystem", "") == candidate["ecosystem"].casefold()):
                candidate["replaces_version"] = previous["replaces_version"]
            updated[self._editing_manual_index] = candidate
        else:
            record = self._editing_record
            if (record is not None and not candidate["exclude"]
                and record["category"] == candidate["category"]
                and record["name"].casefold() == candidate["name"].strip().casefold()
                and record.get("ecosystem", "").casefold() == candidate["ecosystem"].casefold()):
                candidate["replaces_version"] = record["version"]
            updated.append(candidate)
        try:
            self.manual = normalize_manual_technologies(updated)
        except ValueError as error:
            QMessageBox.warning(self, "Invalid technology", str(error))
            return
        self._render_effective()
        self._form_dirty = False
        self.tabs.setCurrentIndex(0)

    def _remove_selected(self) -> None:
        row = self.inventory_table.currentRow()
        if not 0 <= row < len(self._display_rows):
            return
        index = self._display_rows[row]["manual_index"]
        if index is None:
            return
        self.manual.pop(index)
        self._render_effective()
        self._new_technology()
        self.tabs.setCurrentIndex(0)

    def _save(self) -> None:
        if self._form_dirty:
            self._add_or_update()
            if self._form_dirty:
                return
        try:
            self.manual = normalize_manual_technologies(self.manual)
            ambiguous = ambiguous_manual_dependencies(self.project, self.manual)
            if ambiguous:
                raise ValueError("Select an ecosystem for: " + ", ".join(ambiguous))
        except ValueError as error:
            QMessageBox.warning(self, "Invalid technology", str(error))
            return
        self.accept()

    def _update_ecosystem_enabled(self) -> None:
        enabled = self.category.currentData() == "dependencies"
        self.ecosystem.setEnabled(enabled)
        self.exclude.setEnabled(enabled)
        if not enabled:
            self.ecosystem.setCurrentIndex(0)
            self.exclude.setChecked(False)

    def _update_exclusion(self, excluded: bool) -> None:
        self.version.setEnabled(not excluded)
        if excluded:
            self.version.clear()
