# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared technology-centric view used by Inventory and Run check."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)


class TechnologyView(QWidget):
    """Render one aggregate row for every technology/version combination."""

    selectionChanged = Signal()

    def __init__(self, *, selectable: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.selectable = selectable
        self._updating_toggle = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        controls = QHBoxLayout()
        self.select_all = QCheckBox("Select all technologies")
        self.select_all.setTristate(True)
        self.select_all.setToolTip(
            "Select or clear the complete technology scope for this run"
        )
        self.select_all.stateChanged.connect(self.set_all_checks)
        self.select_all.setVisible(selectable)
        controls.addWidget(self.select_all)
        self.summary = QLabel()
        self.summary.setStyleSheet("color:#9fb8cc; padding:2px 8px;")
        controls.addWidget(self.summary)
        controls.addStretch()
        controls.addWidget(QLabel("Filter"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter technologies…")
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.setToolTip(
            "Filter by technology, version, context, evidence, reference date, or project. "
            "Filtering does not change the run selection."
        )
        self.filter_edit.textChanged.connect(self.apply_filter)
        controls.addWidget(self.filter_edit, 1)
        layout.addLayout(controls)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels((
            "Scan" if selectable else "", "Technology", "Version", "Context",
            "Evidence quality", "Baseline", "Reference date", "Projects",
        ))
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tree.itemChanged.connect(self._item_changed)
        for column in (0, 2, 3, 4, 5, 6):
            self.tree.header().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents,
            )
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        if not selectable:
            self.tree.setColumnHidden(0, True)
        layout.addWidget(self.tree, 1)
        self._update_summary()

    def set_rows(
        self, rows: list[dict[str, Any]], *, preserve_selection: bool = False,
    ) -> None:
        previous = set(self.selected_keys()) if preserve_selection else set()
        self.tree.blockSignals(True)
        self.tree.clear()
        quality_labels = {"green": "Certain", "orange": "Uncertain", "red": "Missing"}
        quality_colors = {
            "green": QColor("#66d38f"),
            "orange": QColor("#e5a84b"),
            "red": QColor("#df6f6f"),
        }
        for row in rows:
            deployments = row.get("production_deployments", [])
            environments = sorted({
                str(item.get("environment")) for item in deployments
                if isinstance(item, dict) and item.get("environment")
            }, key=str.casefold)
            inventory_present = bool(row.get("inventory_projects"))
            if environments and inventory_present:
                context = "Inventory + production: " + ", ".join(environments)
            elif environments:
                context = "Production: " + ", ".join(environments)
            else:
                context = "Inventory"

            projects = list(row.get("enabled_projects") or [])
            projects.extend(
                f"{project} (excluded)" for project in row.get("disabled_projects") or []
            )
            if not projects:
                projects = [str(project) for project in row.get("projects") or []]
            reference_date = str(row.get("reference_date") or "")
            reference_ready = row.get("reference_status") == "ready"
            item = QTreeWidgetItem((
                "", str(row.get("name") or "—"), str(row.get("version") or "—"),
                context,
                quality_labels.get(str(row.get("quality")), str(row.get("quality") or "—")),
                str(row.get("baseline_status") or "missing").replace("-", " ").title(),
                reference_date or "Missing", ", ".join(projects),
            ))
            key = str(row.get("key") or "")
            item.setData(0, Qt.ItemDataRole.UserRole, key)
            item.setData(0, Qt.ItemDataRole.UserRole + 1, not reference_ready)
            item.setData(
                0, Qt.ItemDataRole.UserRole + 2,
                list(row.get("enabled_projects") or row.get("projects") or []),
            )
            if self.selectable:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                checked = key in previous if preserve_selection else bool(row.get("selected"))
                item.setCheckState(
                    0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked,
                )
            color = quality_colors.get(str(row.get("quality")))
            if color:
                item.setForeground(2, color)
                item.setForeground(4, color)
            if not reference_ready:
                item.setForeground(6, QColor("#df6f6f"))
                item.setToolTip(
                    6, "The baseline version, trusted release date, or HTTPS reference "
                    "source is incomplete. Selecting this technology blocks the run before "
                    "sources or AI are started.",
                )
            else:
                source_url = str(row.get("reference_source_url") or "")
                item.setToolTip(6, source_url or "Resolved release reference date")
            item.setToolTip(
                4, "Version evidence quality only; this is not a vulnerability status."
            )
            self.tree.addTopLevelItem(item)
        self.tree.blockSignals(False)
        self.apply_filter()
        self.sync_select_all()
        self._update_summary()

    def set_error(self, message: str) -> None:
        self.tree.clear()
        item = QTreeWidgetItem((
            "", "Advisory state unavailable", "—", "—", "Missing", "Blocked", "Missing",
            message,
        ))
        item.setForeground(4, QColor("#df6f6f"))
        item.setForeground(5, QColor("#df6f6f"))
        item.setForeground(6, QColor("#df6f6f"))
        self.tree.addTopLevelItem(item)
        self.apply_filter()
        self.sync_select_all()
        self._update_summary()

    def all_keys(self) -> list[str]:
        return [
            str(item.data(0, Qt.ItemDataRole.UserRole))
            for item in self._checkable_items()
            if item.data(0, Qt.ItemDataRole.UserRole)
        ]

    def selected_keys(self) -> list[str]:
        return [
            str(item.data(0, Qt.ItemDataRole.UserRole))
            for item in self._checkable_items()
            if item.checkState(0) == Qt.CheckState.Checked
            and item.data(0, Qt.ItemDataRole.UserRole)
        ]

    def missing_reference_keys(self, *, selected_only: bool = False) -> list[str]:
        return [
            str(item.data(0, Qt.ItemDataRole.UserRole))
            for item in self._checkable_items()
            if bool(item.data(0, Qt.ItemDataRole.UserRole + 1))
            and (not selected_only or item.checkState(0) == Qt.CheckState.Checked)
        ]

    def project_ids(self, technology_keys: list[str]) -> list[str]:
        selected = set(technology_keys)
        projects: set[str] = set()
        for item in self._checkable_items():
            if str(item.data(0, Qt.ItemDataRole.UserRole)) not in selected:
                continue
            value = item.data(0, Qt.ItemDataRole.UserRole + 2)
            if isinstance(value, list):
                projects.update(str(project) for project in value)
        return sorted(projects, key=str.casefold)

    def apply_filter(self, *_args: object) -> None:
        query = self.filter_edit.text().casefold().strip()
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            searchable = " ".join(
                item.text(column) for column in range(1, self.tree.columnCount())
            ).casefold()
            item.setHidden(bool(query and query not in searchable))
        self._update_summary()

    def set_all_checks(self, state: int) -> None:
        if self._updating_toggle:
            return
        checked = state != Qt.CheckState.Unchecked.value
        self._updating_toggle = True
        try:
            for item in self._checkable_items():
                item.setCheckState(
                    0, Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked,
                )
        finally:
            self._updating_toggle = False
        self.sync_select_all()
        self.selectionChanged.emit()

    def sync_select_all(self, *_args: object) -> None:
        if not self.selectable or self._updating_toggle:
            return
        items = self._checkable_items()
        selected = sum(item.checkState(0) == Qt.CheckState.Checked for item in items)
        if not items or selected == 0:
            state = Qt.CheckState.Unchecked
        elif selected == len(items):
            state = Qt.CheckState.Checked
        else:
            state = Qt.CheckState.PartiallyChecked
        self.select_all.blockSignals(True)
        self.select_all.setEnabled(bool(items))
        self.select_all.setCheckState(state)
        self.select_all.blockSignals(False)
        self._update_summary()

    def _checkable_items(self) -> list[QTreeWidgetItem]:
        return [
            self.tree.topLevelItem(index)
            for index in range(self.tree.topLevelItemCount())
            if self.tree.topLevelItem(index).flags() & Qt.ItemFlag.ItemIsUserCheckable
        ]

    def _item_changed(self, *_args: object) -> None:
        self.sync_select_all()
        self.selectionChanged.emit()

    def _update_summary(self) -> None:
        total = self.tree.topLevelItemCount()
        shown = sum(not self.tree.topLevelItem(index).isHidden() for index in range(total))
        missing = sum(
            bool(self.tree.topLevelItem(index).data(0, Qt.ItemDataRole.UserRole + 1))
            for index in range(total)
        )
        if self.selectable:
            self.summary.setText(
                f"{len(self.selected_keys())} selected · {missing} missing references · "
                f"{shown} of {total} shown"
            )
        else:
            self.summary.setText(
                f"{total} technology versions · {missing} missing references · {shown} shown"
            )
