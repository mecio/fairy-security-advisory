# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Guided editor for per-project technologies declared by the local user."""

from __future__ import annotations

import datetime as dt
from typing import Any

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from scripts.inventory import (
    MANUAL_TECH_CATEGORIES, PRODUCTION_EVIDENCE_TYPES,
    VERSION_STATUSES, normalize_manual_technologies, normalize_production_technologies,
)
from scripts.technology_state import (
    ambiguous_manual_dependencies, project_technology_records, version_quality,
)
from desktop.table_columns import resizable_columns
from desktop import services


CATEGORY_LABELS = {
    "languages": "Language", "runtimes": "Runtime",
    "dependencies": "Dependency",
    "frameworks_and_tooling": "Framework / tooling", "databases": "Database",
    "web_servers_and_proxies": "Web server / proxy", "containers": "Container",
    "operating_systems": "Operating system", "ci_cd": "CI/CD",
    "infrastructure_as_code": "Infrastructure as Code",
    "virtualization_and_services": "Virtualization / service", "other": "Other",
}
EVIDENCE_LABELS = {
    "administrator-confirmed": "Administrator confirmed",
    "authorized-check": "Authorized check",
    "reported-unverified": "Reported / unverified",
}
VERSION_STATUS_LABELS = {
    "confirmed": "Confirmed by user",
    "unverified": "Unverified",
    "hypothetical": "Hypothetical",
}


class InventoryTechnologiesDialog(QDialog):
    """Keep inventory review separate from the add/edit form."""

    def __init__(
        self, project: dict[str, Any], detected: list[str], parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.project = project
        self.setWindowTitle("Edit project technologies")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setMinimumSize(960, 680)
        self.manual = normalize_manual_technologies(project.get("manual_technologies", []))
        self.production = normalize_production_technologies(
            project.get("production_technologies", []),
        )
        self._initial_manual = [dict(item) for item in self.manual]
        self._initial_production = [dict(item) for item in self.production]
        self.ai_version_request: dict[str, Any] | None = None
        self.reference_updated = False
        self._display_rows: list[dict[str, Any]] = []
        self._editing_record: dict[str, Any] | None = None
        self._editing_manual_index: int | None = None
        self._form_dirty = False
        self._editing_production_index: int | None = None
        self._production_form_dirty = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 20, 22, 20)
        layout.setSpacing(12)

        project_label = QLabel(f"Project: {project.get('id', 'unnamed')}")
        project_label.setStyleSheet("font-size: 17px; font-weight: 700;")
        layout.addWidget(project_label)
        explanation = QLabel(
            "Review inventory versions separately from environment-specific production evidence. "
            "Apply changes in their tabs, then save them together."
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
        self.inventory_table = QTableWidget(0, 8)
        self.inventory_table.setHorizontalHeaderLabels((
            "Technology", "Category", "Ecosystem", "Inventory version",
            "Production version", "Production evidence", "Version status", "Source",
        ))
        self.inventory_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.inventory_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        resizable_columns(
            self.inventory_table, (190, 135, 125, 155, 155, 210, 130, 185),
        )
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
        self.release_reference_button = QPushButton("Release reference…")
        self.release_reference_button.setProperty("variant", "info")
        self.release_reference_button.setToolTip(
            "Enter the official release date, baseline version, and source URL for the selected version"
        )
        self.release_reference_button.setEnabled(False)
        self.release_reference_button.clicked.connect(self._edit_release_reference)
        table_actions.addWidget(self.release_reference_button)
        self.find_version_button = QPushButton("Find inventory version with AI")
        self.find_version_button.setProperty("variant", "ai")
        self.find_version_button.setToolTip(
            "Save pending technology changes, then open the AI assistant with a "
            "guided, read-only version research prompt"
        )
        self.find_version_button.setEnabled(False)
        self.find_version_button.clicked.connect(self._find_version_with_ai)
        table_actions.addWidget(self.find_version_button)
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
            "Any saved version is used for advisory matching. Its status is an editable "
            "user-facing assessment and does not change that value. "
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
        self.version.setPlaceholderText("Optional; always used as the advisory version")
        form.addRow("Version", self.version)
        self.version_status = QComboBox()
        self.version_status.addItem("Automatic indication", "")
        for status in VERSION_STATUSES:
            self.version_status.addItem(VERSION_STATUS_LABELS[status], status)
        self.version_status.setToolTip(
            "Informational only: changing this status does not change the version used "
            "for advisory matching."
        )
        form.addRow("Version status", self.version_status)
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

        production_page = QWidget()
        production_layout = QVBoxLayout(production_page)
        production_layout.setContentsMargins(10, 12, 10, 10)
        production_layout.setSpacing(10)
        production_hint = QLabel(
            "Production versions are environment-specific evidence. They remain separate "
            "from inventory versions and survive inventory reloads from project paths. "
            "Without an explicit record, Production defaults to the scanned Inventory version."
        )
        production_hint.setWordWrap(True)
        production_layout.addWidget(production_hint)
        self.production_table = QTableWidget(0, 7)
        self.production_table.setHorizontalHeaderLabels((
            "Technology", "Category", "Ecosystem", "Environment", "Version",
            "Evidence", "Verified UTC",
        ))
        self.production_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.production_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.production_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        resizable_columns(
            self.production_table, (190, 135, 125, 150, 135, 230, 175),
        )
        self.production_table.itemSelectionChanged.connect(self._update_production_actions)
        self.production_table.itemDoubleClicked.connect(
            lambda _item: self._edit_selected_production(),
        )
        production_layout.addWidget(self.production_table, 1)
        production_actions = QHBoxLayout()
        self.add_production_button = QPushButton("Add production version")
        self.add_production_button.setProperty("variant", "info")
        self.add_production_button.clicked.connect(self._new_production)
        production_actions.addWidget(self.add_production_button)
        self.edit_production_button = QPushButton("Edit selected")
        self.edit_production_button.setEnabled(False)
        self.edit_production_button.clicked.connect(self._edit_selected_production)
        production_actions.addWidget(self.edit_production_button)
        self.remove_production_button = QPushButton("Remove selected")
        self.remove_production_button.setProperty("variant", "danger")
        self.remove_production_button.setEnabled(False)
        self.remove_production_button.clicked.connect(self._remove_selected_production)
        production_actions.addWidget(self.remove_production_button)
        production_actions.addStretch()
        production_layout.addLayout(production_actions)
        self.tabs.addTab(production_page, "Production versions")

        production_form_page = QWidget()
        production_form_layout = QVBoxLayout(production_form_page)
        production_form_layout.setContentsMargins(18, 18, 18, 18)
        production_form_layout.setSpacing(14)
        self.production_form_title = QLabel("Add production version")
        self.production_form_title.setStyleSheet(
            "font-size:18px; font-weight:700; color:#c9dded;"
        )
        production_form_layout.addWidget(self.production_form_title)
        evidence_hint = QLabel(
            "Record only administrator evidence or an explicitly authorized check. "
            "A reported, unverified value remains uncertain in advisory analysis."
        )
        evidence_hint.setWordWrap(True)
        production_form_layout.addWidget(evidence_hint)
        production_form = QFormLayout()
        self.production_technology = QComboBox()
        production_form.addRow("Technology", self.production_technology)
        self.production_environment = QLineEdit()
        self.production_environment.setMaxLength(80)
        self.production_environment.setPlaceholderText("For example, production-eu")
        production_form.addRow("Environment", self.production_environment)
        self.production_version = QLineEdit()
        self.production_version.setMaxLength(120)
        self.production_version.setPlaceholderText("Exact observed or reported version")
        production_form.addRow("Production version", self.production_version)
        self.production_evidence_type = QComboBox()
        for evidence_type in PRODUCTION_EVIDENCE_TYPES:
            self.production_evidence_type.addItem(
                EVIDENCE_LABELS[evidence_type], evidence_type,
            )
        production_form.addRow("Evidence type", self.production_evidence_type)
        self.production_verified_at = QLineEdit()
        self.production_verified_at.setMaxLength(40)
        self.production_verified_at.setPlaceholderText("YYYY-MM-DDTHH:MM:SSZ")
        production_form.addRow("Verified at (UTC)", self.production_verified_at)
        self.production_evidence = QLineEdit()
        self.production_evidence.setMaxLength(500)
        self.production_evidence.setPlaceholderText(
            "Evidence reference; do not include credentials or secrets"
        )
        production_form.addRow("Evidence", self.production_evidence)
        production_form_layout.addLayout(production_form)
        production_form_actions = QHBoxLayout()
        apply_production = QPushButton("Apply production version")
        apply_production.setProperty("variant", "info")
        apply_production.clicked.connect(self._add_or_update_production)
        production_form_actions.addWidget(apply_production)
        back_production = QPushButton("Back to production versions")
        back_production.setProperty("variant", "secondary")
        back_production.clicked.connect(lambda: self.tabs.setCurrentIndex(2))
        production_form_actions.addWidget(back_production)
        production_form_actions.addStretch()
        production_form_layout.addLayout(production_form_actions)
        production_form_layout.addStretch()
        self.tabs.addTab(production_form_page, "Add / edit production")

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
        self._render_production()
        self._connect_form_changes()
        self._connect_production_form_changes()

    def _manual_index_for(self, record: dict[str, str]) -> int | None:
        if record["source"] != "manual":
            return None
        return next((index for index, item in enumerate(self.manual)
            if not item.get("exclude") and item["category"] == record["category"]
            and item["name"].casefold() == record["name"].casefold()
            and item.get("version", "") == record["version"]
            and (not item.get("ecosystem") or item["ecosystem"] == record.get("ecosystem", ""))), None)

    @staticmethod
    def _technology_identity(record: dict[str, Any]) -> tuple[str, str, str]:
        return (
            str(record.get("category") or "other"),
            str(record.get("name") or "").casefold(),
            str(record.get("ecosystem") or "").casefold(),
        )

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
        known_identities = {
            self._technology_identity(entry["record"]) for entry in self._display_rows
        }
        for production in self.production:
            identity = self._technology_identity(production)
            if identity in known_identities:
                continue
            self._display_rows.append({
                "record": {
                    "name": production["name"], "category": production["category"],
                    "ecosystem": production.get("ecosystem", ""), "version": "",
                    "quality": "red", "source": "production-only",
                },
                "manual_index": None,
            })
            known_identities.add(identity)
        production_by_identity: dict[tuple[str, str, str], list[dict[str, str]]] = {}
        for production in self.production:
            production_by_identity.setdefault(
                self._technology_identity(production), [],
            ).append(production)
        self.inventory_table.blockSignals(True)
        self.inventory_table.setRowCount(len(self._display_rows))
        colors = {"green": QColor("#66d38f"), "orange": QColor("#e5a84b"), "red": QColor("#df6f6f")}
        labels = {"green": "Certain", "orange": "Uncertain", "red": "Missing"}
        for row, entry in enumerate(self._display_rows):
            record = entry["record"]
            excluded = record["source"] == "excluded"
            deployments = production_by_identity.get(self._technology_identity(record), [])
            inventory_version = record.get("version") or ""
            if deployments:
                production_versions = "\n".join(
                    f"{item['environment']}: {item['version']}" for item in deployments
                )
                production_evidence = "\n".join(
                    f"{item['environment']}: {EVIDENCE_LABELS[item['evidence_type']]} "
                    f"({item['verified_at']})"
                    for item in deployments
                )
            elif inventory_version and not excluded:
                production_versions = f"Default: {inventory_version}"
                production_evidence = "Inventory default · not production verified"
            else:
                production_versions = "—"
                production_evidence = "—"
            status = record.get("version_status", "")
            values = (
                record["name"], CATEGORY_LABELS.get(record["category"], record["category"]),
                record.get("ecosystem") or "—", record.get("version") or "—",
                production_versions, production_evidence,
                "—" if excluded else VERSION_STATUS_LABELS.get(
                    status, labels[record["quality"]],
                ),
                "Excluded by user" if excluded else record["source"].title(),
            )
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setFlags(cell.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if column in {4, 5} and deployments:
                    deployment_qualities = {
                        version_quality(
                            item["version"], f"production-{item['evidence_type']}",
                        )
                        for item in deployments
                    }
                    production_quality = (
                        "red" if "red" in deployment_qualities
                        else "orange" if "orange" in deployment_qualities else "green"
                    )
                    cell.setForeground(colors[production_quality])
                    cell.setToolTip("\n\n".join(
                        f"{item['environment']} — {item['evidence']}"
                        for item in deployments
                    ))
                elif column in {4, 5} and inventory_version and not excluded:
                    cell.setForeground(colors["orange"])
                    cell.setToolTip(
                        "Defaults to the inventory version. This is not verified "
                        "production evidence; add an environment-specific record to override it."
                    )
                else:
                    cell.setForeground(
                        QColor("#aab6c2") if excluded else colors[record["quality"]]
                    )
                    cell.setToolTip(
                        "Excluded from local inventory scope by a manual decision."
                        if excluded else
                        "Inventory version evidence quality only; this is not a vulnerability assessment."
                    )
                self.inventory_table.setItem(row, column, cell)
        self.inventory_table.blockSignals(False)
        self.inventory_table.verticalScrollBar().setValue(scroll)
        self._populate_production_technology_combo()
        self._update_table_actions()

    def _populate_production_technology_combo(self) -> None:
        current = self.production_technology.currentData(Qt.ItemDataRole.UserRole)
        current_identity = (
            self._technology_identity(current) if isinstance(current, dict) else None
        )
        self.production_technology.blockSignals(True)
        self.production_technology.clear()
        seen: set[tuple[str, str, str]] = set()
        production_identities = {
            self._technology_identity(item) for item in self.production
        }
        restored_current = False
        for entry in self._display_rows:
            record = entry["record"]
            identity = self._technology_identity(record)
            if record.get("source") == "excluded" and identity not in production_identities:
                continue
            if identity in seen:
                continue
            seen.add(identity)
            label = record["name"]
            if record.get("ecosystem"):
                label += f" ({record['ecosystem']})"
            self.production_technology.addItem(label, dict(record))
            if identity == current_identity:
                self.production_technology.setCurrentIndex(
                    self.production_technology.count() - 1,
                )
                restored_current = True
        if current_identity is not None and not restored_current:
            # Never let rebuilding the inventory silently retarget a pending
            # production record to the first technology in the combo box.
            self.production_technology.setCurrentIndex(-1)
        self.production_technology.blockSignals(False)
        self.add_production_button.setEnabled(self.production_technology.count() > 0)

    def _update_table_actions(self) -> None:
        row = self.inventory_table.currentRow()
        selected = 0 <= row < len(self._display_rows) and bool(self.inventory_table.selectedItems())
        self.edit_button.setEnabled(selected)
        self.release_reference_button.setEnabled(
            selected and bool(self._display_rows[row]["record"].get("version"))
            and self._display_rows[row]["record"].get("source") != "excluded"
        )
        self.remove_button.setEnabled(selected and self._display_rows[row]["manual_index"] is not None)
        missing_version = (
            selected
            and self._display_rows[row]["record"].get("source") != "excluded"
            and not self._display_rows[row]["record"].get("version")
        )
        self.find_version_button.setEnabled(missing_version)

    def _find_version_with_ai(self) -> None:
        row = self.inventory_table.currentRow()
        if not 0 <= row < len(self._display_rows):
            return
        record = self._display_rows[row]["record"]
        if record.get("source") == "excluded" or record.get("version"):
            return
        identity = self._technology_identity(record)
        changed = (
            self._form_dirty or self._production_form_dirty
            or self.manual != self._initial_manual
            or self.production != self._initial_production
        )
        if changed and QMessageBox.question(
            self,
            "Save technology changes?",
            "You changed Inventory or Production data. Save those changes before "
            "opening AI version research?\n\nChoosing No keeps this dialog open "
            "without discarding your changes.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._save()
        if self.result() != QDialog.DialogCode.Accepted:
            return
        updated = next((
            entry["record"] for entry in self._display_rows
            if self._technology_identity(entry["record"]) == identity
        ), None)
        if updated is not None and not updated.get("version"):
            self.ai_version_request = dict(updated)

    def _connect_form_changes(self) -> None:
        for field in (self.name, self.version, self.note):
            field.textChanged.connect(self._mark_form_dirty)
        self.category.currentIndexChanged.connect(self._mark_form_dirty)
        self.ecosystem.currentTextChanged.connect(self._mark_form_dirty)
        self.version_status.currentIndexChanged.connect(self._mark_form_dirty)
        self.exclude.toggled.connect(self._mark_form_dirty)

    def _render_production(self) -> None:
        self.production_table.blockSignals(True)
        self.production_table.setRowCount(len(self.production))
        for row, item in enumerate(self.production):
            values = (
                item["name"], CATEGORY_LABELS.get(item["category"], item["category"]),
                item.get("ecosystem") or "—", item["environment"], item["version"],
                EVIDENCE_LABELS[item["evidence_type"]], item["verified_at"],
            )
            quality = version_quality(
                item["version"], f"production-{item['evidence_type']}",
            )
            color = {
                "green": QColor("#66d38f"), "orange": QColor("#e5a84b"),
                "red": QColor("#df6f6f"),
            }[quality]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setFlags(cell.flags() & ~Qt.ItemFlag.ItemIsEditable)
                cell.setForeground(color)
                cell.setToolTip(item["evidence"])
                self.production_table.setItem(row, column, cell)
        self.production_table.blockSignals(False)
        self._update_production_actions()

    def _update_production_actions(self) -> None:
        selected = (
            0 <= self.production_table.currentRow() < len(self.production)
            and bool(self.production_table.selectedItems())
        )
        self.edit_production_button.setEnabled(selected)
        self.remove_production_button.setEnabled(selected)

    def _connect_production_form_changes(self) -> None:
        for field in (
            self.production_environment, self.production_version,
            self.production_verified_at, self.production_evidence,
        ):
            field.textChanged.connect(self._mark_production_form_dirty)
        self.production_technology.currentIndexChanged.connect(
            self._mark_production_form_dirty,
        )
        self.production_evidence_type.currentIndexChanged.connect(
            self._mark_production_form_dirty,
        )

    def _mark_production_form_dirty(self, *_args: object) -> None:
        self._production_form_dirty = True

    def _new_production(self) -> None:
        if self.production_technology.count() == 0:
            QMessageBox.information(
                self, "No technology", "Add an inventory technology first.",
            )
            return
        self._editing_production_index = None
        self.production_form_title.setText("Add production version")
        inventory_row = self.inventory_table.currentRow()
        if 0 <= inventory_row < len(self._display_rows):
            identity = self._technology_identity(
                self._display_rows[inventory_row]["record"],
            )
            for index in range(self.production_technology.count()):
                record = self.production_technology.itemData(
                    index, Qt.ItemDataRole.UserRole,
                )
                if isinstance(record, dict) and self._technology_identity(record) == identity:
                    self.production_technology.setCurrentIndex(index)
                    break
        self.production_environment.setText("production")
        technology = self.production_technology.currentData(Qt.ItemDataRole.UserRole)
        self.production_version.setText(
            str(technology.get("version") or "") if isinstance(technology, dict) else ""
        )
        self.production_evidence_type.setCurrentIndex(
            self.production_evidence_type.findData("reported-unverified"),
        )
        self.production_verified_at.setText(
            dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace(
                "+00:00", "Z",
            )
        )
        self.production_evidence.clear()
        self._production_form_dirty = False
        self.tabs.setCurrentIndex(3)
        self.production_environment.setFocus()
        self.production_environment.selectAll()

    def _edit_selected_production(self) -> None:
        row = self.production_table.currentRow()
        if not 0 <= row < len(self.production):
            return
        item = self.production[row]
        self._editing_production_index = row
        self.production_form_title.setText(
            f"Edit production version: {item['name']} / {item['environment']}",
        )
        identity = self._technology_identity(item)
        for index in range(self.production_technology.count()):
            record = self.production_technology.itemData(index, Qt.ItemDataRole.UserRole)
            if isinstance(record, dict) and self._technology_identity(record) == identity:
                self.production_technology.setCurrentIndex(index)
                break
        self.production_environment.setText(item["environment"])
        self.production_version.setText(item["version"])
        self.production_evidence_type.setCurrentIndex(
            self.production_evidence_type.findData(item["evidence_type"]),
        )
        self.production_verified_at.setText(item["verified_at"])
        self.production_evidence.setText(item["evidence"])
        self._production_form_dirty = False
        self.tabs.setCurrentIndex(3)
        self.production_version.setFocus()
        self.production_version.selectAll()

    def _add_or_update_production(self) -> None:
        technology = self.production_technology.currentData(Qt.ItemDataRole.UserRole)
        if not isinstance(technology, dict):
            QMessageBox.warning(self, "Invalid production version", "Select a technology.")
            return
        candidate = {
            "name": technology.get("name", ""),
            "category": technology.get("category", "other"),
            "ecosystem": technology.get("ecosystem", ""),
            "environment": self.production_environment.text(),
            "version": self.production_version.text(),
            "evidence_type": self.production_evidence_type.currentData(),
            "verified_at": self.production_verified_at.text(),
            "evidence": self.production_evidence.text(),
        }
        updated = list(self.production)
        if self._editing_production_index is None:
            updated.append(candidate)
        else:
            updated[self._editing_production_index] = candidate
        try:
            self.production = normalize_production_technologies(updated)
        except ValueError as error:
            QMessageBox.warning(self, "Invalid production version", str(error))
            return
        self._production_form_dirty = False
        self._editing_production_index = None
        self._render_effective()
        self._render_production()
        self.tabs.setCurrentIndex(2)

    def _remove_selected_production(self) -> None:
        row = self.production_table.currentRow()
        if not 0 <= row < len(self.production):
            return
        self.production.pop(row)
        self._render_effective()
        self._render_production()

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
        self.version_status.setCurrentIndex(0)
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
        self.version_status.setCurrentIndex(
            max(0, self.version_status.findData(item.get("version_status", ""))),
        )
        self.exclude.setChecked(item.get("exclude") is True)
        self.note.setText(item.get("note", ""))
        self._form_dirty = False
        self.tabs.setCurrentIndex(1)
        self.version.setFocus()
        self.version.selectAll()

    def _edit_release_reference(self) -> None:
        row = self.inventory_table.currentRow()
        if not 0 <= row < len(self._display_rows):
            return
        record = self._display_rows[row]["record"]
        persisted = project_technology_records(self.project)
        if not any(
            item["category"] == record["category"]
            and item["name"].casefold() == record["name"].casefold()
            and item.get("ecosystem", "") == record.get("ecosystem", "")
            and item.get("version", "") == record.get("version", "")
            for item in persisted
        ):
            QMessageBox.warning(
                self, "Save technology first",
                "Save the inventory version, then reopen Details to add its release reference.",
            )
            return
        try:
            existing = services.release_reference(record)
        except (OSError, ValueError) as error:
            QMessageBox.critical(self, "Release reference unavailable", str(error))
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Release reference: {record['name']} {record['version']}")
        dialog.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        dialog.setMinimumWidth(620)
        form = QFormLayout(dialog)
        hint = QLabel(
            "Use an official release page. The reference date is the start of the "
            "historical advisory search for this version or release line."
        )
        hint.setWordWrap(True)
        form.addRow(hint)
        declared = str(record["version"])
        default_baseline = declared if declared[:1].isdigit() else ""
        baseline = QLineEdit(str(existing.get("baseline_version") or default_baseline))
        baseline.setPlaceholderText("Exact release line, for example 7.2.0")
        form.addRow("Baseline version", baseline)
        date = QLineEdit(str(existing.get("release_date") or ""))
        date.setPlaceholderText("YYYY-MM-DD")
        form.addRow("Reference date", date)
        source = QLineEdit(str(existing.get("source_url") or ""))
        source.setPlaceholderText("https://official-project.example/release-notes")
        form.addRow("Official source URL", source)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        form.addRow(buttons)
        while dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                services.save_release_reference(
                    record, baseline.text(), date.text(), source.text(),
                )
            except (OSError, ValueError) as error:
                QMessageBox.warning(dialog, "Invalid release reference", str(error))
                continue
            self.reference_updated = True
            break

    def _add_or_update(self) -> None:
        candidate = {
            "name": self.name.text(), "category": self.category.currentData(),
            "ecosystem": self.ecosystem.currentText().replace("—", "").strip(),
            "version": "" if self.exclude.isChecked() else self.version.text(),
            "version_status": "" if self.exclude.isChecked()
            else self.version_status.currentData(),
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
        if self._production_form_dirty:
            self._add_or_update_production()
            if self._production_form_dirty:
                return
        try:
            self.manual = normalize_manual_technologies(self.manual)
            self.production = normalize_production_technologies(self.production)
            ambiguous = ambiguous_manual_dependencies(self.project, self.manual)
            if ambiguous:
                raise ValueError("Select an ecosystem for: " + ", ".join(ambiguous))
            ambiguous_production = ambiguous_manual_dependencies(
                self.project, self.production,
            )
            if ambiguous_production:
                raise ValueError(
                    "Select an ecosystem for production dependencies: "
                    + ", ".join(ambiguous_production)
                )
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
        self.version_status.setEnabled(not excluded)
        if excluded:
            self.version.clear()
            self.version_status.setCurrentIndex(0)
