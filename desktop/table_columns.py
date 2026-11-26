# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Consistent, user-resizable columns for desktop tables and trees."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTreeWidget


def resizable_columns(
    view: QTableWidget | QTreeWidget, widths: tuple[int, ...],
) -> None:
    """Give every column a useful starting width while preserving user resizing."""
    header = view.horizontalHeader() if isinstance(view, QTableWidget) else view.header()
    if len(widths) != header.count():
        raise ValueError("A starting width is required for every table column")
    header.setStretchLastSection(False)
    header.setMinimumSectionSize(55)
    for column, width in enumerate(widths):
        header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        header.resizeSection(column, width)
    view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
    view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
    view.setTextElideMode(Qt.TextElideMode.ElideRight)
    view.setToolTip("Drag a column header border to resize it; scroll horizontally to see all columns.")
