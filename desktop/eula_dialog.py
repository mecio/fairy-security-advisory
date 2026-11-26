# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""First-run end-user notice for the desktop application."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QTextBrowser, QVBoxLayout,
)


class EulaDialog(QDialog):
    """Require an explicit acknowledgement before the main window is created."""

    def __init__(self, notice: str, version: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("fAIry Security Advisory — first-run notice")
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        self.setModal(True)
        self.resize(780, 680)
        self.setMinimumSize(680, 560)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 22)
        layout.setSpacing(14)

        title = QLabel("End-user license notice")
        title.setFont(QFont("Sans Serif", 20, QFont.Weight.Bold))
        layout.addWidget(title)

        introduction = QLabel(
            "Please read this notice before using the application. It explains the "
            "as-is warranty disclaimer, limitation of liability, and AI data processing."
        )
        introduction.setWordWrap(True)
        introduction.setStyleSheet("color:#c9dded; padding-bottom:4px;")
        layout.addWidget(introduction)

        self.notice = QTextBrowser()
        self.notice.setMarkdown(notice)
        self.notice.setOpenExternalLinks(False)
        self.notice.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction
            | Qt.TextInteractionFlag.TextSelectableByKeyboard
        )
        layout.addWidget(self.notice, 1)

        self.acceptance = QCheckBox(
            f"I have read and accept EULA version {version}, including the as-is "
            "disclaimer and limitation of liability."
        )
        self.acceptance.setMinimumHeight(42)
        layout.addWidget(self.acceptance)

        actions = QHBoxLayout()
        actions.addStretch()
        decline = QPushButton("Exit")
        decline.setProperty("variant", "secondary")
        decline.clicked.connect(self.reject)
        actions.addWidget(decline)
        self.accept_button = QPushButton("Accept and continue")
        self.accept_button.setProperty("variant", "success")
        self.accept_button.setEnabled(False)
        self.accept_button.clicked.connect(self.accept)
        actions.addWidget(self.accept_button)
        layout.addLayout(actions)

        self.acceptance.toggled.connect(self.accept_button.setEnabled)
