# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""PySide6 application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from desktop.main_window import MainWindow
from desktop.services import ROOT


def run() -> int:
    QCoreApplication.setApplicationName("fAIry Security Advisory")
    QCoreApplication.setOrganizationName("fAIry Security Advisory")
    application = QApplication.instance() or QApplication(sys.argv)
    application.setDesktopFileName("fairy-security-advisory")
    application.setStyle("Fusion")
    icon = ROOT / "desktop/assets/fairy-security-advisory-icon.png"
    if icon.is_file():
        application.setWindowIcon(QIcon(str(icon)))
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(run())
