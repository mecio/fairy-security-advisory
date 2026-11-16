# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""PySide6 application entry point."""

from __future__ import annotations

import sys

from PySide6.QtCore import QCoreApplication
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from desktop.eula_dialog import EulaDialog
from desktop.main_window import MainWindow, STYLE
from desktop import services


def run() -> int:
    QCoreApplication.setApplicationName("fAIry Security Advisory")
    QCoreApplication.setOrganizationName("fAIry Security Advisory")
    application = QApplication.instance() or QApplication(sys.argv)
    application.setDesktopFileName("fairy-security-advisory")
    application.setStyle("Fusion")
    application.setStyleSheet(STYLE)
    icon = services.ROOT / "desktop/assets/fairy-security-advisory-icon.png"
    if icon.is_file():
        application.setWindowIcon(QIcon(str(icon)))
    try:
        accepted = services.eula_accepted()
        if not accepted:
            dialog = EulaDialog(services.eula_text(), services.required_eula_version())
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return 0
            services.accept_eula()
    except (OSError, ValueError, services.ConfigurationError) as error:
        QMessageBox.critical(
            None, "Unable to record EULA acceptance",
            f"The application cannot start until acceptance can be stored locally.\n\n{error}",
        )
        return 1
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(run())
