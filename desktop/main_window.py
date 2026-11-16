# SPDX-FileCopyrightText: 2026 fAIry Security Advisory contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Main Qt Widgets window for the local desktop application."""

from __future__ import annotations

import html
import json
import shlex
import shutil
import time
from pathlib import Path

from PySide6.QtCore import QProcess, QProcessEnvironment, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import (
    QCloseEvent, QColor, QDesktopServices, QFont, QPixmap, QTextCursor, QTextDocument,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from desktop import services
from scripts.ai_usage import TRANSIENT_CODEX_ENV_VARS
from desktop.config_forms import (
    AIAgentsConfigForm, AdvisorySourcesConfigForm, BackupsConfigForm,
    ProjectsConfigForm, ReportsConfigForm,
)


STYLE = """
QMainWindow, QWidget { background: #081426; color: #e8f2ff; }
QWidget#sidebar { background: #0d1e35; }
QWidget#actionCell { background: transparent; }
QLabel#sidebarLogo { background: #0d1e35; border: 0; margin: 0; padding: 0; }
QListWidget#navigation { background: #0d1e35; border: 0; padding: 10px; }
QListWidget#navigation::item { padding: 12px 14px; border-radius: 7px; margin: 2px; }
QListWidget#navigation::item:selected { background: #123e5a; color: #63e7ff; }
QFrame#card { background: #10243d; border: 1px solid #1b3c58; border-radius: 10px; }
QLabel#metricValue { color: #63e7ff; font-size: 28px; font-weight: 700; }
QLabel#chartLabel { color: #c9dded; }
QProgressBar { background: #07101e; border: 1px solid #24415b; border-radius: 5px; height: 14px; text-align: center; }
QProgressBar::chunk { background: #1680a3; border-radius: 4px; }
QPushButton { background: #126582; border: 0; border-radius: 6px; padding: 8px 14px; }
QPushButton:hover { background: #1680a3; }
QPushButton:disabled { background: #334155; color: #94a3b8; }
QPushButton[variant="success"] { background: #4f9d69; color: #ffffff; }
QPushButton[variant="success"]:hover { background: #63b37b; }
QPushButton[variant="danger"] { background: #c96b6b; color: #ffffff; }
QPushButton[variant="danger"]:hover { background: #df7f7f; }
QPushButton[variant="warning"] { background: #d6a84b; color: #172033; }
QPushButton[variant="warning"]:hover { background: #e5bb62; }
QPushButton[variant="ai"] { background: #8b72c7; color: #ffffff; }
QPushButton[variant="ai"]:hover { background: #a087dc; }
QPushButton[variant="secondary"] { background: #4f6475; color: #ffffff; }
QPushButton[variant="secondary"]:hover { background: #647b8e; }
QPushButton:disabled { background: #334155; color: #94a3b8; }
QLineEdit, QPlainTextEdit, QTextBrowser, QTreeWidget, QTableWidget, QListWidget {
  background: #07101e; color: #e8f2ff; border: 1px solid #24415b; border-radius: 6px;
  selection-background-color: #126582; selection-color: #ffffff;
}
QTreeWidget, QTableWidget { alternate-background-color: #0d1e35; }
QTreeWidget::item, QTableWidget::item { color: #e8f2ff; padding: 5px 6px; }
QTreeWidget::item:selected, QTableWidget::item:selected { background: #126582; color: #ffffff; }
QTabWidget::pane { border: 1px solid #24415b; }
QTabBar::tab { background: #10243d; padding: 8px 14px; }
QTabBar::tab:selected { background: #126582; }
QComboBox { background: #10243d; border: 1px solid #24415b; border-radius: 5px; padding: 6px; }
QSpinBox { background: #10243d; border: 1px solid #24415b; border-radius: 5px; padding: 5px; }
QCheckBox { spacing: 8px; padding: 4px 2px; }
QCheckBox::indicator, QTableWidget::indicator, QListWidget::indicator, QTreeWidget::indicator {
  width: 18px; height: 18px;
}
QCheckBox::indicator:unchecked, QTableWidget::indicator:unchecked,
QListWidget::indicator:unchecked, QTreeWidget::indicator:unchecked {
  image: url(desktop/assets/checkbox-unchecked.svg);
}
QCheckBox::indicator:checked, QTableWidget::indicator:checked,
QListWidget::indicator:checked, QTreeWidget::indicator:checked {
  image: url(desktop/assets/checkbox-checked.svg);
}
QCheckBox::indicator:disabled, QTableWidget::indicator:disabled,
QListWidget::indicator:disabled, QTreeWidget::indicator:disabled {
  image: url(desktop/assets/checkbox-disabled.svg);
}
QGroupBox { border: 1px solid #24415b; border-radius: 7px; margin-top: 10px; padding: 10px 8px 8px 8px; }
QGroupBox::title { color: #d8efff; subcontrol-origin: margin; left: 10px; padding: 0 5px; }
QHeaderView::section { background: #10243d; color: #d8efff; padding: 7px; border: 0; }
QStatusBar { background: #0d1e35; color: #e8f2ff; border: 0; min-height: 30px; padding: 4px 10px; }
QStatusBar QLabel { background: #0d1e35; color: #c9dded; border: 0; padding: 2px 8px; }
QLabel#footerIdentity { color: #9fb4c8; }
QStatusBar::item { border: 0; }
"""

PAGE_DASHBOARD = 0
PAGE_CONFIGURATION = 1
PAGE_INVENTORY = 2
PAGE_REPORTS = 3
PAGE_LOGS = 4
PAGE_ASSISTANT = 5
PAGE_RUN = 6
PAGE_STATUS = 7
PAGE_GUIDE = 8
PAGE_ABOUT = 9


class BarChartCard(QFrame):
    """Small dependency-free horizontal bar chart for local report metrics."""

    PALETTE = ("#22b8cf", "#8b5cf6", "#f59e0b", "#22c55e", "#ec4899", "#3b82f6")

    def __init__(self, title: str, colors: dict[str, str] | None = None) -> None:
        super().__init__()
        self.colors = {label.casefold(): color for label, color in (colors or {}).items()}
        self.bars: list[QProgressBar] = []
        self.setObjectName("card")
        self.setMinimumHeight(185)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(12, 10, 12, 12)
        heading = QLabel(title)
        heading.setFont(QFont("Sans Serif", 11, QFont.Weight.Bold))
        self.layout.addWidget(heading)
        self.content = QWidget()
        self.layout.addWidget(self.content, 1)
        self.set_data({})

    def set_data(self, values: dict[str, int]) -> None:
        self.bars = []
        old_content = self.content
        self.content = QWidget()
        rows = QVBoxLayout(self.content)
        rows.setContentsMargins(2, 4, 8, 4)
        rows.setSpacing(5)
        visible = list(values.items())[:6]
        if not visible:
            empty = QLabel("No local report data")
            empty.setStyleSheet("color: #7890a8; font-style: italic;")
            rows.addWidget(empty)
            rows.addStretch()
        else:
            maximum = max(value for _label, value in visible) or 1
            for index, (label, value) in enumerate(visible):
                row = QHBoxLayout()
                text = QLabel(self.fontMetrics().elidedText(
                    label, Qt.TextElideMode.ElideRight, 130,
                ))
                text.setObjectName("chartLabel")
                text.setToolTip(label)
                text.setFixedWidth(135)
                row.addWidget(text)
                bar = QProgressBar()
                bar.setRange(0, maximum)
                bar.setValue(value)
                bar.setFormat("")
                color = self.colors.get(label.casefold(), self.PALETTE[index % len(self.PALETTE)])
                bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")
                bar.setToolTip(f"{label}: {value}")
                self.bars.append(bar)
                row.addWidget(bar, 1)
                count = QLabel(str(value))
                count.setAlignment(Qt.AlignmentFlag.AlignCenter)
                count.setFixedWidth(32)
                row.addWidget(count)
                rows.addLayout(row)
            rows.addStretch()
        self.layout.replaceWidget(old_content, self.content)
        old_content.hide()
        old_content.deleteLater()


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        metadata = services.project_metadata()
        self.setWindowTitle(f"{metadata['name']} {metadata['version']}")
        self.resize(1280, 820)
        self.setMinimumSize(980, 680)
        self.setStyleSheet(STYLE)
        self.process = QProcess(self)
        self.process.setWorkingDirectory(str(services.ROOT))
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        process_environment = QProcessEnvironment.systemEnvironment()
        process_environment.insert("FAIRY_GUI_PROGRESS", "1")
        for variable in TRANSIENT_CODEX_ENV_VARS:
            process_environment.remove(variable)
        self.process.setProcessEnvironment(process_environment)
        self.process.readyReadStandardOutput.connect(self._read_process_output)
        self.process.finished.connect(self._process_finished)
        self.chat_process = QProcess(self)
        self.chat_process.setWorkingDirectory(str(services.ROOT))
        self.chat_process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.chat_process.setProcessEnvironment(process_environment)
        self.chat_process.readyReadStandardOutput.connect(self._read_chat_output)
        self.chat_process.finished.connect(self._chat_finished)
        self.chat_response = ""
        self.pending_issue_update: tuple[str, dict[str, str]] | None = None
        self.current_action: str | None = None
        self.process_output_buffer = ""
        self.analysis_activity_base = ""
        self.analysis_started_at: float | None = None
        self.analysis_activity_generation = 0
        self.analysis_spinner_index = 0
        self.analysis_activity_timer = QTimer(self)
        self.analysis_activity_timer.setInterval(250)
        self.analysis_activity_timer.timeout.connect(self._update_analysis_activity_clock)
        self.config_editors: dict[Path, QPlainTextEdit] = {}
        self.report_paths: dict[int, Path] = {}
        self.log_run_files: list[Path] = []
        self.developer_tools_active = services.developer_tools_enabled()
        self._build_interface()
        self.load_configuration()
        self.refresh_all()

    def _build_interface(self) -> None:
        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        self.navigation = QListWidget()
        self.navigation.setObjectName("navigation")
        navigation_entries: tuple[tuple[str, int] | None, ...] = (
            ("Dashboard", PAGE_DASHBOARD),
            ("Reports", PAGE_REPORTS),
            ("AI issue assistant", PAGE_ASSISTANT),
            ("Run check", PAGE_RUN),
            ("Logs", PAGE_LOGS),
            None,
            ("Inventory", PAGE_INVENTORY),
            ("Configuration", PAGE_CONFIGURATION),
            ("System status", PAGE_STATUS),
            None,
            ("User guide", PAGE_GUIDE),
            ("About", PAGE_ABOUT),
        )
        for entry in navigation_entries:
            if entry is None:
                separator_item = QListWidgetItem("────────────────")
                separator_item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                separator_item.setForeground(QColor("#3b5874"))
                separator_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                separator_item.setSizeHint(QSize(0, 15))
                self.navigation.addItem(separator_item)
                continue
            label, page_index = entry
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, page_index)
            self.navigation.addItem(item)
        self.navigation.currentRowChanged.connect(self._page_selected)
        sidebar_layout.addWidget(self.navigation, 1)
        sidebar_logo = QLabel()
        sidebar_logo.setObjectName("sidebarLogo")
        sidebar_logo.setFixedHeight(72)
        sidebar_logo.setToolTip("fAIry Security Advisory")
        sidebar_pixmap = QPixmap(str(services.ROOT / "docs/assets/fairy-security-advisory-banner.png"))
        if not sidebar_pixmap.isNull():
            sidebar_logo.setPixmap(sidebar_pixmap.scaled(
                188, 70, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            ))
        sidebar_logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(sidebar_logo)
        layout.addWidget(sidebar)

        self.pages = QStackedWidget()
        self.pages.addWidget(self._dashboard_page())
        self.pages.addWidget(self._configuration_page())
        self.pages.addWidget(self._inventory_page())
        self.pages.addWidget(self._reports_page())
        self.pages.addWidget(self._logs_page())
        self.pages.addWidget(self._assistant_page())
        self.pages.addWidget(self._run_page())
        self.pages.addWidget(self._status_page())
        self.pages.addWidget(self._guide_page())
        self.pages.addWidget(self._about_page())
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(central)
        metadata = services.project_metadata()
        self.footer_identity = QLabel(
            f"Version {metadata['version']}  ·  License {metadata['license']}"
        )
        self.footer_identity.setObjectName("footerIdentity")
        self.global_analysis_progress = QProgressBar()
        self.global_analysis_progress.setFixedWidth(150)
        self.global_analysis_progress.setTextVisible(False)
        self.global_analysis_progress.setVisible(False)
        self.global_analysis_label = QLabel()
        self.global_analysis_label.setVisible(False)
        self.statusBar().addPermanentWidget(self.global_analysis_label)
        self.statusBar().addPermanentWidget(self.global_analysis_progress)
        self.statusBar().addPermanentWidget(self.footer_identity)
        self._navigate_to_page(PAGE_DASHBOARD)

    @staticmethod
    def _page(title: str, subtitle: str) -> tuple[QWidget, QVBoxLayout]:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(24, 20, 24, 20)
        heading = QLabel(title)
        heading.setFont(QFont("Sans Serif", 20, QFont.Weight.Bold))
        layout.addWidget(heading)
        description = QLabel(subtitle)
        description.setWordWrap(True)
        description.setStyleSheet("color: #9fb4c8; margin-bottom: 8px;")
        layout.addWidget(description)
        return page, layout

    @staticmethod
    def _card(title: str) -> tuple[QFrame, QVBoxLayout]:
        frame = QFrame()
        frame.setObjectName("card")
        layout = QVBoxLayout(frame)
        label = QLabel(title)
        label.setFont(QFont("Sans Serif", 11, QFont.Weight.Bold))
        layout.addWidget(label)
        return frame, layout

    def _dashboard_page(self) -> QWidget:
        page, layout = self._page(
            "Security dashboard",
            "Current metrics derived from the Git-ignored local follow-up and latest daily report.",
        )
        metrics = QGridLayout()
        self.dashboard_metrics: dict[str, QLabel] = {}
        for column, (key, title) in enumerate((
            ("open", "Open activities"),
            ("today", "Found today"),
            ("month", "Found this month"),
            ("projects", "Projects involved"),
        )):
            card, card_layout = self._card(title)
            value = QLabel("0")
            value.setObjectName("metricValue")
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card_layout.addWidget(value)
            self.dashboard_metrics[key] = value
            metrics.addWidget(card, 0, column)
        layout.addLayout(metrics)

        charts = QGridLayout()
        self.priority_chart = BarChartCard("Activities by priority", {
            "Critical": "#ef4444",
            "High": "#f97316",
            "Medium": "#eab308",
            "Low": "#22c55e",
            "Informational": "#3b82f6",
        })
        self.status_chart = BarChartCard("Activities by status", {
            "Open": "#ef4444",
            "Needs verification": "#f59e0b",
            "Externally closed": "#22c55e",
            "Completed in code": "#14b8a6",
        })
        self.project_chart = BarChartCard("Most involved projects")
        self.language_chart = BarChartCard("Languages in the latest check")
        charts.addWidget(self.priority_chart, 0, 0)
        charts.addWidget(self.status_chart, 0, 1)
        charts.addWidget(self.project_chart, 1, 0)
        charts.addWidget(self.language_chart, 1, 1)
        layout.addLayout(charts, 1)
        actions = QHBoxLayout()
        refresh = QPushButton("Refresh dashboard")
        refresh.setProperty("variant", "secondary")
        refresh.clicked.connect(self.refresh_all)
        actions.addWidget(refresh)
        run = QPushButton("Open Run check")
        run.clicked.connect(lambda: self._navigate_to_page(PAGE_RUN))
        actions.addWidget(run)
        actions.addStretch()
        layout.addLayout(actions)
        return page

    def _configuration_page(self) -> QWidget:
        page, layout = self._page(
            "Configuration",
            "Use guided forms for common settings, or switch to Advanced YAML for complete control.",
        )
        mode_row = QHBoxLayout()
        self.config_mode_label = QLabel("Editing mode")
        mode_row.addWidget(self.config_mode_label)
        self.config_mode = QComboBox()
        self.config_mode.addItems(("Simple", "Advanced YAML"))
        mode_row.addWidget(self.config_mode)
        self.config_mode_hint = QLabel()
        self.config_mode_hint.setStyleSheet("color: #9fb4c8; padding-left: 8px;")
        mode_row.addWidget(self.config_mode_hint)
        mode_row.addStretch()
        self.developer_tools_checkbox = QCheckBox("Developer tools")
        self.developer_tools_checkbox.setToolTip(
            "Show maintainer-only validation actions such as the pre-publication check."
        )
        self.developer_tools_checkbox.setChecked(self.developer_tools_active)
        self.developer_tools_checkbox.toggled.connect(self.set_developer_tools)
        mode_row.addWidget(self.developer_tools_checkbox)
        layout.addLayout(mode_row)

        self.config_tabs = QTabWidget()
        self.config_views: dict[Path, QStackedWidget] = {}
        self.config_simple_forms: dict[Path, QWidget] = {}
        self.config_tab_paths: list[Path | None] = []
        self.config_agent_tabs: dict[int, str] = {}
        self.agent_account_widgets: dict[str, dict[str, QWidget]] = {}
        for title, path in services.CONFIG_FILES:
            editor = QPlainTextEdit()
            editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
            editor.setPlaceholderText(
                "Local configuration is missing. Use Initialize local configuration."
                if path == services.LOCAL_CONFIG else "Configuration file is missing."
            )
            view = QStackedWidget()
            if path == services.LOCAL_CONFIG:
                form = ProjectsConfigForm()
                view.addWidget(form)
                self.config_simple_forms[path] = form
            elif path == services.LOCAL_CONFIG_DIR / "advisory-sources.yaml":
                form = AdvisorySourcesConfigForm()
                view.addWidget(form)
                self.config_simple_forms[path] = form
            elif path == services.LOCAL_CONFIG_DIR / "reports.yaml":
                form = ReportsConfigForm()
                view.addWidget(form)
                self.config_simple_forms[path] = form
            elif path == services.LOCAL_CONFIG_DIR / "ai-agents.yaml":
                form = AIAgentsConfigForm()
                view.addWidget(form)
                self.config_simple_forms[path] = form
            elif path == services.LOCAL_CONFIG_DIR / "backups.yaml":
                form = BackupsConfigForm()
                view.addWidget(form)
                self.config_simple_forms[path] = form
            view.addWidget(editor)
            self.config_views[path] = view
            self.config_tabs.addTab(view, title)
            self.config_tab_paths.append(path)
            self.config_editors[path] = editor
        for provider, title in (("codex", "AI Codex"), ("claude", "AI Claude")):
            index = self.config_tabs.addTab(self._agent_account_panel(provider), title)
            self.config_tab_paths.append(None)
            self.config_agent_tabs[index] = provider
        layout.addWidget(self.config_tabs, 1)
        buttons = QHBoxLayout()
        initialize = QPushButton("Initialize local configuration")
        initialize.setMinimumWidth(185)
        initialize.setProperty("variant", "warning")
        initialize.clicked.connect(self.initialize_local_config)
        buttons.addWidget(initialize)
        reload_button = QPushButton("Reload")
        reload_button.setMinimumWidth(72)
        reload_button.setProperty("variant", "secondary")
        reload_button.clicked.connect(self.load_configuration)
        buttons.addWidget(reload_button)
        validate = QPushButton("Validate YAML")
        validate.setMinimumWidth(125)
        validate.setProperty("variant", "secondary")
        validate.clicked.connect(self.validate_current_configuration)
        buttons.addWidget(validate)
        save = QPushButton("Save current file")
        save.setMinimumWidth(112)
        save.setProperty("variant", "success")
        save.clicked.connect(self.save_current_configuration)
        buttons.addWidget(save)
        restore_defaults = QPushButton("Restore factory defaults…")
        restore_defaults.setMinimumWidth(150)
        restore_defaults.setProperty("variant", "danger")
        restore_defaults.clicked.connect(self.restore_factory_defaults)
        buttons.addWidget(restore_defaults)
        validate_all = QPushButton("Run full validation")
        validate_all.setMinimumWidth(140)
        validate_all.setProperty("variant", "secondary")
        validate_all.clicked.connect(lambda: self.start_action("validate"))
        buttons.addWidget(validate_all)
        backup = QPushButton("Back up configurations")
        backup.setMinimumWidth(160)
        backup.setProperty("variant", "success")
        backup.clicked.connect(self.backup_configuration)
        buttons.addWidget(backup)
        import_backup = QPushButton("Import backup…")
        import_backup.setMinimumWidth(130)
        import_backup.setProperty("variant", "danger")
        import_backup.clicked.connect(self.import_configuration_backup)
        buttons.addWidget(import_backup)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.config_action_buttons = {
            "initialize": initialize,
            "reload": reload_button,
            "validate": validate,
            "save": save,
            "restore": restore_defaults,
            "validate_all": validate_all,
            "backup": backup,
            "import": import_backup,
        }
        self._last_config_tab = self.config_tabs.currentIndex()
        self.config_tabs.currentChanged.connect(self.configuration_tab_changed)
        self.config_mode.currentIndexChanged.connect(self.configuration_mode_changed)
        self.configuration_tab_changed(self.config_tabs.currentIndex())
        return page

    def _agent_account_panel(self, provider: str) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 18, 16, 16)
        display_name = "Codex" if provider == "codex" else "Claude Code"
        title = QLabel(f"{display_name} CLI account")
        title.setFont(QFont("Sans Serif", 17, QFont.Weight.Bold))
        layout.addWidget(title)
        description = QLabel(
            f"Check whether the {display_name} command-line agent is installed and authenticated. "
            "Review usage available to fAIry. Credentials are handled only by the official CLI "
            "and are never stored by fAIry."
        )
        description.setWordWrap(True)
        description.setStyleSheet("color:#9fb4c8; margin-bottom:10px;")
        layout.addWidget(description)
        card, card_layout = self._card("Account status")
        state = QLabel("Checking…")
        state.setFont(QFont("Sans Serif", 20, QFont.Weight.Bold))
        card_layout.addWidget(state)
        detail = QLabel()
        detail.setWordWrap(True)
        detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        detail.setStyleSheet("color:#c9dded; padding:6px 0;")
        card_layout.addWidget(detail)
        usage = QLabel("Usage data will appear after the first fAIry analysis.")
        usage.setWordWrap(True)
        usage.setStyleSheet("color:#9fd3e5; padding:8px 0 2px 0;")
        card_layout.addWidget(usage)
        allowance = QLabel()
        allowance.setWordWrap(True)
        allowance.setStyleSheet("color:#c9dded; padding:2px 0 8px 0;")
        card_layout.addWidget(allowance)
        buttons = QHBoxLayout()
        refresh = QPushButton("Refresh status and usage")
        refresh.setProperty("variant", "secondary")
        refresh.clicked.connect(
            lambda _checked=False, name=provider: self.refresh_agent_account(name)
        )
        buttons.addWidget(refresh)
        login = QPushButton("Log in")
        login.setProperty("variant", "warning")
        login.clicked.connect(lambda _checked=False, name=provider: self.login_agent(name))
        buttons.addWidget(login)
        install = QPushButton("Install")
        install.setProperty("variant", "warning")
        install.clicked.connect(lambda _checked=False, name=provider: self.install_component(name))
        buttons.addWidget(install)
        buttons.addStretch()
        card_layout.addLayout(buttons)
        layout.addWidget(card)
        note = QLabel(
            "After completing authentication in the terminal, return here and refresh status and usage."
        )
        note.setWordWrap(True)
        note.setStyleSheet("color:#7890a8; padding-top:8px;")
        layout.addWidget(note)
        layout.addStretch()
        self.agent_account_widgets[provider] = {
            "state": state, "detail": detail, "usage": usage, "allowance": allowance,
            "login": login, "install": install,
        }
        return panel

    def refresh_agent_account(self, provider: str) -> None:
        _component, state, detail = services.agent_component_status(provider)
        widgets = self.agent_account_widgets.get(provider)
        if not widgets:
            return
        state_label = widgets["state"]
        state_label.setText({
            "Ready": "Authenticated",
            "Login required": "Not authenticated",
            "Missing": "CLI not installed",
        }.get(state, state))
        state_label.setStyleSheet({
            "Ready": "color:#63b37b;",
            "Login required": "color:#e5bb62;",
            "Missing": "color:#df7f7f;",
        }.get(state, "color:#e8f2ff;"))
        widgets["detail"].setText(detail)
        if state == "Ready":
            local_usage, allowance = services.agent_usage_status(provider)
        else:
            local_usage, allowance = "No authenticated usage data available.", ""
        widgets["usage"].setText(local_usage)
        widgets["allowance"].setText(allowance)
        widgets["login"].setVisible(state == "Login required")
        widgets["install"].setVisible(state == "Missing")

    def set_developer_tools(self, enabled: bool) -> None:
        try:
            services.set_developer_tools_enabled(enabled)
        except (OSError, ValueError, services.ConfigurationError) as error:
            self.developer_tools_checkbox.blockSignals(True)
            self.developer_tools_checkbox.setChecked(self.developer_tools_active)
            self.developer_tools_checkbox.blockSignals(False)
            QMessageBox.critical(self, "Developer tools", str(error))
            return
        self.developer_tools_active = enabled
        if hasattr(self, "prepublish_button"):
            self.prepublish_button.setVisible(enabled)
        self.statusBar().showMessage(
            "Developer tools enabled" if enabled else "Developer tools hidden", 5000,
        )

    def configuration_tab_changed(self, index: int) -> None:
        previous = getattr(self, "_last_config_tab", index)
        if previous != index and self.config_mode.currentIndex() == 0:
            previous_path = self.config_tab_paths[previous]
            if previous_path is not None and previous_path in self.config_simple_forms:
                try:
                    self.sync_simple_configuration(previous_path)
                except (ValueError, services.ConfigurationError) as error:
                    self.statusBar().showMessage(f"Unsaved form settings: {error}", 8000)
        self._last_config_tab = index
        self.update_configuration_actions(index)
        self.update_configuration_view()
        provider = self.config_agent_tabs.get(index)
        if provider:
            self.refresh_agent_account(provider)

    def configuration_mode_changed(self, mode: int) -> None:
        path = self.config_tab_paths[self.config_tabs.currentIndex()]
        if path is None:
            return
        if path not in self.config_simple_forms:
            self.update_configuration_view()
            return
        try:
            if mode == 1:
                self.sync_simple_configuration(path)
            else:
                data = services.validate_config_text(self.config_editors[path].toPlainText())
                self.config_simple_forms[path].load_data(data)
        except (ValueError, services.ConfigurationError) as error:
            QMessageBox.warning(self, "Unable to change editing mode", str(error))
            self.config_mode.blockSignals(True)
            self.config_mode.setCurrentIndex(0 if mode == 1 else 1)
            self.config_mode.blockSignals(False)
        self.update_configuration_view()

    def update_configuration_view(self) -> None:
        path = self.config_tab_paths[self.config_tabs.currentIndex()]
        if path is None:
            self.config_mode_label.hide()
            self.config_mode.hide()
            self.config_mode_hint.setText("CLI installation and account authentication status.")
            return
        self.config_mode_label.show()
        self.config_mode.show()
        simple_supported = path in self.config_simple_forms
        self.config_mode.setEnabled(simple_supported)
        if simple_supported:
            origin = "Local override" if path.is_file() else "Factory defaults; Save creates a local override"
            mode_help = (
                "guided form; unknown YAML fields are preserved"
                if self.config_mode.currentIndex() == 0
                else "expert editor with direct access to every setting"
            )
            self.config_mode_hint.setText(f"{origin} · {mode_help}.")
            self.config_views[path].setCurrentIndex(self.config_mode.currentIndex())
        else:
            self.config_mode_hint.setText("Advanced YAML only for this section.")
            self.config_views[path].setCurrentIndex(0)
        simple = simple_supported and self.config_mode.currentIndex() == 0
        self.config_action_buttons["validate"].setText(
            "Validate settings" if simple else "Validate YAML"
        )
        self.config_action_buttons["save"].setText(
            "Save settings" if simple else "Save current file"
        )

    def sync_simple_configuration(self, path: Path) -> None:
        """Merge a guided form into its YAML document without dropping unknown fields."""
        text = self.config_editors[path].toPlainText()
        data = services.validate_config_text(text) if text.strip() else {"schema_version": 1}
        updated = self.config_simple_forms[path].apply_to(data)
        updated.setdefault("schema_version", 1)
        self.config_editors[path].setPlainText(services.dump_config_data(updated))

    def update_configuration_actions(self, index: int) -> None:
        """Show only the actions that are relevant to the selected config tab."""
        path = self.config_tab_paths[index]
        common = {"reload", "validate", "save", "restore"}
        if path is None:
            visible = set()
        elif path == services.LOCAL_CONFIG:
            visible = common | {"initialize", "validate_all"}
        elif path.name == "backups.yaml":
            visible = common | {"backup", "import"}
        else:
            visible = common | {"validate_all"}
        for name, button in self.config_action_buttons.items():
            button.setVisible(name in visible)

    def _inventory_page(self) -> QWidget:
        page, layout = self._page(
            "Technology inventory",
            "Choose which detected projects receive advisory checks and optionally prefer an AI. Technical discovery remains read-only.",
        )
        self.inventory_tree = QTreeWidget()
        self.inventory_tree.setHeaderLabels((
            "Check", "Project", "Preferred AI", "Roles", "Technologies", "Path",
        ))
        self.inventory_tree.setAlternatingRowColors(True)
        self.inventory_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.inventory_tree.setStyleSheet("QTreeWidget::item { min-height: 32px; padding:2px; }")
        for column in (0, 1, 2, 3):
            self.inventory_tree.header().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents,
            )
        self.inventory_tree.header().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.inventory_tree.header().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.inventory_tree.itemChanged.connect(self.update_inventory_count)
        layout.addWidget(self.inventory_tree, 1)
        buttons = QHBoxLayout()
        reload_button = QPushButton("Reload inventory view")
        reload_button.setProperty("variant", "secondary")
        reload_button.clicked.connect(self.load_inventory)
        buttons.addWidget(reload_button)
        scan = QPushButton("Refresh inventory from configured paths")
        scan.setProperty("variant", "warning")
        scan.clicked.connect(self.refresh_inventory)
        buttons.addWidget(scan)
        save_preferences = QPushButton("Save project choices")
        save_preferences.setProperty("variant", "success")
        save_preferences.clicked.connect(self.save_inventory_preferences)
        buttons.addWidget(save_preferences)
        buttons.addStretch()
        self.inventory_count = QLabel()
        buttons.addWidget(self.inventory_count)
        layout.addLayout(buttons)
        return page

    def _reports_page(self) -> QWidget:
        page, layout = self._page(
            "Reports and follow-up", "Rendered local Markdown output. Environment-derived content remains under the Git-ignored output directory.",
        )
        splitter = QSplitter()
        self.report_list = QListWidget()
        self.report_list.setObjectName("reports")
        self.report_list.setMinimumWidth(190)
        self.report_list.setMaximumWidth(240)
        self.report_list.currentRowChanged.connect(self.show_report)
        splitter.addWidget(self.report_list)
        self.report_viewer = QTextBrowser()
        self.report_viewer.setOpenExternalLinks(True)
        self.report_viewer.setPlaceholderText("No local report selected.")
        self.report_stack = QStackedWidget()
        self.report_stack.addWidget(self.report_viewer)
        self.followup_table = QTableWidget(0, 7)
        self.followup_table.setHorizontalHeaderLabels((
            "Activity / advisory", "Project", "Priority", "Owner", "Status",
            "Next action", "Actions",
        ))
        self.followup_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.followup_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.followup_table.verticalHeader().setDefaultSectionSize(76)
        self.followup_table.horizontalHeader().setMinimumHeight(38)
        for column in (1, 5):
            self.followup_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.Stretch,
            )
        for column, width in ((0, 210), (2, 75), (3, 120), (4, 125), (6, 215)):
            self.followup_table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.Fixed,
            )
            self.followup_table.setColumnWidth(column, width)
        self.report_stack.addWidget(self.followup_table)
        splitter.addWidget(self.report_stack)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes((210, 850))
        layout.addWidget(splitter, 1)
        reload_button = QPushButton("Reload reports")
        reload_button.setProperty("variant", "secondary")
        reload_button.clicked.connect(self.load_reports)
        layout.addWidget(reload_button, alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def _logs_page(self) -> QWidget:
        page, layout = self._page(
            "Analysis logs",
            "Browse private run archives by year and month. Logs remain under Git-ignored output/.",
        )
        splitter = QSplitter()
        self.logs_tree = QTreeWidget()
        self.logs_tree.setHeaderLabels(("Archive", "Status", "Coordinator"))
        self.logs_tree.setMinimumWidth(300)
        self.logs_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.logs_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.logs_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.logs_tree.currentItemChanged.connect(self.select_analysis_log_run)
        splitter.addWidget(self.logs_tree)

        viewer_panel = QWidget()
        viewer_layout = QVBoxLayout(viewer_panel)
        viewer_layout.setContentsMargins(0, 0, 0, 0)
        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("File"))
        self.log_file_combo = QComboBox()
        self.log_file_combo.setMinimumWidth(260)
        self.log_file_combo.currentIndexChanged.connect(self.show_analysis_log_file)
        file_row.addWidget(self.log_file_combo)
        file_row.addStretch()
        viewer_layout.addLayout(file_row)
        self.analysis_log_viewer = QPlainTextEdit()
        self.analysis_log_viewer.setReadOnly(True)
        self.analysis_log_viewer.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.analysis_log_viewer.setPlaceholderText("Select an archived analysis run.")
        viewer_layout.addWidget(self.analysis_log_viewer, 1)
        splitter.addWidget(viewer_panel)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes((340, 760))
        layout.addWidget(splitter, 1)

        actions = QHBoxLayout()
        reload_button = QPushButton("Reload logs")
        reload_button.setProperty("variant", "secondary")
        reload_button.clicked.connect(self.load_analysis_logs)
        actions.addWidget(reload_button)
        self.delete_log_button = QPushButton("Delete selected run…")
        self.delete_log_button.setProperty("variant", "danger")
        self.delete_log_button.setEnabled(False)
        self.delete_log_button.clicked.connect(self.delete_selected_analysis_run)
        actions.addWidget(self.delete_log_button)
        actions.addStretch()
        self.analysis_log_count = QLabel()
        actions.addWidget(self.analysis_log_count)
        layout.addLayout(actions)
        return page

    def _assistant_page(self) -> QWidget:
        page, layout = self._page(
            "AI issue assistant",
            "Discuss one follow-up activity at a time. Advice is read-only; proposed status changes require explicit confirmation.",
        )
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Open issue"))
        self.assistant_issue_combo = QComboBox()
        self.assistant_issue_combo.setMinimumWidth(360)
        self.assistant_issue_combo.currentIndexChanged.connect(self.load_assistant_conversation)
        controls.addWidget(self.assistant_issue_combo, 1)
        controls.addWidget(QLabel("Agent"))
        self.assistant_provider_combo = QComboBox()
        self.assistant_provider_combo.addItems(("codex", "claude"))
        controls.addWidget(self.assistant_provider_combo)
        controls.addWidget(QLabel("Profile"))
        self.assistant_profile_combo = QComboBox()
        controls.addWidget(self.assistant_profile_combo)
        layout.addLayout(controls)

        context_card = QFrame()
        context_card.setObjectName("card")
        context_layout = QHBoxLayout(context_card)
        context_layout.setContentsMargins(16, 12, 16, 12)
        context_layout.setSpacing(20)
        project_column = QVBoxLayout()
        project_caption = QLabel("AFFECTED PROJECT")
        project_caption.setStyleSheet(
            "color:#7890a8; font-size:11px; font-weight:700; letter-spacing:1px;"
        )
        project_column.addWidget(project_caption)
        self.assistant_project_label = QLabel("No project selected")
        self.assistant_project_label.setFont(QFont("Sans Serif", 18, QFont.Weight.Bold))
        self.assistant_project_label.setWordWrap(True)
        self.assistant_project_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.assistant_project_label.setStyleSheet("color:#63e7ff; padding:2px 0 4px 0;")
        project_column.addWidget(self.assistant_project_label)
        context_layout.addLayout(project_column, 2)
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.VLine)
        separator.setStyleSheet("color:#24415b;")
        context_layout.addWidget(separator)
        self.assistant_issue_details = QLabel("No open follow-up activity selected.")
        self.assistant_issue_details.setWordWrap(True)
        self.assistant_issue_details.setTextFormat(Qt.TextFormat.RichText)
        self.assistant_issue_details.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.assistant_issue_details.setStyleSheet(
            "color:#c9dded; padding:2px 4px;"
        )
        context_layout.addWidget(self.assistant_issue_details, 3)
        layout.addWidget(context_card)

        self.assistant_conversation = QTextBrowser()
        self.assistant_conversation.setPlaceholderText(
            "Select an open issue and ask for advice or report an issue-management change."
        )
        layout.addWidget(self.assistant_conversation, 1)

        quick = QHBoxLayout()
        for label, prompt in (
            ("Ask for advice", "What should we verify or do next for this issue?"),
            ("Taken in charge", "This issue has been taken in charge by [owner]. The next action is [action]."),
            ("Record resolution", "This issue has been resolved. Completion evidence: [evidence]."),
            ("Not a concern", "This issue is not applicable or does not require concern because [technical rationale/evidence]."),
        ):
            button = QPushButton(label)
            button.setProperty("variant", "ai")
            button.clicked.connect(
                lambda _checked=False, text=prompt: self._set_assistant_prompt(text)
            )
            quick.addWidget(button)
        quick.addStretch()
        layout.addLayout(quick)

        self.assistant_input = QPlainTextEdit()
        self.assistant_input.setMaximumHeight(105)
        self.assistant_input.setPlaceholderText(
            "Ask a question or describe ownership, remediation evidence, or non-applicability rationale…"
        )
        layout.addWidget(self.assistant_input)
        actions = QHBoxLayout()
        self.assistant_send_button = QPushButton("Send to AI")
        self.assistant_send_button.setProperty("variant", "ai")
        self.assistant_send_button.clicked.connect(self.send_assistant_message)
        actions.addWidget(self.assistant_send_button)
        self.assistant_apply_button = QPushButton("Review proposed issue update")
        self.assistant_apply_button.setProperty("variant", "warning")
        self.assistant_apply_button.setEnabled(False)
        self.assistant_apply_button.clicked.connect(self.apply_assistant_update)
        actions.addWidget(self.assistant_apply_button)
        actions.addStretch()
        privacy = QLabel("Issue context is sent to the selected AI; chat history stays under ignored output/.")
        privacy.setStyleSheet("color:#7890a8;")
        actions.addWidget(privacy)
        layout.addLayout(actions)
        return page

    def _run_page(self) -> QWidget:
        page, layout = self._page(
            "Run security checks", "Run deterministic checks or start a non-interactive AI analysis and follow its output.",
        )
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Agent"))
        self.provider_combo = QComboBox()
        self.provider_combo.addItems(("codex", "claude"))
        controls.addWidget(self.provider_combo)
        controls.addWidget(QLabel("Model profile"))
        self.profile_combo = QComboBox()
        controls.addWidget(self.profile_combo)
        controls.addWidget(QLabel("Execution"))
        self.mode_combo = QComboBox()
        controls.addWidget(self.mode_combo)
        controls.addStretch()
        layout.addLayout(controls)

        routing_notice = QLabel(
            "The selected agent is the coordinator and applies only to Inventory "
            "projects whose AI preference is ‘-’. Projects explicitly assigned to "
            "Codex or Claude keep their configured agent."
        )
        routing_notice.setObjectName("routingNotice")
        routing_notice.setWordWrap(True)
        routing_notice.setStyleSheet(
            "background:#10243d; border:1px solid #31516e; border-radius:6px; "
            "color:#c9dded; padding:9px 12px; margin:2px 0 4px 0;"
        )
        layout.addWidget(routing_notice)

        buttons = QHBoxLayout()
        prerequisites = QPushButton("Check prerequisites")
        prerequisites.setProperty("variant", "secondary")
        prerequisites.clicked.connect(lambda: self.start_action("prerequisites"))
        buttons.addWidget(prerequisites)
        sources = QPushButton("Check sources")
        sources.clicked.connect(lambda: self.start_action("sources", mode=self.mode_combo.currentText()))
        buttons.addWidget(sources)
        self.prepublish_button = QPushButton("Pre-publication check")
        self.prepublish_button.setProperty("variant", "warning")
        self.prepublish_button.setToolTip(
            "Maintainer check for publishing fAIry Security Advisory itself."
        )
        self.prepublish_button.clicked.connect(lambda: self.start_action("prepublish"))
        self.prepublish_button.setVisible(self.developer_tools_active)
        buttons.addWidget(self.prepublish_button)
        run = QPushButton("Run complete AI analysis")
        run.setProperty("variant", "ai")
        run.clicked.connect(self.run_ai_analysis)
        buttons.addWidget(run)
        self.stop_button = QPushButton("Stop")
        self.stop_button.setProperty("variant", "danger")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_process)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        activity = QFrame()
        activity.setObjectName("card")
        activity_layout = QHBoxLayout(activity)
        activity_layout.setContentsMargins(14, 10, 14, 10)
        activity_layout.setSpacing(14)
        self.analysis_activity_label = QLabel("No AI analysis is running.")
        self.analysis_activity_label.setMinimumWidth(310)
        activity_layout.addWidget(self.analysis_activity_label)
        self.analysis_project_progress = QProgressBar()
        self.analysis_project_progress.setRange(0, 1)
        self.analysis_project_progress.setValue(0)
        self.analysis_project_progress.setFormat("0 / 0 projects")
        self.analysis_project_progress.setToolTip(
            "Progress advances when an AI provider completes its assigned project group; "
            "AI-internal completion percentages are not available."
        )
        activity_layout.addWidget(self.analysis_project_progress, 1)
        self.analysis_elapsed_label = QLabel("")
        self.analysis_elapsed_label.setMinimumWidth(92)
        self.analysis_elapsed_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        activity_layout.addWidget(self.analysis_elapsed_label)
        layout.addWidget(activity)

        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.log.setPlaceholderText("Process output will appear here.")
        layout.addWidget(self.log, 1)
        clear = QPushButton("Clear log")
        clear.setProperty("variant", "secondary")
        clear.clicked.connect(self.log.clear)
        layout.addWidget(clear, alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def _status_page(self) -> QWidget:
        page, layout = self._page(
            "System status", "Installed agents, optional scanners, local configuration, and inventory state.",
        )
        self.status_table = QTableWidget(0, 4)
        self.status_table.setHorizontalHeaderLabels(("Component", "State", "Details", "Action"))
        self.status_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.status_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.status_table.verticalHeader().setDefaultSectionSize(42)
        self.status_table.verticalHeader().setMinimumSectionSize(38)
        self.status_table.horizontalHeader().setMinimumHeight(38)
        self.status_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.status_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.status_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.status_table.setColumnWidth(3, 230)
        layout.addWidget(self.status_table, 1)
        refresh = QPushButton("Refresh system status")
        refresh.setProperty("variant", "secondary")
        refresh.clicked.connect(self.load_status)
        layout.addWidget(refresh, alignment=Qt.AlignmentFlag.AlignLeft)
        return page

    def _guide_page(self) -> QWidget:
        page, layout = self._page(
            "Desktop user guide",
            "Search the versioned manual and jump directly between matching sections or terms.",
        )
        search = QHBoxLayout()
        search.addWidget(QLabel("Search manual"))
        self.guide_search = QLineEdit()
        self.guide_search.setPlaceholderText("Example: backup, AI chat, inventory, authentication…")
        self.guide_search.returnPressed.connect(self.search_guide_next)
        search.addWidget(self.guide_search, 1)
        previous = QPushButton("Previous")
        previous.setProperty("variant", "secondary")
        previous.clicked.connect(self.search_guide_previous)
        search.addWidget(previous)
        next_button = QPushButton("Next")
        next_button.clicked.connect(self.search_guide_next)
        search.addWidget(next_button)
        contents = QPushButton("Back to top")
        contents.setProperty("variant", "secondary")
        contents.clicked.connect(self.guide_to_top)
        search.addWidget(contents)
        layout.addLayout(search)
        self.guide_search_status = QLabel("Enter a term and press Enter to jump to the first match.")
        self.guide_search_status.setStyleSheet("color:#7890a8; padding:2px 4px 6px 4px;")
        layout.addWidget(self.guide_search_status)
        self.guide_viewer = QTextBrowser()
        self.guide_viewer.setOpenLinks(False)
        self.guide_viewer.anchorClicked.connect(self.open_guide_link)
        self.guide_viewer.document().setDefaultStyleSheet(
            "a { color: #63e7ff; text-decoration: none; } "
            "a:hover { color: #ffffff; text-decoration: underline; }"
        )
        guide = services.ROOT / "docs/gui-user-guide.md"
        if guide.is_file():
            self.guide_viewer.setMarkdown(guide.read_text(encoding="utf-8"))
        else:
            self.guide_viewer.setMarkdown("# User guide unavailable\n\nThe manual file is missing.")
        self.guide_viewer.document().setDefaultStyleSheet(
            "a { color: #63e7ff; text-decoration: none; } "
            "a:hover { color: #ffffff; text-decoration: underline; }"
        )
        layout.addWidget(self.guide_viewer, 1)
        self.guide_last_query = ""
        return page

    def _about_page(self) -> QWidget:
        page, layout = self._page(
            "About fAIry", "Project identity and release information read from VERSION.yaml.",
        )
        banner = QLabel()
        pixmap = QPixmap(str(services.ROOT / "docs/assets/fairy-security-advisory-banner.png"))
        if not pixmap.isNull():
            banner.setPixmap(pixmap.scaledToWidth(760, Qt.TransformationMode.SmoothTransformation))
            banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(banner)
        card, card_layout = self._card("Project information")
        self.about_metadata = QLabel()
        self.about_metadata.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.about_metadata.setStyleSheet("font-size: 14px; line-height: 1.5;")
        card_layout.addWidget(self.about_metadata)
        layout.addWidget(card)
        source = QLabel(
            'Licensed under AGPL-3.0-or-later · '
            '<a style="color:#63e7ff" href="https://www.gnu.org/licenses/agpl-3.0.html">License information</a>'
        )
        source.setOpenExternalLinks(True)
        layout.addWidget(source)
        layout.addStretch()
        return page

    def _page_selected(self, row: int) -> None:
        item = self.navigation.item(row) if row >= 0 else None
        page_index = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(page_index, int):
            return
        self.pages.setCurrentIndex(page_index)
        if page_index == PAGE_INVENTORY:
            self.load_inventory()
        elif page_index == PAGE_REPORTS:
            self.load_reports()
        elif page_index == PAGE_LOGS:
            self.load_analysis_logs()
        elif page_index == PAGE_ASSISTANT:
            self.load_assistant_issues()
        elif page_index == PAGE_STATUS:
            self.load_status()

    def _navigate_to_page(self, page_index: int) -> None:
        for row in range(self.navigation.count()):
            item = self.navigation.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == page_index:
                self.navigation.setCurrentItem(item)
                return

    def _search_guide(self, *, backward: bool) -> None:
        query = self.guide_search.text().strip()
        if not query:
            self.guide_search_status.setText("Enter a search term first.")
            self.guide_search.setFocus()
            return
        if query != self.guide_last_query:
            cursor = self.guide_viewer.textCursor()
            cursor.movePosition(
                QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start,
            )
            self.guide_viewer.setTextCursor(cursor)
            self.guide_last_query = query
        found = (
            self.guide_viewer.find(query, QTextDocument.FindFlag.FindBackward)
            if backward else self.guide_viewer.find(query)
        )
        wrapped = False
        if not found:
            cursor = self.guide_viewer.textCursor()
            cursor.movePosition(
                QTextCursor.MoveOperation.End if backward else QTextCursor.MoveOperation.Start,
            )
            self.guide_viewer.setTextCursor(cursor)
            found = (
                self.guide_viewer.find(query, QTextDocument.FindFlag.FindBackward)
                if backward else self.guide_viewer.find(query)
            )
            wrapped = found
        if found:
            direction = "previous" if backward else "next"
            suffix = " (wrapped)" if wrapped else ""
            self.guide_search_status.setText(f"Showing {direction} match for “{query}”{suffix}.")
            self.guide_viewer.ensureCursorVisible()
        else:
            self.guide_search_status.setText(f"No match found for “{query}”.")

    def search_guide_next(self) -> None:
        self._search_guide(backward=False)

    def search_guide_previous(self) -> None:
        self._search_guide(backward=True)

    def guide_to_top(self) -> None:
        cursor = self.guide_viewer.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.guide_viewer.setTextCursor(cursor)
        self.guide_viewer.ensureCursorVisible()
        self.guide_search_status.setText("Manual positioned at the beginning.")

    def open_guide_link(self, url: QUrl) -> None:
        """Resolve Markdown section links even when Qt omits heading anchors."""
        if url.scheme() or (url.path() and not url.fragment()):
            QDesktopServices.openUrl(url)
            return
        fragment = url.fragment() or url.toString().lstrip("#")
        sections = {
            "starting-the-application": "Starting the application",
            "dashboard": "Dashboard",
            "configuration": "Configuration",
            "technology-inventory": "Technology inventory",
            "reports-and-follow-up": "Reports and follow-up",
            "analysis-logs": "Analysis logs",
            "ai-issue-assistant": "AI issue assistant",
            "running-security-checks": "Running security checks",
            "system-status-and-ai-authentication": "System status and AI authentication",
            "configuration-backups": "Configuration backups",
            "about-version-and-license": "About, version, and license",
            "privacy-and-local-data": "Privacy and local data",
            "troubleshooting": "Troubleshooting",
        }
        title = sections.get(fragment.casefold(), fragment.replace("-", " "))
        index_cursor = self.guide_viewer.document().find(title)
        if index_cursor.isNull():
            self.guide_search_status.setText(f"Section not found: {title}.")
            return
        after_index = QTextCursor(index_cursor)
        after_index.setPosition(index_cursor.selectionEnd())
        heading_cursor = self.guide_viewer.document().find(title, after_index)
        cursor = heading_cursor if not heading_cursor.isNull() else index_cursor
        self.guide_viewer.setTextCursor(cursor)
        self.guide_viewer.ensureCursorVisible()
        self.guide_search_status.setText(f"Opened section “{title}”.")

    def refresh_all(self) -> None:
        self.load_inventory()
        self.load_reports()
        self.load_analysis_logs()
        self.load_status()
        default_profile, profiles, default_mode, modes = services.ai_options()
        self.profile_combo.clear()
        self.profile_combo.addItems(profiles)
        self.profile_combo.setCurrentText(default_profile)
        self.assistant_profile_combo.clear()
        self.assistant_profile_combo.addItems(profiles)
        self.assistant_profile_combo.setCurrentText(default_profile)
        self.mode_combo.clear()
        self.mode_combo.addItems(modes)
        self.mode_combo.setCurrentText(default_mode)
        statistics = services.security_statistics()
        self.dashboard_metrics["open"].setText(str(statistics["open"]))
        self.dashboard_metrics["today"].setText(str(statistics["today"]))
        self.dashboard_metrics["month"].setText(str(statistics["month"]))
        self.dashboard_metrics["projects"].setText(str(len(statistics["projects"])))
        self.priority_chart.set_data(statistics["priorities"])
        self.status_chart.set_data(statistics["statuses"])
        self.project_chart.set_data(statistics["projects"])
        self.language_chart.set_data(statistics["languages"])
        self.load_assistant_issues()
        metadata = services.project_metadata()
        self.about_metadata.setText(
            f"Name: {metadata['name']}\n"
            f"Version: {metadata['version']}\n"
            f"Author: {metadata['author']}\n"
            f"Last modified year: {metadata['last_modified_year']}\n"
            f"License: {metadata['license']}"
        )

    def load_configuration(self) -> None:
        for path, editor in self.config_editors.items():
            effective = services.effective_path_for_local(path)
            editor.setPlainText(effective.read_text(encoding="utf-8") if effective.is_file() else "")
            form = self.config_simple_forms.get(path)
            if form is not None:
                try:
                    data = services.validate_config_text(editor.toPlainText())
                except services.ConfigurationError:
                    data = {"schema_version": 1}
                form.load_data(data)
        self.update_configuration_view()

    def current_configuration(self) -> tuple[Path, QPlainTextEdit]:
        index = self.config_tabs.currentIndex()
        path = self.config_tab_paths[index]
        if path is None:
            raise services.ConfigurationError("The selected tab is an account-status view.")
        return path, self.config_editors[path]

    def validate_current_configuration(self) -> None:
        path, editor = self.current_configuration()
        try:
            if path in self.config_simple_forms and self.config_mode.currentIndex() == 0:
                self.sync_simple_configuration(path)
            services.validate_config_text(editor.toPlainText())
        except (ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Invalid configuration", f"{path.name}:\n\n{error}")
            return
        QMessageBox.information(self, "Configuration valid", f"{path.name} contains valid settings.")

    def save_current_configuration(self) -> None:
        path, editor = self.current_configuration()
        try:
            if path in self.config_simple_forms and self.config_mode.currentIndex() == 0:
                self.sync_simple_configuration(path)
        except (ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to save", str(error))
            return
        if QMessageBox.question(
            self, "Save configuration", f"Replace {path.relative_to(services.ROOT)} with the editor contents?",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            services.write_config_text(
                path, editor.toPlainText(), private=True,
            )
        except (OSError, ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to save", str(error))
            return
        self.statusBar().showMessage(f"Saved {path.relative_to(services.ROOT)}", 5000)
        self.update_configuration_view()
        self.refresh_all()

    def initialize_local_config(self) -> None:
        try:
            created = services.initialize_local_configuration()
        except OSError as error:
            QMessageBox.critical(self, "Unable to initialize", str(error))
            return
        QMessageBox.information(
            self, "Local configuration",
            f"Created {len(created)} local override file(s) under config/local/."
            if created else "All config/local/ override files already exist.",
        )
        self.load_configuration()

    def restore_factory_defaults(self) -> None:
        path, _editor = self.current_configuration()
        try:
            factory = services.factory_for_local(services.CONFIG_DIR, path)
        except KeyError as error:
            QMessageBox.critical(self, "Restore factory defaults", str(error))
            return
        extra_warning = (
            "\n\nThis also removes the currently detected inventory from the local file. "
            "Refresh inventory after restoring."
            if path == services.LOCAL_CONFIG else ""
        )
        if QMessageBox.question(
            self, "Restore factory defaults",
            f"Replace {path.relative_to(services.ROOT)} with the public factory file "
            f"{factory.relative_to(services.ROOT)}?\n\n"
            "All local changes in this section will be lost. A complete configuration "
            f"backup will be created first.{extra_warning}",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            backup = services.create_factory_restore_backup(services.ROOT)
            _factory, restored = services.restore_factory_configuration(path)
        except (
            OSError, KeyError, ValueError, services.ConfigurationError, services.BackupError,
        ) as error:
            QMessageBox.critical(self, "Restore failed", str(error))
            return
        self.load_configuration()
        self.refresh_all()
        QMessageBox.information(
            self, "Factory defaults restored",
            f"Restored: {restored.relative_to(services.ROOT)}\n"
            f"Safety backup: {backup['archive'].relative_to(services.ROOT)}",
        )

    def backup_configuration(self) -> None:
        if QMessageBox.question(
            self, "Back up configurations",
            "Create a private local ZIP containing the configured files?\n\n"
            "The archive remains under the Git-ignored output directory, but it is not encrypted.",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = services.create_configuration_backup(services.ROOT)
        except (OSError, services.BackupError) as error:
            QMessageBox.critical(self, "Backup failed", str(error))
            return
        QMessageBox.information(
            self, "Backup completed",
            f"Archive: {result['archive'].relative_to(services.ROOT)}\n"
            f"Files: {len(result['files'])}\n"
            f"SHA-256: {result['sha256']}",
        )
        self.load_status()

    def import_configuration_backup(self) -> None:
        initial = services.ROOT / "output/config-backups"
        filename, _selected_filter = QFileDialog.getOpenFileName(
            self, "Import configuration backup", str(initial), "ZIP archives (*.zip)",
        )
        if not filename:
            return
        archive = Path(filename)
        try:
            inspected = services.inspect_configuration_backup(services.ROOT, archive)
        except (OSError, services.BackupError) as error:
            QMessageBox.critical(self, "Invalid backup", str(error))
            return
        files = "\n".join(f"• {name}" for name in inspected["files"])
        sidecar = (
            "verified" if inspected["sidecar_verified"]
            else "not present; embedded file hashes verified"
        )
        if QMessageBox.question(
            self, "Confirm configuration import",
            f"Archive: {archive.name}\nCreated: {inspected['created_at']}\n"
            f"Archive checksum: {sidecar}\n\nFiles to replace:\n{files}\n\n"
            "A safety backup of the current configuration will be created first. Continue?",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            result = services.import_configuration_backup(services.ROOT, archive)
        except (OSError, services.BackupError) as error:
            QMessageBox.critical(self, "Import failed", str(error))
            return
        self.load_configuration()
        self.refresh_all()
        QMessageBox.information(
            self, "Import completed",
            f"Imported files: {len(result['files'])}\n"
            f"Safety backup: {result['safety_backup'].relative_to(services.ROOT)}",
        )

    def load_inventory(self) -> None:
        self.inventory_tree.blockSignals(True)
        self.inventory_tree.clear()
        projects = services.inventory_projects()
        for project in projects:
            settings = project.get("advisory_checks", {})
            if not isinstance(settings, dict):
                settings = {}
            item = QTreeWidgetItem((
                "",
                str(project.get("id", "unnamed")),
                "",
                ", ".join(map(str, project.get("roles", []))),
                ", ".join(services.technology_names(project)),
                str(project.get("path", "")),
            ))
            item.setData(0, Qt.ItemDataRole.UserRole, str(project.get("path", "")))
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(
                0, Qt.CheckState.Checked
                if settings.get("enabled", True) else Qt.CheckState.Unchecked,
            )
            self.inventory_tree.addTopLevelItem(item)
            preference = QComboBox()
            preference.addItem("-", "")
            preference.addItem("Codex", "codex")
            preference.addItem("Claude", "claude")
            selected = preference.findData(settings.get("preferred_ai") or "")
            preference.setCurrentIndex(max(0, selected))
            preference.setToolTip("Optional preferred AI for this project's advisory analysis")
            self.inventory_tree.setItemWidget(item, 2, preference)
        self.inventory_tree.blockSignals(False)
        self.update_inventory_count()

    def update_inventory_count(self, _item: QTreeWidgetItem | None = None, _column: int = 0) -> None:
        total = self.inventory_tree.topLevelItemCount()
        enabled = sum(
            self.inventory_tree.topLevelItem(index).checkState(0) == Qt.CheckState.Checked
            for index in range(total)
        )
        self.inventory_count.setText(
            f"{enabled} of {total} selected · inventory {services.inventory_age()}"
        )

    def save_inventory_preferences(self) -> None:
        preferences: dict[str, dict[str, object]] = {}
        for index in range(self.inventory_tree.topLevelItemCount()):
            item = self.inventory_tree.topLevelItem(index)
            selector = self.inventory_tree.itemWidget(item, 2)
            preferences[str(item.data(0, Qt.ItemDataRole.UserRole) or "")] = {
                "enabled": item.checkState(0) == Qt.CheckState.Checked,
                "preferred_ai": selector.currentData() if isinstance(selector, QComboBox) else None,
            }
        try:
            services.update_inventory_preferences(preferences)
        except (OSError, ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to save project choices", str(error))
            return
        self.load_inventory()
        QMessageBox.information(
            self, "Project choices saved",
            "Advisory inclusion and preferred AI choices were saved in ignored local configuration.",
        )

    def refresh_inventory(self) -> None:
        if QMessageBox.question(
            self, "Refresh inventory",
            "Scan the configured project roots in read-only mode and update the ignored local inventory?",
        ) == QMessageBox.StandardButton.Yes:
            self.start_action("refresh", assume_yes=True)

    def load_reports(self) -> None:
        current_path = None
        current = self.report_list.currentItem()
        if current:
            current_path = current.data(Qt.ItemDataRole.UserRole)
        self.report_list.clear()
        self.report_paths.clear()
        for index, (label, path) in enumerate(services.report_entries()):
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, str(path))
            self.report_list.addItem(item)
            self.report_paths[index] = path
            if current_path == str(path):
                self.report_list.setCurrentRow(index)
        if self.report_list.count() and self.report_list.currentRow() < 0:
            self.report_list.setCurrentRow(0)
        if not self.report_list.count():
            self.report_viewer.setMarkdown("# No reports yet\n\nRun a complete advisory check to create local output.")
            self.report_stack.setCurrentWidget(self.report_viewer)

    def show_report(self, row: int) -> None:
        path = self.report_paths.get(row)
        if not path or not path.is_file():
            return
        followup = services.ROOT / str(
            services.reports_config().get("followup_file", "output/followup.md")
        )
        if path.resolve() == followup.resolve():
            self.load_followup_table(path)
            self.report_stack.setCurrentWidget(self.followup_table)
            return
        self.report_stack.setCurrentWidget(self.report_viewer)
        self.report_viewer.setMarkdown(path.read_text(encoding="utf-8", errors="replace"))

    def load_analysis_logs(self) -> None:
        current_path = None
        current = self.logs_tree.currentItem()
        if current:
            current_path = current.data(0, Qt.ItemDataRole.UserRole)
        self.logs_tree.blockSignals(True)
        self.logs_tree.clear()
        parents: dict[tuple[str, ...], QTreeWidgetItem] = {}
        entries = services.analysis_run_entries()
        selected_item = None
        for entry in entries:
            year_key = (str(entry["year"]),)
            year_item = parents.get(year_key)
            if year_item is None:
                year_item = QTreeWidgetItem((year_key[0], "", ""))
                year_item.setFlags(year_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                self.logs_tree.addTopLevelItem(year_item)
                parents[year_key] = year_item
            month_key = (year_key[0], str(entry["month"]))
            month_item = parents.get(month_key)
            if month_item is None:
                month_item = QTreeWidgetItem((month_key[1], "", ""))
                month_item.setFlags(month_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                year_item.addChild(month_item)
                parents[month_key] = month_item
            label = str(entry["started"]).replace("T", " ").replace("+00:00", "Z")
            run_item = QTreeWidgetItem((label, str(entry["status"]), str(entry["coordinator"])))
            run_item.setData(0, Qt.ItemDataRole.UserRole, str(entry["path"]))
            month_item.addChild(run_item)
            if current_path == str(entry["path"]):
                selected_item = run_item
            year_item.setExpanded(True)
            month_item.setExpanded(True)
        self.logs_tree.blockSignals(False)
        self.analysis_log_count.setText(f"{len(entries)} archived run(s)")
        if selected_item is not None:
            self.logs_tree.setCurrentItem(selected_item)
        elif entries:
            first_year = self.logs_tree.topLevelItem(0)
            self.logs_tree.setCurrentItem(first_year.child(0).child(0))
        else:
            self.log_run_files = []
            self.log_file_combo.clear()
            self.analysis_log_viewer.setPlainText("No analysis logs have been created yet.")
            self.delete_log_button.setEnabled(False)

    def select_analysis_log_run(
        self, current: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None,
    ) -> None:
        path_text = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        self.delete_log_button.setEnabled(bool(path_text))
        self.log_file_combo.blockSignals(True)
        self.log_file_combo.clear()
        self.log_run_files = []
        if path_text:
            try:
                self.log_run_files = services.analysis_run_files(Path(str(path_text)))
            except (OSError, services.ConfigurationError) as error:
                self.analysis_log_viewer.setPlainText(str(error))
            else:
                self.log_file_combo.addItems([path.name for path in self.log_run_files])
        self.log_file_combo.blockSignals(False)
        if self.log_run_files:
            self.log_file_combo.setCurrentIndex(0)
            self.show_analysis_log_file(0)
        elif path_text:
            self.analysis_log_viewer.setPlainText("This run contains no readable log files.")

    def show_analysis_log_file(self, index: int) -> None:
        if not 0 <= index < len(self.log_run_files):
            return
        try:
            content = services.read_analysis_run_file(self.log_run_files[index])
        except (OSError, services.ConfigurationError) as error:
            content = str(error)
        self.analysis_log_viewer.setPlainText(content)

    def delete_selected_analysis_run(self) -> None:
        item = self.logs_tree.currentItem()
        path_text = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if not path_text:
            return
        run_id = Path(str(path_text)).name
        if QMessageBox.question(
            self, "Delete analysis log",
            f"Permanently delete the complete local log archive for {run_id}?\n\n"
            "This removes its summary, event log, routing plan, AI output, and evidence dossiers. "
            "Reports and scanned projects are not affected.",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = services.delete_analysis_run(Path(str(path_text)))
        except (OSError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to delete analysis log", str(error))
            return
        self.load_analysis_logs()
        self.statusBar().showMessage(f"Deleted analysis log {removed}", 10000)

    def load_followup_table(self, path: Path | None = None) -> None:
        activities = services.followup_activities(path)
        self.followup_table.setRowCount(len(activities))
        open_ids = {item.get("ID") for item in services.open_followup_activities(path)}
        for row, activity in enumerate(activities):
            advisory = activity.get("Advisory / CVE", "")
            first_advisory = advisory.split(";", 1)[0]
            source_links = services.followup_source_links(activity)
            source_html = ""
            if source_links:
                rendered = []
                for label, url in source_links:
                    short_label = label.rsplit("-", 1)[-1] if (
                        len(source_links) > 1 and label.upper().startswith("CVE-")
                    ) else label
                    rendered.append(
                        f'<a style="color:#63e7ff;" href="{html.escape(url, quote=True)}" '
                        f'title="{html.escape(label, quote=True)}">{html.escape(short_label)}</a>'
                    )
                rendered_links = " · ".join(rendered)
                source_html = f'<br><span style="color:#9fb8cc;">Source: {rendered_links}</span>'
            activity_label = QLabel(
                f"<b>{html.escape(activity.get('ID', ''))}</b><br>"
                f"{html.escape(first_advisory)}{source_html}"
            )
            activity_label.setStyleSheet("background: transparent; padding: 5px 6px;")
            activity_label.setTextFormat(Qt.TextFormat.RichText)
            activity_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
            activity_label.setOpenExternalLinks(True)
            activity_label.setWordWrap(True)
            activity_label.setToolTip(
                advisory + ("\n" + "\n".join(url for _label, url in source_links) if source_links else "")
            )
            self.followup_table.setCellWidget(row, 0, activity_label)
            values = (
                activity.get("Project", ""), activity.get("Priority", ""),
                activity.get("Owner", ""), activity.get("Status", ""),
                activity.get("Next action", ""),
            )
            for column, value in enumerate(values, start=1):
                item = self.followup_table.item(row, column)
                if item is None:
                    item = QTableWidgetItem()
                    self.followup_table.setItem(row, column, item)
                item.setText(value)
                item.setToolTip(value)
                if column == 2:
                    color = {
                        "critical": Qt.GlobalColor.red,
                        "high": Qt.GlobalColor.yellow,
                    }.get(value.casefold())
                    if color:
                        item.setForeground(color)
            issue_id = activity.get("ID", "")
            is_open = issue_id in open_ids
            existing = self.followup_table.cellWidget(row, 6)
            if existing and existing.property("issue_id") == issue_id:
                for button in existing.findChildren(QPushButton):
                    button.setEnabled(is_open)
                continue
            if existing:
                existing.hide()
                self.followup_table.removeCellWidget(row, 6)
                existing.deleteLater()
            action_cell = QWidget()
            action_cell.setObjectName("actionCell")
            action_cell.setProperty("issue_id", issue_id)
            action_layout = QHBoxLayout(action_cell)
            action_layout.setContentsMargins(4, 4, 4, 4)
            action_layout.setSpacing(6)
            solved = QPushButton("Set as solved")
            solved.setProperty("variant", "success")
            solved.setEnabled(is_open)
            solved.clicked.connect(
                lambda _checked=False, identifier=issue_id: self.set_followup_solved(identifier)
            )
            action_layout.addWidget(solved)
            chat = QPushButton("AI chat")
            chat.setProperty("variant", "ai")
            chat.setEnabled(is_open)
            chat.clicked.connect(
                lambda _checked=False, identifier=issue_id: self.open_followup_ai_chat(identifier)
            )
            action_layout.addWidget(chat)
            self.followup_table.setCellWidget(row, 6, action_cell)

    def set_followup_solved(self, issue_id: str) -> None:
        issue = next(
            (item for item in services.open_followup_activities() if item.get("ID") == issue_id),
            None,
        )
        if not issue:
            QMessageBox.information(self, "Already closed", f"Activity {issue_id} is no longer open.")
            self.load_reports()
            return
        evidence, accepted = QInputDialog.getMultiLineText(
            self, "Completion evidence",
            f"Evidence required to solve {issue_id} for {issue.get('Project')}:\n"
            "Include the verified version, environment, test, ticket, or procedure reference.",
        )
        evidence = evidence.strip()
        if not accepted:
            return
        if not evidence:
            QMessageBox.warning(
                self, "Evidence required",
                "The activity cannot be marked solved without completion evidence.",
            )
            return
        if QMessageBox.question(
            self, "Set activity as solved",
            f"ID: {issue_id}\nProject: {issue.get('Project')}\n\nEvidence:\n{evidence}\n\n"
            "Mark this exact follow-up activity as Completed?",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            services.update_followup_activity(issue_id, {
                "Status": "Completed",
                "Next action": "No further action",
                "Completion evidence": evidence,
            })
            services.archive_closed_followups(services.ROOT)
        except (OSError, ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to update follow-up", str(error))
            return
        self.refresh_all()
        QMessageBox.information(
            self, "Activity solved",
            f"{issue_id} was marked Completed with evidence and remains linked to {issue.get('Project')}.",
        )

    def open_followup_ai_chat(self, issue_id: str) -> None:
        self._navigate_to_page(PAGE_ASSISTANT)
        for index in range(self.assistant_issue_combo.count()):
            issue = self.assistant_issue_combo.itemData(index, Qt.ItemDataRole.UserRole)
            if isinstance(issue, dict) and issue.get("ID") == issue_id:
                self.assistant_issue_combo.setCurrentIndex(index)
                self._set_assistant_prompt(
                    "What should we do next to remediate or safely close this issue? "
                    "List the checks, evidence, and recommended resolution steps."
                )
                return
        QMessageBox.information(
            self, "Issue not open", f"Activity {issue_id} is not available among open follow-ups.",
        )

    def load_assistant_issues(self) -> None:
        current = self.assistant_issue_combo.currentData(Qt.ItemDataRole.UserRole)
        current_id = current.get("ID") if isinstance(current, dict) else None
        self.assistant_issue_combo.blockSignals(True)
        self.assistant_issue_combo.clear()
        for issue in services.open_followup_activities():
            label = (
                f"{issue.get('Project', 'unknown')}  |  {issue.get('ID', 'unknown')}  |  "
                f"{issue.get('Priority', 'unknown')}  |  {issue.get('Status', 'unknown')}"
            )
            self.assistant_issue_combo.addItem(label, issue)
            if issue.get("ID") == current_id:
                self.assistant_issue_combo.setCurrentIndex(self.assistant_issue_combo.count() - 1)
        self.assistant_issue_combo.blockSignals(False)
        self.load_assistant_conversation()

    def selected_assistant_issue(self) -> dict[str, str] | None:
        value = self.assistant_issue_combo.currentData(Qt.ItemDataRole.UserRole)
        return value if isinstance(value, dict) else None

    def load_assistant_conversation(self, _index: int | None = None) -> None:
        issue = self.selected_assistant_issue()
        self.pending_issue_update = None
        self.assistant_apply_button.setEnabled(False)
        if not issue:
            self.assistant_project_label.setText("No project selected")
            self.assistant_issue_details.setText("No open follow-up activity selected.")
            self.assistant_conversation.clear()
            self.assistant_send_button.setEnabled(False)
            return
        self.assistant_send_button.setEnabled(
            self.chat_process.state() == QProcess.ProcessState.NotRunning
        )
        project = str(issue.get("Project") or "Unknown project")
        self.assistant_project_label.setText(project)
        self.assistant_project_label.setToolTip(project)
        priority = html.escape(str(issue.get("Priority") or "Unknown"))
        priority_color = {
            "critical": "#df7f7f", "high": "#e5bb62", "medium": "#9fd3e5",
            "low": "#8fd3a4",
        }.get(priority.casefold(), "#c9dded")
        self.assistant_issue_details.setText(
            f'<span style="color:#7890a8;">ACTIVITY</span> '
            f'<b>{html.escape(str(issue.get("ID") or "Unknown"))}</b><br>'
            f'<span style="color:#7890a8;">ADVISORY</span> '
            f'<b>{html.escape(str(issue.get("Advisory / CVE") or "Unknown"))}</b><br>'
            f'<span style="color:{priority_color};"><b>{priority}</b></span> priority &nbsp;·&nbsp; '
            f'{html.escape(str(issue.get("Status") or "Unknown"))} &nbsp;·&nbsp; '
            f'Owner: {html.escape(str(issue.get("Owner") or "Unassigned"))}<br>'
            f'<span style="color:#7890a8;">NEXT</span> '
            f'{html.escape(str(issue.get("Next action") or "Not specified"))}'
        )
        entries = services.assistant_history(issue.get("ID", "general"))
        if not entries:
            self.assistant_conversation.setHtml(
                "<p style='color:#7890a8'><i>No local conversation for this issue yet.</i></p>"
            )
            return
        blocks = []
        for entry in entries:
            user = entry.get("role") == "user"
            label = "You" if user else "AI assistant"
            color = "#63e7ff" if user else "#c4b5fd"
            content = html.escape(entry.get("content", "")).replace("\n", "<br>")
            blocks.append(
                f"<p><b style='color:{color}'>{label}</b><br>{content}</p>"
            )
        self.assistant_conversation.setHtml("".join(blocks))
        self.assistant_conversation.moveCursor(QTextCursor.MoveOperation.End)

    def _set_assistant_prompt(self, text: str) -> None:
        self.assistant_input.setPlainText(text)
        self.assistant_input.setFocus()
        self.assistant_input.moveCursor(QTextCursor.MoveOperation.End)

    def send_assistant_message(self) -> None:
        issue = self.selected_assistant_issue()
        message = self.assistant_input.toPlainText().strip()
        if not issue:
            QMessageBox.warning(self, "No open issue", "Select an open follow-up activity first.")
            return
        if not message:
            QMessageBox.warning(self, "Empty message", "Write a question or issue update first.")
            return
        if self.chat_process.state() != QProcess.ProcessState.NotRunning:
            QMessageBox.warning(self, "Assistant busy", "Wait for the current AI response.")
            return
        issue_id = issue.get("ID", "")
        history = services.assistant_history(issue_id)
        prompt = services.assistant_prompt(issue, message, history)
        try:
            command = services.assistant_command(
                self.assistant_provider_combo.currentText(),
                self.assistant_profile_combo.currentText(), prompt,
            )
            services.append_assistant_history(issue_id, "user", message)
        except (OSError, services.ConfigurationError, ValueError) as error:
            QMessageBox.critical(self, "Unable to start AI assistant", str(error))
            return
        self.assistant_input.clear()
        self.chat_response = ""
        self.pending_issue_update = None
        self.assistant_apply_button.setEnabled(False)
        self.assistant_send_button.setEnabled(False)
        self.statusBar().showMessage(f"Waiting for AI guidance on {issue_id}…")
        self.load_assistant_conversation()
        self.assistant_send_button.setEnabled(False)
        self.chat_process.setProperty("issue_id", issue_id)
        self.chat_process.start(command[0], command[1:])
        self.chat_process.closeWriteChannel()

    def _read_chat_output(self) -> None:
        self.chat_response += bytes(
            self.chat_process.readAllStandardOutput()
        ).decode("utf-8", errors="replace")

    def _chat_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self._read_chat_output()
        issue_id = str(self.chat_process.property("issue_id") or "")
        if exit_code != 0:
            error = bytes(self.chat_process.readAllStandardError()).decode(
                "utf-8", errors="replace",
            ).strip()
            QMessageBox.critical(
                self, "AI assistant failed",
                error or f"The AI process exited with code {exit_code}.",
            )
            self.assistant_send_button.setEnabled(bool(self.selected_assistant_issue()))
            self.statusBar().showMessage("AI assistant failed", 8000)
            return
        visible, proposal = services.extract_issue_update(self.chat_response)
        if not visible:
            visible = "The AI returned no explanatory text."
        try:
            services.append_assistant_history(issue_id, "assistant", visible)
        except OSError as error:
            QMessageBox.warning(self, "Conversation history", str(error))
        self.load_assistant_conversation()
        if proposal:
            self.pending_issue_update = (issue_id, proposal)
            self.assistant_apply_button.setEnabled(True)
            self.statusBar().showMessage(
                f"AI proposed an update for {issue_id}; review it before applying", 10000,
            )
        else:
            self.statusBar().showMessage("AI guidance received", 5000)
        self.assistant_send_button.setEnabled(bool(self.selected_assistant_issue()))

    def apply_assistant_update(self) -> None:
        if not self.pending_issue_update:
            return
        issue_id, proposal = self.pending_issue_update
        issue = next(
            (item for item in services.followup_activities() if item.get("ID") == issue_id),
            None,
        )
        if not issue:
            QMessageBox.critical(self, "Issue unavailable", f"Follow-up activity {issue_id} no longer exists.")
            return
        try:
            changes = services.proposal_changes(proposal)
        except services.ConfigurationError as error:
            QMessageBox.warning(self, "Incomplete proposal", str(error))
            return
        summary = "\n".join(f"{field}: {value}" for field, value in changes.items())
        if QMessageBox.question(
            self, "Apply follow-up update",
            f"Update only this activity?\n\nID: {issue_id}\nProject: {issue.get('Project')}\n\n{summary}\n\n"
            "This changes the ignored local follow-up report.",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            services.update_followup_activity(issue_id, changes)
            services.archive_closed_followups(services.ROOT)
        except (OSError, ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to update follow-up", str(error))
            return
        self.pending_issue_update = None
        self.assistant_apply_button.setEnabled(False)
        self.refresh_all()
        QMessageBox.information(
            self, "Follow-up updated",
            f"Activity {issue_id} for {issue.get('Project')} was updated and remains linked by ID.",
        )

    def load_status(self) -> None:
        rows = services.component_status()
        self.status_table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = self.status_table.item(row, column)
                if item is None:
                    item = QTableWidgetItem()
                    self.status_table.setItem(row, column, item)
                item.setText(value)
                if column == 1:
                    item.setForeground(
                        Qt.GlobalColor.green if value == "Ready" else
                        (Qt.GlobalColor.yellow if value in {"Optional", "Not created", "Login required"}
                         else Qt.GlobalColor.red)
                    )
            component, state, _details = values
            actions = []
            if component == "Configuration backup":
                actions = [
                    ("Back up", self.backup_configuration),
                    ("Import", self.import_configuration_backup),
                ]
            elif component == "Linux desktop launcher":
                actions = [
                    ("Remove", self.remove_desktop_launcher)
                    if state == "Ready" else
                    ("Install", self.install_desktop_launcher)
                ]
            elif state != "Ready" and component == "Local configuration":
                actions = [("Initialize", self.initialize_local_config)]
            elif state != "Ready" and component == "Inventory":
                actions = [("Refresh", self.refresh_inventory)]
            elif state == "Login required" and component in {"codex", "claude"}:
                actions = [(
                    "Log in",
                    lambda _checked=False, name=component: self.login_agent(name),
                )]
            elif state != "Ready" and services.installation_plan(component):
                actions = [(
                    "Install",
                    lambda _checked=False, name=component: self.install_component(name),
                )]

            existing = self.status_table.cellWidget(row, 3)
            if not actions:
                if existing:
                    existing.hide()
                    self.status_table.removeCellWidget(row, 3)
                    existing.deleteLater()
                continue
            action_signature = "|".join(label for label, _handler in actions)
            if (
                existing and existing.property("component") == component
                and existing.property("actions") == action_signature
            ):
                continue
            if existing:
                existing.hide()
                self.status_table.removeCellWidget(row, 3)
                existing.deleteLater()
            action_cell = QWidget()
            action_cell.setObjectName("actionCell")
            action_cell.setProperty("component", component)
            action_cell.setProperty("actions", action_signature)
            action_layout = QHBoxLayout(action_cell)
            action_layout.setContentsMargins(4, 3, 4, 3)
            action_layout.setSpacing(6)
            for label, handler in actions:
                button = QPushButton(label)
                button.setProperty("variant", {
                    "Back up": "success",
                    "Import": "danger",
                    "Install": "warning",
                    "Log in": "warning",
                    "Initialize": "warning",
                    "Refresh": "secondary",
                    "Remove": "danger",
                }.get(label, "secondary"))
                button.setMinimumHeight(32)
                button.clicked.connect(handler)
                action_layout.addWidget(button)
            self.status_table.setCellWidget(row, 3, action_cell)
        for provider in self.agent_account_widgets:
            self.refresh_agent_account(provider)

    def install_desktop_launcher(self) -> None:
        if QMessageBox.question(
            self, "Install application launcher",
            "Add fAIry Security Advisory and its icon to the current Linux user's "
            "application menu?\n\nNo administrator privileges are required.",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            desktop_path, _icon_path = services.install_desktop_launcher()
        except OSError as error:
            QMessageBox.critical(self, "Desktop integration failed", str(error))
            return
        self.load_status()
        QMessageBox.information(
            self, "Application launcher installed",
            f"Installed: {desktop_path}\n\nThe menu may take a few seconds to refresh.",
        )

    def remove_desktop_launcher(self) -> None:
        if QMessageBox.question(
            self, "Remove application launcher",
            "Remove fAIry Security Advisory from the current user's application menu?\n\n"
            "The project, configuration, reports, and backups will not be removed.",
        ) != QMessageBox.StandardButton.Yes:
            return
        try:
            desktop_path, _icon_path = services.remove_desktop_launcher()
        except OSError as error:
            QMessageBox.critical(self, "Unable to remove desktop integration", str(error))
            return
        self.load_status()
        QMessageBox.information(
            self, "Application launcher removed", f"Removed: {desktop_path}",
        )

    def login_agent(self, provider: str) -> None:
        """Open the provider's official interactive login in a visible terminal."""
        executable = services.resolve_agent_executable(provider)
        if not executable:
            self.install_component(provider)
            return
        command = (
            [executable, "login"] if provider == "codex"
            else [executable, "auth", "login"]
        )
        if QMessageBox.question(
            self, f"Log in to {provider}",
            f"Open the official {provider} account login in a terminal?\n\n"
            "Credentials and tokens are handled by the CLI and are never stored by fAIry.",
        ) != QMessageBox.StandardButton.Yes:
            return
        terminal = next(
            (path for name in ("x-terminal-emulator", "gnome-terminal", "konsole")
             if (path := shutil.which(name))),
            None,
        )
        if not terminal:
            QApplication.clipboard().setText(shlex.join(command))
            QMessageBox.warning(
                self, "Terminal unavailable",
                "No supported terminal emulator was found. The login command was copied to the clipboard.",
            )
            return
        script = (
            f"{shlex.join(command)}\n"
            "status=$?\n"
            "printf '\\nAuthentication finished with exit code %s.\\n' \"$status\"\n"
            "printf 'Return to fAIry, refresh System status, then press Enter to close…'\n"
            "read -r _\n"
            "exit \"$status\""
        )
        arguments = (
            ["--", "bash", "-lc", script]
            if Path(terminal).name == "gnome-terminal"
            else ["-e", "bash", "-lc", script]
        )
        result = QProcess.startDetached(terminal, arguments, str(services.ROOT))
        started = result[0] if isinstance(result, tuple) else bool(result)
        if not started:
            QApplication.clipboard().setText(shlex.join(command))
            QMessageBox.critical(
                self, "Unable to open terminal",
                "The login terminal could not be started. The command was copied to the clipboard.",
            )
            return
        self.statusBar().showMessage(
            f"{provider} login opened; refresh System status when authentication finishes", 12000,
        )

    def install_component(self, component: str) -> None:
        """Review and launch a fixed installation plan in a visible terminal."""
        plan = services.installation_plan(component)
        if not plan:
            QMessageBox.information(
                self, "Installation unavailable",
                f"No automatic installation plan is available for {component} on this system.",
            )
            return
        if plan.get("blocked"):
            dialog = QMessageBox(self)
            dialog.setIcon(QMessageBox.Icon.Warning)
            dialog.setWindowTitle(f"Cannot install {component} safely")
            dialog.setText(f"{plan['blocked']}\n\nNo installation command will be executed.")
            dialog.setDetailedText(plan["command"])
            documentation_button = dialog.addButton(
                "Open official documentation", QMessageBox.ButtonRole.ActionRole,
            )
            dialog.addButton(QMessageBox.StandardButton.Cancel)
            dialog.exec()
            if dialog.clickedButton() == documentation_button:
                QDesktopServices.openUrl(QUrl(plan["documentation"]))
            return
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setWindowTitle(f"Install {component}")
        dialog.setText(
            f"This command changes the local system and may download software.\n\n"
            f"{plan['note']}\n\nOfficial documentation:\n{plan['documentation']}"
        )
        dialog.setDetailedText(plan["command"])
        install_button = dialog.addButton("Install in terminal", QMessageBox.ButtonRole.AcceptRole)
        copy_button = dialog.addButton("Copy command", QMessageBox.ButtonRole.ActionRole)
        dialog.addButton(QMessageBox.StandardButton.Cancel)
        dialog.exec()
        if dialog.clickedButton() == copy_button:
            QApplication.clipboard().setText(plan["command"])
            self.statusBar().showMessage(f"Copied {component} installation command", 5000)
            return
        if dialog.clickedButton() != install_button:
            return

        terminal = next(
            (path for name in ("x-terminal-emulator", "gnome-terminal", "konsole")
             if (path := shutil.which(name))),
            None,
        )
        if not terminal:
            QApplication.clipboard().setText(plan["command"])
            QMessageBox.warning(
                self, "Terminal unavailable",
                "No supported terminal emulator was found. The command was copied to the clipboard.",
            )
            return
        script = (
            "set -o pipefail\n"
            f"{plan['command']}\n"
            "status=$?\n"
            "printf '\\nInstallation finished with exit code %s.\\n' \"$status\"\n"
            "printf 'Press Enter to close this terminal…'\n"
            "read -r _\n"
            "exit \"$status\""
        )
        if Path(terminal).name == "gnome-terminal":
            arguments = ["--", "bash", "-lc", script]
        else:
            arguments = ["-e", "bash", "-lc", script]
        result = QProcess.startDetached(terminal, arguments, str(services.ROOT))
        started = result[0] if isinstance(result, tuple) else bool(result)
        if not started:
            QApplication.clipboard().setText(plan["command"])
            QMessageBox.critical(
                self, "Unable to open terminal",
                "The installation terminal could not be started. The command was copied to the clipboard.",
            )
            return
        self.statusBar().showMessage(
            f"{component} installer opened; refresh system status when it finishes", 10000,
        )

    def run_ai_analysis(self) -> None:
        provider = self.provider_combo.currentText()
        profile = self.profile_combo.currentText()
        mode = self.mode_combo.currentText()
        try:
            routing = services.analysis_routing(provider)
            models = {
                name: services.ai_model(name, profile)
                for name in routing["required_providers"]
            }
        except (ValueError, services.ConfigurationError) as error:
            QMessageBox.critical(self, "Unable to build analysis plan", str(error))
            return
        if not routing["selected"]:
            QMessageBox.warning(
                self, "No projects selected",
                "Select at least one project in Technology inventory before running analysis.",
            )
            return
        model_summary = ", ".join(
            f"{name}: {models[name]}" for name in routing["required_providers"]
        )
        if QMessageBox.question(
            self, "Start AI analysis",
            f"Start routed analysis with {provider} as coordinator, profile {profile}, "
            f"and {mode} mode?\n\n"
            f"Projects — {routing['summary']}\n"
            f"Models — {model_summary}\n\n"
            "Projects with '-' use the coordinator. Preferred Codex/Claude projects "
            "use that provider.\n\n"
            "The agent may access the network and update ignored local output files.",
        ) != QMessageBox.StandardButton.Yes:
            return
        self.start_action(
            "ai-check", provider=provider, profile=profile, mode=mode,
            assume_yes=True, non_interactive=True,
        )

    def start_action(
        self, action: str, *, provider: str | None = None,
        profile: str | None = None, mode: str | None = None,
        assume_yes: bool = False, non_interactive: bool = False,
    ) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            QMessageBox.warning(self, "Process already running", "Stop or wait for the current operation first.")
            return
        command = services.action_command(
            action, provider=provider, profile=profile, mode=mode,
            assume_yes=assume_yes, non_interactive=non_interactive,
        )
        self._navigate_to_page(PAGE_RUN)
        self.log.appendPlainText(f"\n$ {shlex.join(command)}\n")
        self.current_action = action
        self.process_output_buffer = ""
        if action == "ai-check":
            self._start_analysis_activity()
        self.stop_button.setEnabled(True)
        self.statusBar().showMessage(f"Running {action}…")
        self.process.start(command[0], command[1:])
        self.process.closeWriteChannel()

    def _read_process_output(self) -> None:
        data = bytes(self.process.readAllStandardOutput()).decode("utf-8", errors="replace")
        if not data:
            return
        self.process_output_buffer += data
        visible_lines: list[str] = []
        while "\n" in self.process_output_buffer:
            line, self.process_output_buffer = self.process_output_buffer.split("\n", 1)
            if not self._consume_analysis_progress_line(line):
                visible_lines.append(line + "\n")
        if visible_lines:
            self._append_process_output("".join(visible_lines))

    def _append_process_output(self, text: str) -> None:
        self.log.moveCursor(QTextCursor.MoveOperation.End)
        self.log.insertPlainText(text)
        self.log.ensureCursorVisible()

    def _consume_analysis_progress_line(self, line: str) -> bool:
        prefix = "::fairy-analysis-progress::"
        if not line.startswith(prefix):
            return False
        try:
            event = json.loads(line[len(prefix):])
        except (json.JSONDecodeError, TypeError):
            return False
        if isinstance(event, dict):
            self._handle_analysis_progress(event)
            return True
        return False

    def _start_analysis_activity(self) -> None:
        self.analysis_activity_generation += 1
        self.analysis_started_at = time.monotonic()
        self.analysis_spinner_index = 0
        self.analysis_activity_base = "Preparing advisory analysis"
        self.analysis_project_progress.setRange(0, 0)
        self.analysis_project_progress.setFormat("Preparing…")
        self.global_analysis_progress.setRange(0, 0)
        self.global_analysis_label.setVisible(True)
        self.global_analysis_progress.setVisible(True)
        self.analysis_activity_timer.start()
        self._update_analysis_activity_clock()

    def _handle_analysis_progress(self, event: dict[str, object]) -> None:
        phase = str(event.get("phase") or "analysis").replace("_", " ")
        status = str(event.get("status") or "running")
        provider = str(event.get("provider") or "AI").title()
        completed = max(0, int(event.get("completed") or 0))
        total = max(0, int(event.get("total") or 0))
        active = max(0, int(event.get("active_projects") or 0))
        message = str(event.get("message") or phase.title())

        if total:
            completed = min(completed, total)
            for progress in (self.analysis_project_progress, self.global_analysis_progress):
                progress.setRange(0, total)
                progress.setValue(completed)
            self.analysis_project_progress.setFormat(f"{completed} / {total} projects")
            self.global_analysis_progress.setFormat(f"{completed}/{total}")
        activity = f"{provider} · {message}"
        if active:
            noun = "project" if active == 1 else "projects"
            activity += f" · {active} {noun}"
        self.analysis_activity_base = activity
        self._update_analysis_activity_clock()
        if status == "failed":
            self._finish_analysis_activity(False, activity)
        elif status == "completed" and phase == "complete":
            self._finish_analysis_activity(True, activity)

    def _update_analysis_activity_clock(self) -> None:
        if self.analysis_started_at is None:
            return
        frames = ("◐", "◓", "◑", "◒")
        frame = frames[self.analysis_spinner_index % len(frames)]
        self.analysis_spinner_index += 1
        text = f"{frame} {self.analysis_activity_base}"
        self.analysis_activity_label.setText(text)
        self.global_analysis_label.setText(text)
        elapsed = max(0, int(time.monotonic() - self.analysis_started_at))
        minutes, seconds = divmod(elapsed, 60)
        self.analysis_elapsed_label.setText(f"Elapsed {minutes:02d}:{seconds:02d}")

    def _finish_analysis_activity(self, successful: bool, detail: str = "") -> None:
        if self.analysis_started_at is None:
            return
        self.analysis_activity_timer.stop()
        state = "Completed" if successful else "Failed"
        symbol = "✓" if successful else "!"
        suffix = f" · {detail}" if detail else ""
        final_text = f"{symbol} Analysis {state.lower()}{suffix}"
        self.analysis_activity_label.setText(final_text)
        self.global_analysis_label.setText(final_text)
        if successful and self.analysis_project_progress.maximum() > 0:
            maximum = self.analysis_project_progress.maximum()
            self.analysis_project_progress.setValue(maximum)
            self.global_analysis_progress.setValue(maximum)
        self.analysis_started_at = None
        generation = self.analysis_activity_generation
        QTimer.singleShot(10000, lambda: self._hide_finished_analysis_activity(generation))

    def _hide_finished_analysis_activity(self, generation: int) -> None:
        if generation != self.analysis_activity_generation or self.analysis_started_at is not None:
            return
        self.global_analysis_label.setVisible(False)
        self.global_analysis_progress.setVisible(False)

    def _process_finished(self, exit_code: int, _status: QProcess.ExitStatus) -> None:
        self._read_process_output()
        if self.process_output_buffer:
            if not self._consume_analysis_progress_line(self.process_output_buffer):
                self._append_process_output(self.process_output_buffer)
            self.process_output_buffer = ""
        self.log.appendPlainText(f"\nProcess finished with exit code {exit_code}.\n")
        if self.current_action == "ai-check" and self.analysis_started_at is not None:
            self._finish_analysis_activity(exit_code == 0)
        self.current_action = None
        self.stop_button.setEnabled(False)
        self.statusBar().showMessage(
            "Operation completed" if exit_code == 0 else f"Operation failed with exit code {exit_code}", 8000,
        )
        if exit_code == 0:
            try:
                services.archive_closed_followups(services.ROOT)
            except (OSError, ValueError) as error:
                self.log.appendPlainText(f"\nFollow-up archival warning: {error}\n")
        self.refresh_all()

    def stop_process(self) -> None:
        if self.process.state() == QProcess.ProcessState.NotRunning:
            return
        if self.current_action == "ai-check" and self.analysis_started_at is not None:
            self.analysis_activity_base = "Stopping advisory analysis"
        self.process.terminate()
        QTimer.singleShot(3000, self._kill_if_running)

    def _kill_if_running(self) -> None:
        if self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()

    def closeEvent(self, event: QCloseEvent) -> None:
        active = [
            process for process in (self.process, self.chat_process)
            if process.state() != QProcess.ProcessState.NotRunning
        ]
        if active:
            answer = QMessageBox.question(
                self, "Process running", "Stop the active process or AI conversation and close the application?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            for process in active:
                process.kill()
                process.waitForFinished(2000)
        event.accept()
