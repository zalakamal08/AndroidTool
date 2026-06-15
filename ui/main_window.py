import os
import sys
from pathlib import Path
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget,
                             QTextEdit, QPushButton, QMessageBox, QLabel)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QTextCursor
from ui.home_tab import HomeTab
from ui.install_tab import InstallTab
from ui.extract_tab import ExtractTab
from ui.frida_tab import FridaTab
from ui.state_manager import StateManager


def _inject_platform_tools_path():
    """
    Inject the bundled platform-tools directory into this process's PATH
    at startup so ADB works immediately if platform-tools is already present.
    """
    project_root = Path(__file__).parent.parent
    pt_dir = project_root / "tools" / "platform-tools"
    adb_name = "adb.exe" if os.name == "nt" else "adb"
    if (pt_dir / adb_name).exists():
        pt_str = str(pt_dir)
        current = os.environ.get("PATH", "")
        if pt_str not in current:
            os.environ["PATH"] = pt_str + os.pathsep + current


class AndroidPentestTool(QMainWindow):
    def __init__(self):
        super().__init__()
        # Inject bundled ADB path at startup
        _inject_platform_tools_path()

        # Shared state: last extracted/selected APK path for cross-tab flow
        self._last_selected_apk: str = ""

        self.state = StateManager.instance()
        self.init_ui()

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def init_ui(self):
        self.setWindowTitle("Android APK Pentesting Tool")
        self.setGeometry(100, 100, 920, 720)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Credits Footer
        footer_label = QLabel("Developed with 💡 by <b>zalakamal08</b> & <b>patelharsch</b>")
        footer_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        footer_label.setStyleSheet("color: #808080; font-size: 11px; margin-top: 5px; margin-right: 5px;")
        main_layout.addWidget(footer_label)

        # Console
        self.console = QTextEdit()
        self.console.setReadOnly(True)

        # Home Tab
        self.home_tab = HomeTab(self)
        self.tabs.addTab(self.home_tab, "🏠 Home")

        # Install Tab
        self.install_tab = InstallTab(self)
        self.tabs.addTab(self.install_tab, "🔧 Install Tools")

        # Extract APK Tab
        self.extract_tab = ExtractTab(self)
        self.tabs.addTab(self.extract_tab, "📱 Extract APK")

        # Console Tab
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        console_layout.addWidget(self.console)
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.console.clear)
        console_layout.addWidget(clear_btn)
        self.tabs.addTab(console_tab, "📋 Console")

        # Frida Tab
        self.frida_tab = FridaTab(self)
        self.tabs.addTab(self.frida_tab, "🍃 Frida")

        # Status bar
        self.statusBar().showMessage("Ready")

        self._apply_styles()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log(self, message: str, level: str = "info"):
        """Append a colour-coded, timestamped message to the console and auto-scroll."""
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")

        # level → (hex colour, prefix shown in the console)
        style = {
            "info":    ("#00ff00", "INFO"),
            "warning": ("#ffaa00", "WARN"),
            "error":   ("#ff4444", "ERR "),
            "success": ("#00e5ff", " OK "),
            # cmd  — shell command being executed (blue, $ prefix)
            "cmd":     ("#569cd6", " $  "),
            # output — raw tool stdout (muted grey, no prefix noise)
            "output":  ("#9e9e9e", "    "),
        }
        color, prefix = style.get(level, ("#00ff00", "INFO"))

        if not message:
            return

        self.console.append(
            f'<span style="color:#555555;">[{ts}]</span> '
            f'<span style="color:{color};">[{prefix}] {message}</span>'
        )
        self.console.moveCursor(QTextCursor.MoveOperation.End)

    # ------------------------------------------------------------------
    # Tab switching helpers
    # ------------------------------------------------------------------

    def switch_to_extract_tab(self):
        self.tabs.setCurrentWidget(self.extract_tab)

    def switch_to_install_tab(self):
        self.tabs.setCurrentWidget(self.install_tab)

    def switch_to_home_tab(self):
        self.tabs.setCurrentWidget(self.home_tab)

    # ------------------------------------------------------------------
    # Cross-tab APK path sharing
    # ------------------------------------------------------------------

    def set_last_selected_apk(self, path: str):
        """Store the most recently selected/extracted APK for cross-tab use."""
        self._last_selected_apk = path

    def get_last_selected_apk(self) -> str:
        return self._last_selected_apk

    # ------------------------------------------------------------------
    # Active worker tracking (for safe close)
    # ------------------------------------------------------------------

    def get_active_workers(self) -> list:
        """Return all QThread workers that are currently running."""
        workers = []
        for tab in [self.home_tab, self.extract_tab, self.frida_tab]:
            w = getattr(tab, "worker", None)
            if w is not None and w.isRunning():
                workers.append(w)
        return workers

    # ------------------------------------------------------------------
    # Close event — ask user if operation is in progress
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        workers = self.get_active_workers()
        if workers:
            reply = QMessageBox.question(
                self,
                "Operation in Progress",
                "An operation is currently running.\n\nExit anyway? "
                "(The background process will be terminated.)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.No:
                event.ignore()
                return
            # Terminate running workers
            for w in workers:
                w.terminate()
                w.wait(2000)  # Wait up to 2 s

        event.accept()

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------

    def _apply_styles(self):
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
                font-size: 13px;
            }

            QTabWidget::pane {
                background-color: #252526;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
            }

            QTabBar::tab {
                background-color: #2d2d2d;
                color: #808080;
                padding: 10px 20px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }

            QTabBar::tab:selected {
                background-color: #252526;
                color: #ffffff;
            }

            QTabBar::tab:hover:!selected {
                background-color: #3c3c3c;
            }

            QLineEdit {
                background-color: #2d2d2d;
                color: #e0e0e0;
                padding: 8px 12px;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
            }

            QLineEdit:focus {
                border: 1px solid #0078d4;
            }

            QPushButton {
                background-color: #0078d4;
                color: white;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }

            QPushButton:hover {
                background-color: #1084d8;
            }

            QPushButton:pressed {
                background-color: #006cbd;
            }

            QPushButton:disabled {
                background-color: #3c3c3c;
                color: #808080;
            }

            QListWidget {
                background-color: #2d2d2d;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 4px;
            }

            QListWidget::item {
                padding: 6px 8px;
                border-radius: 2px;
            }

            QListWidget::item:selected {
                background-color: #0078d4;
            }

            QListWidget::item:hover:!selected {
                background-color: #3c3c3c;
            }

            QTextEdit {
                background-color: #1e1e1e;
                color: #00ff00;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 8px;
            }

            QProgressBar {
                background-color: #2d2d2d;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                text-align: center;
            }

            QProgressBar::chunk {
                background-color: #0078d4;
                border-radius: 3px;
            }

            QStatusBar {
                background-color: #007acc;
                color: white;
            }

            QScrollBar:vertical {
                background-color: #2d2d2d;
                width: 10px;
            }

            QScrollBar::handle:vertical {
                background-color: #5a5a5a;
                border-radius: 5px;
                min-height: 20px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #787878;
            }

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }

            QGroupBox {
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                margin-top: 10px;
                padding-top: 10px;
                font-weight: bold;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }

            QCheckBox {
                spacing: 8px;
                padding: 5px;
            }

            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 3px;
                border: 1px solid #3c3c3c;
                background-color: #2d2d2d;
            }

            QCheckBox::indicator:checked {
                background-color: #0078d4;
                border-color: #0078d4;
            }

            QComboBox {
                background-color: #2d2d2d;
                color: #e0e0e0;
                border: 1px solid #3c3c3c;
                border-radius: 4px;
                padding: 6px 10px;
            }

            QComboBox::drop-down {
                border: none;
            }

            QComboBox QAbstractItemView {
                background-color: #2d2d2d;
                color: #e0e0e0;
                selection-background-color: #0078d4;
            }
        """)