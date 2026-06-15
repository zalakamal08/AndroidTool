import os
import zipfile
import re
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QProgressBar, QGroupBox,
    QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QFrame, QTextEdit,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

from workers.apk_worker import APKWorker
from workers.adb_worker import ADBWorker
from ui.state_manager import StateManager, DIR_APK_HOME, DIR_AAB_HOME, DIR_MERGE, DIR_OUTPUT


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _open_folder(path: str):
    folder = Path(path)
    if not folder.is_dir():
        folder = folder.parent
    if os.name == "nt":
        os.startfile(str(folder))
    else:
        import subprocess
        subprocess.Popen(["xdg-open", str(folder)])


def _read_apk_info(apk_path: str) -> dict:
    """
    Quick APK metadata using aapt if available, otherwise binary search fallback.
    """
    info = {"package": "", "version_name": "", "version_code": "", "min_sdk": ""}
    try:
        pt_dir = Path(__file__).parent.parent / "tools" / "platform-tools"
        aapt   = pt_dir / ("aapt.exe" if os.name == "nt" else "aapt")
        if aapt.exists():
            import subprocess
            result = subprocess.run(
                [str(aapt), "dump", "badging", apk_path],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    for part in line.split():
                        if part.startswith("name="):
                            info["package"] = part.split("=", 1)[1].strip("'\"")
                        elif part.startswith("versionName="):
                            info["version_name"] = part.split("=", 1)[1].strip("'\"")
                        elif part.startswith("versionCode="):
                            info["version_code"] = part.split("=", 1)[1].strip("'\"")
                elif line.startswith("sdkVersion:"):
                    info["min_sdk"] = line.split(":", 1)[1].strip().strip("'\"")
            return info
    except Exception:
        pass

    # Binary manifest fallback
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            raw = z.read("AndroidManifest.xml")
        text_chunks = re.findall(rb"[\x20-\x7e]{5,}", raw)
        for chunk in text_chunks:
            s = chunk.decode("ascii", errors="ignore")
            if re.match(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$", s):
                info["package"] = s
                break
    except Exception:
        pass

    return info


# ──────────────────────────────────────────────────────────────────────────────
# Success dialog
# ──────────────────────────────────────────────────────────────────────────────

class SuccessDialog(QDialog):
    def __init__(self, parent, operation: str, output_path: str):
        super().__init__(parent)
        self.output_path = output_path
        self.setWindowTitle("Operation Complete")
        self.setMinimumWidth(440)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        title = QLabel(f"✅ {operation}")
        title.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        layout.addWidget(title)

        path_label = QLabel(f"<b>Output:</b><br><code>{output_path}</code>")
        path_label.setWordWrap(True)
        path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(path_label)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #3c3c3c;")
        layout.addWidget(line)

        btn_box    = QDialogButtonBox()
        ok_btn     = QPushButton("OK")
        ok_btn.setDefault(True)
        folder_btn = QPushButton("📂 Open Folder")
        folder_btn.setStyleSheet("background-color: #107c10;")
        copy_btn   = QPushButton("📋 Copy Path")

        btn_box.addButton(ok_btn,     QDialogButtonBox.ButtonRole.AcceptRole)
        btn_box.addButton(folder_btn, QDialogButtonBox.ButtonRole.ActionRole)
        btn_box.addButton(copy_btn,   QDialogButtonBox.ButtonRole.ActionRole)
        layout.addWidget(btn_box)

        ok_btn.clicked.connect(self.accept)
        folder_btn.clicked.connect(lambda: _open_folder(self.output_path))
        copy_btn.clicked.connect(self._copy_path)

    def _copy_path(self):
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(self.output_path)


# ──────────────────────────────────────────────────────────────────────────────
# APK Info dialog  (shown by "APK Info" button)
# ──────────────────────────────────────────────────────────────────────────────

class APKInfoDialog(QDialog):
    """Displays detailed APK analysis: permissions, components, cert, file stats."""

    def __init__(self, parent, info: dict):
        super().__init__(parent)
        self.info = info
        self.setWindowTitle(f"APK Info — {info.get('package', Path(info.get('path', '')).name)}")
        self.setMinimumSize(600, 520)
        self.resize(680, 580)

        outer = QVBoxLayout(self)
        outer.setSpacing(10)

        # ── Header ────────────────────────────────────────────────────
        hdr = QGroupBox("Package")
        hdr_lay = QGridLayout(hdr)
        rows = [
            ("Package",      info.get("package", "—")),
            ("Version",      f"{info.get('version_name', '—')}  (code {info.get('version_code', '—')})"),
            ("Min SDK",      info.get("min_sdk", "—")),
            ("Target SDK",   info.get("target_sdk", "—")),
            ("Size",         f"{info.get('size_mb', '?')} MB"),
            ("Files in APK", str(info.get("file_count", "—"))),
        ]
        for r, (k, v) in enumerate(rows):
            hdr_lay.addWidget(QLabel(f"<b>{k}:</b>"), r, 0)
            val = QLabel(v)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            hdr_lay.addWidget(val, r, 1)
        outer.addWidget(hdr)

        # ── Permissions ───────────────────────────────────────────────
        perms = info.get("permissions", [])
        perm_group = QGroupBox(f"Permissions ({len(perms)})")
        pg_lay = QVBoxLayout(perm_group)

        perm_text = QTextEdit()
        perm_text.setReadOnly(True)
        perm_text.setMaximumHeight(160)
        perm_text.setFont(QFont("Consolas", 10))

        DANGEROUS = {
            "READ_CONTACTS", "WRITE_CONTACTS", "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_CALL_LOG",
            "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "READ_PHONE_STATE",
            "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "USE_BIOMETRIC",
            "USE_FINGERPRINT", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
            "READ_MEDIA_AUDIO", "MANAGE_EXTERNAL_STORAGE", "BLUETOOTH_SCAN",
            "BLUETOOTH_CONNECT", "NEARBY_WIFI_DEVICES",
        }

        if perms:
            lines = []
            for p in sorted(perms):
                short = p.split(".")[-1]
                flag  = "⚠️ " if short in DANGEROUS else "   "
                lines.append(f"{flag}{p}")
            perm_text.setPlainText("\n".join(lines))
        else:
            perm_text.setPlainText("No permissions found (install platform-tools for full analysis)")

        pg_lay.addWidget(perm_text)

        if perms:
            danger_count = sum(1 for p in perms if p.split(".")[-1] in DANGEROUS)
            note = QLabel(f"⚠️ {danger_count} dangerous permission(s) detected" if danger_count
                          else "✅ No dangerous permissions")
            note.setStyleSheet(
                "color: #ffaa00; font-weight: bold;" if danger_count
                else "color: #00ff00;"
            )
            pg_lay.addWidget(note)
        outer.addWidget(perm_group)

        # ── Activities ────────────────────────────────────────────────
        activities = info.get("activities", [])
        if activities:
            act_group = QGroupBox(f"Launchable Activities ({len(activities)})")
            act_lay   = QVBoxLayout(act_group)
            act_text  = QTextEdit()
            act_text.setReadOnly(True)
            act_text.setMaximumHeight(80)
            act_text.setFont(QFont("Consolas", 10))
            act_text.setPlainText("\n".join(activities))
            act_lay.addWidget(act_text)
            outer.addWidget(act_group)

        # ── Certificate ───────────────────────────────────────────────
        cert = info.get("cert_info", "")
        cert_group = QGroupBox("Signing Certificate")
        cert_lay   = QVBoxLayout(cert_group)
        cert_text  = QTextEdit()
        cert_text.setReadOnly(True)
        cert_text.setMaximumHeight(100)
        cert_text.setFont(QFont("Consolas", 10))
        cert_text.setPlainText(cert if cert else "Certificate info unavailable (apksigner not found in platform-tools)")
        cert_lay.addWidget(cert_text)
        outer.addWidget(cert_group)

        # ── Buttons ───────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        close_btn  = QPushButton("Close")
        export_btn = QPushButton("📋 Copy Report")
        export_btn.setStyleSheet("background-color: #5c2d91;")
        btn_row.addWidget(export_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        outer.addLayout(btn_row)

        close_btn.clicked.connect(self.accept)
        export_btn.clicked.connect(self._copy_report)

    def _copy_report(self):
        from PyQt6.QtWidgets import QApplication
        info = self.info
        lines = [
            "=== APK Analysis Report ===",
            f"File:        {info.get('path', '')}",
            f"Package:     {info.get('package', '—')}",
            f"Version:     {info.get('version_name', '—')} (code {info.get('version_code', '—')})",
            f"Min SDK:     {info.get('min_sdk', '—')}",
            f"Target SDK:  {info.get('target_sdk', '—')}",
            f"Size:        {info.get('size_mb', '?')} MB",
            f"Files:       {info.get('file_count', '?')}",
            "",
            f"Permissions ({len(info.get('permissions', []))}):",
        ]
        for p in sorted(info.get("permissions", [])):
            lines.append(f"  {p}")
        if info.get("cert_info"):
            lines += ["", "Certificate:", info["cert_info"]]
        QApplication.clipboard().setText("\n".join(lines))
        QMessageBox.information(self, "Copied", "Report copied to clipboard.")


# ──────────────────────────────────────────────────────────────────────────────
# Home Tab
# ──────────────────────────────────────────────────────────────────────────────

class HomeTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.worker = None
        self.state  = StateManager.instance()
        self._op_buttons: list     = []
        self._current_apk_path: str = ""

        self.default_dir = Path.home() / "Android"
        self.default_dir.mkdir(exist_ok=True)

        self.init_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # ── Title ──────────────────────────────────────────────────────
        title = QLabel("🔒 Android APK Pentesting Tool")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Select an operation to get started")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #808080; margin-bottom: 4px;")
        layout.addWidget(subtitle)

        # ── Recent Files ───────────────────────────────────────────────
        recent_group  = QGroupBox("📂 Recent Files")
        recent_layout = QVBoxLayout(recent_group)
        recent_layout.setSpacing(4)

        self.recent_list = QListWidget()
        self.recent_list.setMinimumHeight(60)
        self.recent_list.setMaximumHeight(130)
        self.recent_list.setToolTip("Double-click to pre-select for an operation")
        self.recent_list.itemDoubleClicked.connect(self._on_recent_double_click)
        recent_layout.addWidget(self.recent_list)

        hint_row = QHBoxLayout()
        recent_hint = QLabel("Double-click a recent file to pre-select it.")
        recent_hint.setStyleSheet("color: #808080; font-size: 11px;")
        hint_row.addWidget(recent_hint, 1)

        clear_recent_btn = QPushButton("🗑 Clear All")
        clear_recent_btn.setToolTip("Remove all recent files from the list")
        clear_recent_btn.setMaximumWidth(90)
        clear_recent_btn.setStyleSheet(
            "QPushButton { background-color: #5a2a2a; font-size: 11px; padding: 3px 6px; }"
            "QPushButton:hover { background-color: #7a3a3a; }"
        )
        clear_recent_btn.clicked.connect(self._clear_recent_files)
        hint_row.addWidget(clear_recent_btn)
        recent_layout.addLayout(hint_row)

        layout.addWidget(recent_group)
        self._refresh_recent_list()

        # ── Selected File Info Panel ───────────────────────────────────
        self.info_panel = QGroupBox("ℹ️ Selected File")
        info_layout     = QHBoxLayout(self.info_panel)
        self.info_label = QLabel("No file selected")
        self.info_label.setStyleSheet("color: #808080; font-size: 12px;")
        self.info_label.setWordWrap(True)
        info_layout.addWidget(self.info_label, 1)

        self.apk_info_btn = QPushButton("🔍 APK Info")
        self.apk_info_btn.setToolTip("Show full permissions, components, and certificate details")
        self.apk_info_btn.setMaximumWidth(100)
        self.apk_info_btn.setStyleSheet(
            "QPushButton { background-color: #5c2d91; font-size: 12px; padding: 5px 8px; }"
            "QPushButton:hover { background-color: #7b3fbf; }"
        )
        self.apk_info_btn.setVisible(False)
        self.apk_info_btn.clicked.connect(self._show_apk_info)
        info_layout.addWidget(self.apk_info_btn)

        self.info_panel.setVisible(False)
        layout.addWidget(self.info_panel)

        # ── Operation Buttons Grid ─────────────────────────────────────
        grid = QGridLayout()
        grid.setSpacing(8)

        # (label, row, col, handler, tooltip)
        operations = [
            ("🔧 Install Tools",          0, 0, self.install_tools,
             "Download and install required tools (APKTool, bundletool, etc.)"),
            ("📱 Extract APK",            0, 1, self.extract_apk,
             "Pull an APK from a connected Android device"),

            ("🔗 Merge Split APKs",       1, 0, self.merge_split_apks,
             "Combine a directory of split APKs into a single APK using APKEditor"),
            ("📦 Decompile APK",          1, 1, self.decompile_apk,
             "Disassemble an APK into smali code, resources, and manifest using APKTool"),

            ("🔨 Recompile APK",          2, 0, self.recompile_apk,
             "Rebuild a previously decompiled APK directory back into an APK (apktool b)"),
            ("✍️ Resign APK",             2, 1, self.resign_apk,
             "Re-sign any APK with a debug certificate (uber-apk-signer)"),

            ("🔓 Remove SSL Pinning",     3, 0, self.remove_ssl_pinning,
             "Patch SSL pinning via apk-mitm (requires Node.js)"),
            ("🛡️ NSC Patch",             3, 1, self.nsc_patch,
             "Inject a permissive Network Security Config to trust user CAs — no Node.js needed"),

            ("📲 AAB → APK",             4, 0, self.convert_aab_to_apk,
             "Convert an Android App Bundle (.aab) to a signed universal APK"),
            ("📲 Install to Device",      4, 1, self.install_to_device,
             "Push the selected APK to a connected device via ADB (adb install -r -d)"),
        ]

        for text, row, col, action, tip in operations:
            btn = QPushButton(text)
            btn.setToolTip(tip)
            btn.clicked.connect(action)
            btn.setMinimumHeight(60)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #0e639c;
                    font-size: 13px;
                    font-weight: bold;
                    border-radius: 6px;
                }
                QPushButton:hover   { background-color: #1177bb; }
                QPushButton:pressed { background-color: #0d5289; }
                QPushButton:disabled { background-color: #3c3c3c; color: #606060; }
            """)
            grid.addWidget(btn, row, col)
            self._op_buttons.append(btn)

        layout.addLayout(grid)

        # ── Progress + Cancel row ──────────────────────────────────────
        prog_row = QHBoxLayout()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        prog_row.addWidget(self.progress_bar, 1)

        self.cancel_btn = QPushButton("✖ Cancel")
        self.cancel_btn.setVisible(False)
        self.cancel_btn.setStyleSheet(
            "QPushButton { background-color: #8b0000; font-weight: bold; max-width: 90px; }"
            "QPushButton:hover { background-color: #a00000; }"
        )
        self.cancel_btn.clicked.connect(self._cancel_operation)
        prog_row.addWidget(self.cancel_btn)

        layout.addLayout(prog_row)
        layout.addStretch()

        # ── Working directory info ─────────────────────────────────────
        info = QLabel(f"📁 Default working directory: {self.default_dir}")
        info.setStyleSheet(
            "background-color: #2d2d2d; padding: 8px; border-radius: 4px; color: #aaaaaa;"
        )
        info.setWordWrap(True)
        layout.addWidget(info)

    # ------------------------------------------------------------------
    # Recent files
    # ------------------------------------------------------------------

    def _refresh_recent_list(self):
        self.recent_list.clear()
        recent = self.state.get_recent_files()
        if not recent:
            item = QListWidgetItem("(no recent files)")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.recent_list.addItem(item)
            return
        for entry in recent:
            p     = Path(entry["path"])
            ts    = entry.get("ts", "")
            ftype = entry.get("type", "apk").upper()
            label = f"[{ftype}] {p.name}  —  {p.parent}  ({ts})"
            item  = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, entry["path"])
            self.recent_list.addItem(item)

    def _clear_recent_files(self):
        reply = QMessageBox.question(
            self, "Clear Recent Files",
            "Remove all files from the recent list?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.state.clear_recent_files()
            self._refresh_recent_list()

    def _on_recent_double_click(self, item: QListWidgetItem):
        path = item.data(Qt.ItemDataRole.UserRole)
        if not path:
            return
        if not Path(path).exists():
            QMessageBox.warning(self, "File Not Found", f"The file no longer exists:\n{path}")
            self.state.remove_recent_file(path)
            self._refresh_recent_list()
            return
        self._set_current_file(path)
        self.parent.log(f"Pre-selected: {path}", "info")

    # ------------------------------------------------------------------
    # Selected file / info panel
    # ------------------------------------------------------------------

    def _set_current_file(self, path: str):
        self._current_apk_path = path
        self.parent.set_last_selected_apk(path)

        p   = Path(path)
        ext = p.suffix.lower()
        lines = [f"<b>File:</b> {p.name}", f"<b>Path:</b> {p.parent}"]

        if ext == ".apk":
            info = _read_apk_info(path)
            if info["package"]:
                lines.append(f"<b>Package:</b> {info['package']}")
            if info["version_name"]:
                lines.append(f"<b>Version:</b> {info['version_name']} (code {info['version_code']})")
            if info["min_sdk"]:
                lines.append(f"<b>Min SDK:</b> {info['min_sdk']}")
        elif ext == ".aab":
            lines.append("<b>Type:</b> Android App Bundle")

        size_mb = p.stat().st_size / (1024 * 1024)
        lines.append(f"<b>Size:</b> {size_mb:.2f} MB")

        self.info_label.setText("<br>".join(lines))
        self.info_panel.setVisible(True)
        self.apk_info_btn.setVisible(ext == ".apk")

    # ------------------------------------------------------------------
    # APK Info action
    # ------------------------------------------------------------------

    def _show_apk_info(self):
        if not self._current_apk_path or not Path(self._current_apk_path).exists():
            QMessageBox.warning(self, "No File", "Select an APK first.")
            return
        self.parent.log("Analyzing APK...", "info")
        self._set_buttons_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)

        self._info_worker = APKWorker("get_apk_detailed_info", self._current_apk_path)
        self._info_worker.finished.connect(self._on_apk_info_done)
        self._info_worker.error.connect(self._on_apk_info_error)
        self._info_worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self._info_worker.start()

    def _on_apk_info_done(self, info: dict):
        self.progress_bar.setVisible(False)
        self._set_buttons_enabled(True)
        dlg = APKInfoDialog(self, info)
        dlg.exec()

    def _on_apk_info_error(self, msg: str):
        self.progress_bar.setVisible(False)
        self._set_buttons_enabled(True)
        self.parent.log(msg, "error")
        QMessageBox.critical(self, "Analysis Error", msg)

    # ------------------------------------------------------------------
    # Button enable/disable
    # ------------------------------------------------------------------

    def _set_buttons_enabled(self, enabled: bool):
        for btn in self._op_buttons:
            btn.setEnabled(enabled)
        self.apk_info_btn.setEnabled(enabled)

    # ------------------------------------------------------------------
    # Cancel
    # ------------------------------------------------------------------

    def _cancel_operation(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel()
            self.worker.wait(3000)
        self.progress_bar.setVisible(False)
        self.cancel_btn.setVisible(False)
        self._set_buttons_enabled(True)
        self.parent.statusBar().showMessage("Cancelled")
        self.parent.log("Operation cancelled by user.", "warning")

    # ------------------------------------------------------------------
    # Operation launchers — navigation
    # ------------------------------------------------------------------

    def install_tools(self):
        self.parent.switch_to_install_tab()

    def extract_apk(self):
        self.parent.switch_to_extract_tab()

    # ------------------------------------------------------------------
    # Operation launchers — file pickers
    # ------------------------------------------------------------------

    def merge_split_apks(self):
        start_dir = self.state.get_dir(DIR_MERGE, str(self.default_dir))
        directory = QFileDialog.getExistingDirectory(
            self, "Select Split APK Directory", start_dir
        )
        if not directory:
            return
        self.state.set_dir(DIR_MERGE, directory)
        if not list(Path(directory).glob("*.apk")):
            QMessageBox.warning(self, "No APKs", f"No APK files found in:\n{directory}")
            return
        self._run_operation("merge_split_apks", directory, directory, "Merging split APKs...")

    def decompile_apk(self):
        start = self._current_apk_path or self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        start_dir = str(Path(start).parent) if Path(start).is_file() else start
        apk_file, _ = QFileDialog.getOpenFileName(
            self, "Select APK to Decompile", start_dir, "APK Files (*.apk)"
        )
        if not apk_file:
            return
        self.state.set_dir_from_file(DIR_APK_HOME, apk_file)
        self.state.add_recent_file(apk_file, "apk")
        self._set_current_file(apk_file)
        self._refresh_recent_list()
        self._run_operation("decompile_apk", apk_file, str(Path(apk_file).parent),
                            "Decompiling APK...")

    def recompile_apk(self):
        """Select a decompiled APK directory (must contain apktool.yml) and rebuild it."""
        start_dir = self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        directory = QFileDialog.getExistingDirectory(
            self, "Select Decompiled APK Directory (contains apktool.yml)", start_dir
        )
        if not directory:
            return
        if not (Path(directory) / "apktool.yml").exists():
            QMessageBox.warning(
                self, "Invalid Directory",
                "The selected directory does not contain apktool.yml.\n"
                "Please choose a directory that was decompiled by APKTool."
            )
            return
        output_dir = str(Path(directory).parent)
        self._run_operation("recompile_apk", directory, output_dir, "Recompiling APK...")

    def remove_ssl_pinning(self):
        start_dir = self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        apk_file, _ = QFileDialog.getOpenFileName(
            self, "Select APK", start_dir, "APK Files (*.apk)"
        )
        if not apk_file:
            return
        self.state.set_dir_from_file(DIR_APK_HOME, apk_file)
        self.state.add_recent_file(apk_file, "apk")
        self._set_current_file(apk_file)
        self._refresh_recent_list()
        output = str(Path(apk_file).parent / "patched_apk")
        self._run_operation("remove_ssl_pinning", apk_file, output, "Removing SSL pinning...")

    def nsc_patch(self):
        """NSC patch — alternative SSL bypass that requires no Node.js."""
        start_dir = self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        apk_file, _ = QFileDialog.getOpenFileName(
            self, "Select APK for NSC Patch", start_dir, "APK Files (*.apk)"
        )
        if not apk_file:
            return
        self.state.set_dir_from_file(DIR_APK_HOME, apk_file)
        self.state.add_recent_file(apk_file, "apk")
        self._set_current_file(apk_file)
        self._refresh_recent_list()
        output = str(Path(apk_file).parent / "nsc_patched")
        self._run_operation(
            "patch_network_security_config", apk_file, output,
            "Patching Network Security Config..."
        )

    def resign_apk(self):
        start_dir = self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        apk_file, _ = QFileDialog.getOpenFileName(
            self, "Select APK", start_dir, "APK Files (*.apk)"
        )
        if not apk_file:
            return
        self.state.set_dir_from_file(DIR_APK_HOME, apk_file)
        self.state.add_recent_file(apk_file, "apk")
        self._set_current_file(apk_file)
        self._refresh_recent_list()
        output = str(Path(apk_file).parent / "signed_apk")
        self._run_operation("resign_apk", apk_file, output, "Signing APK...")

    def convert_aab_to_apk(self):
        start_dir = self.state.get_dir(DIR_AAB_HOME, str(self.default_dir))
        aab_file, _ = QFileDialog.getOpenFileName(
            self, "Select AAB", start_dir, "AAB Files (*.aab)"
        )
        if not aab_file:
            return
        self.state.set_dir_from_file(DIR_AAB_HOME, aab_file)
        self.state.add_recent_file(aab_file, "aab")
        self._set_current_file(aab_file)
        self._refresh_recent_list()
        self._run_operation("convert_aab_to_apk", aab_file, str(Path(aab_file).parent),
                            "Converting AAB to APK...")

    def install_to_device(self):
        """
        Install APK(s) to a connected device via ADB.
        Always opens a file browser — pre-fills to the current/output APK directory.
        Multi-select → adb install-multiple (split APK support).
        """
        start_dir = (
            str(Path(self._current_apk_path).parent)
            if self._current_apk_path and Path(self._current_apk_path).exists()
            else self.state.get_dir(DIR_APK_HOME, str(self.default_dir))
        )
        apk_files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select APK file(s) — hold Ctrl/Shift to select multiple (split APKs)",
            start_dir,
            "APK Files (*.apk)",
        )
        if not apk_files:
            return

        count    = len(apk_files)
        apk_name = Path(apk_files[0]).name if count == 1 else f"{count} split APKs"
        names    = "\n".join(Path(p).name for p in apk_files)

        reply = QMessageBox.question(
            self, "Install to Device",
            f"Install  {apk_name}  to the connected Android device?\n\n"
            + (f"Files:\n{names}\n\n" if count > 1 else "")
            + "The device must have USB Debugging enabled.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.parent.log(f"Installing {apk_name} via ADB...", "info")
        self.parent.statusBar().showMessage("Installing APK to device...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self._set_buttons_enabled(False)
        self.cancel_btn.setVisible(True)

        if count > 1:
            self.worker = ADBWorker("install_multiple_apks", apk_files)
        else:
            self.worker = ADBWorker("install_apk", apk_files[0])
        self.worker.finished.connect(self._on_install_done)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.command.connect(lambda c: self.parent.log(c, "cmd"))
        self.worker.start()

    def _on_install_done(self, result: dict):
        self.progress_bar.setVisible(False)
        self.cancel_btn.setVisible(False)
        self._set_buttons_enabled(True)
        self.parent.statusBar().showMessage("Installed!")
        apks = result.get("apks", [result.get("apk", "")])
        count = len(apks) if isinstance(apks, list) else 1
        self.parent.log(f"✓ {count} APK(s) installed on device!", "success")
        QMessageBox.information(
            self, "Installed",
            f"{count} APK(s) installed successfully!\n\n{result.get('output', '')}"
        )

    # ------------------------------------------------------------------
    # Pre-fill from cross-tab
    # ------------------------------------------------------------------

    def prefill_apk(self, apk_path: str):
        if Path(apk_path).exists():
            self._set_current_file(apk_path)
            self.state.add_recent_file(apk_path, "apk")
            self._refresh_recent_list()
            self.parent.log(f"✓ Pre-selected extracted APK: {apk_path}", "success")

    # ------------------------------------------------------------------
    # Common operation runner
    # ------------------------------------------------------------------

    def _run_operation(self, operation: str, input_path: str,
                       output_path: str, status_msg: str):
        self.parent.log(f"Operation: {operation}", "info")
        self.parent.log(f"Input:     {input_path}", "info")
        self.parent.log(f"Output:    {output_path}", "info")
        self.parent.statusBar().showMessage(status_msg)

        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self._set_buttons_enabled(False)
        self.cancel_btn.setVisible(True)

        self.worker = APKWorker(operation, input_path, output_path)
        self.worker.finished.connect(self._on_complete)
        self.worker.error.connect(self._on_error)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.command.connect(lambda c: self.parent.log(c, "cmd"))
        self.worker.start()

    # ------------------------------------------------------------------
    # Completion handlers
    # ------------------------------------------------------------------

    def _on_complete(self, result: dict):
        self.progress_bar.setVisible(False)
        self.cancel_btn.setVisible(False)
        self._set_buttons_enabled(True)
        self.parent.statusBar().showMessage("Complete!")

        op_name = result.get("operation", "Operation").replace("_", " ").title()
        output  = result.get("output", "N/A")

        self.parent.log(f"✓ {op_name} completed!", "success")
        self.parent.log(f"Output: {output}", "success")
        self.state.set_dir(DIR_OUTPUT, output)

        # If the output is an APK file, auto-select it so subsequent
        # operations (e.g. Install to Device) use the processed file.
        if output and output.endswith(".apk") and Path(output).exists():
            self._set_current_file(output)
            self.state.add_recent_file(output, "apk")
            self._refresh_recent_list()
            self.parent.log(f"Auto-selected output: {Path(output).name}", "info")

        dlg = SuccessDialog(self, op_name, output)
        dlg.exec()

    def _on_error(self, error_msg: str):
        self.progress_bar.setVisible(False)
        self.cancel_btn.setVisible(False)
        self._set_buttons_enabled(True)
        self.parent.statusBar().showMessage("Error")
        self.parent.log(error_msg, "error")
        QMessageBox.critical(self, "Error", error_msg)
