import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton,
    QLineEdit, QListWidget, QLabel, QMessageBox,
    QProgressBar, QFileDialog, QComboBox, QGroupBox, QFrame,
    QMenu, QApplication,
)
from PyQt6.QtCore import QTimer, Qt

from workers.adb_worker import ADBWorker
from ui.state_manager import StateManager, DIR_EXTRACT_OUT


class ExtractTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.worker = None
        self.state  = StateManager.instance()
        self._devices: list             = []
        self._last_extracted_apks: list = []
        self._has_searched: bool        = False
        self._is_searching: bool        = False

        self.default_dir = Path.home() / "Android"
        self.default_dir.mkdir(exist_ok=True)

        self.init_ui()
        QTimer.singleShot(500, self._refresh_devices)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # ── Device section ─────────────────────────────────────────────
        device_group  = QGroupBox("📱 Device")
        device_layout = QVBoxLayout(device_group)

        # Status row
        status_row = QHBoxLayout()
        self.device_status_label = QLabel("🔍 Checking for devices...")
        self.device_status_label.setStyleSheet("color: #808080;")
        status_row.addWidget(self.device_status_label, 1)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(200)
        self.device_combo.setToolTip("Select target device / emulator")
        self.device_combo.setVisible(False)
        self.device_combo.currentIndexChanged.connect(self._on_device_selected)
        status_row.addWidget(self.device_combo)

        self.refresh_device_btn = QPushButton("🔄 Refresh")
        self.refresh_device_btn.setMinimumWidth(100)
        self.refresh_device_btn.setMaximumWidth(120)
        self.refresh_device_btn.clicked.connect(self._refresh_devices)
        status_row.addWidget(self.refresh_device_btn)

        device_layout.addLayout(status_row)

        # Device info bar (shown after device detected)
        self.device_info_label = QLabel("")
        self.device_info_label.setStyleSheet(
            "color: #aaaaaa; font-size: 11px; padding: 2px 4px;"
        )
        self.device_info_label.setWordWrap(True)
        self.device_info_label.setVisible(False)
        device_layout.addWidget(self.device_info_label)

        layout.addWidget(device_group)

        # ── Package search row ─────────────────────────────────────────
        search_row = QHBoxLayout()

        search_row.addWidget(QLabel("Filter:"))

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Filter by package name (e.g. com.example) — leave empty to list all"
        )
        self.search_input.returnPressed.connect(self.search_packages)
        search_row.addWidget(self.search_input, 1)

        # Package type filter
        self.type_combo = QComboBox()
        self.type_combo.setToolTip("Filter package type")
        self.type_combo.addItem("All Packages",   "all")
        self.type_combo.addItem("3rd Party Only", "3rdparty")
        self.type_combo.addItem("System Only",    "system")
        self.type_combo.setMinimumWidth(130)
        self.type_combo.setMaximumWidth(160)
        self.type_combo.currentIndexChanged.connect(self._on_type_changed)
        search_row.addWidget(self.type_combo)

        self.search_btn = QPushButton("🔍 Search")
        self.search_btn.setMinimumWidth(90)
        self.search_btn.setMaximumWidth(110)
        self.search_btn.clicked.connect(self.search_packages)
        search_row.addWidget(self.search_btn)

        layout.addLayout(search_row)

        # ── Command display ────────────────────────────────────────────
        self.cmd_display = QLineEdit()
        self.cmd_display.setReadOnly(True)
        self.cmd_display.setPlaceholderText("No command running...")
        self.cmd_display.setStyleSheet(
            "background-color: #1e1e1e; color: #569cd6;"
            "font-family: 'Consolas', monospace; padding: 6px;"
        )
        layout.addWidget(self.cmd_display)

        # ── Package list ───────────────────────────────────────────────
        count_row = QHBoxLayout()
        self.pkg_count_label = QLabel("Packages Found: —")
        count_row.addWidget(self.pkg_count_label)
        count_row.addStretch()
        layout.addLayout(count_row)

        self.package_list = QListWidget()
        self.package_list.setMinimumHeight(120)
        self.package_list.setMaximumHeight(260)
        self.package_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.package_list.customContextMenuRequested.connect(self._show_package_context_menu)
        self.package_list.itemClicked.connect(self._on_package_click)
        self.package_list.itemDoubleClicked.connect(self.extract_apk)
        layout.addWidget(self.package_list)

        # ── Selected package ───────────────────────────────────────────
        sel_row = QHBoxLayout()
        sel_row.addWidget(QLabel("Selected:"))
        self.selected_label = QLabel("None")
        self.selected_label.setStyleSheet("color: #0078d4; font-weight: bold;")
        sel_row.addWidget(self.selected_label, 1)
        layout.addLayout(sel_row)

        # ── Output directory ───────────────────────────────────────────
        out_row = QHBoxLayout()
        saved_out = self.state.get_dir(DIR_EXTRACT_OUT, str(self.default_dir))
        self.output_input = QLineEdit(saved_out)
        browse_btn = QPushButton("📁 Browse")
        browse_btn.setMinimumWidth(90)
        browse_btn.setMaximumWidth(110)
        browse_btn.clicked.connect(self._browse_output)
        out_row.addWidget(QLabel("Output:"))
        out_row.addWidget(self.output_input, 1)
        out_row.addWidget(browse_btn)
        layout.addLayout(out_row)

        # ── Extract button ─────────────────────────────────────────────
        self.extract_btn = QPushButton("📦 Extract Selected APK from Device")
        self.extract_btn.clicked.connect(self.extract_apk)
        self.extract_btn.setEnabled(False)
        self.extract_btn.setMinimumHeight(40)
        layout.addWidget(self.extract_btn)

        # ── Progress bar ───────────────────────────────────────────────
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # ── Post-extract actions ───────────────────────────────────────
        self.post_extract_frame = QFrame()
        post_grid = QGridLayout(self.post_extract_frame)
        post_grid.setContentsMargins(0, 0, 0, 0)
        post_grid.setSpacing(6)

        self.open_folder_btn = QPushButton("📂 Open Folder")
        self.open_folder_btn.setStyleSheet("background-color: #107c10;")
        self.open_folder_btn.setMinimumHeight(36)
        self.open_folder_btn.clicked.connect(self._open_output_folder)

        self.run_ops_btn = QPushButton("⚡ Analyze in Home Tab →")
        self.run_ops_btn.setStyleSheet("background-color: #5c2d91;")
        self.run_ops_btn.setMinimumHeight(36)
        self.run_ops_btn.setToolTip("Switch to Home tab with this APK pre-selected")
        self.run_ops_btn.clicked.connect(self._go_to_home_with_apk)

        self.install_btn = QPushButton("📲 Install to Device")
        self.install_btn.setStyleSheet("background-color: #0e639c;")
        self.install_btn.setMinimumHeight(36)
        self.install_btn.setToolTip(
            "Browse and select APK(s) to install via ADB.\n"
            "Select multiple files for split APK install (adb install-multiple)."
        )
        self.install_btn.clicked.connect(self._install_apk_browse)

        self.uninstall_btn = QPushButton("🗑 Uninstall Package")
        self.uninstall_btn.setStyleSheet("background-color: #8b0000;")
        self.uninstall_btn.setMinimumHeight(36)
        self.uninstall_btn.setToolTip("Uninstall the selected package from the device")
        self.uninstall_btn.clicked.connect(self._uninstall_selected)

        # 2×2 grid — no button ever gets cropped
        post_grid.addWidget(self.open_folder_btn, 0, 0)
        post_grid.addWidget(self.run_ops_btn,     0, 1)
        post_grid.addWidget(self.install_btn,     1, 0)
        post_grid.addWidget(self.uninstall_btn,   1, 1)
        post_grid.setColumnStretch(0, 1)
        post_grid.setColumnStretch(1, 1)

        self.post_extract_frame.setVisible(False)
        layout.addWidget(self.post_extract_frame)

        # ── Tip label ──────────────────────────────────────────────────
        self.tip_label = QLabel("💡 APKs will be saved to: <output>/Android/<package_name>/")
        self.tip_label.setStyleSheet(
            "background-color: #2d2d2d; padding: 6px; border-radius: 4px; color: #aaaaaa;"
        )
        self.tip_label.setWordWrap(True)
        layout.addWidget(self.tip_label)

    # ------------------------------------------------------------------
    # Device management
    # ------------------------------------------------------------------

    def _refresh_devices(self):
        self.refresh_device_btn.setEnabled(False)
        self.device_status_label.setText("🔍 Scanning for devices...")
        self.device_status_label.setStyleSheet("color: #808080;")
        self.device_info_label.setVisible(False)

        self._device_worker = ADBWorker("list_devices")
        self._device_worker.finished.connect(self._on_devices_found)
        self._device_worker.error.connect(self._on_device_error)
        self._device_worker.start()

    def _on_devices_found(self, devices: list):
        self.refresh_device_btn.setEnabled(True)
        self._devices = devices

        if not devices:
            self.device_status_label.setText("❌ No device connected")
            self.device_status_label.setStyleSheet("color: #ff5555;")
            self.device_combo.setVisible(False)
            self.device_info_label.setVisible(False)
            return

        if len(devices) == 1:
            d     = devices[0]
            label = d["model"] or d["serial"]
            self.device_status_label.setText(f"✅ Connected: {label} ({d['serial']})")
            self.device_status_label.setStyleSheet("color: #00ff00;")
            self.device_combo.setVisible(False)
        else:
            self.device_status_label.setText(f"✅ {len(devices)} devices — select one:")
            self.device_status_label.setStyleSheet("color: #00e5ff;")
            self.device_combo.clear()
            for d in devices:
                self.device_combo.addItem(
                    f"{d['model'] or d['serial']}  [{d['serial']}]", d["serial"]
                )
            self.device_combo.setVisible(True)

        # Fetch rich device info for the first/selected device
        self._fetch_device_info()

        # Auto-search packages the first time a device is detected
        if not self.package_list.count():
            QTimer.singleShot(300, self.search_packages)

    def _on_device_error(self, _msg: str):
        self.refresh_device_btn.setEnabled(True)
        self.device_status_label.setText("⚠️ ADB unavailable — install platform-tools first")
        self.device_status_label.setStyleSheet("color: #ffaa00;")
        self.device_combo.setVisible(False)
        self.device_info_label.setVisible(False)

    def _on_device_selected(self, _index: int):
        """When user switches device in the combo, refresh device info."""
        self._fetch_device_info()

    def _get_selected_serial(self) -> str:
        if self.device_combo.isVisible() and self.device_combo.count() > 0:
            return self.device_combo.currentData() or ""
        if len(self._devices) == 1:
            return self._devices[0]["serial"]
        return ""

    def _fetch_device_info(self):
        """Fetch detailed device properties and show them in the info bar."""
        serial = self._get_selected_serial()
        self._info_worker = ADBWorker("get_device_info", device_serial=serial)
        self._info_worker.finished.connect(self._on_device_info)
        self._info_worker.error.connect(lambda _: None)   # silent on failure
        self._info_worker.start()

    def _on_device_info(self, info: dict):
        parts = []
        if info.get("manufacturer") and info.get("model"):
            parts.append(f"{info['manufacturer']} {info['model']}")
        if info.get("android_version"):
            parts.append(f"Android {info['android_version']} (SDK {info.get('sdk', '?')})")
        if info.get("abi"):
            parts.append(f"ABI: {info['abi']}")
        if info.get("ram_gb"):
            parts.append(f"RAM: {info['ram_gb']}")

        if parts:
            self.device_info_label.setText(" · ".join(parts))
            self.device_info_label.setVisible(True)

    # ------------------------------------------------------------------
    # Output directory
    # ------------------------------------------------------------------

    def _browse_output(self):
        current = self.output_input.text() or self.state.get_dir(DIR_EXTRACT_OUT, str(self.default_dir))
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory", current)
        if directory:
            self.output_input.setText(directory)
            self.state.set_dir(DIR_EXTRACT_OUT, directory)

    # ------------------------------------------------------------------
    # Package list interaction
    # ------------------------------------------------------------------

    def _on_package_click(self, item):
        self.selected_label.setText(item.text())
        self.extract_btn.setEnabled(True)

    # ------------------------------------------------------------------
    # Search packages
    # ------------------------------------------------------------------

    def search_packages(self):
        # If already searching, act as cancel
        if self._is_searching:
            if self.worker and self.worker.isRunning():
                self.worker.terminate()
                self.worker.wait(500)
            self._set_searching(False)
            return

        self._has_searched = True
        self.package_list.clear()
        self.pkg_count_label.setText("Packages Found: —")
        self.selected_label.setText("None")
        self.extract_btn.setEnabled(False)
        self.post_extract_frame.setVisible(False)
        self.tip_label.setText("💡 APKs will be saved to: <output>/Android/<package_name>/")
        self._set_searching(True)

        serial      = self._get_selected_serial()
        search_term = self.search_input.text().strip()
        filter_type = self.type_combo.currentData()   # "all" | "3rdparty" | "system"

        self.worker = ADBWorker("list_packages", search_term, filter_type,
                                device_serial=serial)
        self.worker.finished.connect(self._on_search_done)
        self.worker.error.connect(self._on_error)
        self.worker.command.connect(self.cmd_display.setText)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.start()

    def _on_search_done(self, packages: list):
        self._set_searching(False)
        count = len(packages)
        filter_label = self.type_combo.currentText()
        self.pkg_count_label.setText(f"Packages Found: {count} [{filter_label}]")

        if not packages:
            QMessageBox.information(
                self, "No Results",
                "No packages found matching your filter.\n\n"
                "Try a shorter search term, or switch the package type filter."
            )
            return

        self.package_list.addItems(packages)
        self.parent.log(f"Found {count} package(s) [{filter_label}]", "success")

    # ------------------------------------------------------------------
    # Extract APK
    # ------------------------------------------------------------------

    def extract_apk(self):
        item = self.package_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No Selection", "Select a package first.")
            return

        output_dir = self.output_input.text().strip()
        if not output_dir:
            QMessageBox.warning(self, "No Output", "Specify an output directory.")
            return

        self.state.set_dir(DIR_EXTRACT_OUT, output_dir)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        self._set_loading(True)

        serial = self._get_selected_serial()
        self.worker = ADBWorker("extract_apk", item.text(), output_dir,
                                device_serial=serial)
        self.worker.finished.connect(self._on_extract_done)
        self.worker.error.connect(self._on_error)
        self.worker.command.connect(self.cmd_display.setText)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.start()

    def _on_extract_done(self, result: dict):
        self._set_loading(False)
        self._last_extracted_apks = result.get("files", [])
        pkg       = result["package"]
        count     = result["count"]
        directory = result["directory"]

        self.parent.log(f"✓ Extracted {count} file(s) for {pkg}", "success")
        self.parent.log(f"  Location: {directory}", "success")

        self.tip_label.setText(f"✅ Extracted → {directory}")
        self.post_extract_frame.setVisible(True)

        QMessageBox.information(
            self, "Extraction Complete",
            f"Package:  {pkg}\nFiles:    {count}\nLocation: {directory}"
        )

    # ------------------------------------------------------------------
    # Post-extract actions
    # ------------------------------------------------------------------

    def _open_output_folder(self):
        folder = (
            str(Path(self._last_extracted_apks[0]).parent)
            if self._last_extracted_apks
            else self.output_input.text()
        )
        if os.name == "nt":
            os.startfile(folder)
        elif os.name == "posix":
            import subprocess
            subprocess.Popen(["xdg-open", folder])

    def _install_apk_browse(self):
        """
        Browse for one or more APK files and install them via ADB.
        Single APK  → adb install -r -d
        Multiple    → adb install-multiple -r -d  (split APK support)
        Pre-fills to the last extracted APK directory for convenience.
        """
        start_dir = (
            str(Path(self._last_extracted_apks[0]).parent)
            if self._last_extracted_apks
            else self.output_input.text()
        )
        apk_files, _ = QFileDialog.getOpenFileNames(
            self,
            "Select APK file(s) to install — hold Ctrl/Shift for multiple (split APKs)",
            start_dir,
            "APK Files (*.apk)",
        )
        if not apk_files:
            return

        count = len(apk_files)
        names = ", ".join(Path(p).name for p in apk_files)
        op    = "install_multiple_apks" if count > 1 else "install_apk"
        label = f"{count} split APK(s)" if count > 1 else Path(apk_files[0]).name

        reply = QMessageBox.question(
            self, "Install to Device",
            f"Install  {label}  to the connected device?\n\n"
            + (f"Files:\n{names}\n\n" if count > 1 else "")
            + "The device must have USB Debugging enabled.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_loading(True)
        serial = self._get_selected_serial()

        if count > 1:
            self.worker = ADBWorker("install_multiple_apks", apk_files, device_serial=serial)
        else:
            self.worker = ADBWorker("install_apk", apk_files[0], device_serial=serial)

        self.worker.finished.connect(self._on_install_done)
        self.worker.error.connect(self._on_error)
        self.worker.command.connect(self.cmd_display.setText)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.start()

    def _on_install_done(self, result: dict):
        self._set_loading(False)
        apks = result.get("apks", [result.get("apk", "")])
        count = len(apks) if isinstance(apks, list) else 1
        self.parent.log(f"✓ {count} APK(s) installed on device!", "success")
        QMessageBox.information(
            self, "Installed",
            f"{count} APK(s) installed successfully!\n\n{result.get('output', '')}"
        )

    def _go_to_home_with_apk(self):
        if not self._last_extracted_apks:
            return
        apk_path = self._last_extracted_apks[0]
        self.parent.home_tab.prefill_apk(apk_path)
        self.parent.switch_to_home_tab()

    def _uninstall_selected(self):
        """Uninstall the currently selected package from the device."""
        item = self.package_list.currentItem()
        if not item:
            QMessageBox.warning(self, "No Selection", "Select a package to uninstall.")
            return

        pkg = item.text()
        reply = QMessageBox.question(
            self, "Uninstall Package",
            f"Permanently uninstall  {pkg}  from the device?\n\n"
            "This cannot be undone (the extracted APK will still be kept).",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._set_loading(True)
        serial = self._get_selected_serial()

        self.worker = ADBWorker("uninstall_package", pkg, device_serial=serial)
        self.worker.finished.connect(self._on_uninstall_done)
        self.worker.error.connect(self._on_error)
        self.worker.command.connect(self.cmd_display.setText)
        self.worker.progress.connect(lambda m: self.parent.log(m, "output"))
        self.worker.start()

    def _on_uninstall_done(self, result: dict):
        self._set_loading(False)
        pkg = result.get("package", "")
        self.parent.log(f"✓ {pkg} uninstalled!", "success")
        QMessageBox.information(self, "Uninstalled", f"{pkg} was uninstalled from the device.")
        # Refresh package list
        self.search_packages()

    # ------------------------------------------------------------------
    # Error handling
    # ------------------------------------------------------------------

    def _on_error(self, msg: str):
        if self._is_searching:
            self._set_searching(False)
        else:
            self._set_loading(False)
        self.parent.log(msg, "error")

        if "No Android device" in msg or "ADB" in msg:
            QMessageBox.critical(
                self, "Device Error",
                f"{msg}\n\nTip: Click '🔄 Refresh' after reconnecting the device."
            )
        else:
            QMessageBox.critical(self, "Error", msg)

    # ------------------------------------------------------------------
    # Type combo auto-search
    # ------------------------------------------------------------------

    def _on_type_changed(self, _index: int):
        """Re-run search when the package type filter changes, but only after a first search."""
        if self._has_searched and not self._is_searching:
            self.search_packages()

    # ------------------------------------------------------------------
    # Package list context menu
    # ------------------------------------------------------------------

    def _show_package_context_menu(self, pos):
        item = self.package_list.itemAt(pos)
        if not item:
            return
        menu = QMenu(self)
        copy_action    = menu.addAction("📋 Copy Package Name")
        extract_action = menu.addAction("📦 Extract APK")
        action = menu.exec(self.package_list.mapToGlobal(pos))
        if action == copy_action:
            QApplication.clipboard().setText(item.text())
        elif action == extract_action:
            self.package_list.setCurrentItem(item)
            self._on_package_click(item)
            self.extract_apk()

    # ------------------------------------------------------------------
    # Search loading state (separate from extract loading)
    # ------------------------------------------------------------------

    def _set_searching(self, searching: bool):
        """Toggle the search-in-progress state — turns Search btn into Cancel and back."""
        self._is_searching = searching
        self.progress_bar.setVisible(searching)
        self.progress_bar.setRange(0, 0 if searching else 100)
        self.refresh_device_btn.setEnabled(not searching)
        has_selection = self.package_list.currentItem() is not None
        self.extract_btn.setEnabled(not searching and has_selection)
        if searching:
            self.search_btn.setText("✖ Cancel")
            self.search_btn.setStyleSheet("QPushButton { background-color: #8b0000; }")
        else:
            self.search_btn.setText("🔍 Search")
            self.search_btn.setStyleSheet("")

    # ------------------------------------------------------------------
    # Loading state
    # ------------------------------------------------------------------

    def _set_loading(self, loading: bool):
        self.progress_bar.setVisible(loading)
        self.progress_bar.setRange(0, 0 if loading else 100)
        self.search_btn.setEnabled(not loading)
        self.refresh_device_btn.setEnabled(not loading)
        has_selection = self.package_list.currentItem() is not None
        self.extract_btn.setEnabled(not loading and has_selection)
