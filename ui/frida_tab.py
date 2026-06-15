"""Frida Tab — Dynamic instrumentation via Frida."""
from pathlib import Path

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QPushButton,
    QLabel, QLineEdit, QCheckBox, QGroupBox, QTextEdit,
    QFileDialog, QComboBox, QMessageBox, QProgressBar, QFrame,
    QRadioButton, QApplication,
)

from PyQt6.QtGui import QFont, QTextCursor

from workers.frida_worker import FridaWorker, SCRIPTS


class FridaTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent  = parent
        self.worker: FridaWorker | None = None
        self._frida_version: str  = ""
        self._server_running: bool = False
        self._is_running: bool     = False

        self.init_ui()
        # Delay first check so the window finishes loading first
        from PyQt6.QtCore import QTimer
        QTimer.singleShot(1200, self._check_status)

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def init_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # ── Frida Server ───────────────────────────────────────────────
        server_group = QGroupBox("🍃 Frida Server")
        server_lay   = QVBoxLayout(server_group)

        status_row = QHBoxLayout()
        self.server_status_label = QLabel("🔍 Checking Frida installation...")
        self.server_status_label.setStyleSheet("color: #808080;")
        status_row.addWidget(self.server_status_label, 1)

        self.setup_btn = QPushButton("⚙️ Setup & Start Server")
        self.setup_btn.setMinimumWidth(180)
        self.setup_btn.setToolTip(
            "Automatically download the correct frida-server binary,\n"
            "push it to the device via ADB, and start it."
        )
        self.setup_btn.clicked.connect(self._setup_server)
        status_row.addWidget(self.setup_btn)

        self.check_btn = QPushButton("🔄 Refresh")
        self.check_btn.setMinimumWidth(90)
        self.check_btn.setMaximumWidth(110)
        self.check_btn.clicked.connect(self._check_status)
        status_row.addWidget(self.check_btn)

        server_lay.addLayout(status_row)

        device_note = QLabel(
            "💡 Device selection is shared with the Extract APK tab. "
            "Select your device there first if multiple devices are connected."
        )
        device_note.setStyleSheet("color: #606060; font-size: 11px;")
        device_note.setWordWrap(True)
        server_lay.addWidget(device_note)

        root.addWidget(server_group)

        # ── Target ────────────────────────────────────────────────────
        target_group = QGroupBox("🎯 Target")
        target_lay   = QGridLayout(target_group)
        target_lay.setSpacing(8)

        target_lay.addWidget(QLabel("Package:"), 0, 0)
        self.package_combo = QComboBox()
        self.package_combo.setEditable(True)
        self.package_combo.lineEdit().setPlaceholderText(
            "com.example.app — type or click 'List Processes'"
        )
        target_lay.addWidget(self.package_combo, 0, 1)

        self.list_proc_btn = QPushButton("🔄 List Processes")
        self.list_proc_btn.setMinimumWidth(140)
        self.list_proc_btn.setToolTip("Run frida-ps to list all running apps")
        self.list_proc_btn.clicked.connect(self._refresh_processes)
        target_lay.addWidget(self.list_proc_btn, 0, 2)

        target_lay.addWidget(QLabel("Mode:"), 1, 0)
        mode_row = QHBoxLayout()
        self.spawn_radio  = QRadioButton("Spawn (fresh start)")
        self.attach_radio = QRadioButton("Attach (already running)")
        self.spawn_radio.setChecked(True)
        self.spawn_radio.setToolTip(
            "Start the app from scratch with Frida injected before any code runs.\n"
            "Best for catching early initialization (SSL setup, root checks, etc.)"
        )
        self.attach_radio.setToolTip(
            "Attach to an already-running process.\n"
            "Use when the app is already open."
        )
        mode_row.addWidget(self.spawn_radio)
        mode_row.addWidget(self.attach_radio)
        mode_row.addStretch()
        target_lay.addLayout(mode_row, 1, 1, 1, 2)

        root.addWidget(target_group)

        # ── Scripts ───────────────────────────────────────────────────
        scripts_group = QGroupBox("📜 Scripts to Inject")
        scripts_lay   = QVBoxLayout(scripts_group)
        scripts_lay.setSpacing(6)

        # Built-in script checkboxes in 2-column grid
        checks_grid = QGridLayout()
        checks_grid.setSpacing(6)

        self.script_checks: dict[str, QCheckBox] = {}
        # HTTP Toolkit level — full-width, highlighted row at the top
        htk_cb = QCheckBox("🔐 HTTP Toolkit Level  (Deep SSL Bypass — try this when basic bypass fails)")
        htk_cb.setToolTip(
            "Comprehensive multi-layer SSL bypass matching HTTP Toolkit's coverage:\n"
            "• TrustManagerImpl.verifyChain (Conscrypt core — most important)\n"
            "• SSLContext.init universal TrustManager\n"
            "• OkHttp3/4 + OkHttp2 CertificatePinner\n"
            "• X509TrustManagerExtensions (Volley, Retrofit)\n"
            "• WebViewClient, HttpsURLConnection, Apache HTTP\n"
            "• NetworkSecurityConfig pinning check\n"
            "• OpenSSLSocketImpl + ConscryptEngine\n"
            "• Vendor TMs: TrustKit, Huawei, Samsung, Tencent, Appcelerator, Xamarin\n"
            "• Native BoringSSL: SSL_CTX_set_custom_verify, SSL_CTX_set_verify, SSL_get_psk_identity"
        )
        htk_cb.setChecked(False)
        htk_cb.setStyleSheet(
            "QCheckBox { color: #e5c07b; font-weight: bold; padding: 4px; "
            "background-color: #2a2200; border: 1px solid #5a4800; border-radius: 4px; }"
            "QCheckBox:checked { color: #ffcc00; background-color: #332800; }"
        )
        self.script_checks["httptoolkit_level"] = htk_cb
        scripts_lay.addWidget(htk_cb)

        script_defs = [
            ("flutter_unpinning",
             "🐦 Flutter SSL Unpinning",
             "Trust custom certificate for Flutter apps (which ignore native BoringSSL hooks)",
             False),
            ("ssl_pinning",
             "🔓 SSL Pinning Bypass (Basic)",
             "Basic bypass: TrustManager, OkHttp3 CertificatePinner, WebViewClient SSL errors",
             True),
            ("root_detection",
             "🛡️ Root Detection Bypass",
             "Hide su binary, spoof Build props, block Runtime.exec root commands",
             True),
            ("biometric_bypass",
             "👆 Biometric / Auth Bypass",
             "Auto-succeed BiometricPrompt and FingerprintManager callbacks",
             False),
            ("anti_debug",
             "🐛 Anti-Debug Bypass",
             "Block ptrace PTRACE_TRACEME, Debug.isDebuggerConnected, TracerPid checks",
             False),
            ("network_logger",
             "🌐 Network Logger",
             "Log all OkHttp3 URLs, headers, and POST bodies to the output pane",
             False),
            ("method_tracer",
             "🔎 Method Tracer",
             "Hook every method on a target Java class (configure class name below)",
             False),
        ]

        for idx, (key, label, tip, default) in enumerate(script_defs):
            cb = QCheckBox(label)
            cb.setToolTip(tip)
            cb.setChecked(default)
            self.script_checks[key] = cb
            checks_grid.addWidget(cb, idx // 2, idx % 2)

        scripts_lay.addLayout(checks_grid)

        # Method tracer class input (shown only when relevant)
        tracer_row = QHBoxLayout()
        tracer_label = QLabel("  Tracer class:")
        tracer_label.setStyleSheet("color: #808080; font-size: 12px;")
        self.tracer_class_input = QLineEdit()
        self.tracer_class_input.setPlaceholderText(
            "Fully-qualified Java class, e.g. com.example.LoginActivity"
        )
        tracer_row.addWidget(tracer_label)
        tracer_row.addWidget(self.tracer_class_input, 1)
        scripts_lay.addLayout(tracer_row)

        # Divider
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #3c3c3c;")
        scripts_lay.addWidget(sep)

        # Custom script row
        custom_row = QHBoxLayout()
        self.custom_check = QCheckBox("📂 Custom .js Script:")
        self.custom_check.setToolTip("Inject an additional custom Frida script from disk")
        self.custom_path_input = QLineEdit()
        self.custom_path_input.setPlaceholderText("Path to custom .js file...")
        self.custom_path_input.setReadOnly(True)
        custom_browse_btn = QPushButton("Browse")
        custom_browse_btn.setMinimumWidth(80)
        custom_browse_btn.setMaximumWidth(100)
        custom_browse_btn.clicked.connect(self._browse_custom_script)
        custom_row.addWidget(self.custom_check)
        custom_row.addWidget(self.custom_path_input, 1)
        custom_row.addWidget(custom_browse_btn)
        scripts_lay.addLayout(custom_row)

        root.addWidget(scripts_group)

        # ── Proxy Redirect ────────────────────────────────────────────
        proxy_group = QGroupBox("🔀 Proxy Traffic Redirect  (optional — for full MITM capture)")
        proxy_lay   = QHBoxLayout(proxy_group)
        proxy_lay.setSpacing(8)

        self.proxy_check = QCheckBox("Redirect ALL TCP to proxy")
        self.proxy_check.setToolTip(
            "Injects native-connect-hook.js + android-proxy-override.js\n"
            "(from HTTP Toolkit's Frida interception scripts).\n\n"
            "Hooks libc connect() at the socket level — routes every outgoing\n"
            "TCP connection through your MITM proxy regardless of app config.\n"
            "Essential for Flutter, Cronet, and apps that ignore system proxy.\n\n"
            "Set Host:Port to your Burp Suite / HTTP Toolkit / Proxyman address."
        )
        self.proxy_check.setChecked(False)
        proxy_lay.addWidget(self.proxy_check)

        proxy_lay.addWidget(QLabel("Host:"))
        self.proxy_host_input = QLineEdit()
        self.proxy_host_input.setPlaceholderText("192.168.1.100")
        self.proxy_host_input.setMaximumWidth(160)
        self.proxy_host_input.setToolTip("IP of your PC running the proxy (must be reachable from the device)")
        proxy_lay.addWidget(self.proxy_host_input)

        proxy_lay.addWidget(QLabel("Port:"))
        self.proxy_port_input = QLineEdit()
        self.proxy_port_input.setPlaceholderText("8080")
        self.proxy_port_input.setMaximumWidth(70)
        self.proxy_port_input.setToolTip("Proxy listen port (e.g. 8080 for Burp, 8000 for HTTP Toolkit)")
        proxy_lay.addWidget(self.proxy_port_input)

        proxy_lay.addStretch()

        proxy_note = QLabel("Blocks HTTP/3 (QUIC) · redirects IPv4 & IPv6")
        proxy_note.setStyleSheet("color: #606060; font-size: 11px;")
        proxy_lay.addWidget(proxy_note)

        root.addWidget(proxy_group)

        # ── Launch / Stop ─────────────────────────────────────────────
        action_row = QHBoxLayout()
        action_row.setSpacing(8)

        self.launch_btn = QPushButton("▶  Launch with Frida")
        self.launch_btn.setMinimumHeight(44)
        self.launch_btn.setStyleSheet(
            "QPushButton {"
            "  background-color: #107c10; font-size: 14px; font-weight: bold;"
            "  border-radius: 5px;"
            "}"
            "QPushButton:hover   { background-color: #138a13; }"
            "QPushButton:disabled { background-color: #3c3c3c; color: #606060; }"
        )
        self.launch_btn.clicked.connect(self._launch_frida)
        action_row.addWidget(self.launch_btn, 3)

        self.stop_btn = QPushButton("⏹  Stop")
        self.stop_btn.setMinimumHeight(44)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(
            "QPushButton {"
            "  background-color: #8b0000; font-size: 14px; font-weight: bold;"
            "  border-radius: 5px;"
            "}"
            "QPushButton:hover   { background-color: #a00000; }"
            "QPushButton:disabled { background-color: #3c3c3c; color: #606060; }"
        )
        self.stop_btn.clicked.connect(self._stop_frida)
        action_row.addWidget(self.stop_btn, 1)

        root.addLayout(action_row)

        # ── Progress bar ──────────────────────────────────────────────
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        root.addWidget(self.progress_bar)

        # ── Output console ────────────────────────────────────────────
        output_group = QGroupBox("📋 Frida Output")
        output_lay   = QVBoxLayout(output_group)

        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFont(QFont("Consolas", 11))
        self.output_console.setStyleSheet(
            "QTextEdit {"
            "  background-color: #0d0d0d;"
            "  color: #00ff88;"
            "  border: 1px solid #3c3c3c;"
            "  border-radius: 4px;"
            "  padding: 6px;"
            "}"
        )
        self.output_console.setMinimumHeight(180)
        output_lay.addWidget(self.output_console)

        out_btn_row = QHBoxLayout()
        clear_btn = QPushButton("🗑 Clear")
        clear_btn.setMaximumWidth(80)
        clear_btn.clicked.connect(self.output_console.clear)
        copy_btn  = QPushButton("📋 Copy Output")
        copy_btn.setMaximumWidth(130)
        copy_btn.clicked.connect(self._copy_output)
        save_btn  = QPushButton("💾 Save Log")
        save_btn.setMaximumWidth(110)
        save_btn.clicked.connect(self._save_log)
        out_btn_row.addWidget(clear_btn)
        out_btn_row.addStretch()
        out_btn_row.addWidget(copy_btn)
        out_btn_row.addWidget(save_btn)
        output_lay.addLayout(out_btn_row)

        root.addWidget(output_group, 1)   # stretch = 1 → expands to fill remaining space

    # ------------------------------------------------------------------
    # Status check
    # ------------------------------------------------------------------

    def _check_status(self):
        self._set_controls_busy(True)
        self.server_status_label.setText("🔍 Checking...")
        self.server_status_label.setStyleSheet("color: #808080;")

        self.worker = FridaWorker("check_frida", device_serial=self._get_serial())
        self.worker.finished.connect(self._on_status_done)
        self.worker.error.connect(self._on_status_error)
        self.worker.progress.connect(self._append_output)
        self.worker.start()

    def _on_status_done(self, info: dict):
        self._set_controls_busy(False)
        self._frida_version  = info.get("frida_version", "")
        self._server_running = info.get("server_running", False)

        if not info.get("frida_installed"):
            self.server_status_label.setText(
                "⚠️ frida-tools not installed  —  run:  pip install frida-tools"
            )
            self.server_status_label.setStyleSheet("color: #ffaa00;")
            return

        if self._server_running:
            pid = info.get("server_pid", "")
            self.server_status_label.setText(
                f"✅ frida {self._frida_version}  ·  server running (PID {pid})"
            )
            self.server_status_label.setStyleSheet("color: #00ff00;")
        else:
            self.server_status_label.setText(
                f"⚠️ frida {self._frida_version} installed  ·  server NOT running on device"
            )
            self.server_status_label.setStyleSheet("color: #ffaa00;")

    def _on_status_error(self, msg: str):
        self._set_controls_busy(False)
        self.server_status_label.setText(f"❌ {msg}")
        self.server_status_label.setStyleSheet("color: #ff5555;")

    # ------------------------------------------------------------------
    # Server setup
    # ------------------------------------------------------------------

    def _setup_server(self):
        self._set_controls_busy(True)
        self._append_output("── Setting up frida-server ──────────────────────")
        self.worker = FridaWorker("setup_server", device_serial=self._get_serial())
        self.worker.finished.connect(self._on_setup_done)
        self.worker.error.connect(self._on_setup_error)
        self.worker.progress.connect(self._append_output)
        self.worker.start()

    def _on_setup_done(self, result: dict):
        self._set_controls_busy(False)
        msg = f"✓ frida-server {result.get('version')} ({result.get('arch')}) started successfully!"
        self._append_output(msg)
        self.parent.log(msg, "success")
        self._check_status()

    def _on_setup_error(self, msg: str):
        self._set_controls_busy(False)
        self._append_output(f"✗ Setup failed: {msg}")
        QMessageBox.critical(self, "Server Setup Failed", msg)

    # ------------------------------------------------------------------
    # Process list
    # ------------------------------------------------------------------

    def _refresh_processes(self):
        self.list_proc_btn.setEnabled(False)
        self.worker = FridaWorker("list_processes", device_serial=self._get_serial())
        self.worker.finished.connect(self._on_processes_done)
        self.worker.error.connect(self._on_processes_error)
        self.worker.start()

    def _on_processes_done(self, result: dict):
        self.list_proc_btn.setEnabled(True)
        lines = result.get("processes", [])
        current_text = self.package_combo.currentText()
        self.package_combo.clear()
        # Parse "PID  Name" lines (skip header)
        for line in lines[1:]:
            parts = line.split(None, 1)
            if len(parts) == 2:
                self.package_combo.addItem(parts[1].strip(), parts[0])
        # Restore previous selection if possible
        idx = self.package_combo.findText(current_text)
        if idx >= 0:
            self.package_combo.setCurrentIndex(idx)
        elif current_text:
            self.package_combo.setCurrentText(current_text)
        self._append_output(f"Listed {max(0, len(lines) - 1)} processes")

    def _on_processes_error(self, msg: str):
        self.list_proc_btn.setEnabled(True)
        self._append_output(f"frida-ps error: {msg}")

    # ------------------------------------------------------------------
    # Custom script
    # ------------------------------------------------------------------

    def _browse_custom_script(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Custom Frida Script", "",
            "JavaScript Files (*.js);;All Files (*)"
        )
        if path:
            self.custom_path_input.setText(path)
            self.custom_check.setChecked(True)

    # ------------------------------------------------------------------
    # Launch / Stop
    # ------------------------------------------------------------------

    def _launch_frida(self):
        package = self.package_combo.currentText().strip()
        if not package:
            QMessageBox.warning(self, "No Target",
                                "Enter a package name or click 'List Processes' to pick one.")
            return

        # Build script list
        scripts_to_run: list[str] = []
        for key, cb in self.script_checks.items():
            if not cb.isChecked():
                continue
            script = SCRIPTS[key]
            if key == "method_tracer":
                cls = self.tracer_class_input.text().strip()
                if not cls:
                    QMessageBox.warning(
                        self, "Method Tracer — Missing Class",
                        "Method Tracer is checked but no class name is entered.\n"
                        "Enter the fully-qualified class name or uncheck Method Tracer."
                    )
                    return
                script = script.replace("%%TARGET_CLASS%%", cls)
            scripts_to_run.append(script)

        # Proxy redirect script (native-connect-hook + android-proxy-override)
        if self.proxy_check.isChecked():
            p_host = self.proxy_host_input.text().strip()
            p_port = self.proxy_port_input.text().strip()
            if not p_host or not p_port:
                QMessageBox.warning(self, "Proxy Config Missing",
                                    "Proxy redirect is enabled but Host or Port is empty.\n"
                                    "Enter the IP and port of your MITM proxy.")
                return
            if not p_port.isdigit() or not (1 <= int(p_port) <= 65535):
                QMessageBox.warning(self, "Invalid Port",
                                    f"'{p_port}' is not a valid port number (1–65535).")
                return
            proxy_script = SCRIPTS["proxy_redirect"] \
                .replace("%%PROXY_HOST%%", p_host) \
                .replace("%%PROXY_PORT%%", p_port)
            scripts_to_run.insert(0, proxy_script)   # inject first so connect() hook is earliest

        if self.custom_check.isChecked():
            custom_path = self.custom_path_input.text().strip()
            if custom_path:
                p = Path(custom_path)
                if not p.exists():
                    QMessageBox.warning(self, "Custom Script Not Found",
                                        f"File does not exist:\n{custom_path}")
                    return
                scripts_to_run.append(p.read_text(encoding="utf-8"))

        if not scripts_to_run:
            QMessageBox.warning(self, "No Scripts Selected",
                                "Check at least one script to inject, or load a custom script.")
            return

        mode = "spawn" if self.spawn_radio.isChecked() else "attach"
        script_names = [
            label for key, label in [
                ("httptoolkit_level","HTTP Toolkit Level SSL Bypass"),
                ("flutter_unpinning","Flutter SSL Unpinning"),
                ("ssl_pinning",      "SSL Pinning Bypass"),
                ("root_detection",   "Root Detection Bypass"),
                ("biometric_bypass", "Biometric Bypass"),
                ("anti_debug",       "Anti-Debug Bypass"),
                ("network_logger",   "Network Logger"),
                ("method_tracer",    "Method Tracer"),
            ]
            if self.script_checks[key].isChecked()
        ]
        if self.proxy_check.isChecked():
            ph = self.proxy_host_input.text().strip()
            pp = self.proxy_port_input.text().strip()
            script_names.insert(0, f"Proxy Redirect → {ph}:{pp}")
        if self.custom_check.isChecked() and self.custom_path_input.text():
            script_names.append("Custom Script")

        reply = QMessageBox.question(
            self, "Launch Frida",
            f"Launch Frida against:\n\n"
            f"  Package : {package}\n"
            f"  Mode    : {mode}\n"
            f"  Scripts : {', '.join(script_names)}\n\n"
            "The device must have frida-server running.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.output_console.clear()
        self._append_output(f"── Frida → {package}  [{mode}] ─────────────────────")
        self._is_running = True
        self._set_controls_busy(True)
        self.launch_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        self.worker = FridaWorker(
            "run_frida", package, scripts_to_run, mode,
            device_serial=self._get_serial()
        )
        self.worker.finished.connect(self._on_frida_done)
        self.worker.error.connect(self._on_frida_error)
        self.worker.progress.connect(self._append_output)
        self.worker.start()

    def _stop_frida(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait(3000)
        self._is_running = False
        self._set_controls_busy(False)
        self.launch_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._append_output("── Frida stopped by user ─────────────────────────")

    def _on_frida_done(self, _result: dict):
        self._is_running = False
        self._set_controls_busy(False)
        self.launch_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._append_output("── Frida session ended ────────────────────────────")

    def _on_frida_error(self, msg: str):
        self._is_running = False
        self._set_controls_busy(False)
        self.launch_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._append_output(f"✗ Error: {msg}")
        QMessageBox.critical(self, "Frida Error", msg)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def _append_output(self, line: str):
        line = line.strip()
        if not line:
            return

        # Color-code by content
        if line.startswith("[*]") or "complete" in line.lower() or "✓" in line:
            color = "#00ff88"
        elif line.startswith("✗") or "error" in line.lower() or "failed" in line.lower() or "not found" in line.lower():
            color = "#ff5555"
        elif line.startswith("[SSL✓]") or line.startswith("== SSL") or "SSL bypass" in line:
            color = "#e5c07b"
        elif line.startswith("[SSL]"):
            color = "#ffaa00"
        elif line.startswith("[Proxy]"):
            color = "#56b6c2"
        elif line.startswith("[Net]"):
            color = "#00e5ff"
        elif line.startswith("[Root]"):
            color = "#ff9e64"
        elif line.startswith("[Auth]") or line.startswith("[Biometric]"):
            color = "#e5c07b"
        elif line.startswith("[AntiDebug]"):
            color = "#98c379"
        elif line.startswith("[Trace]"):
            color = "#c678dd"
        elif line.startswith("──"):
            color = "#569cd6"
        elif line.startswith("⚠️") or "warn" in line.lower():
            color = "#ffaa00"
        else:
            color = "#d0d0d0"

        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        self.output_console.append(f'<span style="color:{color};">{safe}</span>')
        self.output_console.moveCursor(QTextCursor.MoveOperation.End)

    def _copy_output(self):
        QApplication.clipboard().setText(self.output_console.toPlainText())

    def _save_log(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Frida Log", "frida_output.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            Path(path).write_text(self.output_console.toPlainText(), encoding="utf-8")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_serial(self) -> str:
        """Borrow the selected device serial from the Extract APK tab."""
        try:
            return self.parent.extract_tab._get_selected_serial()
        except Exception:
            return ""

    def _set_controls_busy(self, busy: bool):
        """Toggle non-running controls. Does NOT touch launch/stop buttons during a session."""
        self.progress_bar.setVisible(busy)
        self.progress_bar.setRange(0, 0 if busy else 100)
        self.setup_btn.setEnabled(not busy)
        self.check_btn.setEnabled(not busy)
        self.list_proc_btn.setEnabled(not busy)
        if not self._is_running:
            self.launch_btn.setEnabled(not busy)
