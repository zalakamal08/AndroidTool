from pathlib import Path
import subprocess
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QCheckBox, QProgressBar, QTextEdit,
                             QGroupBox, QGridLayout, QFrame)
from PyQt6.QtCore import Qt
from workers.tools_installer import ToolsInstallerWorker, TOOL_URLS


class InstallTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.worker = None
        self.tools_dir = Path(__file__).parent.parent / "tools"
        self.tool_files = {
            "apktool": "apktool.jar",
            "bundletool": "bundletool-all.jar",
            "uber-apk-signer": "uber-apk-signer.jar",
            "apkeditor": "APKEditor.jar",
            "platform-tools": "platform-tools",  # folder
        }
        self.init_ui()
        self.check_installed_tools()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        
        # Title
        title = QLabel("🔧 Install Required Tools")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(title)
        
        # Status summary
        self.status_label = QLabel("Checking installed tools...")
        self.status_label.setStyleSheet("font-size: 13px; padding: 8px; background-color: #2d2d2d; border-radius: 4px;")
        layout.addWidget(self.status_label)
        
        # JAR Tools Group
        jar_group = QGroupBox("JAR Tools")
        jar_layout = QGridLayout()
        jar_layout.setSpacing(8)
        
        self.tool_rows = {}
        tools = [
            ("apktool", "APKTool", "Decompile/recompile APKs"),
            ("bundletool", "Bundletool", "AAB to APK conversion"),
            ("uber-apk-signer", "Uber APK Signer", "Sign APKs"),
            ("apkeditor", "APKEditor", "Merge split APKs"),
            ("platform-tools", "ADB Platform Tools", "Device communication"),
        ]
        
        for i, (tool_id, name, desc) in enumerate(tools):
            # Status indicator (colored bar)
            indicator = QFrame()
            indicator.setFixedWidth(6)
            indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
            
            # Tool info
            info_label = QLabel(f"<b>{name}</b> - {desc}")
            
            # Install checkbox
            checkbox = QCheckBox()
            checkbox.setChecked(True)
            checkbox.setToolTip(f"Install {name}")
            
            jar_layout.addWidget(indicator, i, 0)
            jar_layout.addWidget(info_label, i, 1)
            jar_layout.addWidget(checkbox, i, 2)
            
            self.tool_rows[tool_id] = {"indicator": indicator, "label": info_label, "checkbox": checkbox}
        
        jar_group.setLayout(jar_layout)
        layout.addWidget(jar_group)
        
        # System Dependencies Group
        sys_group = QGroupBox("System Dependencies")
        sys_layout = QGridLayout()
        sys_layout.setSpacing(8)
        
        # Java
        self.java_indicator = QFrame()
        self.java_indicator.setFixedWidth(6)
        self.java_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
        self.java_label = QLabel("<b>Java</b> - Required for JAR tools")
        self.java_check = QCheckBox()
        self.java_check.setChecked(True)
        sys_layout.addWidget(self.java_indicator, 0, 0)
        sys_layout.addWidget(self.java_label, 0, 1)
        sys_layout.addWidget(self.java_check, 0, 2)
        
        # Node.js
        self.node_indicator = QFrame()
        self.node_indicator.setFixedWidth(6)
        self.node_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
        self.node_label = QLabel("<b>Node.js</b> - Required for apk-mitm")
        self.node_check = QCheckBox()
        self.node_check.setChecked(True)
        sys_layout.addWidget(self.node_indicator, 1, 0)
        sys_layout.addWidget(self.node_label, 1, 1)
        sys_layout.addWidget(self.node_check, 1, 2)
        
        # apk-mitm
        self.apkmitm_indicator = QFrame()
        self.apkmitm_indicator.setFixedWidth(6)
        self.apkmitm_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
        self.apkmitm_label = QLabel("<b>apk-mitm</b> - SSL pinning bypass tool")
        self.apkmitm_check = QCheckBox()
        self.apkmitm_check.setChecked(True)
        sys_layout.addWidget(self.apkmitm_indicator, 2, 0)
        sys_layout.addWidget(self.apkmitm_label, 2, 1)
        sys_layout.addWidget(self.apkmitm_check, 2, 2)
        
        sys_group.setLayout(sys_layout)
        layout.addWidget(sys_group)
        
        # Buttons row
        btn_layout = QHBoxLayout()
        
        self.refresh_btn = QPushButton("🔄 Refresh Status")
        self.refresh_btn.clicked.connect(self.check_installed_tools)
        btn_layout.addWidget(self.refresh_btn)
        
        self.install_btn = QPushButton("📥 Install Selected Tools")
        self.install_btn.setMinimumHeight(40)
        self.install_btn.clicked.connect(self.start_installation)
        self.install_btn.setStyleSheet("""
            QPushButton { background-color: #107c10; font-weight: bold; }
            QPushButton:hover { background-color: #0e6b0e; }
        """)
        btn_layout.addWidget(self.install_btn, 1)
        
        layout.addLayout(btn_layout)
        
        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMaximumHeight(120)
        self.log_output.setStyleSheet("""
            background-color: #1e1e1e; color: #00ff00;
            font-family: 'Consolas', monospace; font-size: 11px;
        """)
        layout.addWidget(self.log_output)
        
        layout.addStretch()
    
    def check_installed_tools(self):
        """Check which tools are already installed and update UI"""
        installed_count = 0
        total_count = len(self.tool_files) + 3  # JAR tools + java, node, apkmitm
        
        # Check JAR tools
        for tool_id, filename in self.tool_files.items():
            path = self.tools_dir / filename
            is_installed = path.exists()
            
            if tool_id in self.tool_rows:
                row = self.tool_rows[tool_id]
                if is_installed:
                    row["indicator"].setStyleSheet("background-color: #107c10; border-radius: 3px;")
                    row["checkbox"].setChecked(False)
                    row["checkbox"].setEnabled(False)
                    installed_count += 1
                else:
                    row["indicator"].setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
                    row["checkbox"].setChecked(True)
                    row["checkbox"].setEnabled(True)
        
        # Check Java
        java_installed = self._check_command("java", "-version")
        if java_installed:
            self.java_indicator.setStyleSheet("background-color: #107c10; border-radius: 3px;")
            self.java_check.setChecked(False)
            self.java_check.setEnabled(False)
            installed_count += 1
        else:
            self.java_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
            self.java_check.setChecked(True)
            self.java_check.setEnabled(True)
        
        # Check Node.js
        node_installed = self._check_command("node", "--version")
        if node_installed:
            self.node_indicator.setStyleSheet("background-color: #107c10; border-radius: 3px;")
            self.node_check.setChecked(False)
            self.node_check.setEnabled(False)
            installed_count += 1
        else:
            self.node_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
            self.node_check.setChecked(True)
            self.node_check.setEnabled(True)
        
        # Check apk-mitm (special case - doesn't have --version, check if command exists)
        apkmitm_installed = self._check_apkmitm()
        if apkmitm_installed:
            self.apkmitm_indicator.setStyleSheet("background-color: #107c10; border-radius: 3px;")
            self.apkmitm_check.setChecked(False)
            self.apkmitm_check.setEnabled(False)
            installed_count += 1
        else:
            self.apkmitm_indicator.setStyleSheet("background-color: #3c3c3c; border-radius: 3px;")
            self.apkmitm_check.setChecked(True)
            self.apkmitm_check.setEnabled(True)
        
        # Update status label
        missing = total_count - installed_count
        if missing == 0:
            self.status_label.setText("✅ All tools installed!")
            self.status_label.setStyleSheet("font-size: 13px; padding: 8px; background-color: #1a3d1a; border-radius: 4px; color: #00ff00;")
        else:
            self.status_label.setText(f"📦 {installed_count}/{total_count} tools installed - {missing} missing")
            self.status_label.setStyleSheet("font-size: 13px; padding: 8px; background-color: #3d3a1a; border-radius: 4px; color: #ffc107;")
    
    def _check_command(self, *args):
        """Check if a command exists and runs"""
        try:
            result = subprocess.run(args, capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def _check_apkmitm(self):
        """Special check for apk-mitm which doesn't support --version properly"""
        try:
            # apk-mitm outputs usage to stderr when run without args
            result = subprocess.run(["apk-mitm"], capture_output=True, text=True, timeout=5, shell=True)
            output = result.stdout + result.stderr
            # Check if output contains usage pattern
            return "apk-mitm" in output.lower() or "apk" in output.lower()
        except:
            return False
    
    def start_installation(self):
        """Start installing only the selected tools"""
        self.install_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.log_output.clear()
        
        self.log("Starting installation of selected tools...")
        
        # Get list of tools to install
        tools_to_install = []
        for tool_id, row in self.tool_rows.items():
            if row["checkbox"].isChecked() and row["checkbox"].isEnabled():
                tools_to_install.append(tool_id)
        
        self.worker = ToolsInstallerWorker(
            str(self.tools_dir),
            install_java=self.java_check.isChecked() and self.java_check.isEnabled(),
            install_node=self.node_check.isChecked() and self.node_check.isEnabled(),
            install_apkmitm=self.apkmitm_check.isChecked() and self.apkmitm_check.isEnabled(),
            tools_to_install=tools_to_install
        )
        self.worker.progress.connect(self.log)
        self.worker.status.connect(self.update_tool_status)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()
    
    def log(self, message):
        self.log_output.append(message)
    
    def update_tool_status(self, tool_name, status):
        if tool_name in self.tool_rows:
            row = self.tool_rows[tool_name]
            colors = {"downloading": "#ffc107", "done": "#107c10", "error": "#ff5555"}
            row["indicator"].setStyleSheet(f"background-color: {colors.get(status, '#3c3c3c')}; border-radius: 3px;")
    
    def on_finished(self, results):
        self.install_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.check_installed_tools()
        
        self.log(f"\n{'='*35}")
        self.log(f"✓ Downloaded: {len(results['downloaded'])}")
        self.log(f"• Skipped: {len(results['skipped'])}")
        if results['failed']:
            self.log(f"✗ Failed: {len(results['failed'])}")
        self.log(f"{'='*35}")
    
    def on_error(self, error_msg):
        self.install_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.log(f"ERROR: {error_msg}")
