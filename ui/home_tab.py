from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QPushButton, QLabel, QFileDialog, QMessageBox,
                             QProgressBar)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from workers.apk_worker import APKWorker


class HomeTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.worker = None
        self.default_dir = Path.home() / "Android"
        self.default_dir.mkdir(exist_ok=True)  # Create Android folder if not exists
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("🔒 Android APK Pentesting Tool")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Select an operation to get started")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666; font-size: 14px; margin-bottom: 20px;")
        layout.addWidget(subtitle)
        
        # Create grid for operation buttons
        grid_layout = QGridLayout()
        grid_layout.setSpacing(15)
        
        # Button configurations: (text, row, col, action)
        buttons = [
            ("🔧 Install Tools", 0, 0, self.install_tools),
            ("📱 Extract APK", 0, 1, self.extract_apk),
            ("🔗 Merge Split APKs", 1, 0, self.merge_split_apks),
            ("📦 Decompile APK", 1, 1, self.decompile_apk),
            ("🔓 Remove SSL Pinning", 2, 0, self.remove_ssl_pinning),
            ("✍️ Resign APK", 2, 1, self.resign_apk),
        ]
        
        for text, row, col, action in buttons:
            btn = self.create_operation_button(text, action)
            grid_layout.addWidget(btn, row, col)
        
        layout.addLayout(grid_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Add stretch to push everything to top
        layout.addStretch()
        
        # Info section
        info_label = QLabel(f"ℹ️ Default working directory: {self.default_dir}")
        info_label.setStyleSheet("""
            background-color: #e3f2fd;
            padding: 10px;
            border-radius: 5px;
            color: #1976d2;
        """)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
    
    def create_operation_button(self, text, action):
        """Create a styled operation button"""
        btn = QPushButton(text)
        btn.clicked.connect(action)
        btn.setMinimumHeight(80)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 15px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 8px;
                text-align: center;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        return btn
    
    def install_tools(self):
        """Install required tools - placeholder for now"""
        QMessageBox.information(
            self,
            "Install Tools",
            "Tool installation functionality will be implemented soon.\n\n"
            "For now, please ensure you have the following tools installed:\n"
            "• ADB (Android Debug Bridge)\n"
            "• Java Runtime Environment (JRE 8 or higher)\n"
            "• APKTool (apktool.jar and apktool.bat in tools folder)\n"
            "• APKEditor (APKEditor.jar in tools folder)\n"
            "• uber-apk-signer (uber-apk-signer.jar in tools folder)\n"
            "• apk-mitm (npm install -g apk-mitm)\n\n"
            f"Tools folder location: {Path(__file__).parent.parent / 'tools'}"
        )
        self.parent.log("Install Tools feature - Coming soon!", "info")
    
    def extract_apk(self):
        """Switch to Extract APK tab"""
        self.parent.switch_to_extract_tab()
        self.parent.log("Switched to Extract APK tab", "info")
    
    def merge_split_apks(self):
        """Merge split APKs using APKEditor"""
        # Ask user to select split APK directory - start from Android folder
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Split APK Directory (containing .apk files)",
            str(self.default_dir),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not directory:
            self.parent.log("Merge operation cancelled by user", "warning")
            return
        
        # Validate directory
        dir_path = Path(directory)
        apk_files = list(dir_path.glob("*.apk"))
        if not apk_files:
            QMessageBox.warning(
                self,
                "No APK Files",
                f"No APK files found in the selected directory:\n{directory}\n\n"
                "Please select a directory containing split APK files."
            )
            self.parent.log(f"No APK files found in: {directory}", "error")
            return
        
        self.parent.log(f"Found {len(apk_files)} APK file(s) in directory", "info")
        
        # Output will be created in the SAME directory as split APKs
        # Worker will handle moving the merged APK back to the original folder
        output_dir = dir_path  # Use the same directory
        
        self.parent.log(f"Output will be saved to: {output_dir}", "info")
        self.parent.log(f"Starting merge for: {directory}", "info")
        self.parent.statusBar().showMessage("Merging split APKs...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Start worker
        self.worker = APKWorker("merge_split_apks", directory, str(output_dir))
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(lambda cmd: self.parent.log(f"Command: {cmd}", "info"))
        self.worker.start()
    
    def decompile_apk(self):
        """Decompile APK using APKTool"""
        # Ask user to select APK file - start from Android folder
        apk_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select APK File to Decompile",
            str(self.default_dir),
            "APK Files (*.apk);;All Files (*.*)"
        )
        
        if not apk_file:
            self.parent.log("Decompile operation cancelled by user", "warning")
            return
        
        # Validate file
        apk_path = Path(apk_file)
        if not apk_path.exists():
            QMessageBox.critical(
                self,
                "File Not Found",
                f"The selected APK file does not exist:\n{apk_file}"
            )
            return
        
        # Create output directory automatically in the same directory as APK
        output_dir = apk_path.parent / "decompiled" / apk_path.stem
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.parent.log(f"Output will be saved to: {output_dir}", "info")
        self.parent.log(f"Starting decompilation for: {apk_file}", "info")
        self.parent.statusBar().showMessage("Decompiling APK...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Start worker - pass parent directory, worker will create subdirectory
        self.worker = APKWorker("decompile_apk", apk_file, str(apk_path.parent / "decompiled"))
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(lambda cmd: self.parent.log(f"Command: {cmd}", "info"))
        self.worker.start()
    
    def remove_ssl_pinning(self):
        """Remove SSL pinning using apk-mitm"""
        # Ask user to select APK file - start from Android folder
        apk_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select APK File to Remove SSL Pinning",
            str(self.default_dir),
            "APK Files (*.apk);;All Files (*.*)"
        )
        
        if not apk_file:
            self.parent.log("SSL pinning removal cancelled by user", "warning")
            return
        
        # Validate file
        apk_path = Path(apk_file)
        if not apk_path.exists():
            QMessageBox.critical(
                self,
                "File Not Found",
                f"The selected APK file does not exist:\n{apk_file}"
            )
            return
        
        # Create output directory automatically in the same directory as APK
        output_dir = apk_path.parent / "patched_apk"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.parent.log(f"Output will be saved to: {output_dir}", "info")
        self.parent.log(f"Removing SSL pinning for: {apk_file}", "info")
        self.parent.statusBar().showMessage("Removing SSL pinning...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Start worker
        self.worker = APKWorker("remove_ssl_pinning", apk_file, str(output_dir))
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(lambda cmd: self.parent.log(f"Command: {cmd}", "info"))
        self.worker.start()
    
    def resign_apk(self):
        """Resign APK using uber-apk-signer"""
        # Ask user to select APK file - start from Android folder
        apk_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select APK File to Resign",
            str(self.default_dir),
            "APK Files (*.apk);;All Files (*.*)"
        )
        
        if not apk_file:
            self.parent.log("Resign operation cancelled by user", "warning")
            return
        
        # Validate file
        apk_path = Path(apk_file)
        if not apk_path.exists():
            QMessageBox.critical(
                self,
                "File Not Found",
                f"The selected APK file does not exist:\n{apk_file}"
            )
            return
        
        # Create output directory automatically in the same directory as APK
        output_dir = apk_path.parent / "signed_apk"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        self.parent.log(f"Output will be saved to: {output_dir}", "info")
        self.parent.log(f"Resigning APK: {apk_file}", "info")
        self.parent.statusBar().showMessage("Resigning APK...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Start worker
        self.worker = APKWorker("resign_apk", apk_file, str(output_dir))
        self.worker.finished.connect(self.on_operation_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(lambda cmd: self.parent.log(f"Command: {cmd}", "info"))
        self.worker.start()
    
    def on_operation_complete(self, result):
        """Handle operation completion"""
        self.progress_bar.setVisible(False)
        
        operation = result.get('operation', 'Operation')
        self.parent.log(f"✓ {operation.title()} completed successfully!", "success")
        self.parent.log(f"Input: {result.get('input', 'N/A')}", "success")
        self.parent.log(f"Output: {result.get('output', 'N/A')}", "success")
        
        self.parent.statusBar().showMessage("Operation complete!")
        
        # Format operation name nicely
        op_name = operation.replace('_', ' ').title()
        
        msg = f"""{op_name} Successful!

Input: {result.get('input', 'N/A')}
Output: {result.get('output', 'N/A')}

You can now find the output files in the specified directory.
"""
        QMessageBox.information(self, "Success", msg)
    
    def on_error(self, error_msg):
        """Handle errors"""
        self.progress_bar.setVisible(False)
        self.parent.log(error_msg, "error")
        self.parent.statusBar().showMessage("Error occurred")
        QMessageBox.critical(self, "Error", error_msg)