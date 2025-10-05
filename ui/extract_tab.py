from pathlib import Path
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLineEdit, QListWidget, QLabel, QMessageBox,
                             QProgressBar, QFileDialog)
from PyQt6.QtCore import Qt
from workers.adb_worker import ADBWorker


class ExtractTab(QWidget):
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.worker = None
        self.default_dir = Path.home() / "Android"
        self.default_dir.mkdir(exist_ok=True)  # Create Android folder if not exists
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Search section
        search_layout = QHBoxLayout()
        search_label = QLabel("Search Package:")
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter package name or keyword (e.g., com.example)")
        self.search_input.returnPressed.connect(self.search_packages)
        self.search_btn = QPushButton("🔍 Search")
        self.search_btn.clicked.connect(self.search_packages)
        
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input, 1)
        search_layout.addWidget(self.search_btn)
        layout.addLayout(search_layout)
        
        # Command display section
        cmd_layout = QVBoxLayout()
        cmd_label = QLabel("Current Command:")
        self.cmd_display = QLineEdit()
        self.cmd_display.setReadOnly(True)
        self.cmd_display.setPlaceholderText("No command running...")
        self.cmd_display.setStyleSheet("""
            QLineEdit {
                background-color: #2b2b2b;
                color: #00ff00;
                font-family: 'Courier New';
                font-size: 12px;
                padding: 8px;
                border: 2px solid #4CAF50;
            }
        """)
        cmd_layout.addWidget(cmd_label)
        cmd_layout.addWidget(self.cmd_display)
        layout.addLayout(cmd_layout)
        
        # Package list
        list_label = QLabel("Packages Found:")
        layout.addWidget(list_label)
        
        self.package_list = QListWidget()
        self.package_list.itemClicked.connect(self.on_package_clicked)
        self.package_list.itemDoubleClicked.connect(self.extract_apk)
        layout.addWidget(self.package_list)
        
        # Selected package info
        selected_layout = QHBoxLayout()
        selected_label = QLabel("Selected Package:")
        self.selected_package_label = QLabel("None")
        self.selected_package_label.setStyleSheet("color: #0066cc; font-weight: bold;")
        selected_layout.addWidget(selected_label)
        selected_layout.addWidget(self.selected_package_label, 1)
        layout.addLayout(selected_layout)
        
        # Output directory
        output_layout = QHBoxLayout()
        output_label = QLabel("Output Directory:")
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setText(str(self.default_dir))
        
        browse_btn = QPushButton("📁 Browse")
        browse_btn.clicked.connect(self.browse_output_dir)
        
        output_layout.addWidget(output_label)
        output_layout.addWidget(self.output_dir_input, 1)
        output_layout.addWidget(browse_btn)
        layout.addLayout(output_layout)
        
        # Extract button
        self.extract_btn = QPushButton("📦 Extract Selected APK")
        self.extract_btn.clicked.connect(self.extract_apk)
        self.extract_btn.setEnabled(False)
        self.extract_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
        layout.addWidget(self.extract_btn)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Info label
        info_label = QLabel(f"💡 Tip: APKs will be saved to {self.default_dir}/[package_name]/")
        info_label.setStyleSheet("""
            background-color: #fff3cd;
            padding: 8px;
            border-radius: 4px;
            color: #856404;
            font-size: 12px;
        """)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
    
    def browse_output_dir(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            self.output_dir_input.text(),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if directory:
            self.output_dir_input.setText(directory)
            self.parent.log(f"Output directory set to: {directory}", "info")
    
    def search_packages(self):
        """Search for packages"""
        search_term = self.search_input.text().strip()
        self.package_list.clear()
        self.selected_package_label.setText("None")
        self.extract_btn.setEnabled(False)
        
        self.parent.log(f"Searching packages with term: '{search_term if search_term else 'all packages'}'")
        self.parent.statusBar().showMessage("Searching packages...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        # Disable buttons during search
        self.search_btn.setEnabled(False)
        self.extract_btn.setEnabled(False)
        
        # Start worker thread
        self.worker = ADBWorker("list_packages", search_term)
        self.worker.finished.connect(self.on_search_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(self.update_command_display)
        self.worker.start()
    
    def on_search_complete(self, packages):
        """Handle search completion"""
        self.progress_bar.setVisible(False)
        self.search_btn.setEnabled(True)
        
        if not packages:
            search_term = self.search_input.text().strip()
            if search_term:
                msg = f"No packages found matching '{search_term}'"
                self.parent.log(msg, "warning")
                self.parent.statusBar().showMessage("No packages found")
                QMessageBox.information(
                    self, 
                    "No Results", 
                    f"No packages found matching '{search_term}'.\n\n"
                    "Try a different search term or leave it empty to see all packages."
                )
            else:
                self.parent.log("No packages found on device", "warning")
                self.parent.statusBar().showMessage("No packages found")
                QMessageBox.warning(
                    self,
                    "No Packages",
                    "No packages found on the device.\n\n"
                    "Please check your device connection."
                )
            return
        
        self.package_list.addItems(packages)
        self.parent.log(f"Found {len(packages)} package(s)", "success")
        self.parent.statusBar().showMessage(
            f"Found {len(packages)} packages. Click to select and extract."
        )
    
    def on_package_clicked(self, item):
        """Handle single-click on package"""
        package_name = item.text()
        self.selected_package_label.setText(package_name)
        self.extract_btn.setEnabled(True)
        self.parent.log(f"Selected package: {package_name}", "info")
    
    def update_command_display(self, cmd):
        """Update the command display field"""
        if cmd:
            self.cmd_display.setText(cmd)
        else:
            self.cmd_display.clear()
            self.cmd_display.setPlaceholderText("No command running...")
    
    def on_error(self, error_msg):
        """Handle errors"""
        self.progress_bar.setVisible(False)
        self.search_btn.setEnabled(True)
        self.extract_btn.setEnabled(True)
        self.parent.log(error_msg, "error")
        self.parent.statusBar().showMessage("Error occurred")
        QMessageBox.critical(self, "Error", error_msg)
    
    def extract_apk(self):
        """Extract APK for selected package"""
        current_item = self.package_list.currentItem()
        if not current_item:
            QMessageBox.warning(
                self, 
                "No Selection", 
                "Please select a package from the list first."
            )
            return
        
        package_name = current_item.text()
        output_dir = self.output_dir_input.text().strip()
        
        # Validate output directory
        if not output_dir:
            QMessageBox.warning(
                self, 
                "No Output Directory", 
                "Please specify an output directory."
            )
            return
        
        output_path = Path(output_dir)
        if not output_path.exists():
            reply = QMessageBox.question(
                self,
                "Create Directory",
                f"Output directory does not exist:\n{output_dir}\n\n"
                "Do you want to create it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                try:
                    output_path.mkdir(parents=True, exist_ok=True)
                    self.parent.log(f"Created output directory: {output_dir}", "success")
                except Exception as e:
                    QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to create directory:\n{str(e)}"
                    )
                    return
            else:
                return
        
        self.parent.log(f"Starting extraction for: {package_name}")
        self.parent.statusBar().showMessage(f"Extracting {package_name}...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Disable buttons
        self.extract_btn.setEnabled(False)
        self.search_btn.setEnabled(False)
        
        # Start extraction
        self.worker = ADBWorker("extract_apk", package_name, output_dir)
        self.worker.finished.connect(self.on_extract_complete)
        self.worker.error.connect(self.on_error)
        self.worker.progress.connect(self.parent.log)
        self.worker.command.connect(self.update_command_display)
        self.worker.start()
    
    def on_extract_complete(self, result):
        """Handle extraction completion"""
        self.progress_bar.setVisible(False)
        self.extract_btn.setEnabled(True)
        self.search_btn.setEnabled(True)
        
        self.parent.log(f"✓ Extraction complete!", "success")
        self.parent.log(f"Package: {result['package']}", "success")
        self.parent.log(f"Directory: {result['directory']}", "success")
        self.parent.log(f"Files extracted: {result['count']}", "success")
        
        self.parent.statusBar().showMessage("Extraction complete!")
        
        # Format file list
        file_list = '\n'.join(['• ' + Path(f).name for f in result['files']])
        
        msg = f"""Extraction Successful!

Package: {result['package']}
Output Directory: {result['directory']}
Files Extracted: {result['count']}

Files:
{file_list}
"""
        QMessageBox.information(self, "Success", msg)