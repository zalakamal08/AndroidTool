from pathlib import Path
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QTabWidget,
                             QTextEdit, QPushButton, QMessageBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from ui.home_tab import HomeTab
from ui.extract_tab import ExtractTab


class AndroidPentestTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Android APK Pentesting Tool")
        self.setGeometry(100, 100, 1000, 750)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create console for sharing across tabs
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "background-color: #1e1e1e; color: #00ff00; font-family: 'Courier New';"
        )
        
        # Home Tab
        self.home_tab = HomeTab(self)
        self.tabs.addTab(self.home_tab, "🏠 Home")
        
        # Extract APK Tab
        self.extract_tab = ExtractTab(self)
        self.tabs.addTab(self.extract_tab, "📱 Extract APK")
        
        # Console/Log Tab
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        
        console_layout.addWidget(self.console)
        
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.console.clear)
        console_layout.addWidget(clear_btn)
        
        self.tabs.addTab(console_tab, "📋 Console")
        
        # Status bar
        self.statusBar().showMessage("Ready. Select an operation from Home tab.")
        
        # Apply global styles
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
            }
            QPushButton {
                padding: 8px 15px;
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
            QListWidget {
                border: 2px solid #ddd;
                border-radius: 4px;
                padding: 5px;
                font-size: 13px;
            }
            QLabel {
                font-size: 13px;
            }
        """)
    
    def log(self, message, level="info"):
        """Add message to console"""
        colors = {
            "info": "#00ff00",
            "warning": "#ffaa00",
            "error": "#ff0000",
            "success": "#00ffff"
        }
        color = colors.get(level, "#00ff00")
        self.console.append(f'<span style="color: {color};">[{level.upper()}] {message}</span>')
    
    def switch_to_extract_tab(self):
        """Switch to extract APK tab"""
        self.tabs.setCurrentWidget(self.extract_tab)