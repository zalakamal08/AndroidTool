import subprocess
import urllib.request
import zipfile
import shutil
import os
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


# Tool download URLs (updated as of Jan 2026)
TOOL_URLS = {
    "apktool": {
        "url": "https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar",
        "filename": "apktool.jar",
        "type": "jar"
    },
    "bundletool": {
        "url": "https://github.com/google/bundletool/releases/download/1.17.2/bundletool-all-1.17.2.jar",
        "filename": "bundletool-all.jar",
        "type": "jar"
    },
    "uber-apk-signer": {
        "url": "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar",
        "filename": "uber-apk-signer.jar",
        "type": "jar"
    },
    "apkeditor": {
        "url": "https://github.com/REAndroid/APKEditor/releases/download/V1.4.1/APKEditor-1.4.1.jar",
        "filename": "APKEditor.jar",
        "type": "jar"
    },
    "platform-tools": {
        "url": "https://dl.google.com/android/repository/platform-tools-latest-windows.zip",
        "filename": "platform-tools.zip",
        "type": "zip"
    }
}


class ToolsInstallerWorker(QThread):
    """Worker thread for downloading and installing tools"""
    progress = pyqtSignal(str)
    status = pyqtSignal(str, str)  # tool_name, status ("downloading", "done", "error", "skipped")
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, tools_dir, install_java=False, install_node=False, install_apkmitm=False, tools_to_install=None):
        super().__init__()
        self.tools_dir = Path(tools_dir)
        self.install_java = install_java
        self.install_node = install_node
        self.install_apkmitm = install_apkmitm
        self.tools_to_install = tools_to_install  # List of tool IDs to install, None = all
        self.results = {"downloaded": [], "skipped": [], "failed": [], "installed": []}
    
    def run(self):
        try:
            self.tools_dir.mkdir(parents=True, exist_ok=True)
            
            # Download JAR tools (only selected ones)
            for tool_name, tool_info in TOOL_URLS.items():
                if self.tools_to_install is None or tool_name in self.tools_to_install:
                    self._download_tool(tool_name, tool_info)
            
            # Create apktool.bat wrapper for Windows
            self._create_apktool_bat()
            
            # Install system dependencies
            if self.install_java:
                self._check_or_install_java()
            
            if self.install_node:
                self._check_or_install_node()
            
            if self.install_apkmitm:
                self._install_apkmitm()
            
            self.finished.emit(self.results)
            
        except Exception as e:
            self.error.emit(str(e))
    
    def _download_tool(self, tool_name, tool_info):
        """Download a single tool"""
        target_path = self.tools_dir / tool_info["filename"]
        
        # Skip if already exists
        if target_path.exists() and tool_info["type"] == "jar":
            self.progress.emit(f"✓ {tool_name} already exists")
            self.status.emit(tool_name, "skipped")
            self.results["skipped"].append(tool_name)
            return
        
        try:
            self.progress.emit(f"Downloading {tool_name}...")
            self.status.emit(tool_name, "downloading")
            
            # Download file
            urllib.request.urlretrieve(tool_info["url"], target_path)
            
            # Handle zip files (platform-tools)
            if tool_info["type"] == "zip":
                self._extract_zip(target_path, tool_name)
            else:
                self.progress.emit(f"✓ {tool_name} downloaded")
                self.status.emit(tool_name, "done")
                self.results["downloaded"].append(tool_name)
                
        except Exception as e:
            self.progress.emit(f"✗ {tool_name} failed: {str(e)}")
            self.status.emit(tool_name, "error")
            self.results["failed"].append(tool_name)
    
    def _extract_zip(self, zip_path, tool_name):
        """Extract zip file and cleanup"""
        try:
            self.progress.emit(f"Extracting {tool_name}...")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.tools_dir)
            
            # Remove zip file after extraction
            zip_path.unlink()
            
            # If this was platform-tools, inject directory into process PATH
            # so adb.exe is immediately usable without restarting the app.
            if tool_name == "platform-tools":
                pt_dir = str(self.tools_dir / "platform-tools")
                current_path = os.environ.get("PATH", "")
                if pt_dir not in current_path:
                    os.environ["PATH"] = pt_dir + os.pathsep + current_path
                    self.progress.emit(f"✓ Added platform-tools to process PATH")
            
            self.progress.emit(f"✓ {tool_name} extracted")
            self.status.emit(tool_name, "done")
            self.results["downloaded"].append(tool_name)
            
        except Exception as e:
            self.progress.emit(f"✗ Failed to extract {tool_name}: {str(e)}")
            self.status.emit(tool_name, "error")
            self.results["failed"].append(tool_name)
    
    def _create_apktool_bat(self):
        """Create apktool.bat wrapper script"""
        bat_path = self.tools_dir / "apktool.bat"
        jar_path = self.tools_dir / "apktool.jar"
        
        if not jar_path.exists():
            return
            
        bat_content = f'''@echo off
setlocal
set BASENAME=apktool
chcp 65001 2>nul >nul
set java_exe=java
%java_exe% -jar -Duser.language=en -Dfile.encoding=UTF8 "%~dp0%BASENAME%.jar" %*
endlocal
'''
        bat_path.write_text(bat_content)
        self.progress.emit("✓ Created apktool.bat")
    
    def _check_or_install_java(self):
        """Check if Java is installed, guide user if not"""
        self.progress.emit("Checking Java installation...")
        
        try:
            result = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.progress.emit("✓ Java is installed")
                self.results["installed"].append("java")
                return
        except:
            pass
        
        self.progress.emit("⚠ Java not found. Please install Java 8+ from:")
        self.progress.emit("  https://adoptium.net/temurin/releases/")
        self.results["failed"].append("java")
    
    def _check_or_install_node(self):
        """Check if Node.js is installed, guide user if not"""
        self.progress.emit("Checking Node.js installation...")
        
        try:
            result = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.progress.emit(f"✓ Node.js {result.stdout.strip()} is installed")
                self.results["installed"].append("node")
                return
        except:
            pass
        
        self.progress.emit("⚠ Node.js not found. Please install from:")
        self.progress.emit("  https://nodejs.org/")
        self.results["failed"].append("node")
    
    def _install_apkmitm(self):
        """Install apk-mitm via npm"""
        self.progress.emit("Installing apk-mitm...")
        
        try:
            # Check if npm is available
            result = subprocess.run(["npm", "--version"], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                self.progress.emit("⚠ npm not found. Install Node.js first.")
                self.results["failed"].append("apk-mitm")
                return
            
            # Install apk-mitm globally
            self.progress.emit("Running: npm install -g apk-mitm")
            result = subprocess.run(
                ["npm", "install", "-g", "apk-mitm"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                self.progress.emit("✓ apk-mitm installed successfully")
                self.results["installed"].append("apk-mitm")
            else:
                self.progress.emit(f"⚠ apk-mitm install failed: {result.stderr}")
                self.results["failed"].append("apk-mitm")
                
        except subprocess.TimeoutExpired:
            self.progress.emit("⚠ apk-mitm installation timed out")
            self.results["failed"].append("apk-mitm")
        except Exception as e:
            self.progress.emit(f"⚠ apk-mitm error: {str(e)}")
            self.results["failed"].append("apk-mitm")
