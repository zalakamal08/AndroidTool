"""ADB Worker for Android device operations"""
import subprocess
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


class ADBWorker(QThread):
    """Worker thread for ADB operations to prevent GUI freezing"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    command = pyqtSignal(str)
    
    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
    
    def run(self):
        try:
            if self.operation == "list_packages":
                result = self.list_packages(self.args[0] if self.args else "")
                self.finished.emit(result)
            elif self.operation == "extract_apk":
                result = self.extract_apk(self.args[0], self.args[1])
                self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
    
    def check_adb_connection(self):
        """Check if ADB is installed and device is connected"""
        try:
            # Check if ADB is installed
            cmd = 'adb version'
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
            
            if result.returncode != 0:
                raise Exception(
                    "ADB (Android Debug Bridge) not found.\n"
                    "Please install ADB and ensure it's in your system PATH.\n"
                    "Download from: https://developer.android.com/studio/releases/platform-tools"
                )
            
            # Check device connection
            cmd = 'adb devices'
            self.command.emit(cmd)
            result = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=10)
            
            if result.returncode != 0:
                raise Exception(f"ADB command failed: {result.stderr}")
            
            # Parse output to check for connected devices
            lines = result.stdout.strip().split('\n')
            devices = [line for line in lines[1:] if line.strip() and '\tdevice' in line]
            
            if not devices:
                raise Exception(
                    "No Android device connected.\n\n"
                    "Please:\n"
                    "1. Connect your Android device via USB\n"
                    "2. Enable 'USB Debugging' in Developer Options\n"
                    "3. Accept the USB debugging authorization on your device\n"
                    "4. Run 'adb devices' to verify connection"
                )
            
            return True
            
        except subprocess.TimeoutExpired:
            raise Exception("ADB command timed out. Please check your ADB installation.")
        except Exception as e:
            raise e
    
    def list_packages(self, search_term):
        """List all packages matching search term"""
        self.progress.emit("Connecting to device...")
        
        # Check ADB connection
        self.check_adb_connection()
        
        self.progress.emit("Fetching packages...")
        
        # Get list of packages
        # -3 flag shows only third-party packages
        if search_term:
            cmd = 'adb shell pm list packages'
        else:
            cmd = 'adb shell pm list packages'
        
        self.command.emit(cmd)
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                shell=True,
                timeout=30
            )
        except subprocess.TimeoutExpired:
            raise Exception("Package listing timed out. Please check your device connection.")
        
        if result.returncode != 0:
            raise Exception(f"ADB command failed: {result.stderr}")
        
        # Parse package names
        packages = []
        for line in result.stdout.splitlines():
            if line.startswith('package:'):
                pkg_name = line.replace('package:', '').strip()
                if not search_term or search_term.lower() in pkg_name.lower():
                    packages.append(pkg_name)
        
        # Sort packages alphabetically
        packages.sort()
        
        self.command.emit("")
        return packages
    
    def extract_apk(self, package_name, output_dir):
        """Extract APK from device"""
        self.progress.emit(f"Finding APK path for {package_name}...")
        
        # Check ADB connection
        self.check_adb_connection()
        
        # Validate package name
        if not package_name or not package_name.strip():
            raise Exception("Invalid package name")
        
        # Get APK path
        cmd = f'adb shell pm path {package_name}'
        self.command.emit(cmd)
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                shell=True,
                timeout=10
            )
        except subprocess.TimeoutExpired:
            raise Exception("Finding APK path timed out. Please check your device connection.")
        
        if result.returncode != 0 or not result.stdout:
            raise Exception(
                f"Could not find APK for package: {package_name}\n\n"
                f"Please verify:\n"
                f"1. The package name is correct\n"
                f"2. The app is installed on the device\n"
                f"3. You have proper permissions"
            )
        
        # Parse APK paths
        apk_paths = []
        for line in result.stdout.splitlines():
            if line.startswith('package:'):
                apk_path = line.replace('package:', '').strip()
                if apk_path:
                    apk_paths.append(apk_path)
        
        if not apk_paths:
            raise Exception(f"No APK paths found for {package_name}")
        
        self.progress.emit(f"Found {len(apk_paths)} APK file(s)")
        
        # Create directories
        output_dir_path = Path(output_dir).resolve()
        android_dir = output_dir_path / "Android"
        android_dir.mkdir(exist_ok=True)
        
        pkg_dir = android_dir / package_name
        pkg_dir.mkdir(parents=True, exist_ok=True)
        
        self.progress.emit(f"Created directory: {pkg_dir}")
        
        # Pull APKs
        pulled_files = []
        for idx, apk_path in enumerate(apk_paths):
            self.progress.emit(f"Pulling APK {idx+1}/{len(apk_paths)}: {Path(apk_path).name}")
            
            # Determine output filename
            if len(apk_paths) == 1:
                output_file = pkg_dir / f"{package_name}.apk"
            else:
                # For split APKs, preserve original filename
                output_file = pkg_dir / Path(apk_path).name
            
            cmd = f'adb pull "{apk_path}" "{output_file}"'
            self.command.emit(cmd)
            
            try:
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    shell=True,
                    timeout=120  # 2 minutes for large APKs
                )
            except subprocess.TimeoutExpired:
                self.progress.emit(f"⚠ Timeout pulling {apk_path}")
                continue
            
            if result.returncode == 0 and output_file.exists():
                pulled_files.append(str(output_file))
                file_size = output_file.stat().st_size / (1024 * 1024)  # MB
                self.progress.emit(f"✓ Pulled: {output_file.name} ({file_size:.2f} MB)")
            else:
                self.progress.emit(f"⚠ Failed to pull {apk_path}")
        
        if not pulled_files:
            raise Exception(
                "Failed to pull any APK files from device.\n\n"
                "This might be due to:\n"
                "1. Insufficient permissions\n"
                "2. Connection issues\n"
                "3. Storage problems"
            )
        
        self.command.emit("")
        return {
            'package': package_name,
            'directory': str(pkg_dir),
            'files': pulled_files,
            'count': len(pulled_files)
        }