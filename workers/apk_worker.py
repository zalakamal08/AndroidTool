import subprocess
import os
import shutil
import sys
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


class APKWorker(QThread):
    """Worker thread for APK operations (decompile, merge, resign, SSL pinning removal)"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)
    command = pyqtSignal(str)
    
    def __init__(self, operation, *args):
        super().__init__()
        self.operation = operation
        self.args = args
        # Get the project root directory (where main.py is located)
        self.project_root = Path(__file__).parent.parent
        self.tools_dir = self.project_root / "tools"
    
    def run(self):
        try:
            if self.operation == "merge_split_apks":
                result = self.merge_split_apks(self.args[0], self.args[1])
                self.finished.emit(result)
            elif self.operation == "decompile_apk":
                result = self.decompile_apk(self.args[0], self.args[1])
                self.finished.emit(result)
            elif self.operation == "remove_ssl_pinning":
                result = self.remove_ssl_pinning(self.args[0], self.args[1])
                self.finished.emit(result)
            elif self.operation == "resign_apk":
                result = self.resign_apk(self.args[0], self.args[1])
                self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
    
    def merge_split_apks(self, split_apk_dir, output_dir):
        """Merge split APKs using APKEditor"""
        self.progress.emit("Starting APK merge process...")
        
        split_path = Path(split_apk_dir).resolve()
        if not split_path.exists() or not split_path.is_dir():
            raise Exception(f"Invalid directory: {split_apk_dir}")
        
        # Check for APK files in directory
        apk_files = list(split_path.glob("*.apk"))
        if not apk_files:
            raise Exception(f"No APK files found in directory: {split_apk_dir}")
        
        # Check if APKEditor exists in tools directory
        apkeditor_path = self.tools_dir / "APKEditor.jar"
        
        if not apkeditor_path.exists():
            raise Exception(
                f"APKEditor.jar not found at: {apkeditor_path}\n"
                f"Please ensure the tools directory exists with all required tools."
            )
        
        # Create temporary output directory for merging
        temp_output_dir = split_path.parent / "temp_merged_output"
        temp_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Get directory name for output filename
        output_name = split_path.name + "_merged.apk"
        temp_output_file = temp_output_dir / output_name
        
        self.progress.emit(f"Found {len(apk_files)} APK file(s) to merge...")
        self.progress.emit("Merging split APKs...")
        
        # Run APKEditor merge command
        cmd = f'java -jar "{apkeditor_path}" m -i "{split_path}" -o "{temp_output_file}"'
        self.command.emit(cmd)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        
        if result.returncode != 0:
            # Clean up temp directory
            shutil.rmtree(temp_output_dir, ignore_errors=True)
            error_msg = result.stderr if result.stderr else result.stdout
            raise Exception(f"APKEditor merge failed: {error_msg}")
        
        if not temp_output_file.exists():
            # Clean up temp directory
            shutil.rmtree(temp_output_dir, ignore_errors=True)
            raise Exception("Merged APK was not created. Check if the APKs are valid split APKs.")
        
        # Move the merged APK to the original folder
        final_output_file = split_path / output_name
        self.progress.emit(f"Moving merged APK to: {split_path}")
        shutil.move(str(temp_output_file), str(final_output_file))
        
        # Clean up temp directory
        shutil.rmtree(temp_output_dir, ignore_errors=True)
        
        self.progress.emit("✓ Merge completed successfully!")
        self.command.emit("")
        
        return {
            'operation': 'merge',
            'input': str(split_path),
            'output': str(final_output_file),
            'success': True
        }
    
    def decompile_apk(self, apk_path, output_dir):
        """Decompile APK using APKTool"""
        self.progress.emit("Starting APK decompilation...")
        
        apk_file = Path(apk_path).resolve()
        if not apk_file.exists() or not apk_file.is_file():
            raise Exception(f"APK file not found: {apk_path}")
        
        if apk_file.suffix.lower() != '.apk':
            raise Exception(f"Invalid file type. Expected .apk, got: {apk_file.suffix}")
        
        # Check if APKTool exists - support both .bat (Windows) and .jar (cross-platform)
        apktool_bat = self.tools_dir / "apktool.bat"
        apktool_jar = self.tools_dir / "apktool.jar"
        
        if os.name == 'nt' and apktool_bat.exists():  # Windows
            apktool_cmd = f'"{apktool_bat}"'
        elif apktool_jar.exists():  # Cross-platform
            apktool_cmd = f'java -jar "{apktool_jar}"'
        else:
            raise Exception(
                f"APKTool not found at: {self.tools_dir}\n"
                f"Please ensure apktool.bat (Windows) or apktool.jar exists in the tools directory."
            )
        
        # Create output directory name
        output_path = Path(output_dir).resolve() / f"{apk_file.stem}_decompiled"
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.progress.emit(f"Decompiling to: {output_path}")
        
        # Run APKTool decompile command
        cmd = f'{apktool_cmd} d "{apk_file}" -o "{output_path}" -f'
        self.command.emit(cmd)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        
        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            raise Exception(f"APKTool decompilation failed: {error_msg}")
        
        # Verify decompilation output
        if not output_path.exists() or not any(output_path.iterdir()):
            raise Exception("Decompilation completed but no files were created")
        
        self.progress.emit("✓ Decompilation completed successfully!")
        self.command.emit("")
        
        return {
            'operation': 'decompile',
            'input': str(apk_file),
            'output': str(output_path),
            'success': True
        }
    
    def check_apk_mitm(self):
        """Check if apk-mitm is installed and return the correct command"""
        # Try different methods to find apk-mitm
        
        # Method 1: Direct command (works if in PATH)
        try:
            result = subprocess.run(
                'apk-mitm --version',
                capture_output=True,
                text=True,
                shell=True,
                timeout=5
            )
            if result.returncode == 0:
                return 'apk-mitm'
        except:
            pass
        
        # Method 2: Try npx (Node Package Runner)
        try:
            result = subprocess.run(
                'npx apk-mitm --version',
                capture_output=True,
                text=True,
                shell=True,
                timeout=5
            )
            if result.returncode == 0:
                return 'npx apk-mitm'
        except:
            pass
        
        # Method 3: Check common npm global install locations
        if os.name == 'nt':  # Windows
            npm_paths = [
                Path(os.environ.get('APPDATA', '')) / 'npm' / 'apk-mitm.cmd',
                Path(os.environ.get('APPDATA', '')) / 'npm' / 'node_modules' / 'apk-mitm' / 'bin' / 'apk-mitm.js',
            ]
        else:  # Linux/Mac
            npm_paths = [
                Path('/usr/local/bin/apk-mitm'),
                Path.home() / '.npm-global' / 'bin' / 'apk-mitm',
                Path('/usr/bin/apk-mitm'),
            ]
        
        for npm_path in npm_paths:
            if npm_path.exists():
                if npm_path.suffix == '.js':
                    return f'node "{npm_path}"'
                else:
                    return f'"{npm_path}"'
        
        # Not found
        raise Exception(
            "apk-mitm not found!\n\n"
            "Please install it using one of these methods:\n"
            "1. npm install -g apk-mitm\n"
            "2. Use npx: npx apk-mitm (will auto-download)\n\n"
            "After installation, make sure npm global bin is in your PATH.\n"
            "Run 'npm config get prefix' to find your npm global directory."
        )
    
    def remove_ssl_pinning(self, apk_path, output_dir):
        """Remove SSL pinning using apk-mitm"""
        self.progress.emit("Starting SSL pinning removal...")
        
        apk_file = Path(apk_path).resolve()
        if not apk_file.exists() or not apk_file.is_file():
            raise Exception(f"APK file not found: {apk_path}")
        
        if apk_file.suffix.lower() != '.apk':
            raise Exception(f"Invalid file type. Expected .apk, got: {apk_file.suffix}")
        
        # Check if apk-mitm is installed
        self.progress.emit("Checking for apk-mitm...")
        apk_mitm_cmd = self.check_apk_mitm()
        self.progress.emit(f"Found apk-mitm: {apk_mitm_cmd}")
        
        # Create output directory
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Copy APK to output directory for processing
        temp_apk = output_path / apk_file.name
        self.progress.emit(f"Copying APK to output directory...")
        shutil.copy2(apk_file, temp_apk)
        
        self.progress.emit("Removing SSL pinning and patching APK...")
        self.progress.emit("This may take a few minutes...")
        
        # Run apk-mitm
        cmd = f'{apk_mitm_cmd} "{temp_apk}"'
        self.command.emit(cmd)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True,
            cwd=str(output_path)
        )
        
        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            raise Exception(f"apk-mitm failed: {error_msg}")
        
        # apk-mitm creates a file with -patched suffix
        patched_apk = output_path / f"{apk_file.stem}-patched.apk"
        
        if not patched_apk.exists():
            # Try alternative naming
            patched_apk = output_path / f"{temp_apk.stem}-patched.apk"
            if not patched_apk.exists():
                raise Exception("Patched APK not found after processing")
        
        # Remove temporary APK if it's different from patched
        if temp_apk.exists() and temp_apk != patched_apk:
            temp_apk.unlink()
        
        self.progress.emit("✓ SSL pinning removed successfully!")
        self.command.emit("")
        
        return {
            'operation': 'remove_ssl_pinning',
            'input': str(apk_file),
            'output': str(patched_apk),
            'success': True
        }
    
    def resign_apk(self, apk_path, output_dir):
        """Resign APK using uber-apk-signer"""
        self.progress.emit("Starting APK resigning...")
        
        apk_file = Path(apk_path).resolve()
        if not apk_file.exists() or not apk_file.is_file():
            raise Exception(f"APK file not found: {apk_path}")
        
        if apk_file.suffix.lower() != '.apk':
            raise Exception(f"Invalid file type. Expected .apk, got: {apk_file.suffix}")
        
        # Check if uber-apk-signer exists
        signer_path = self.tools_dir / "uber-apk-signer.jar"
        
        if not signer_path.exists():
            raise Exception(
                f"uber-apk-signer.jar not found at: {signer_path}\n"
                f"Please ensure the tools directory exists with all required tools."
            )
        
        # Create output directory
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        
        self.progress.emit("Signing APK with debug certificate...")
        
        # Run uber-apk-signer
        cmd = f'java -jar "{signer_path}" --apks "{apk_file}" --out "{output_path}"'
        self.command.emit(cmd)
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        
        if result.returncode != 0:
            error_msg = result.stderr if result.stderr else result.stdout
            raise Exception(f"APK signing failed: {error_msg}")
        
        # Find the signed APK (usually has -aligned-debugSigned suffix)
        signed_apks = list(output_path.glob(f"{apk_file.stem}*-aligned-debugSigned.apk"))
        
        if not signed_apks:
            # Try alternative patterns
            signed_apks = list(output_path.glob(f"*{apk_file.stem}*.apk"))
        
        if not signed_apks:
            signed_apks = list(output_path.glob("*.apk"))
        
        if not signed_apks:
            raise Exception("Signed APK not found after processing")
        
        signed_apk = signed_apks[0]
        
        self.progress.emit("✓ APK resigned successfully!")
        self.command.emit("")
        
        return {
            'operation': 'resign',
            'input': str(apk_file),
            'output': str(signed_apk),
            'success': True
        }