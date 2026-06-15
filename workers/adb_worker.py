"""ADB Worker — Android device operations via ADB."""
import subprocess
import os
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


def _get_adb_cmd() -> str:
    """
    Resolve the adb executable.
    Priority: bundled tools/platform-tools/adb → system PATH adb.
    Also injects platform-tools into the process PATH so child processes find it.
    """
    project_root = Path(__file__).parent.parent
    pt_dir       = project_root / "tools" / "platform-tools"
    adb_name     = "adb.exe" if os.name == "nt" else "adb"
    bundled_adb  = pt_dir / adb_name

    if bundled_adb.exists():
        pt_str  = str(pt_dir)
        current = os.environ.get("PATH", "")
        if pt_str not in current:
            os.environ["PATH"] = pt_str + os.pathsep + current
        return str(bundled_adb)

    return "adb"


class ADBWorker(QThread):
    """Worker thread for ADB operations — prevents GUI freezing."""
    finished = pyqtSignal(object)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)
    command  = pyqtSignal(str)

    def __init__(self, operation, *args, device_serial: str = ""):
        super().__init__()
        self.operation     = operation
        self.args          = args
        self.device_serial = device_serial
        self._resolved_serial: str | None = None  # cached for duration of run()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_serial(self) -> str:
        """Validate stored serial against live 'adb devices'; auto-pick if stale.
        Result is cached for the lifetime of this worker run() call."""
        if self._resolved_serial is not None:
            return self._resolved_serial
        adb = _get_adb_cmd()
        try:
            r = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=10)
            live = []
            for line in r.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[1] == "device":
                    live.append(parts[0])
            if not live:
                serial = self.device_serial
            elif self.device_serial and self.device_serial in live:
                serial = self.device_serial
            elif len(live) == 1:
                serial = live[0]
            else:
                serial = ""
        except Exception:
            serial = self.device_serial
        self._resolved_serial = serial
        return serial

    def _adb(self, *args) -> list:
        """Build an adb command list, optionally targeting a specific device."""
        adb = _get_adb_cmd()
        cmd = [adb]
        serial = self._resolve_serial()
        if serial:
            cmd += ["-s", serial]
        cmd += list(args)
        return cmd

    def _run(self, cmd: list, timeout: int = 30) -> subprocess.CompletedProcess:
        """Run a command list and return the result."""
        display = " ".join(f'"{c}"' if " " in c else c for c in cmd)
        self.command.emit(display)
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, shell=False)

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def run(self):
        try:
            dispatch = {
                "list_packages":    self._dispatch_list_packages,
                "extract_apk":      self._dispatch_extract_apk,
                "list_devices":     self._dispatch_list_devices,
                "get_device_info":  self._dispatch_get_device_info,
                "install_apk":          self._dispatch_install_apk,
                "install_multiple_apks":self._dispatch_install_multiple_apks,
                "uninstall_package":    self._dispatch_uninstall_package,
            }
            handler = dispatch.get(self.operation)
            if handler is None:
                raise Exception(f"Unknown ADB operation: {self.operation}")
            result = handler()
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    def _dispatch_list_packages(self):
        search = self.args[0] if self.args else ""
        filter_type = self.args[1] if len(self.args) > 1 else "all"
        return self.list_packages(search, filter_type)

    def _dispatch_extract_apk(self):
        return self.extract_apk(self.args[0], self.args[1])

    def _dispatch_list_devices(self):
        return self.list_devices()

    def _dispatch_get_device_info(self):
        return self.get_device_info()

    def _dispatch_install_apk(self):
        return self.install_apk(self.args[0])

    def _dispatch_install_multiple_apks(self):
        return self.install_multiple_apks(list(self.args[0]))

    def _dispatch_uninstall_package(self):
        return self.uninstall_package(self.args[0])

    # ------------------------------------------------------------------
    # ADB connection check
    # ------------------------------------------------------------------

    def check_adb_connection(self):
        """Raise a descriptive Exception if ADB or a device is unavailable."""
        try:
            result = self._run(self._adb("version"), timeout=5)
            if result.returncode != 0:
                raise Exception(
                    "ADB (Android Debug Bridge) not found.\n"
                    "Install platform-tools via the '🔧 Install Tools' tab."
                )

            result = self._run(self._adb("devices"), timeout=10)
            if result.returncode != 0:
                raise Exception(f"ADB command failed: {result.stderr}")

            lines   = result.stdout.strip().split("\n")
            devices = [l for l in lines[1:] if l.strip() and "\tdevice" in l]

            if not devices:
                raise Exception(
                    "No Android device connected.\n\n"
                    "Please:\n"
                    "1. Connect your Android device via USB\n"
                    "2. Enable 'USB Debugging' in Developer Options\n"
                    "3. Accept the USB debugging prompt on your device\n"
                    "4. Click '🔄 Refresh Devices'"
                )
            return True

        except subprocess.TimeoutExpired:
            raise Exception("ADB command timed out. Check your ADB installation.")
        except Exception:
            raise

    # ------------------------------------------------------------------
    # list_devices
    # ------------------------------------------------------------------

    def list_devices(self) -> list:
        """Return [{serial, state, model}] for every connected device."""
        adb = _get_adb_cmd()
        try:
            result = subprocess.run(
                [adb, "devices", "-l"],
                capture_output=True, text=True, timeout=10, shell=False
            )
        except subprocess.TimeoutExpired:
            raise Exception("ADB timed out listing devices.")

        devices = []
        for line in result.stdout.strip().splitlines()[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                serial = parts[0]
                model  = ""
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.replace("model:", "").replace("_", " ")
                        break
                devices.append({"serial": serial, "state": "device", "model": model})
        return devices

    # ------------------------------------------------------------------
    # get_device_info  — NEW
    # ------------------------------------------------------------------

    def get_device_info(self) -> dict:
        """
        Query a rich set of device properties via getprop.
        Returns a dict with keys: model, manufacturer, android_version, sdk,
        abi, brand, build, screen_density, screen_size.
        """
        self.progress.emit("Fetching device information...")

        prop_map = {
            "model":           "ro.product.model",
            "manufacturer":    "ro.product.manufacturer",
            "brand":           "ro.product.brand",
            "android_version": "ro.build.version.release",
            "sdk":             "ro.build.version.sdk",
            "abi":             "ro.product.cpu.abi",
            "build":           "ro.build.display.id",
            "fingerprint":     "ro.build.fingerprint",
            "serial":          "ro.serialno",
        }

        info = {}
        for key, prop in prop_map.items():
            cmd = self._adb("shell", "getprop", prop)
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=5, shell=False
                )
                info[key] = result.stdout.strip()
            except Exception:
                info[key] = ""

        # Also get total RAM via /proc/meminfo
        try:
            result = subprocess.run(
                self._adb("shell", "cat", "/proc/meminfo"),
                capture_output=True, text=True, timeout=5, shell=False
            )
            for line in result.stdout.splitlines():
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    info["ram_gb"] = f"{kb / 1048576:.1f} GB"
                    break
        except Exception:
            info["ram_gb"] = ""

        self.progress.emit(
            f"✓ Device: {info.get('manufacturer', '')} {info.get('model', '')} "
            f"(Android {info.get('android_version', '?')}, SDK {info.get('sdk', '?')})"
        )
        self.command.emit("")
        return info

    # ------------------------------------------------------------------
    # list_packages  (updated: supports filter_type)
    # ------------------------------------------------------------------

    def list_packages(self, search_term: str, filter_type: str = "all") -> list:
        """
        List packages, optionally filtered by type:
          'all'      → pm list packages
          '3rdparty' → pm list packages -3
          'system'   → pm list packages -s
        """
        self.progress.emit("Connecting to device...")
        self.check_adb_connection()
        self.progress.emit("Fetching packages...")

        pm_args = ["shell", "pm", "list", "packages"]
        if filter_type == "3rdparty":
            pm_args.append("-3")
        elif filter_type == "system":
            pm_args.append("-s")

        cmd = self._adb(*pm_args)
        self.command.emit(" ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30, shell=False
            )
        except subprocess.TimeoutExpired:
            raise Exception("Package listing timed out. Check your device connection.")

        if result.returncode != 0:
            raise Exception(f"ADB command failed: {result.stderr}")

        packages = []
        for line in result.stdout.splitlines():
            if line.startswith("package:"):
                pkg_name = line.replace("package:", "").strip()
                if not search_term or search_term.lower() in pkg_name.lower():
                    packages.append(pkg_name)

        packages.sort()
        self.command.emit("")
        return packages

    # ------------------------------------------------------------------
    # extract_apk
    # ------------------------------------------------------------------

    def extract_apk(self, package_name: str, output_dir: str) -> dict:
        """Extract APK(s) for the given package from the connected device."""
        self.progress.emit(f"Finding APK path for {package_name}...")
        self.check_adb_connection()

        if not package_name or not package_name.strip():
            raise Exception("Invalid package name.")

        cmd = self._adb("shell", "pm", "path", package_name)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10, shell=False
            )
            self.command.emit(" ".join(cmd))
        except subprocess.TimeoutExpired:
            raise Exception("Finding APK path timed out.")

        if result.returncode != 0 or not result.stdout:
            raise Exception(
                f"Could not find APK for: {package_name}\n\n"
                "Verify the package name is correct and the app is installed."
            )

        apk_paths = [
            line.replace("package:", "").strip()
            for line in result.stdout.splitlines()
            if line.startswith("package:")
        ]

        if not apk_paths:
            raise Exception(f"No APK paths found for {package_name}.")

        self.progress.emit(f"Found {len(apk_paths)} APK file(s)")

        output_dir_path = Path(output_dir).resolve()
        if output_dir_path.name.lower() == "android":
            pkg_dir = output_dir_path / package_name
        else:
            android_dir = output_dir_path / "Android"
            android_dir.mkdir(exist_ok=True)
            pkg_dir = android_dir / package_name

        pkg_dir.mkdir(parents=True, exist_ok=True)
        self.progress.emit(f"Output: {pkg_dir}")

        pulled_files = []
        for idx, apk_path in enumerate(apk_paths):
            self.progress.emit(f"Pulling {idx+1}/{len(apk_paths)}: {Path(apk_path).name}")

            output_file = (
                pkg_dir / f"{package_name}.apk"
                if len(apk_paths) == 1
                else pkg_dir / Path(apk_path).name
            )

            pull_cmd = self._adb("pull", apk_path, str(output_file))
            self.command.emit(" ".join(pull_cmd))

            try:
                result = subprocess.run(
                    pull_cmd, capture_output=True, text=True, timeout=120, shell=False
                )
            except subprocess.TimeoutExpired:
                self.progress.emit(f"⚠ Timeout pulling {apk_path}")
                continue

            if result.returncode == 0 and output_file.exists():
                pulled_files.append(str(output_file))
                size_mb = output_file.stat().st_size / (1024 * 1024)
                self.progress.emit(f"✓ {output_file.name} ({size_mb:.2f} MB)")
            else:
                self.progress.emit(f"⚠ Failed: {result.stderr.strip()}")

        if not pulled_files:
            raise Exception(
                "Failed to pull any APK files.\n\n"
                "This may be due to:\n"
                "1. Insufficient permissions (try a rooted device)\n"
                "2. Connection issues — re-plug USB cable\n"
                "3. The app uses a non-standard storage location"
            )

        self.command.emit("")
        return {
            "package":   package_name,
            "directory": str(pkg_dir),
            "files":     pulled_files,
            "count":     len(pulled_files),
        }

    # ------------------------------------------------------------------
    # install_apk  — NEW
    # ------------------------------------------------------------------

    def install_apk(self, apk_path: str) -> dict:
        """
        Push and install an APK to the connected device.
        Uses -r (replace existing) and -d (allow version downgrade).
        """
        self.progress.emit(f"Installing: {Path(apk_path).name}")
        self.check_adb_connection()

        if not Path(apk_path).exists():
            raise Exception(f"APK file not found: {apk_path}")

        cmd = self._adb("install", "-r", "-d", apk_path)
        self.command.emit(" ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120, shell=False
            )
        except subprocess.TimeoutExpired:
            raise Exception("APK installation timed out. Check USB connection.")

        output = (result.stdout + " " + result.stderr).strip()

        if result.returncode != 0 or "Failure" in output or "FAILED" in output:
            raise Exception(
                f"Installation failed:\n{output}\n\n"
                "Common causes:\n"
                "• INSTALL_FAILED_UPDATE_INCOMPATIBLE — uninstall the old version first\n"
                "• INSTALL_FAILED_OLDER_SDK — device Android version is too old\n"
                "• INSTALL_PARSE_FAILED — APK may be corrupt or unsigned"
            )

        self.progress.emit("✓ APK installed successfully!")
        self.command.emit("")
        return {
            "operation": "install_apk",
            "apk":       apk_path,
            "output":    output,
            "success":   True,
        }

    # ------------------------------------------------------------------
    # install_multiple_apks  (split APK support)
    # ------------------------------------------------------------------

    def install_multiple_apks(self, apk_paths: list) -> dict:
        """
        Install one or more APKs to the connected device.
        Single APK  → adb install -r -d
        Split APKs  → adb install-multiple -r -d <apk1> <apk2> ...
        """
        if not apk_paths:
            raise Exception("No APK files provided.")

        self.check_adb_connection()

        for p in apk_paths:
            if not Path(p).exists():
                raise Exception(f"APK file not found: {p}")

        if len(apk_paths) == 1:
            return self.install_apk(apk_paths[0])

        names = [Path(p).name for p in apk_paths]
        self.progress.emit(f"Installing {len(apk_paths)} split APKs: {', '.join(names)}")

        cmd = self._adb("install-multiple", "-r", "-d") + [str(p) for p in apk_paths]
        self.command.emit(" ".join(f'"{c}"' if " " in c else c for c in cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, shell=False
            )
        except subprocess.TimeoutExpired:
            raise Exception("APK installation timed out. Check USB connection.")

        output = (result.stdout + " " + result.stderr).strip()

        if result.returncode != 0 or "Failure" in output or "FAILED" in output:
            raise Exception(
                f"Installation failed:\n{output}\n\n"
                "Common causes:\n"
                "• INSTALL_FAILED_UPDATE_INCOMPATIBLE — uninstall the old version first\n"
                "• INSTALL_FAILED_OLDER_SDK — device Android version is too old\n"
                "• INSTALL_PARSE_FAILED — APK may be corrupt or unsigned\n"
                "• For split APKs, all APKs must belong to the same package"
            )

        self.progress.emit(f"✓ {len(apk_paths)} APK(s) installed successfully!")
        self.command.emit("")
        return {
            "operation": "install_multiple_apks",
            "apks":      apk_paths,
            "output":    output,
            "success":   True,
        }

    # ------------------------------------------------------------------
    # uninstall_package  — NEW
    # ------------------------------------------------------------------

    def uninstall_package(self, package_name: str) -> dict:
        """Uninstall a package from the connected device."""
        self.progress.emit(f"Uninstalling: {package_name}")
        self.check_adb_connection()

        cmd = self._adb("uninstall", package_name)
        self.command.emit(" ".join(cmd))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60, shell=False
            )
        except subprocess.TimeoutExpired:
            raise Exception("Uninstall timed out.")

        output = (result.stdout + " " + result.stderr).strip()

        if result.returncode != 0 or "Failure" in output:
            raise Exception(f"Uninstall failed:\n{output}")

        self.progress.emit(f"✓ {package_name} uninstalled!")
        self.command.emit("")
        return {"operation": "uninstall_package", "package": package_name, "success": True}
