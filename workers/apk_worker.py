import subprocess
import os
import re
import shutil
import zipfile
from pathlib import Path
from PyQt6.QtCore import QThread, pyqtSignal


class APKWorker(QThread):
    """Worker thread for APK operations — decompile, recompile, merge, sign, SSL patch, AAB→APK."""
    finished = pyqtSignal(object)
    error    = pyqtSignal(str)
    progress = pyqtSignal(str)
    command  = pyqtSignal(str)

    def __init__(self, operation, *args):
        super().__init__()
        self.operation    = operation
        self.args         = args
        self.project_root = Path(__file__).parent.parent
        self.tools_dir    = self.project_root / "tools"
        self._proc        = None   # current Popen for cancel()

    # ------------------------------------------------------------------
    # Cancellation
    # ------------------------------------------------------------------

    def cancel(self):
        """Terminate the currently running subprocess, if any."""
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Dispatcher
    # ------------------------------------------------------------------

    def run(self):
        try:
            dispatch = {
                "merge_split_apks":              self.merge_split_apks,
                "decompile_apk":                 self.decompile_apk,
                "recompile_apk":                 self.recompile_apk,
                "remove_ssl_pinning":            self.remove_ssl_pinning,
                "patch_network_security_config": self.patch_network_security_config,
                "resign_apk":                    self.resign_apk,
                "convert_aab_to_apk":            self.convert_aab_to_apk,
                "get_apk_detailed_info":         self.get_apk_detailed_info,
            }
            handler = dispatch.get(self.operation)
            if handler is None:
                raise Exception(f"Unknown operation: {self.operation}")
            result = handler(*self.args)
            self.finished.emit(result)
        except Exception as exc:
            self.error.emit(str(exc))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apktool_cmd(self) -> str:
        bat = self.tools_dir / "apktool.bat"
        jar = self.tools_dir / "apktool.jar"
        if os.name == "nt" and bat.exists():
            return f'"{bat}"'
        if jar.exists():
            return f'java -jar "{jar}"'
        raise Exception("APKTool not found. Install it from the Install Tools tab.")

    def _signer_jar(self) -> Path:
        p = self.tools_dir / "uber-apk-signer.jar"
        if not p.exists():
            raise Exception("uber-apk-signer.jar not found. Install it from the Install Tools tab.")
        return p

    def _aapt(self):
        pt = self.tools_dir / "platform-tools"
        a  = pt / ("aapt.exe" if os.name == "nt" else "aapt")
        return a if a.exists() else None

    def _run_streaming(self, cmd: str, cwd=None) -> tuple:
        """
        Run a shell command with real-time stdout+stderr streaming.
        Each non-empty output line is emitted as a progress signal.
        Returns (returncode, full_output_str).
        """
        self.command.emit(cmd)
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True,
            cwd=str(cwd) if cwd else None,
            encoding="utf-8",
            errors="replace",
        )
        lines = []
        for raw_line in self._proc.stdout:
            line = raw_line.rstrip("\n\r")
            if line.strip():
                lines.append(line)
                self.progress.emit(line)
        self._proc.wait()
        rc = self._proc.returncode
        self._proc = None
        return rc, "\n".join(lines)

    # ------------------------------------------------------------------
    # Merge split APKs
    # ------------------------------------------------------------------

    def merge_split_apks(self, split_apk_dir, output_dir):
        self.progress.emit("Starting APK merge process...")

        split_path = Path(split_apk_dir).resolve()
        if not split_path.exists() or not split_path.is_dir():
            raise Exception(f"Invalid directory: {split_apk_dir}")

        apk_files = list(split_path.glob("*.apk"))
        if not apk_files:
            raise Exception(f"No APK files found in: {split_apk_dir}")

        apkeditor = self.tools_dir / "APKEditor.jar"
        if not apkeditor.exists():
            raise Exception(f"APKEditor.jar not found at: {apkeditor}\nInstall it from the Install Tools tab.")

        temp_dir  = split_path.parent / "temp_merged_output"
        temp_dir.mkdir(parents=True, exist_ok=True)
        out_name  = split_path.name + "_merged.apk"
        temp_file = temp_dir / out_name

        self.progress.emit(f"Found {len(apk_files)} APK file(s) — merging...")

        cmd = f'java -jar "{apkeditor}" m -i "{split_path}" -o "{temp_file}"'
        rc, out = self._run_streaming(cmd)

        if rc != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"APKEditor merge failed:\n{out[-2000:]}")

        if not temp_file.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception("Merged APK was not created. Verify that the APKs are valid split APKs.")

        final = split_path / out_name
        shutil.move(str(temp_file), str(final))
        shutil.rmtree(temp_dir, ignore_errors=True)

        self.progress.emit("✓ Merge completed!")
        self.command.emit("")
        return {"operation": "merge", "input": str(split_path), "output": str(final), "success": True}

    # ------------------------------------------------------------------
    # Decompile APK  (apktool d)
    # ------------------------------------------------------------------

    def decompile_apk(self, apk_path, output_dir):
        self.progress.emit("Starting APK decompilation...")

        apk_file = Path(apk_path).resolve()
        if not apk_file.exists():
            raise Exception(f"APK not found: {apk_path}")
        if apk_file.suffix.lower() != ".apk":
            raise Exception(f"Expected .apk, got: {apk_file.suffix}")

        apktool_cmd = self._apktool_cmd()
        output_path = Path(output_dir).resolve() / f"{apk_file.stem}_decompiled"

        if output_path.exists():
            shutil.rmtree(output_path)
        output_path.mkdir(parents=True, exist_ok=True)

        self.progress.emit(f"Output directory: {output_path}")

        cmd = f'{apktool_cmd} d "{apk_file}" -o "{output_path}" -f'
        rc, out = self._run_streaming(cmd)

        if rc != 0:
            raise Exception(f"APKTool decompilation failed:\n{out[-2000:]}")
        if not output_path.exists() or not any(output_path.iterdir()):
            raise Exception("Decompilation produced no output files.")

        self.progress.emit("✓ Decompilation completed!")
        self.command.emit("")
        return {"operation": "decompile", "input": str(apk_file), "output": str(output_path), "success": True}

    # ------------------------------------------------------------------
    # Recompile APK  (apktool b) — NEW
    # ------------------------------------------------------------------

    def recompile_apk(self, decompiled_dir, output_dir):
        """
        Recompile a directory previously decompiled by APKTool back into an APK.
        Completes the decompile → modify → recompile → resign workflow.
        """
        self.progress.emit("Starting APK recompilation...")

        src = Path(decompiled_dir).resolve()
        if not src.exists() or not src.is_dir():
            raise Exception(f"Decompiled directory not found: {decompiled_dir}")
        if not (src / "apktool.yml").exists():
            raise Exception(
                "Not a valid APKTool decompiled directory (apktool.yml missing).\n"
                f"Path: {decompiled_dir}"
            )

        apktool_cmd = self._apktool_cmd()
        out_dir = Path(output_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_apk = out_dir / f"{src.name}_recompiled.apk"

        self.progress.emit(f"Recompiling: {src.name}")
        self.progress.emit(f"Output: {out_apk}")

        cmd = f'{apktool_cmd} b "{src}" -o "{out_apk}"'
        rc, out = self._run_streaming(cmd)

        if rc != 0:
            raise Exception(f"APKTool recompile failed:\n{out[-2000:]}")

        if not out_apk.exists():
            # APKTool sometimes puts output in <dir>/dist/
            dist = src / "dist"
            candidates = list(dist.glob("*.apk")) if dist.exists() else []
            if candidates:
                shutil.copy2(candidates[0], out_apk)
            else:
                raise Exception(
                    "Recompiled APK not found. Check console output for errors.\n"
                    "Common causes: resource errors, missing frameworks, aapt2 issues."
                )

        self.progress.emit("✓ Recompilation completed!")
        self.progress.emit("Tip: Sign the recompiled APK using 'Resign APK' before installing.")
        self.command.emit("")
        return {"operation": "recompile_apk", "input": str(src), "output": str(out_apk), "success": True}

    # ------------------------------------------------------------------
    # Remove SSL pinning  (apk-mitm)
    # ------------------------------------------------------------------

    def remove_ssl_pinning(self, apk_path, output_dir):
        self.progress.emit("Starting SSL pinning removal via apk-mitm...")

        apk_file = Path(apk_path).resolve()
        if not apk_file.exists():
            raise Exception(f"APK not found: {apk_path}")
        if apk_file.suffix.lower() != ".apk":
            raise Exception(f"Expected .apk, got: {apk_file.suffix}")

        apk_mitm_cmd = self._find_apk_mitm()
        self.progress.emit(f"Found apk-mitm: {apk_mitm_cmd}")

        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        temp_apk = output_path / apk_file.name
        shutil.copy2(apk_file, temp_apk)

        self.progress.emit("Patching... (this may take several minutes)")

        cmd = f'{apk_mitm_cmd} "{temp_apk}"'
        rc, out = self._run_streaming(cmd, cwd=output_path)

        if rc != 0:
            raise Exception(f"apk-mitm failed:\n{out[-2000:]}")

        patched = output_path / f"{apk_file.stem}-patched.apk"
        if not patched.exists():
            patched = output_path / f"{temp_apk.stem}-patched.apk"
        if not patched.exists():
            raise Exception(
                "Patched APK not found after apk-mitm completed.\n"
                "Try 'NSC Patch' as an alternative SSL bypass that requires no Node.js."
            )

        if temp_apk.exists() and temp_apk != patched:
            temp_apk.unlink()

        self.progress.emit("✓ SSL pinning removed!")
        self.command.emit("")
        return {"operation": "remove_ssl_pinning", "input": str(apk_file), "output": str(patched), "success": True}

    # ------------------------------------------------------------------
    # NSC Patch — Network Security Config SSL bypass  — NEW
    # ------------------------------------------------------------------

    def patch_network_security_config(self, apk_path, output_dir):
        """
        Alternative SSL bypass that requires NO Node.js / apk-mitm.

        Pipeline:
          1. Decompile with APKTool
          2. Inject permissive res/xml/network_security_config.xml
          3. Patch AndroidManifest.xml to reference the NSC
          4. Recompile with APKTool
          5. Sign with uber-apk-signer

        Works on many apps that apk-mitm cannot handle (Flutter, Xamarin, etc.)
        After installing the patched APK, add your proxy's CA cert as a user certificate
        on the device — the app will trust it.
        """
        self.progress.emit("Starting NSC (Network Security Config) SSL bypass patch...")

        apk_file = Path(apk_path).resolve()
        if not apk_file.exists():
            raise Exception(f"APK not found: {apk_path}")
        if apk_file.suffix.lower() != ".apk":
            raise Exception(f"Expected .apk, got: {apk_file.suffix}")

        apktool_cmd = self._apktool_cmd()
        signer      = self._signer_jar()

        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)
        work_dir = output_path / f"{apk_file.stem}_nsc_work"

        try:
            # ── Step 1: Decompile ──────────────────────────────────────────
            self.progress.emit("Step 1/4: Decompiling APK...")
            cmd = f'{apktool_cmd} d "{apk_file}" -o "{work_dir}" -f'
            rc, out = self._run_streaming(cmd)
            if rc != 0:
                raise Exception(f"Decompilation failed:\n{out[-1500:]}")

            # ── Step 2: Inject NSC XML ─────────────────────────────────────
            self.progress.emit("Step 2/4: Injecting Network Security Config...")

            xml_dir = work_dir / "res" / "xml"
            xml_dir.mkdir(parents=True, exist_ok=True)

            nsc_xml = (
                '<?xml version="1.0" encoding="utf-8"?>\n'
                '<network-security-config>\n'
                '    <!-- Trust user-installed CAs (e.g. Burp Suite, mitmproxy) -->\n'
                '    <base-config cleartextTrafficPermitted="true">\n'
                '        <trust-anchors>\n'
                '            <certificates src="system"/>\n'
                '            <certificates src="user"/>\n'
                '        </trust-anchors>\n'
                '    </base-config>\n'
                '    <debug-overrides>\n'
                '        <trust-anchors>\n'
                '            <certificates src="system"/>\n'
                '            <certificates src="user"/>\n'
                '        </trust-anchors>\n'
                '    </debug-overrides>\n'
                '</network-security-config>\n'
            )
            (xml_dir / "network_security_config.xml").write_text(nsc_xml, encoding="utf-8")
            self.progress.emit("✓ NSC XML written to res/xml/network_security_config.xml")

            # Patch AndroidManifest.xml
            manifest = work_dir / "AndroidManifest.xml"
            if manifest.exists():
                text = manifest.read_text(encoding="utf-8", errors="replace")
                nsc_attr = 'android:networkSecurityConfig="@xml/network_security_config"'
                if 'networkSecurityConfig' in text:
                    # Replace existing NSC reference
                    text = re.sub(
                        r'android:networkSecurityConfig="[^"]*"',
                        nsc_attr,
                        text
                    )
                    self.progress.emit("✓ Replaced existing NSC reference in AndroidManifest.xml")
                else:
                    # Inject after <application
                    text = re.sub(
                        r'(<application(?!\w))',
                        rf'\1 {nsc_attr}',
                        text,
                        count=1
                    )
                    self.progress.emit("✓ Injected NSC reference into AndroidManifest.xml")
                manifest.write_text(text, encoding="utf-8")

            # ── Step 3: Recompile ──────────────────────────────────────────
            self.progress.emit("Step 3/4: Recompiling patched APK...")
            unsigned = output_path / f"{apk_file.stem}_nsc_unsigned.apk"

            cmd = f'{apktool_cmd} b "{work_dir}" -o "{unsigned}"'
            rc, out = self._run_streaming(cmd)
            if rc != 0:
                raise Exception(f"Recompilation failed:\n{out[-1500:]}")

            if not unsigned.exists():
                dist_dir = work_dir / "dist"
                cands = list(dist_dir.glob("*.apk")) if dist_dir.exists() else []
                if cands:
                    shutil.copy2(cands[0], unsigned)
                else:
                    raise Exception("Recompiled APK not found. Examine the console output for APKTool errors.")

            # ── Step 4: Sign ───────────────────────────────────────────────
            self.progress.emit("Step 4/4: Signing with debug certificate...")
            cmd = f'java -jar "{signer}" -a "{unsigned}" --overwrite'
            rc, out = self._run_streaming(cmd)
            if rc != 0:
                raise Exception(f"Signing failed:\n{out[-1000:]}")

            # uber-apk-signer renames the file; locate it
            final = output_path / f"{apk_file.stem}_nsc_patched.apk"
            signed_cands = list(output_path.glob(f"{apk_file.stem}_nsc_unsigned*Signed*.apk"))
            if signed_cands:
                if final.exists():
                    final.unlink()
                shutil.move(str(signed_cands[0]), str(final))
            elif unsigned.exists():
                if final.exists():
                    final.unlink()
                unsigned.rename(final)

        finally:
            if work_dir.exists():
                shutil.rmtree(work_dir, ignore_errors=True)

        if not final.exists():
            raise Exception("NSC-patched APK was not produced. Check console output for errors.")

        self.progress.emit("✓ NSC patch completed!")
        self.progress.emit("Next step: install the patched APK, then add your proxy CA cert as a user certificate on the device.")
        self.command.emit("")
        return {
            "operation": "patch_network_security_config",
            "input":     str(apk_file),
            "output":    str(final),
            "success":   True,
        }

    # ------------------------------------------------------------------
    # Resign APK
    # ------------------------------------------------------------------

    def resign_apk(self, apk_path, output_dir):
        self.progress.emit("Starting APK resigning...")

        apk_file = Path(apk_path).resolve()
        if not apk_file.exists():
            raise Exception(f"APK not found: {apk_path}")
        if apk_file.suffix.lower() != ".apk":
            raise Exception(f"Expected .apk, got: {apk_file.suffix}")

        signer = self._signer_jar()
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        self.progress.emit("Signing with debug certificate...")

        cmd = f'java -jar "{signer}" --apks "{apk_file}" --out "{output_path}"'
        rc, out = self._run_streaming(cmd)

        if rc != 0:
            raise Exception(f"Signing failed:\n{out[-2000:]}")

        candidates = (
            list(output_path.glob(f"{apk_file.stem}*-aligned-debugSigned.apk"))
            or list(output_path.glob(f"*{apk_file.stem}*.apk"))
            or list(output_path.glob("*.apk"))
        )
        if not candidates:
            raise Exception("Signed APK not found after processing.")

        self.progress.emit("✓ APK resigned!")
        self.command.emit("")
        return {"operation": "resign", "input": str(apk_file), "output": str(candidates[0]), "success": True}

    # ------------------------------------------------------------------
    # AAB → APK
    # ------------------------------------------------------------------

    def convert_aab_to_apk(self, aab_path, output_dir):
        self.progress.emit("Starting AAB to APK conversion...")

        aab_file = Path(aab_path).resolve()
        if not aab_file.exists():
            raise Exception(f"AAB not found: {aab_path}")
        if aab_file.suffix.lower() != ".aab":
            raise Exception(f"Expected .aab, got: {aab_file.suffix}")

        bundletool = self.tools_dir / "bundletool-all.jar"
        if not bundletool.exists():
            raise Exception("bundletool-all.jar not found. Install it from the Install Tools tab.")

        signer      = self._signer_jar()
        output_path = Path(output_dir).resolve()
        output_path.mkdir(parents=True, exist_ok=True)

        basename  = aab_file.stem
        apks_file = output_path / f"{basename}.apks"

        # Step 1
        self.progress.emit("Step 1/3: Building universal APKs with bundletool...")
        cmd = (
            f'java -jar "{bundletool}" build-apks '
            f'--bundle="{aab_file}" --output="{apks_file}" --mode=universal'
        )
        rc, out = self._run_streaming(cmd)
        if rc != 0:
            raise Exception(f"bundletool failed:\n{out[-2000:]}")
        if not apks_file.exists():
            raise Exception("APKS file was not created by bundletool.")

        # Step 2
        self.progress.emit("Step 2/3: Extracting universal.apk...")
        universal_apk = output_path / "universal.apk"
        with zipfile.ZipFile(apks_file, "r") as z:
            z.extract("universal.apk", output_path)
        if not universal_apk.exists():
            raise Exception("universal.apk not found in APKS archive.")

        # Step 3
        self.progress.emit("Step 3/3: Signing...")
        cmd = f'java -jar "{signer}" -a "{universal_apk}" --overwrite'
        rc, out = self._run_streaming(cmd)
        if rc != 0:
            raise Exception(f"Signing failed:\n{out[-1000:]}")

        final = output_path / f"{basename}-signed.apk"
        if universal_apk.exists():
            if final.exists():
                final.unlink()
            universal_apk.rename(final)

        # Cleanup
        for tmp in [
            apks_file,
            output_path / f"{basename}.apks.idsig",
            output_path / "universal.apk.idsig",
            output_path / "toc.pb",
        ]:
            if tmp.exists():
                try:
                    tmp.unlink()
                except Exception:
                    pass

        if not final.exists():
            raise Exception("Final signed APK not created.")

        self.progress.emit("✓ AAB to APK conversion completed!")
        self.command.emit("")
        return {"operation": "convert_aab_to_apk", "input": str(aab_file), "output": str(final), "success": True}

    # ------------------------------------------------------------------
    # Get detailed APK info  — NEW
    # ------------------------------------------------------------------

    def get_apk_detailed_info(self, apk_path):
        """
        Extract full APK metadata without decompiling:
          - package, version, SDK levels
          - all declared permissions
          - launchable activities
          - file count and size
          - signing certificate details (if apksigner available)
        """
        apk_file = Path(apk_path).resolve()
        if not apk_file.exists():
            raise Exception(f"APK not found: {apk_path}")

        self.progress.emit(f"Analyzing: {apk_file.name}")

        info = {
            "operation":    "get_apk_detailed_info",
            "path":         str(apk_file),
            "package":      "",
            "version_name": "",
            "version_code": "",
            "min_sdk":      "",
            "target_sdk":   "",
            "permissions":  [],
            "activities":   [],
            "size_mb":      round(apk_file.stat().st_size / (1024 * 1024), 2),
            "file_count":   0,
            "cert_info":    "",
            "success":      True,
        }

        # ── aapt metadata ─────────────────────────────────────────────
        aapt = self._aapt()
        if aapt:
            self.progress.emit("Extracting metadata via aapt...")
            result = subprocess.run(
                [str(aapt), "dump", "badging", str(apk_file)],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.splitlines():
                if line.startswith("package:"):
                    for part in line.split():
                        if part.startswith("name="):
                            info["package"] = part.split("=", 1)[1].strip("'\"")
                        elif part.startswith("versionName="):
                            info["version_name"] = part.split("=", 1)[1].strip("'\"")
                        elif part.startswith("versionCode="):
                            info["version_code"] = part.split("=", 1)[1].strip("'\"")
                elif line.startswith("sdkVersion:"):
                    info["min_sdk"] = line.split(":", 1)[1].strip().strip("'\"")
                elif line.startswith("targetSdkVersion:"):
                    info["target_sdk"] = line.split(":", 1)[1].strip().strip("'\"")
                elif line.startswith("uses-permission:"):
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        info["permissions"].append(m.group(1))
                elif line.startswith("launchable-activity:"):
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        info["activities"].append(m.group(1))
            self.progress.emit(f"✓ {len(info['permissions'])} permissions found via aapt")
        else:
            self.progress.emit("aapt not found — skipping deep metadata (install platform-tools)")

        # ── apksigner cert info ────────────────────────────────────────
        pt_dir    = self.tools_dir / "platform-tools"
        apksigner = pt_dir / ("apksigner.bat" if os.name == "nt" else "apksigner")
        if apksigner.exists():
            self.progress.emit("Reading certificate info via apksigner...")
            try:
                result = subprocess.run(
                    [str(apksigner), "verify", "--print-certs", str(apk_file)],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    info["cert_info"] = result.stdout.strip()
                    self.progress.emit("✓ Certificate info retrieved")
            except Exception:
                pass

        # ── file count ─────────────────────────────────────────────────
        try:
            with zipfile.ZipFile(apk_file, "r") as z:
                info["file_count"] = len(z.namelist())
        except Exception:
            pass

        self.progress.emit("✓ Analysis complete!")
        self.command.emit("")
        return info

    # ------------------------------------------------------------------
    # apk-mitm detection helper
    # ------------------------------------------------------------------

    def _find_apk_mitm(self) -> str:
        for candidate in ["apk-mitm", "npx apk-mitm"]:
            try:
                r = subprocess.run(
                    candidate + " --version",
                    capture_output=True, text=True, shell=True, timeout=5
                )
                if r.returncode == 0:
                    return candidate
            except Exception:
                pass

        npm_paths = (
            [
                Path(os.environ.get("APPDATA", "")) / "npm" / "apk-mitm.cmd",
                Path(os.environ.get("APPDATA", "")) / "npm" / "node_modules" / "apk-mitm" / "bin" / "apk-mitm.js",
            ]
            if os.name == "nt"
            else [
                Path("/usr/local/bin/apk-mitm"),
                Path.home() / ".npm-global" / "bin" / "apk-mitm",
            ]
        )
        for p in npm_paths:
            if p.exists():
                return f'node "{p}"' if p.suffix == ".js" else f'"{p}"'

        raise Exception(
            "apk-mitm not found.\n\n"
            "Install via:  npm install -g apk-mitm\n\n"
            "Alternatively use 'NSC Patch' — it bypasses SSL pinning without Node.js."
        )
