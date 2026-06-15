# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A PyQt6 desktop GUI tool for Android APK pentesting. It wraps common Android reverse-engineering and dynamic analysis tools (APKTool, bundletool, Frida, ADB, apk-mitm) behind a dark-themed tabbed interface, targeting Windows. Distributed as a single-file `AndroidTool.exe` via PyInstaller.

## Running the App

```powershell
python main.py
```

Dependencies: `PyQt6`, `frida-tools`. Install with `pip install PyQt6 frida-tools`.

## Building the Executable

```powershell
pyinstaller AndroidTool.spec
```

Output lands in `dist/AndroidTool.exe`. The spec bundles only Python sources — external tools (APKTool, bundletool, etc.) are downloaded at runtime by the Install Tools tab.

## Architecture

### Thread model
Every operation that shells out runs in a `QThread` worker. Workers emit four signals:
- `finished(object)` — result dict on success
- `error(str)` — error message on failure
- `progress(str)` — streamed stdout lines
- `command(str)` — the shell command string (shown in console as `cmd` level)

The UI connects to these signals and never blocks the event loop. `APKWorker._run_streaming()` is the core helper — it opens a `subprocess.Popen`, iterates stdout line-by-line, and emits each line as `progress`.

### Workers
| File | Responsibility |
|---|---|
| [workers/apk_worker.py](workers/apk_worker.py) | APK operations: decompile, recompile, merge split APKs, resign, SSL pinning removal (apk-mitm), NSC patch, AAB→APK, detailed APK info |
| [workers/adb_worker.py](workers/adb_worker.py) | ADB: list devices, pull APKs from device, install APKs, list installed packages |
| [workers/frida_worker.py](workers/frida_worker.py) | Frida: check install, auto-download + push frida-server, list processes, run instrumentation sessions |
| [workers/tools_installer.py](workers/tools_installer.py) | Downloads JAR tools and platform-tools zip from GitHub/Google; creates `apktool.bat` wrapper |

### UI Tabs
| File | Tab |
|---|---|
| [ui/home_tab.py](ui/home_tab.py) | Main operations grid (10 buttons), recent files, selected file info panel, APKInfoDialog |
| [ui/install_tab.py](ui/install_tab.py) | Per-tool download checkboxes with status indicators |
| [ui/extract_tab.py](ui/extract_tab.py) | ADB device list, installed package browser, APK pull |
| [ui/frida_tab.py](ui/frida_tab.py) | Frida server setup, target package, script checkboxes, proxy redirect, output console |
| [ui/main_window.py](ui/main_window.py) | `AndroidPentestTool(QMainWindow)` — hosts all tabs, shared console, `log()` method, cross-tab APK path sharing |
| [ui/state_manager.py](ui/state_manager.py) | Singleton JSON persistence at `~/.androidtool_state.json` — last-used directories and recent files list |

### Cross-tab data flow
- `AndroidPentestTool.set_last_selected_apk()` / `get_last_selected_apk()` shares the active APK path across tabs.
- `HomeTab.prefill_apk()` is called by the Extract tab after a successful pull to pre-select the APK.
- `FridaTab._get_serial()` borrows the device serial from `ExtractTab._get_selected_serial()`.
- `StateManager.instance()` is a singleton accessed by all tabs for directory memory and recent files.

### Tools directory layout
All external tool JARs live under `tools/` in the project root:
- `tools/apktool.jar` + `tools/apktool.bat` (Windows wrapper)
- `tools/bundletool-all.jar`
- `tools/uber-apk-signer.jar`
- `tools/APKEditor.jar`
- `tools/platform-tools/` — ADB, aapt, apksigner, fastboot, etc.
- `tools/frida/` — downloaded frida-server binaries (per-arch, per-version)

`main_window.py` injects `tools/platform-tools` into `os.environ["PATH"]` at startup so ADB is immediately available. The same injection happens in `adb_worker.py` and `tools_installer.py` when platform-tools is freshly downloaded.

### Frida scripts
`workers/frida_worker.py` contains the `SCRIPTS` dict — all built-in Frida JS is stored as inline Python strings keyed by short names (`ssl_pinning`, `root_detection`, `httptoolkit_level`, etc.). The `method_tracer` script uses `%%TARGET_CLASS%%` as a placeholder replaced at launch time.

### Windows subprocess handling
`main.py` monkey-patches `subprocess.Popen` to always pass `CREATE_NO_WINDOW` on Windows, preventing console popups when shelling out to Java/ADB.

## Key Conventions

- All workers follow the same signal contract (`finished`, `error`, `progress`, `command`). When adding a new operation to an existing worker, add a method and register it in that worker's `dispatch` dict inside `run()`.
- Operation results are plain dicts with at minimum `{"operation": str, "input": str, "output": str, "success": bool}`.
- `HomeTab._run_operation()` is the standard launcher for APK operations — it sets up the progress bar, disables buttons, and wires all four worker signals.
- The NSC patch pipeline (decompile → inject XML → recompile → sign) is the template for multi-step operations that need cleanup on failure — use a `try/finally` to remove the working directory.
