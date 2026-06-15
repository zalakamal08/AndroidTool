# Android APK Pentesting Tool

A powerful, GUI-based Android security testing toolkit for pentesters and security researchers. No command-line knowledge required — everything is point-and-click.

Developed with 💡 by **[zalakamal08](https://github.com/zalakamal08)** & **[patelharsch](https://github.com/theharsh02)**

---

## 📥 Download & Run (No Python Required)

Pre-built executables are available on the [Releases page](../../releases).

1. Go to the **Releases** section on the right side of this page.
2. Download **`AndroidTool.exe`** from the latest release.
3. Double-click to run — no installation needed.

> **Note:** Windows Defender or antivirus may flag this tool because it deals with APK reverse engineering. This is a false positive. Click **"More Info" → "Run Anyway"** to launch.

---

## 🛠️ Features

### 🏠 Home Tab
Central launchpad for all operations. One click takes you directly to any feature:
- Install Tools
- Extract APK from device
- Merge Split APKs
- Decompile APK
- Remove SSL Pinning
- Resign APK
- Convert AAB → APK
- Install APK to Device

### 🔧 Install Tools Tab
Automatically downloads and sets up all required dependencies with a single click:
- `apktool` — APK decompilation and recompilation
- `APKEditor` — merging split APKs
- `uber-apk-signer` — APK signing
- `bundletool` — AAB to APK conversion
- `ADB` (Android Debug Bridge) — device communication
- `frida-tools` — dynamic instrumentation (for Frida tab)

### 📱 Extract APK Tab
Extract installed apps directly from a connected Android device:
- Lists all connected ADB devices
- Browses apps installed on the device (user apps or system apps)
- Pulls the APK (or split APK set) to your computer
- Supports multi-device environments

### 🔓 APK Operations (Home Tab)
Full static analysis and patching pipeline:
| Operation | Description |
|---|---|
| **Merge Split APKs** | Combine a directory of `.apk` split files into a single universal APK |
| **Decompile APK** | Disassemble an APK using `apktool` to inspect smali code, resources, and manifest |
| **Remove SSL Pinning** | Patch the APK to bypass certificate pinning (modify `network_security_config.xml` + smali hooks) |
| **Resign APK** | Re-sign a modified APK with a debug keystore via `uber-apk-signer` |
| **Convert AAB → APK** | Convert an Android App Bundle to a universal, installable APK using `bundletool` |
| **Install to Device** | Push and install an APK directly to a connected device via `adb install` |

### 🍃 Frida Tab — Dynamic Instrumentation
A full Frida control panel for runtime analysis and bypass:

**Frida Server Management**
- Auto-detect installed `frida-tools` version
- One-click setup: downloads the correct `frida-server` binary for your device's architecture, pushes it via ADB, and starts it
- Live server status indicator

**Target Selection**
- Enter a package name manually or click **List Processes** to enumerate running apps
- Choose **Spawn** mode (inject before any app code runs) or **Attach** mode (hook into a running process)

**Built-in Bypass Scripts**

| Script | Description |
|---|---|
| **HTTP Toolkit Level SSL Bypass** | Comprehensive 25+ layer SSL/TLS bypass — Conscrypt, OkHttp, Volley, WebView, Xamarin, Flutter, BoringSSL native hooks, and vendor TMs (Huawei, Samsung, Tencent, TrustKit) |
| **Flutter SSL Unpinning** | Targets Flutter's custom Dart HTTP stack which ignores Android's native SSL APIs |
| **SSL Pinning Bypass (Basic)** | Standard bypass: TrustManager, OkHttp3 CertificatePinner, WebViewClient |
| **Root Detection Bypass** | Hides `su` binary, spoofs `Build` props, blocks `Runtime.exec` root commands |
| **Biometric / Auth Bypass** | Auto-succeeds `BiometricPrompt` and `FingerprintManager` callbacks |
| **Anti-Debug Bypass** | Blocks `ptrace PTRACE_TRACEME`, `Debug.isDebuggerConnected`, `TracerPid` checks |
| **Network Logger** | Logs all OkHttp3 URLs, headers, and POST bodies to the output console |
| **Method Tracer** | Hooks every method on a target Java class — enter the fully-qualified class name |

**Proxy Traffic Redirect**
- Redirect ALL TCP traffic to a MITM proxy (Burp Suite, HTTP Toolkit, Proxyman)
- Hooks `libc connect()` at the native socket level — bypasses app-level proxy detection
- Works for Flutter, Cronet, and apps that ignore the Android system proxy setting
- Blocks HTTP/3 (QUIC) to force HTTPS inspection

**Frida Output Console**
- Color-coded live output (SSL events, proxy intercepts, network logs, errors)
- Copy output to clipboard or save as a log file

---

## 🚀 Running from Source

**Requirements:** Python 3.10+, Java (for apktool/bundletool)

```bash
pip install PyQt6 frida-tools pyinstaller
python main.py
```

**Build standalone EXE:**
```bash
pyinstaller AndroidTool.spec
```

---

## 🏗️ Project Structure

```
AndroidTool/
├── main.py                    # Entry point
├── ui/
│   ├── home_tab.py            # Home / quick-launch tab
│   ├── install_tab.py         # Tool installer tab
│   ├── extract_tab.py         # APK extraction from device
│   ├── frida_tab.py           # Dynamic instrumentation tab
│   ├── main_window.py         # Main window / tab container
│   └── state_manager.py       # Shared state across tabs
├── workers/
│   ├── apk_worker.py          # APK operations (decompile, patch, sign, convert)
│   ├── adb_worker.py          # ADB device communication
│   ├── frida_worker.py        # Frida server setup, script injection
│   └── tools_installer.py     # Dependency downloader
├── tools/
│   ├── platform-tools/        # Bundled ADB binaries (Windows)
│   ├── APKEditor.jar
│   ├── apktool.jar
│   ├── bundletool-all.jar
│   └── uber-apk-signer.jar
└── .github/workflows/
    └── build.yml              # GitHub Actions — builds & releases EXE automatically
```

---

## ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Only use it against applications and devices you own or have explicit permission to test. The authors are not responsible for misuse.

---

## 🤝 Credits

| Contributor | Role |
|---|---|
| **[zalakamal08](https://github.com/zalakamal08)** | Creator & maintainer |
| **[patelharsch](https://github.com/theharsh02)** | Co-developer (Frida tab, CI/CD, polish) |
