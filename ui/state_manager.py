"""
StateManager — Persistent state for the Android APK Tool.

Saves/restores:
  - Last-used directory per operation type
  - Recent files list (up to MAX_RECENT entries)

Data stored at: ~/.androidtool_state.json
"""

import json
import os
from pathlib import Path
from datetime import datetime


MAX_RECENT = 10
STATE_FILE = Path.home() / ".androidtool_state.json"

# Keys used for per-operation last directories
DIR_APK_HOME   = "last_apk_dir_home"    # Home tab APK browse
DIR_AAB_HOME   = "last_aab_dir_home"    # Home tab AAB browse
DIR_MERGE      = "last_merge_dir"       # Merge split APKs directory
DIR_OUTPUT     = "last_output_dir"      # Generic output dir
DIR_EXTRACT_OUT = "last_extract_output" # Extract tab output dir


class StateManager:
    """
    Lightweight JSON-backed state persistence.
    Thread-safe for reads; writes happen only on the main thread.
    """

    _instance = None

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = StateManager()
        return cls._instance

    def __init__(self):
        self._data = {
            "dirs": {},
            "recent_files": [],   # list of {"path": str, "ts": iso-str, "type": "apk"|"aab"}
        }
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self):
        try:
            if STATE_FILE.exists():
                raw = STATE_FILE.read_text(encoding="utf-8")
                loaded = json.loads(raw)
                # Merge carefully so missing keys don't crash
                if isinstance(loaded.get("dirs"), dict):
                    self._data["dirs"] = loaded["dirs"]
                if isinstance(loaded.get("recent_files"), list):
                    self._data["recent_files"] = loaded["recent_files"]
        except Exception:
            pass  # Corrupt file → start fresh

    def save(self):
        try:
            STATE_FILE.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8"
            )
        except Exception:
            pass  # Don't crash the app if we can't write state

    # ------------------------------------------------------------------
    # Directory helpers
    # ------------------------------------------------------------------

    def get_dir(self, key: str, fallback: str | None = None) -> str:
        """Return the last-used directory for the given key, or fallback."""
        saved = self._data["dirs"].get(key)
        if saved and Path(saved).exists():
            return saved
        if fallback and Path(fallback).exists():
            return fallback
        # Default: user home
        return str(Path.home())

    def set_dir(self, key: str, directory: str):
        """Persist the directory for the given key."""
        self._data["dirs"][key] = str(directory)
        self.save()

    def set_dir_from_file(self, key: str, file_path: str):
        """Persist the *parent directory* of a selected file."""
        self.set_dir(key, str(Path(file_path).parent))

    # ------------------------------------------------------------------
    # Recent files helpers
    # ------------------------------------------------------------------

    def add_recent_file(self, path: str, file_type: str = "apk"):
        """Add (or bump) a file to the top of the recent list."""
        path = str(Path(path).resolve())
        # Remove existing entry for the same path
        self._data["recent_files"] = [
            f for f in self._data["recent_files"] if f.get("path") != path
        ]
        # Prepend
        self._data["recent_files"].insert(0, {
            "path": path,
            "ts": datetime.now().isoformat(timespec="seconds"),
            "type": file_type,
        })
        # Trim
        self._data["recent_files"] = self._data["recent_files"][:MAX_RECENT]
        self.save()

    def get_recent_files(self) -> list[dict]:
        """Return recent files, filtering out ones that no longer exist."""
        return [
            f for f in self._data["recent_files"]
            if Path(f.get("path", "")).exists()
        ]

    def remove_recent_file(self, path: str):
        self._data["recent_files"] = [
            f for f in self._data["recent_files"]
            if f.get("path") != str(path)
        ]
        self.save()

    def clear_recent_files(self):
        """Remove all recent files."""
        self._data["recent_files"] = []
        self.save()
