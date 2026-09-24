#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JJS KODI Toolbox - Windows GUI.

The tool backs up, restores, and transfers complete Kodi profiles between Android
(ADB) and LibreELEC (SSH). It can also install or update a local Kodi APK on Android,
uninstall a selected Android Kodi package, stage a local LibreELEC update TAR, and
capture Kodi screenshots to a local Windows folder.

Backup files are uncompressed TAR archives. New backups contain transfer metadata.
On cross-platform or cross-architecture restore, platform-specific binary add-ons
and Kodi's add-on database are omitted automatically; user data remains portable.
"""

from __future__ import annotations

import base64
import copy
import ctypes
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import shlex
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    from . import jjs_kodi_database as kodi_db
except ImportError:
    import jjs_kodi_database as kodi_db


APP_TITLE = "JJS KODI Toolbox"
APP_VERSION = "1.18"
META_NAME = "JJS_PROFILE_TRANSFER.json"

DEFAULT_ADB_PORT = 5555
DEFAULT_SSH_PORT = 22
DEFAULT_ADB_DIR = Path(r"C:\ADB")
ADB_DOWNLOAD_URL = "https://dl.google.com/android/repository/platform-tools-latest-windows.zip"

KNOWN_ANDROID_LABELS = {
    "org.xbmc.kodi": "Kodi",
    "org.jjs.kodi": "Kodi JJS",
}
NATIVE_EXTENSIONS = {".so", ".dll", ".dylib", ".pyd"}
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class TransferError(RuntimeError):
    pass


def app_root() -> Path:
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "JJSKodiToolbox"
    root.mkdir(parents=True, exist_ok=True)
    return root


def config_path() -> Path:
    return app_root() / "config.json"


def known_hosts_path() -> Path:
    path = app_root() / "known_hosts"
    if not path.exists():
        path.touch()
    return path


def default_backup_dir() -> Path:
    docs = Path.home() / "Documents"
    return docs / "Kodi-Profile-Backups"


def default_screenshot_dir() -> Path:
    pictures = Path.home() / "Pictures"
    return pictures / "Kodi-Screenshots"


def default_database_backup_dir() -> Path:
    docs = Path.home() / "Documents"
    return docs / "Kodi-Database-Backups"


def normalize_windows_unc_path(value: str) -> str:
    """Return a native Windows UNC spelling for paths received from Tk dialogs."""
    raw = value.strip()
    if raw.startswith("//"):
        return "\\\\" + raw[2:].replace("/", "\\")
    if raw.startswith("\\\\"):
        return "\\\\" + raw[2:].replace("/", "\\")
    return raw


def replace_unc_server(value: str, server: str) -> str:
    native = normalize_windows_unc_path(value)
    if not native.startswith("\\\\"):
        return native
    remainder = native[2:]
    if "\\" not in remainder:
        return native
    _old_server, tail = remainder.split("\\", 1)
    return f"\\\\{server}\\{tail}"


def unc_ip_fallback_paths(value: str) -> list[str]:
    """Resolve a UNC hostname to IPv4 alternatives, preserving share/path."""
    native = normalize_windows_unc_path(value)
    if not native.startswith("\\\\"):
        return []

    remainder = native[2:]
    if "\\" not in remainder:
        return []
    host, _tail = remainder.split("\\", 1)

    try:
        ipaddress.ip_address(host)
        return []
    except ValueError:
        pass

    candidates: list[str] = []
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except OSError:
        return []

    for info in infos:
        ip = info[4][0]
        candidate = replace_unc_server(native, ip)
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def safe_filename_part(value: str) -> str:
    value = value.strip().replace(":", "_")
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "-", value)
    value = re.sub(r"\s+", "-", value)
    value = re.sub(r"-+", "-", value).strip(" .-")
    return value or "Kodi"


def safe_filename_text(value: str) -> str:
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "-", value.strip())
    value = re.sub(r"\s+", " ", value).strip(" .-")
    return value or "Kodi"


def arch_family(value: str) -> str:
    value = (value or "").strip().lower()
    if value in {"aarch64", "arm64-v8a", "arm64"}:
        return "arm64"
    if value in {"x86_64", "amd64"}:
        return "x86_64"
    if value.startswith("arm"):
        return "arm"
    if value in {"x86", "i386", "i686"}:
        return "x86"
    return value or "unknown"


def normalize_tar_name(name: str, legacy_wrapped: bool = False) -> str:
    name = name.replace("\\", "/")
    while name.startswith("./"):
        name = name[2:]
    name = name.strip("/")
    if legacy_wrapped:
        if name == ".kodi":
            return ""
        if name.startswith(".kodi/"):
            name = name[len(".kodi/") :]
    return name


def validate_tar_path(name: str) -> None:
    raw = name.replace("\\", "/")
    if raw.startswith("/"):
        raise TransferError(f"Unsafe absolute path in backup: {name}")
    parts = [p for p in PurePosixPath(raw).parts if p not in ("", ".")]
    if ".." in parts:
        raise TransferError(f"Unsafe path in backup: {name}")


class PromptHostKeyPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    def __init__(self, app: "TransferApp") -> None:
        self.app = app

    def missing_host_key(self, client, hostname, key) -> None:
        digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
        fingerprint = f"SHA256:{digest}"
        ok = self.app._ask_yes_no(
            "SSH host key",
            f"The SSH host {hostname} is not known yet.\n\n"
            f"Key type: {key.get_name()}\n"
            f"Fingerprint: {fingerprint}\n\n"
            "Trust this host and save the key?",
        )
        if not ok:
            raise TransferError("SSH host key was not accepted.")
        client._host_keys.add(hostname, key.get_name(), key)
        client.save_host_keys(str(known_hosts_path()))
        self.app.log(f"SSH host key saved: {hostname} {fingerprint}")


class TransferApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_TITLE}  {APP_VERSION}")
        self.geometry("1040x820")
        self.minsize(920, 720)

        self._ui_queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._busy = False
        self._adb_path: Path | None = None
        self._log_file: Path | None = None
        self._endpoint_profiles: dict[str, dict[str, dict]] = {"source": {}, "target": {}}
        self._endpoint_vars: dict[str, dict[str, tk.Variable]] = {}
        self._endpoint_widgets: dict[str, dict[str, object]] = {}
        self._install_profile_map: dict[str, dict] = {}
        self._action_buttons: list[ttk.Button] = []
        self._progress_bars: dict[str, ttk.Progressbar] = {}
        self._progress_vars: dict[str, tk.StringVar] = {}
        self._progress_values: dict[str, float] = {
            "profile": 0.0,
            "install": 0.0,
            "screenshot": 0.0,
            "database": 0.0,
        }
        self._active_progress_key: str | None = None
        self._log_widgets: list[tk.Text] = []
        self._cancel_event = threading.Event()
        self._cancel_enabled = False
        self._operation_dialog: tk.Toplevel | None = None
        self._operation_dialog_title_var: tk.StringVar | None = None
        self._operation_dialog_progress_var: tk.StringVar | None = None
        self._operation_dialog_result_var: tk.StringVar | None = None
        self._operation_dialog_bar: ttk.Progressbar | None = None
        self._operation_dialog_button: ttk.Button | None = None
        self._operation_pending_message: tuple[str, str] | None = None

        self._load_config()
        self._build_ui()
        self.after(100, self._drain_ui_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- config ----------
    def _load_config(self) -> None:
        try:
            self._cfg = json.loads(config_path().read_text(encoding="utf-8"))
        except Exception:
            self._cfg = {}

    def _save_config(self) -> None:
        cfg = {
            "adb_dir": self.adb_dir_var.get().strip(),
            "backup_dir": self.backup_dir_var.get().strip(),
            "backup_file": self.backup_file_var.get().strip(),
            "safety_backup": bool(self.safety_backup_var.get()),
            "screenshot_dir": self.screenshot_dir_var.get().strip(),
            "database_backup_dir": self.database_backup_dir_var.get().strip(),
            "database_restore_file": self.database_restore_file_var.get().strip(),
            "database_source_mode": self.database_source_mode_var.get().strip(),
            "database_host": self.database_host_var.get().strip(),
            "database_port": self.database_port_var.get().strip(),
            "database_user": self.database_user_var.get().strip(),
            "database_music_prefix": self.database_music_prefix_var.get().strip(),
            "database_video_prefix": self.database_video_prefix_var.get().strip(),
            "install_file": self.install_file_var.get().strip(),
            "uninstall_backup": bool(self.uninstall_backup_var.get()),
        }
        for role in ("source", "target"):
            v = self._endpoint_vars.get(role, {})
            if v:
                cfg[role] = {
                    "type": str(v["type"].get()),
                    "ip": str(v["ip"].get()).strip(),
                    "port": str(v["port"].get()).strip(),
                    "user": str(v["user"].get()).strip(),
                    "profile": str(v["profile"].get()).strip(),
                }

        try:
            config_path().write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass

    # ---------- UI ----------
    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_TITLE, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="Manage Kodi profiles, databases, installs/updates, and screenshots on Android/ADB and LibreELEC/SSH.",
        ).pack(anchor="w", pady=(2, 10))

        self.adb_dir_var = tk.StringVar(value=str(self._cfg.get("adb_dir", DEFAULT_ADB_DIR)))
        self.backup_dir_var = tk.StringVar(value=str(self._cfg.get("backup_dir", default_backup_dir())))
        self.backup_file_var = tk.StringVar(value=str(self._cfg.get("backup_file", "")))
        self.safety_backup_var = tk.BooleanVar(value=bool(self._cfg.get("safety_backup", True)))
        self.screenshot_dir_var = tk.StringVar(
            value=str(self._cfg.get("screenshot_dir", default_screenshot_dir()))
        )
        self.database_backup_dir_var = tk.StringVar(
            value=str(self._cfg.get("database_backup_dir", default_database_backup_dir()))
        )
        self.database_restore_file_var = tk.StringVar(
            value=str(self._cfg.get("database_restore_file", ""))
        )
        self.database_source_mode_var = tk.StringVar(
            value=str(self._cfg.get("database_source_mode", "Kodi source"))
        )
        self.database_host_var = tk.StringVar(value=str(self._cfg.get("database_host", "")))
        self.database_port_var = tk.StringVar(value=str(self._cfg.get("database_port", "3306")))
        self.database_user_var = tk.StringVar(value=str(self._cfg.get("database_user", "")))
        self.database_password_var = tk.StringVar(value="")
        self.database_music_prefix_var = tk.StringVar(
            value=str(self._cfg.get("database_music_prefix", "MyMusic"))
        )
        self.database_video_prefix_var = tk.StringVar(
            value=str(self._cfg.get("database_video_prefix", "MyVideos"))
        )
        self.install_file_var = tk.StringVar(value=str(self._cfg.get("install_file", "")))
        self.uninstall_backup_var = tk.BooleanVar(value=bool(self._cfg.get("uninstall_backup", True)))

        style = ttk.Style(self)
        style.configure(
            "JJS.TNotebook",
            tabmargins=(4, 4, 4, 0),
            borderwidth=1,
            relief="solid",
        )
        style.configure(
            "JJS.TNotebook.Tab",
            padding=(18, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "JJS.TNotebook.Tab",
            padding=[("selected", (20, 10)), ("!selected", (18, 8))],
            relief=[("selected", "raised"), ("!selected", "flat")],
        )

        notebook = ttk.Notebook(outer, style="JJS.TNotebook")
        notebook.pack(fill="both", expand=True)

        profile_tab = ttk.Frame(notebook, padding=10)
        install_tab = ttk.Frame(notebook, padding=10)
        screenshot_tab = ttk.Frame(notebook, padding=10)
        database_tab = ttk.Frame(notebook, padding=10)
        notebook.add(profile_tab, text="Profile Backup / Restore / Transfer")
        notebook.add(install_tab, text="Kodi Install / Update")
        notebook.add(screenshot_tab, text="Screenshots")
        notebook.add(database_tab, text="Databases")

        self._build_profile_tab(profile_tab)
        self._build_install_tab(install_tab)
        self._build_screenshot_tab(screenshot_tab)
        self._build_database_tab(database_tab)

    def _build_profile_tab(self, outer) -> None:
        endpoints = ttk.Frame(outer)
        endpoints.pack(fill="x")
        endpoints.columnconfigure(0, weight=1)
        endpoints.columnconfigure(1, weight=1)

        self._build_endpoint(endpoints, "source", "Source A", 0)
        self._build_endpoint(endpoints, "target", "Target B", 1)

        options = ttk.LabelFrame(outer, text="Backup", padding=10)
        options.pack(fill="x", pady=(10, 0))
        options.columnconfigure(1, weight=1)

        self._path_row(options, 0, "ADB folder:", self.adb_dir_var, self._browse_adb_dir)
        self._path_row(options, 1, "Backup destination:", self.backup_dir_var, self._browse_backup_dir)
        self._path_row(options, 2, "Backup to restore:", self.backup_file_var, self._browse_backup_file)
        ttk.Checkbutton(
            options,
            text="Automatically back up the existing target profile before restore",
            variable=self.safety_backup_var,
        ).grid(row=3, column=1, sticky="w", pady=(5, 0))

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=10)

        for text, fn in (
            ("Check source", lambda: self._start_worker(lambda: self._check_endpoint("source"), operation_title="Check source")),
            ("Check target", lambda: self._start_worker(lambda: self._check_endpoint("target"), operation_title="Check target")),
            ("BACKUP", lambda: self._start_worker(self._backup_only, operation_title="Profile backup")),
            ("RESTORE", lambda: self._start_worker(self._restore_only, operation_title="Profile restore")),
            ("TRANSFER A → B", lambda: self._start_worker(self._transfer, operation_title="Profile transfer A → B")),
        ):
            b = ttk.Button(actions, text=text, command=fn)
            b.pack(side="left", padx=(0, 8))
            self._action_buttons.append(b)

        status = ttk.LabelFrame(outer, text="Status", padding=8)
        status.pack(fill="x", pady=(0, 10))
        status.columnconfigure(1, weight=1)
        self.status_vars: dict[str, tk.StringVar] = {}
        for row, (key, label) in enumerate(
            (
                ("source", "Source"),
                ("target", "Target"),
                ("backup", "Backup"),
                ("restore", "Restore"),
                ("result", "Result"),
            )
        ):
            ttk.Label(status, text=label + ":").grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=2)
            var = tk.StringVar(value="—")
            self.status_vars[key] = var
            ttk.Label(status, textvariable=var).grid(row=row, column=1, sticky="w", pady=2)

        log_box = ttk.LabelFrame(outer, text="Log", padding=6)
        log_box.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_box, wrap="word", height=14, font=("Consolas", 9), state="disabled")
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log_widgets.append(self.log_text)

    def _build_install_tab(self, outer) -> None:
        connection = ttk.LabelFrame(outer, text="Target device", padding=10)
        connection.pack(fill="x")
        connection.columnconfigure(1, weight=1)
        self._build_install_endpoint(connection)

        file_box = ttk.LabelFrame(outer, text="Local installation file", padding=10)
        file_box.pack(fill="x", pady=(10, 0))
        file_box.columnconfigure(1, weight=1)
        self._path_row(file_box, 0, "File:", self.install_file_var, self._browse_install_file)
        self._install_file_hint = ttk.Label(file_box, text="")
        self._install_file_hint.grid(row=1, column=1, sticky="w", pady=(2, 0))

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=10)

        self.install_check_button = ttk.Button(
            actions,
            text="Check device",
            command=lambda: self._start_worker(
                self._check_install_target, "install", "Check install target"
            ),
        )
        self.install_check_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.install_check_button)

        self.install_action_button = ttk.Button(
            actions,
            text="INSTALL / UPDATE",
            command=lambda: self._start_worker(
                self._install_or_update, "install", "Kodi install / update"
            ),
        )
        self.install_action_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.install_action_button)

        self.uninstall_button = ttk.Button(
            actions,
            text="UNINSTALL",
            command=lambda: self._start_worker(
                self._uninstall_android_kodi, "install", "Uninstall Kodi"
            ),
        )
        self.uninstall_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.uninstall_button)

        self.uninstall_backup_check = ttk.Checkbutton(
            outer,
            text="Back up the selected Kodi profile before uninstalling",
            variable=self.uninstall_backup_var,
        )
        self.uninstall_backup_check.pack(anchor="w", pady=(0, 8))

        status = ttk.LabelFrame(outer, text="Status", padding=8)
        status.pack(fill="x", pady=(0, 10))
        status.columnconfigure(1, weight=1)
        self.install_status_frame = status
        for row, (key, label) in enumerate(
            (
                ("install_device", "Device"),
                ("install_kodi", "Installed Kodi"),
                ("install", "Installation"),
            )
        ):
            ttk.Label(status, text=label + ":").grid(row=row, column=0, sticky="nw", padx=(0, 10), pady=2)
            var = tk.StringVar(value="—")
            self.status_vars[key] = var
            ttk.Label(status, textvariable=var).grid(row=row, column=1, sticky="w", pady=2)

        log_box = ttk.LabelFrame(outer, text="Log", padding=6)
        log_box.pack(fill="both", expand=True)
        self.install_log_text = tk.Text(
            log_box,
            wrap="word",
            height=14,
            font=("Consolas", 9),
            state="disabled",
        )
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.install_log_text.yview)
        self.install_log_text.configure(yscrollcommand=scroll.set)
        self.install_log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log_widgets.append(self.install_log_text)

        self._install_type_changed(initial=True)

    def _build_screenshot_tab(self, outer) -> None:
        ttk.Label(
            outer,
            text="Uses the same connection data as Source A. Changes in either tab are synchronized immediately.",
        ).pack(anchor="w", pady=(0, 10))

        connection = ttk.LabelFrame(outer, text="Kodi source", padding=10)
        connection.pack(fill="x")
        connection.columnconfigure(1, weight=1)
        self._build_screenshot_endpoint(connection)

        destination = ttk.LabelFrame(outer, text="Screenshot destination", padding=10)
        destination.pack(fill="x", pady=(10, 0))
        destination.columnconfigure(1, weight=1)
        self._path_row(
            destination,
            0,
            "Folder:",
            self.screenshot_dir_var,
            self._browse_screenshot_dir,
        )
        ttk.Label(
            destination,
            text="Thin solid-black outer borders are removed automatically when possible.",
        ).grid(row=1, column=1, sticky="w", pady=(2, 0))

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=10)

        self.screenshot_check_button = ttk.Button(
            actions,
            text="Check source",
            command=lambda: self._start_worker(
                lambda: self._check_endpoint("source"),
                "screenshot",
                "Check screenshot source",
            ),
        )
        self.screenshot_check_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.screenshot_check_button)

        self.screenshot_button = ttk.Button(
            actions,
            text="Take Screenshot",
            command=lambda: self._start_worker(
                self._take_screenshot, "screenshot", "Take screenshot"
            ),
        )
        self.screenshot_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.screenshot_button)

        status = ttk.LabelFrame(outer, text="Status", padding=8)
        status.pack(fill="x", pady=(0, 10))
        status.columnconfigure(1, weight=1)
        ttk.Label(status, text="Source:").grid(
            row=0, column=0, sticky="nw", padx=(0, 10), pady=2
        )
        ttk.Label(status, textvariable=self.status_vars["source"]).grid(
            row=0, column=1, sticky="w", pady=2
        )
        ttk.Label(status, text="Screenshot:").grid(
            row=1, column=0, sticky="nw", padx=(0, 10), pady=2
        )
        var = tk.StringVar(value="—")
        self.status_vars["screenshot"] = var
        ttk.Label(status, textvariable=var).grid(row=1, column=1, sticky="w", pady=2)

        log_box = ttk.LabelFrame(outer, text="Log", padding=6)
        log_box.pack(fill="both", expand=True)
        self.screenshot_log_text = tk.Text(
            log_box,
            wrap="word",
            height=14,
            font=("Consolas", 9),
            state="disabled",
        )
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.screenshot_log_text.yview)
        self.screenshot_log_text.configure(yscrollcommand=scroll.set)
        self.screenshot_log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log_widgets.append(self.screenshot_log_text)

    def _build_screenshot_endpoint(self, frame) -> None:
        source_vars = self._endpoint_vars["source"]
        type_var = source_vars["type"]
        ip_var = source_vars["ip"]
        port_var = source_vars["port"]
        user_var = source_vars["user"]
        password_var = source_vars["password"]
        profile_var = source_vars["profile"]

        ttk.Label(frame, text="Connection:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        type_box = ttk.Combobox(
            frame,
            textvariable=type_var,
            values=("Android (ADB)", "LibreELEC (SSH)"),
            state="readonly",
            width=18,
        )
        type_box.grid(row=0, column=1, sticky="ew", pady=3)
        type_box.bind("<<ComboboxSelected>>", lambda _e: self._endpoint_type_changed("source"))

        ttk.Label(frame, text="IP:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        iprow = ttk.Frame(frame)
        iprow.grid(row=1, column=1, sticky="ew", pady=3)
        iprow.columnconfigure(0, weight=1)
        ttk.Entry(iprow, textvariable=ip_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(iprow, text="Port:").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(iprow, textvariable=port_var, width=7).grid(row=0, column=2)

        user_label = ttk.Label(frame, text="SSH-User:")
        user_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        user_entry = ttk.Entry(frame, textvariable=user_var)
        user_entry.grid(row=2, column=1, sticky="ew", pady=3)

        pass_label = ttk.Label(frame, text="SSH password:")
        pass_label.grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        pass_entry = ttk.Entry(frame, textvariable=password_var, show="●")
        pass_entry.grid(row=3, column=1, sticky="ew", pady=3)

        ttk.Label(frame, text="Kodi:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        profile_box = ttk.Combobox(frame, textvariable=profile_var)
        profile_box.grid(row=4, column=1, sticky="ew", pady=3)

        self._endpoint_widgets["screenshot"] = {
            "profile": profile_box,
            "ssh_rows": (user_label, user_entry, pass_label, pass_entry),
        }
        self._refresh_screenshot_connection_rows()

    def _refresh_screenshot_connection_rows(self) -> None:
        widgets = self._endpoint_widgets.get("screenshot")
        if not widgets:
            return
        is_android = str(self._endpoint_vars["source"]["type"].get()).startswith("Android")
        for widget in widgets["ssh_rows"]:
            if is_android:
                widget.grid_remove()
            else:
                widget.grid()

    def _build_database_tab(self, outer) -> None:
        ttk.Label(
            outer,
            text="Back up or restore MusicDB / VideoDB from Source A or connect directly to a MariaDB server.",
        ).pack(anchor="w", pady=(0, 10))

        connection = ttk.LabelFrame(outer, text="Database source", padding=10)
        connection.pack(fill="x")
        connection.columnconfigure(1, weight=1)
        self._build_database_endpoint(connection)

        files = ttk.LabelFrame(outer, text="Database backup files", padding=10)
        files.pack(fill="x", pady=(10, 0))
        files.columnconfigure(1, weight=1)
        self._path_row(
            files, 0, "Backup destination:", self.database_backup_dir_var, self._browse_database_backup_dir
        )
        self._path_row(
            files, 1, "Backup to restore:", self.database_restore_file_var, self._browse_database_restore_file
        )
        ttk.Label(
            files,
            text="Uses the JJS Music Library Manager backup format (ZIP format version 2).",
        ).grid(row=2, column=1, sticky="w", pady=(2, 0))

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=10)
        for text, fn in (
            ("Check DBs", self._check_databases),
            ("BACKUP MusicDB", lambda: self._database_backup("music")),
            ("RESTORE MusicDB", lambda: self._database_restore("music")),
            ("BACKUP VideoDB", lambda: self._database_backup("video")),
            ("RESTORE VideoDB", lambda: self._database_restore("video")),
        ):
            button = ttk.Button(
                actions,
                text=text,
                command=lambda f=fn, title=text: self._start_worker(
                    f, "database", title.replace("BACKUP", "Backup").replace("RESTORE", "Restore")
                ),
            )
            button.pack(side="left", padx=(0, 8))
            self._action_buttons.append(button)

        status = ttk.LabelFrame(outer, text="Status", padding=8)
        status.pack(fill="x", pady=(0, 10))
        status.columnconfigure(1, weight=1)
        for row, (key, label) in enumerate(
            (
                ("database_source", "Source"),
                ("music_db", "MusicDB"),
                ("video_db", "VideoDB"),
                ("database", "Operation"),
            )
        ):
            ttk.Label(status, text=label + ":").grid(
                row=row, column=0, sticky="nw", padx=(0, 10), pady=2
            )
            var = tk.StringVar(value="—")
            self.status_vars[key] = var
            ttk.Label(status, textvariable=var).grid(row=row, column=1, sticky="w", pady=2)

        log_box = ttk.LabelFrame(outer, text="Log", padding=6)
        log_box.pack(fill="both", expand=True)
        self.database_log_text = tk.Text(
            log_box, wrap="word", height=14, font=("Consolas", 9), state="disabled"
        )
        scroll = ttk.Scrollbar(log_box, orient="vertical", command=self.database_log_text.yview)
        self.database_log_text.configure(yscrollcommand=scroll.set)
        self.database_log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log_widgets.append(self.database_log_text)

    def _build_database_endpoint(self, frame) -> None:
        ttk.Label(frame, text="Mode:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        mode_box = ttk.Combobox(
            frame,
            textvariable=self.database_source_mode_var,
            values=("Kodi source", "MariaDB server"),
            state="readonly",
            width=20,
        )
        mode_box.grid(row=0, column=1, sticky="w", pady=3)
        mode_box.bind("<<ComboboxSelected>>", lambda _e: self._database_mode_changed())

        kodi_frame = ttk.Frame(frame)
        kodi_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        kodi_frame.columnconfigure(1, weight=1)

        source_vars = self._endpoint_vars["source"]
        type_var = source_vars["type"]
        ip_var = source_vars["ip"]
        port_var = source_vars["port"]
        user_var = source_vars["user"]
        password_var = source_vars["password"]
        profile_var = source_vars["profile"]

        ttk.Label(kodi_frame, text="Connection:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        type_box = ttk.Combobox(
            kodi_frame,
            textvariable=type_var,
            values=("Android (ADB)", "LibreELEC (SSH)"),
            state="readonly",
            width=18,
        )
        type_box.grid(row=0, column=1, sticky="ew", pady=3)
        type_box.bind("<<ComboboxSelected>>", lambda _e: self._endpoint_type_changed("source"))

        ttk.Label(kodi_frame, text="IP:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        iprow = ttk.Frame(kodi_frame)
        iprow.grid(row=1, column=1, sticky="ew", pady=3)
        iprow.columnconfigure(0, weight=1)
        ttk.Entry(iprow, textvariable=ip_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(iprow, text="Port:").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(iprow, textvariable=port_var, width=7).grid(row=0, column=2)

        user_label = ttk.Label(kodi_frame, text="SSH-User:")
        user_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        user_entry = ttk.Entry(kodi_frame, textvariable=user_var)
        user_entry.grid(row=2, column=1, sticky="ew", pady=3)

        pass_label = ttk.Label(kodi_frame, text="SSH password:")
        pass_label.grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        pass_entry = ttk.Entry(kodi_frame, textvariable=password_var, show="●")
        pass_entry.grid(row=3, column=1, sticky="ew", pady=3)

        ttk.Label(kodi_frame, text="Kodi:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        profile_box = ttk.Combobox(kodi_frame, textvariable=profile_var)
        profile_box.grid(row=4, column=1, sticky="ew", pady=3)

        server_frame = ttk.Frame(frame)
        server_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        server_frame.columnconfigure(1, weight=1)

        ttk.Label(server_frame, text="Server:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        hostrow = ttk.Frame(server_frame)
        hostrow.grid(row=0, column=1, sticky="ew", pady=3)
        hostrow.columnconfigure(0, weight=1)
        ttk.Entry(hostrow, textvariable=self.database_host_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(hostrow, text="Port:").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(hostrow, textvariable=self.database_port_var, width=7).grid(row=0, column=2)

        ttk.Label(server_frame, text="User:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Entry(server_frame, textvariable=self.database_user_var).grid(row=1, column=1, sticky="ew", pady=3)

        ttk.Label(server_frame, text="Password:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Entry(server_frame, textvariable=self.database_password_var, show="●").grid(
            row=2, column=1, sticky="ew", pady=3
        )

        ttk.Label(server_frame, text="Music prefix:").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Entry(server_frame, textvariable=self.database_music_prefix_var).grid(
            row=3, column=1, sticky="ew", pady=3
        )

        ttk.Label(server_frame, text="Video prefix:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        ttk.Entry(server_frame, textvariable=self.database_video_prefix_var).grid(
            row=4, column=1, sticky="ew", pady=3
        )

        ttk.Label(
            server_frame,
            text="Server, port, user and prefixes are saved. The MariaDB password is not stored.",
        ).grid(row=5, column=1, sticky="w", pady=(2, 0))

        self._endpoint_widgets["database"] = {
            "profile": profile_box,
            "ssh_rows": (user_label, user_entry, pass_label, pass_entry),
            "kodi_frame": kodi_frame,
            "server_frame": server_frame,
        }
        self._refresh_database_connection_rows()
        self._database_mode_changed()

    def _database_mode_changed(self) -> None:
        widgets = self._endpoint_widgets.get("database")
        if not widgets:
            return
        direct = self.database_source_mode_var.get().strip() == "MariaDB server"
        if direct:
            widgets["kodi_frame"].grid_remove()
            widgets["server_frame"].grid()
        else:
            widgets["server_frame"].grid_remove()
            widgets["kodi_frame"].grid()
            self._refresh_database_connection_rows()

    def _refresh_database_connection_rows(self) -> None:
        widgets = self._endpoint_widgets.get("database")
        if not widgets:
            return
        is_android = str(self._endpoint_vars["source"]["type"].get()).startswith("Android")
        for widget in widgets["ssh_rows"]:
            if is_android:
                widget.grid_remove()
            else:
                widget.grid()

    def _build_install_endpoint(self, frame) -> None:
        # Target B and the Install / Update tab are two views of the same target device.
        # Reuse the exact same Tk variables so edits in either tab are visible immediately
        # in the other tab and there is no second, diverging device configuration.
        target_vars = self._endpoint_vars["target"]
        type_var = target_vars["type"]
        ip_var = target_vars["ip"]
        port_var = target_vars["port"]
        user_var = target_vars["user"]
        password_var = target_vars["password"]
        profile_var = target_vars["profile"]

        self._endpoint_vars["install"] = target_vars

        ttk.Label(frame, text="Connection:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        type_box = ttk.Combobox(
            frame,
            textvariable=type_var,
            values=("Android (ADB)", "LibreELEC (SSH)"),
            state="readonly",
            width=18,
        )
        type_box.grid(row=0, column=1, sticky="ew", pady=3)
        type_box.bind("<<ComboboxSelected>>", lambda _e: self._install_type_changed())

        ttk.Label(frame, text="IP:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        iprow = ttk.Frame(frame)
        iprow.grid(row=1, column=1, sticky="ew", pady=3)
        iprow.columnconfigure(0, weight=1)
        ttk.Entry(iprow, textvariable=ip_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(iprow, text="Port:").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(iprow, textvariable=port_var, width=7).grid(row=0, column=2)

        user_label = ttk.Label(frame, text="SSH-User:")
        user_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        user_entry = ttk.Entry(frame, textvariable=user_var)
        user_entry.grid(row=2, column=1, sticky="ew", pady=3)

        pass_label = ttk.Label(frame, text="SSH password:")
        pass_label.grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        pass_entry = ttk.Entry(frame, textvariable=password_var, show="●")
        pass_entry.grid(row=3, column=1, sticky="ew", pady=3)

        adb_label = ttk.Label(frame, text="ADB folder:")
        adb_label.grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        adb_holder = ttk.Frame(frame)
        adb_holder.grid(row=4, column=1, sticky="ew", pady=3)
        adb_holder.columnconfigure(0, weight=1)
        ttk.Entry(adb_holder, textvariable=self.adb_dir_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(adb_holder, text="Browse…", command=self._browse_adb_dir, takefocus=False).grid(
            row=0, column=1, padx=(6, 0)
        )

        kodi_label = ttk.Label(frame, text="Installed Kodi:")
        kodi_label.grid(row=5, column=0, sticky="w", padx=(0, 8), pady=3)
        profile_box = ttk.Combobox(frame, textvariable=profile_var, state="readonly")
        profile_box.grid(row=5, column=1, sticky="ew", pady=3)
        profile_box.bind("<<ComboboxSelected>>", lambda _e: self._refresh_install_controls())

        self._endpoint_widgets["install"] = {
            "user": user_entry,
            "password": pass_entry,
            "profile": profile_box,
            "ssh_rows": (user_label, user_entry, pass_label, pass_entry),
            "adb_rows": (adb_label, adb_holder),
            "kodi_rows": (kodi_label, profile_box),
        }

    def _install_type_changed(self, initial: bool = False) -> None:
        v = self._endpoint_vars["install"]
        is_android = str(v["type"].get()).startswith("Android")
        port = str(v["port"].get()).strip()

        if not initial:
            if is_android and port in ("", str(DEFAULT_SSH_PORT)):
                v["port"].set(str(DEFAULT_ADB_PORT))
            elif not is_android and port in ("", str(DEFAULT_ADB_PORT)):
                v["port"].set(str(DEFAULT_SSH_PORT))

        # Keep the profile-tab Target B controls in sync with the same connection type.
        for role in ("target", "install"):
            widgets = self._endpoint_widgets.get(role, {})
            for widget in widgets.get("ssh_rows", ()):
                if is_android:
                    widget.grid_remove()
                else:
                    widget.grid()

        for widget in self._endpoint_widgets["install"]["adb_rows"]:
            if is_android:
                widget.grid()
            else:
                widget.grid_remove()

        for widget in self._endpoint_widgets["install"]["kodi_rows"]:
            if is_android:
                widget.grid()
            else:
                widget.grid_remove()

        if not is_android and not str(v["user"].get()).strip():
            v["user"].set("root")

        if hasattr(self, "_install_file_hint"):
            self._install_file_hint.configure(
                text="Select a local APK file." if is_android else "Select a local LibreELEC update TAR."
            )
        if hasattr(self, "install_action_button"):
            self.install_action_button.configure(
                text="INSTALL / UPDATE" if is_android else "TRANSFER UPDATE"
            )
        if hasattr(self, "uninstall_button"):
            if is_android:
                self.uninstall_button.pack(side="left", padx=(0, 8))
                self.uninstall_backup_check.pack(
                    anchor="w",
                    pady=(0, 8),
                    before=self.install_status_frame,
                )
            else:
                self.uninstall_button.pack_forget()
                self.uninstall_backup_check.pack_forget()

        # A connection-type change invalidates the previously discovered device state.
        if not initial:
            self._install_profile_map = {}
            v["profile"].set("")
            self._endpoint_widgets["install"]["profile"].configure(values=())
            self._endpoint_widgets["target"]["profile"].configure(values=())
            self._endpoint_profiles["target"] = {}
            if hasattr(self, "status_vars"):
                self._set_status("target", "—")
                self._set_status("install_device", "—")
                self._set_status("install_kodi", "—")
                self._set_status("install", "—")
        self._refresh_install_controls()

    def _refresh_install_controls(self) -> None:
        if not hasattr(self, "uninstall_button"):
            return
        is_android = str(self._endpoint_vars["install"]["type"].get()).startswith("Android")
        selected = str(self._endpoint_vars["install"]["profile"].get()).strip()
        can_uninstall = is_android and selected in self._install_profile_map and not self._busy
        self.uninstall_button.configure(state="normal" if can_uninstall else "disabled")

    def _build_endpoint(self, parent, role: str, title: str, column: int) -> None:
        saved = self._cfg.get(role, {})
        frame = ttk.LabelFrame(parent, text=title, padding=10)
        frame.grid(row=0, column=column, sticky="nsew", padx=(0, 5) if column == 0 else (5, 0))
        frame.columnconfigure(1, weight=1)

        type_var = tk.StringVar(value=str(saved.get("type", "Android (ADB)")))
        ip_var = tk.StringVar(value=str(saved.get("ip", "")))
        default_port = DEFAULT_ADB_PORT if type_var.get().startswith("Android") else DEFAULT_SSH_PORT
        port_var = tk.StringVar(value=str(saved.get("port", default_port)))
        user_var = tk.StringVar(value=str(saved.get("user", "root")))
        password_var = tk.StringVar(value="")
        profile_var = tk.StringVar(value=str(saved.get("profile", "")))

        self._endpoint_vars[role] = {
            "type": type_var,
            "ip": ip_var,
            "port": port_var,
            "user": user_var,
            "password": password_var,
            "profile": profile_var,
        }

        ttk.Label(frame, text="Connection:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=3)
        type_box = ttk.Combobox(
            frame,
            textvariable=type_var,
            values=("Android (ADB)", "LibreELEC (SSH)"),
            state="readonly",
            width=18,
        )
        type_box.grid(row=0, column=1, sticky="ew", pady=3)
        type_box.bind("<<ComboboxSelected>>", lambda _e, r=role: self._endpoint_type_changed(r))

        ttk.Label(frame, text="IP:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=3)
        iprow = ttk.Frame(frame)
        iprow.grid(row=1, column=1, sticky="ew", pady=3)
        iprow.columnconfigure(0, weight=1)
        ttk.Entry(iprow, textvariable=ip_var).grid(row=0, column=0, sticky="ew")
        ttk.Label(iprow, text="Port:").grid(row=0, column=1, padx=(8, 4))
        ttk.Entry(iprow, textvariable=port_var, width=7).grid(row=0, column=2)

        user_label = ttk.Label(frame, text="SSH-User:")
        user_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=3)
        user_entry = ttk.Entry(frame, textvariable=user_var)
        user_entry.grid(row=2, column=1, sticky="ew", pady=3)

        pass_label = ttk.Label(frame, text="SSH password:")
        pass_label.grid(row=3, column=0, sticky="w", padx=(0, 8), pady=3)
        pass_entry = ttk.Entry(frame, textvariable=password_var, show="●")
        pass_entry.grid(row=3, column=1, sticky="ew", pady=3)

        ttk.Label(frame, text="Kodi:").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=3)
        profile_box = ttk.Combobox(frame, textvariable=profile_var)
        profile_box.grid(row=4, column=1, sticky="ew", pady=3)

        self._endpoint_widgets[role] = {
            "user": user_entry,
            "password": pass_entry,
            "profile": profile_box,
            "ssh_rows": (
                user_label,
                user_entry,
                pass_label,
                pass_entry,
            ),
        }
        self._endpoint_type_changed(role, initial=True)

    def _endpoint_type_changed(self, role: str, initial: bool = False) -> None:
        v = self._endpoint_vars[role]
        is_android = str(v["type"].get()).startswith("Android")
        port = str(v["port"].get()).strip()
        if not initial:
            if is_android and port in ("", str(DEFAULT_SSH_PORT)):
                v["port"].set(str(DEFAULT_ADB_PORT))
            elif not is_android and port in ("", str(DEFAULT_ADB_PORT)):
                v["port"].set(str(DEFAULT_SSH_PORT))
            # A profile from the other platform must never survive a connection-type switch.
            v["profile"].set("")
            self._endpoint_widgets[role]["profile"].configure(values=())
            if role == "source" and "screenshot" in self._endpoint_widgets:
                self._endpoint_widgets["screenshot"]["profile"].configure(values=())
            if role == "source" and "database" in self._endpoint_widgets:
                self._endpoint_widgets["database"]["profile"].configure(values=())
            if role == "target" and "install" in self._endpoint_widgets:
                self._endpoint_widgets["install"]["profile"].configure(values=())

        for widget in self._endpoint_widgets[role]["ssh_rows"]:
            if is_android:
                widget.grid_remove()
            else:
                widget.grid()

        if not is_android and not str(v["user"].get()).strip():
            v["user"].set("root")
        self._endpoint_profiles[role] = {}

        if role == "target" and "install" in self._endpoint_widgets:
            self._install_type_changed(initial=initial)
        if role == "source":
            self._refresh_screenshot_connection_rows()
            self._refresh_database_connection_rows()

    def _path_row(self, parent, row: int, label: str, variable: tk.StringVar, command) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=3)
        holder = ttk.Frame(parent)
        holder.grid(row=row, column=1, sticky="ew", pady=3)
        holder.columnconfigure(0, weight=1)
        ttk.Entry(holder, textvariable=variable).grid(row=0, column=0, sticky="ew")
        ttk.Button(holder, text="Browse…", command=command, takefocus=False).grid(
            row=0, column=1, padx=(6, 0)
        )

    def _browse_adb_dir(self) -> None:
        p = filedialog.askdirectory(initialdir=self.adb_dir_var.get() or str(DEFAULT_ADB_DIR))
        if p:
            self.adb_dir_var.set(p)

    def _browse_backup_dir(self) -> None:
        initial = self.backup_dir_var.get() or str(default_backup_dir())
        p = filedialog.askdirectory(initialdir=initial)
        if p:
            self.backup_dir_var.set(p)

    def _browse_backup_file(self) -> None:
        initial = self.backup_dir_var.get() or str(default_backup_dir())
        p = filedialog.askopenfilename(
            title="Select Kodi profile backup",
            initialdir=initial,
            filetypes=[("Kodi profile TAR", "*.tar"), ("All files", "*.*")],
        )
        if p:
            self.backup_file_var.set(p)

    def _browse_screenshot_dir(self) -> None:
        initial = self.screenshot_dir_var.get() or str(default_screenshot_dir())
        p = filedialog.askdirectory(initialdir=initial)
        if p:
            self.screenshot_dir_var.set(p)

    def _browse_database_backup_dir(self) -> None:
        initial = self.database_backup_dir_var.get() or str(default_database_backup_dir())
        p = filedialog.askdirectory(initialdir=initial)
        if p:
            self.database_backup_dir_var.set(p)

    def _browse_database_restore_file(self) -> None:
        initial = self.database_backup_dir_var.get() or str(default_database_backup_dir())
        p = filedialog.askopenfilename(
            title="Select JJS database backup",
            initialdir=initial,
            filetypes=[("JJS database backup", "*.zip"), ("All files", "*.*")],
        )
        if p:
            self.database_restore_file_var.set(p)

    def _browse_install_file(self) -> None:
        is_android = str(self._endpoint_vars["install"]["type"].get()).startswith("Android")
        current = self.install_file_var.get().strip()
        initial = str(Path(current).parent) if current else str(Path.home())
        if is_android:
            filetypes = [("Android APK", "*.apk"), ("All files", "*.*")]
            title = "Select Kodi APK"
        else:
            filetypes = [("LibreELEC update TAR", "*.tar"), ("All files", "*.*")]
            title = "Select LibreELEC update TAR"
        p = filedialog.askopenfilename(title=title, initialdir=initial, filetypes=filetypes)
        if p:
            self.install_file_var.set(p)

    # ---------- UI/log helpers ----------
    def _set_status(self, key: str, text: str) -> None:
        self._ui_queue.put(("status", (key, text)))

    def log(self, text: str) -> None:
        stamp = dt.datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {text}"
        self._ui_queue.put(("log", line))
        if self._log_file:
            try:
                self._log_file.parent.mkdir(parents=True, exist_ok=True)
                with self._log_file.open("a", encoding="utf-8", errors="replace") as f:
                    f.write(line + "\n")
            except Exception:
                pass

    def _drain_ui_queue(self) -> None:
        try:
            while True:
                kind, payload = self._ui_queue.get_nowait()
                if kind == "log":
                    for widget in self._log_widgets:
                        widget.configure(state="normal")
                        widget.insert("end", str(payload) + "\n")
                        widget.see("end")
                        widget.configure(state="disabled")
                elif kind == "status":
                    key, text = payload
                    self.status_vars[key].set(text)
                elif kind == "busy":
                    self._apply_busy(bool(payload))
                elif kind == "progress":
                    key, value, label = payload
                    bar = self._progress_bars.get(key)
                    var = self._progress_vars.get(key)
                    if bar is not None:
                        bar["value"] = value
                    if var is not None:
                        var.set(label)
                    if self._operation_dialog is not None and self._operation_dialog.winfo_exists():
                        if self._operation_dialog_bar is not None:
                            self._operation_dialog_bar["value"] = value
                        if self._operation_dialog_progress_var is not None:
                            self._operation_dialog_progress_var.set(label)
                elif kind == "profiles":
                    role, values, selected_text, done = payload
                    try:
                        self._endpoint_widgets[role]["profile"].configure(values=values)
                        if role == "source" and "screenshot" in self._endpoint_widgets:
                            self._endpoint_widgets["screenshot"]["profile"].configure(values=values)
                        if role == "source" and "database" in self._endpoint_widgets:
                            self._endpoint_widgets["database"]["profile"].configure(values=values)
                        self._endpoint_vars[role]["profile"].set(selected_text)
                    finally:
                        done.set()
                elif kind == "install_profiles":
                    values, selected_text, done = payload
                    try:
                        self._endpoint_widgets["install"]["profile"].configure(values=values)
                        self._endpoint_vars["install"]["profile"].set(selected_text)
                        self._refresh_install_controls()
                    finally:
                        done.set()
                elif kind == "message":
                    level, title, msg = payload
                    if self._operation_dialog is not None and self._operation_dialog.winfo_exists():
                        self._operation_pending_message = (level, str(msg))
                    else:
                        fn = {
                            "info": messagebox.showinfo,
                            "warning": messagebox.showwarning,
                            "error": messagebox.showerror,
                        }[level]
                        fn(title, msg, parent=self)
                elif kind == "operation_done":
                    state, message, error_status_key = payload
                    self._finish_operation_dialog(state, str(message or ""), error_status_key)
        except queue.Empty:
            pass
        self.after(100, self._drain_ui_queue)

    def _center_child_on_main(self, dialog: tk.Toplevel) -> None:
        self.update_idletasks()
        dialog.update_idletasks()
        main_x = self.winfo_rootx()
        main_y = self.winfo_rooty()
        main_w = max(self.winfo_width(), self.winfo_reqwidth())
        main_h = max(self.winfo_height(), self.winfo_reqheight())
        child_w = max(dialog.winfo_reqwidth(), 480)
        child_h = max(dialog.winfo_reqheight(), 185)
        x = main_x + max(0, (main_w - child_w) // 2)
        y = main_y + max(0, (main_h - child_h) // 2)
        dialog.geometry(f"{child_w}x{child_h}+{x}+{y}")

    def _show_operation_dialog(self, title: str) -> None:
        self._close_operation_dialog()
        self._operation_pending_message = None

        dialog = tk.Toplevel(self)
        self._operation_dialog = dialog
        dialog.withdraw()
        dialog.title(APP_TITLE)
        dialog.transient(self)
        dialog.resizable(False, False)

        body = ttk.Frame(dialog, padding=18)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)

        self._operation_dialog_title_var = tk.StringVar(value=title)
        ttk.Label(
            body,
            textvariable=self._operation_dialog_title_var,
            font=("Segoe UI", 11, "bold"),
        ).grid(row=0, column=0, sticky="w")

        self._operation_dialog_progress_var = tk.StringVar(value="0% – Starting")
        ttk.Label(
            body,
            textvariable=self._operation_dialog_progress_var,
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(12, 4))

        self._operation_dialog_bar = ttk.Progressbar(
            body, mode="determinate", maximum=100, length=420
        )
        self._operation_dialog_bar.grid(row=2, column=0, sticky="ew")

        self._operation_dialog_result_var = tk.StringVar(value="")
        ttk.Label(
            body,
            textvariable=self._operation_dialog_result_var,
            justify="left",
            anchor="w",
            wraplength=440,
        ).grid(row=3, column=0, sticky="ew", pady=(12, 0))

        button_row = ttk.Frame(body)
        button_row.grid(row=4, column=0, sticky="e", pady=(14, 0))
        self._operation_dialog_button = ttk.Button(
            button_row, text="Cancel", command=self._request_cancel, width=12
        )
        self._operation_dialog_button.pack()

        dialog.protocol("WM_DELETE_WINDOW", self._request_cancel)
        self._center_child_on_main(dialog)
        dialog.deiconify()
        dialog.lift()
        dialog.grab_set()

    def _request_cancel(self) -> None:
        if not self._busy:
            self._close_operation_dialog()
            return
        if self._cancel_event.is_set():
            return
        self._cancel_event.set()
        if self._operation_dialog_progress_var is not None:
            current = self._operation_dialog_progress_var.get()
            percent = current.split("%", 1)[0] + "%" if "%" in current else ""
            self._operation_dialog_progress_var.set(
                (percent + " – Cancelling…").strip(" –")
            )
        if self._operation_dialog_button is not None:
            self._operation_dialog_button.configure(state="disabled", text="Cancelling…")

    def _check_cancelled(self) -> None:
        if self._cancel_enabled and self._cancel_event.is_set():
            raise TransferError("Operation cancelled by user.")

    def _finish_operation_dialog(self, state: str, message: str, error_status_key: str) -> None:
        dialog = self._operation_dialog
        if dialog is None or not dialog.winfo_exists():
            return

        pending = self._operation_pending_message
        if pending is not None:
            level, pending_message = pending
            if (
                pending_message.strip()
                and (
                    (state == "success" and level == "info")
                    or (state == "error" and level in ("warning", "error"))
                )
            ):
                message = pending_message.strip()

        if state == "success" and not message:
            status_text = ""
            if error_status_key in ("install", "screenshot", "database"):
                status_var = self.status_vars.get(error_status_key)
                status_text = status_var.get().strip() if status_var is not None else ""
            if status_text and status_text != "—" and "in progress" not in status_text.lower():
                message = status_text
            else:
                message = "Operation completed successfully."
        elif state == "cancelled" and not message:
            message = "Operation cancelled."
        elif state == "error" and not message:
            message = "Operation failed."

        if self._operation_dialog_title_var is not None:
            suffix = {
                "success": " – Complete",
                "cancelled": " – Cancelled",
                "error": " – Error",
            }.get(state, "")
            base = self._operation_dialog_title_var.get().split(" – ", 1)[0]
            self._operation_dialog_title_var.set(base + suffix)

        if self._operation_dialog_result_var is not None:
            self._operation_dialog_result_var.set(message)
        if self._operation_dialog_progress_var is not None:
            if state == "success":
                self._operation_dialog_progress_var.set("100% – Complete")
                if self._operation_dialog_bar is not None:
                    self._operation_dialog_bar["value"] = 100
            elif state == "cancelled":
                current = float(self._operation_dialog_bar["value"]) if self._operation_dialog_bar is not None else 0
                self._operation_dialog_progress_var.set(f"{int(round(current))}% – Cancelled")
            else:
                current = float(self._operation_dialog_bar["value"]) if self._operation_dialog_bar is not None else 0
                self._operation_dialog_progress_var.set(f"{int(round(current))}% – Error")

        if self._operation_dialog_button is not None:
            self._operation_dialog_button.configure(
                text="OK", state="normal", command=self._close_operation_dialog
            )
        dialog.protocol("WM_DELETE_WINDOW", self._close_operation_dialog)
        self._center_child_on_main(dialog)
        self._operation_pending_message = None

    def _close_operation_dialog(self) -> None:
        dialog = self._operation_dialog
        self._operation_dialog = None
        self._operation_dialog_title_var = None
        self._operation_dialog_progress_var = None
        self._operation_dialog_result_var = None
        self._operation_dialog_bar = None
        self._operation_dialog_button = None
        self._operation_pending_message = None
        if dialog is not None:
            try:
                dialog.grab_release()
            except Exception:
                pass
            try:
                dialog.destroy()
            except Exception:
                pass

    def _set_progress(
        self,
        value: float,
        text: str = "",
        key: str | None = None,
    ) -> None:
        if threading.current_thread() is not threading.main_thread():
            self._check_cancelled()
        progress_key = key or self._active_progress_key
        if not progress_key:
            return
        value = max(0.0, min(100.0, float(value)))
        self._progress_values[progress_key] = value
        percent = int(round(value))
        label = f"{percent}%"
        if text:
            label += f" – {text}"
        self._ui_queue.put(("progress", (progress_key, value, label)))

    def _set_progress_fraction(
        self,
        start: float,
        end: float,
        done: int,
        total: int,
        text: str,
    ) -> None:
        if total <= 0:
            self._set_progress(start, text)
            return
        fraction = max(0.0, min(1.0, done / total))
        self._set_progress(start + (end - start) * fraction, text)

    def _apply_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in self._action_buttons:
            button.configure(state=state)
        if not busy:
            self._refresh_install_controls()

    def _start_worker(
        self,
        fn,
        error_status_key: str = "result",
        operation_title: str = "Operation",
    ) -> None:
        if self._busy:
            return
        self._save_config()
        progress_key = {
            "install": "install",
            "screenshot": "screenshot",
            "database": "database",
        }.get(error_status_key, "profile")
        self._active_progress_key = progress_key
        self._cancel_event.clear()
        self._cancel_enabled = True
        self._apply_busy(True)
        self._show_operation_dialog(operation_title)
        self._set_progress(0, "Starting", progress_key)
        threading.Thread(
            target=self._worker_wrapper,
            args=(fn, error_status_key, progress_key),
            daemon=True,
        ).start()

    def _worker_wrapper(self, fn, error_status_key: str, progress_key: str) -> None:
        state = "error"
        result_message = ""
        try:
            self._prepare_log_file()
            self._check_cancelled()
            fn()
            self._check_cancelled()
            state = "success"
        except TransferError as e:
            text = str(e)
            cancelled = "cancel" in text.lower() or self._cancel_event.is_set()
            state = "cancelled" if cancelled else "error"
            result_message = "Operation cancelled." if cancelled else text
            self.log(("CANCELLED: " if cancelled else "ERROR: ") + text)
            if error_status_key in self.status_vars:
                self._set_status(
                    error_status_key,
                    "Cancelled" if cancelled else f"ERROR: {text}",
                )
        except Exception as e:
            state = "error"
            result_message = f"Unexpected error:\n\n{type(e).__name__}: {e}"
            self.log(f"UNEXPECTED ERROR: {type(e).__name__}: {e}")
            if error_status_key in self.status_vars:
                self._set_status(error_status_key, f"ERROR: {type(e).__name__}: {e}")
        finally:
            self._cancel_enabled = False
            if state == "success":
                self._set_progress(100, "Complete", progress_key)
            elif state == "cancelled":
                self._set_progress(
                    self._progress_values.get(progress_key, 0.0),
                    "Cancelled",
                    progress_key,
                )
            else:
                self._set_progress(
                    self._progress_values.get(progress_key, 0.0),
                    "Error",
                    progress_key,
                )
            self._active_progress_key = None
            self._ui_queue.put(("operation_done", (state, result_message, error_status_key)))
            self._ui_queue.put(("busy", False))

    def _prepare_log_file(self) -> None:
        root = app_root() / "Logs"
        root.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self._log_file = root / f"jjs-kodi-toolbox-{stamp}.log"
        self.log(f"{APP_TITLE} {APP_VERSION}")

    def _ask_yes_no(self, title: str, message: str) -> bool:
        done = threading.Event()
        answer = {"value": False}

        def ask() -> None:
            try:
                parent = (
                    self._operation_dialog
                    if self._operation_dialog is not None and self._operation_dialog.winfo_exists()
                    else self
                )
                answer["value"] = bool(messagebox.askyesno(title, message, parent=parent))
            finally:
                done.set()

        self.after(0, ask)
        done.wait()
        return answer["value"]

    # ---------- subprocess / ADB ----------
    def _run(
        self,
        args: list[str],
        timeout: int | None = 60,
        check: bool = False,
        log_command: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        if log_command:
            self.log("$ " + subprocess.list2cmdline(args))
        try:
            cp = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
        except subprocess.TimeoutExpired as e:
            raise TransferError(f"Timeout while running: {subprocess.list2cmdline(args)}") from e
        out = (cp.stdout or "").strip()
        if out:
            for line in out.splitlines():
                self.log("  " + line)
        if check and cp.returncode != 0:
            raise TransferError(f"Command failed (code {cp.returncode}): {subprocess.list2cmdline(args)}")
        return cp

    def _run_binary(
        self,
        args: list[str],
        timeout: int | None = 60,
    ) -> subprocess.CompletedProcess[bytes]:
        self.log("$ " + subprocess.list2cmdline(args))
        try:
            cp = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                creationflags=CREATE_NO_WINDOW,
            )
        except subprocess.TimeoutExpired as e:
            raise TransferError(f"Timeout while running: {subprocess.list2cmdline(args)}") from e
        err = (cp.stderr or b"").decode("utf-8", errors="replace").strip()
        for line in err.splitlines():
            if line:
                self.log("  ! " + line)
        return cp

    def _find_or_install_adb(self) -> Path:
        configured = Path(self.adb_dir_var.get().strip() or str(DEFAULT_ADB_DIR))
        candidates = [configured / "adb.exe"]
        path_adb = shutil.which("adb")
        if path_adb:
            candidates.append(Path(path_adb))

        for candidate in candidates:
            if candidate.is_file():
                cp = self._run([str(candidate), "version"], timeout=20)
                if cp.returncode == 0:
                    self._adb_path = candidate
                    return candidate

        if not self._ask_yes_no(
            "Install ADB",
            f"ADB was not found.\n\nDownload and install the official Android Platform Tools package to\n"
            f"{configured}\n?",
        ):
            raise TransferError("ADB was not found and installation was cancelled.")

        try:
            configured.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise TransferError(f"No write permission for {configured}.") from e

        self.log("Downloading Android Platform Tools from Google …")
        with tempfile.TemporaryDirectory(prefix="jjs-adb-") as td:
            zpath = Path(td) / "platform-tools.zip"
            try:
                urllib.request.urlretrieve(ADB_DOWNLOAD_URL, zpath)
            except Exception as e:
                raise TransferError(f"ADB download failed: {e}") from e
            with zipfile.ZipFile(zpath) as zf:
                zf.extractall(td)
            src = Path(td) / "platform-tools"
            if not (src / "adb.exe").is_file():
                raise TransferError("The downloaded Platform Tools archive does not contain adb.exe.")
            for item in src.iterdir():
                dst = configured / item.name
                if item.is_dir():
                    shutil.copytree(item, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dst)

        adb = configured / "adb.exe"
        if self._run([str(adb), "version"], timeout=20).returncode != 0:
            raise TransferError("ADB was installed but could not be started.")
        self._adb_path = adb
        return adb

    def _validate_ip_port(self, role: str) -> tuple[str, int]:
        v = self._endpoint_vars[role]
        ip = str(v["ip"].get()).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            label = {"source": "Source", "target": "Target", "install": "Install target"}.get(role, "Target")
            raise TransferError(f"{label}: invalid IP address.") from e
        try:
            port = int(str(v["port"].get()).strip())
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError as e:
            label = {"source": "Source", "target": "Target", "install": "Install target"}.get(role, "Target")
            raise TransferError(f"{label}: invalid port.") from e
        return ip, port

    def _adb(self, serial: str, *args: str, timeout: int | None = 60, check: bool = False):
        adb = self._find_or_install_adb()
        return self._run([str(adb), "-s", serial, *args], timeout=timeout, check=check)

    def _connect_android(self, role: str) -> tuple[str, dict[str, str]]:
        ip, port = self._validate_ip_port(role)
        serial = f"{ip}:{port}"
        adb = self._find_or_install_adb()

        cp = self._run([str(adb), "connect", serial], timeout=30)
        out = (cp.stdout or "").lower()
        if cp.returncode != 0 or "unable" in out or "failed" in out:
            raise TransferError(f"ADB connection to {serial} failed.")

        state = self._adb(serial, "get-state", timeout=15)
        if state.returncode != 0 or "device" not in (state.stdout or ""):
            raise TransferError(f"{serial} is not available as an ADB device.")

        def prop(name: str) -> str:
            return self._adb(serial, "shell", "getprop", name, timeout=15).stdout.strip()

        info = {
            "manufacturer": prop("ro.product.manufacturer"),
            "model": prop("ro.product.model"),
            "arch": prop("ro.product.cpu.abi"),
            "android": prop("ro.build.version.release"),
        }
        return serial, info

    def _android_package_version(self, serial: str, package: str) -> str:
        command = f"dumpsys package {shlex.quote(package)} | grep 'versionName=' | head -1"
        dump = self._adb(serial, "shell", command, timeout=30).stdout or ""
        vm = re.search(r"\bversionName=([^\s]+)", dump)
        return vm.group(1) if vm else ""

    def _discover_android_profiles(self, serial: str) -> list[dict]:
        packages: set[str] = set()

        found = self._adb(
            serial,
            "shell",
            "find /sdcard/Android/data -mindepth 3 -maxdepth 3 -type d -name .kodi 2>/dev/null",
            timeout=30,
        ).stdout or ""
        for line in found.splitlines():
            m = re.match(r"^/sdcard/Android/data/([^/]+)/files/\.kodi/?$", line.strip())
            if m:
                packages.add(m.group(1))

        listed = self._adb(serial, "shell", "pm list packages", timeout=30).stdout or ""
        for line in listed.splitlines():
            if line.startswith("package:"):
                package = line.split(":", 1)[1].strip()
                low = package.lower()
                if "kodi" in low or "xbmc" in low:
                    packages.add(package)

        packages.update(KNOWN_ANDROID_LABELS)
        profiles: list[dict] = []
        for package in sorted(packages):
            installed = self._adb(serial, "shell", "pm", "path", package, timeout=15).stdout or ""
            if "package:" not in installed:
                continue
            label = KNOWN_ANDROID_LABELS.get(package, package)
            root = f"/sdcard/Android/data/{package}/files/.kodi"
            exists = self._adb(serial, "shell", f"test -d {shlex.quote(root)}", timeout=15).returncode == 0
            profiles.append(
                {
                    "name": label,
                    "identifier": package,
                    "profile_root": root,
                    "profile_exists": exists,
                    "version": self._android_package_version(serial, package),
                }
            )

        return profiles

    # ---------- SSH / LibreELEC ----------
    def _ssh_client(self, role: str):
        if paramiko is None:
            raise TransferError("SSH support is unavailable. Please use the EXE version of the tool.")

        ip, port = self._validate_ip_port(role)
        v = self._endpoint_vars[role]
        user = str(v["user"].get()).strip() or "root"
        password = str(v["password"].get())
        if not password:
            raise TransferError("SSH password is required.")

        client = paramiko.SSHClient()
        # Authentication uses username/password only. The server host key is stored locally in known_hosts.
        client.load_system_host_keys()
        try:
            client.load_host_keys(str(known_hosts_path()))
        except Exception:
            pass
        client.set_missing_host_key_policy(PromptHostKeyPolicy(self))

        try:
            client.connect(
                hostname=ip,
                port=port,
                username=user,
                password=password,
                allow_agent=False,
                look_for_keys=False,
                timeout=15,
                banner_timeout=15,
                auth_timeout=20,
            )
        except TransferError:
            raise
        except Exception as e:
            raise TransferError(f"SSH connection to {user}@{ip}:{port} failed: {e}") from e
        return client

    def _ssh_exec(self, client, command: str, timeout: int | None = 60) -> tuple[int, str, str]:
        self.log(f"$ ssh: {command}")
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            code = stdout.channel.recv_exit_status()
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
        except Exception as e:
            raise TransferError(f"SSH command failed: {e}") from e
        for line in out.splitlines():
            if line:
                self.log("  " + line)
        for line in err.splitlines():
            if line:
                self.log("  ! " + line)
        return code, out, err

    # ---------- screenshots ----------
    def _screenshot_destination(self, device: str, ip: str) -> Path:
        root_text = normalize_windows_unc_path(
            self.screenshot_dir_var.get().strip() or str(default_screenshot_dir())
        )
        root = Path(root_text)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise TransferError(f"Screenshot destination folder could not be created: {root}: {e}") from e

        device_name = safe_filename_text(device)
        ip_text = safe_filename_text(ip)
        stamp = dt.datetime.now().strftime("%y%d%m-%H%M")
        candidate = root / f"{device_name} ({ip_text})-{stamp}.png"
        n = 2
        while candidate.exists():
            candidate = root / f"{device_name} ({ip_text})-{stamp}-{n}.png"
            n += 1
        return candidate

    def _trim_black_screenshot_borders(self, path: Path) -> tuple[int, int, int, int] | None:
        if Image is None:
            self.log("Pillow is unavailable; automatic black-border trimming was skipped.")
            return None
        try:
            with Image.open(path) as source:
                image = source.convert("RGB")
                width, height = image.size
                bbox = image.getbbox()
                if bbox is None:
                    self.log("WARNING: the captured screenshot is completely black.")
                    return None

                left, top, right, bottom = bbox
                right_margin = width - right
                bottom_margin = height - bottom
                max_x = max(1, int(width * 0.08))
                max_y = max(1, int(height * 0.08))

                crop_left = left if 0 < left <= max_x else 0
                crop_top = top if 0 < top <= max_y else 0
                crop_right = right_margin if 0 < right_margin <= max_x else 0
                crop_bottom = bottom_margin if 0 < bottom_margin <= max_y else 0

                # LibreELEC/Kodi screenshots can contain very dark pillarbox borders
                # that are not mathematically RGB 0,0,0 because a few edge pixels
                # contain tiny residual values. Detect only a narrow, contiguous
                # near-black band at the outer edge and require a clear transition
                # back to real image content. This keeps the crop conservative.
                exact_box = (
                    crop_left,
                    crop_top,
                    width - crop_right,
                    height - crop_bottom,
                )
                working = image.crop(exact_box)
                work_w, work_h = working.size

                def edge_band(values: list[float], from_end: bool, max_width: int) -> int:
                    threshold = 1.25
                    sequence = list(reversed(values)) if from_end else values
                    count = 0
                    for value in sequence:
                        if value <= threshold and count < max_width:
                            count += 1
                        else:
                            break
                    if count == 0 or count >= max_width or count >= len(sequence):
                        return 0
                    # Do not crop unless the first content sample is clearly brighter
                    # than the detected border band.
                    if sequence[count] <= threshold * 1.5:
                        return 0
                    return count

                if work_w > 2 and work_h > 2:
                    column_means_img = working.resize((work_w, 1), Image.Resampling.BOX)
                    column_means = [
                        sum(pixel) / 3.0
                        for pixel in column_means_img.getdata()
                    ]
                    row_means_img = working.resize((1, work_h), Image.Resampling.BOX)
                    row_means = [
                        sum(pixel) / 3.0
                        for pixel in row_means_img.getdata()
                    ]

                    near_left = edge_band(column_means, False, max(2, int(work_w * 0.08)))
                    near_right = edge_band(column_means, True, max(2, int(work_w * 0.08)))
                    near_top = edge_band(row_means, False, max(2, int(work_h * 0.08)))
                    near_bottom = edge_band(row_means, True, max(2, int(work_h * 0.08)))

                    crop_left += near_left
                    crop_right += near_right
                    crop_top += near_top
                    crop_bottom += near_bottom

                if not any((crop_left, crop_top, crop_right, crop_bottom)):
                    return None

                box = (
                    crop_left,
                    crop_top,
                    width - crop_right,
                    height - crop_bottom,
                )
                cropped = image.crop(box)
                cropped.save(path, format="PNG")
                return crop_left, crop_top, crop_right, crop_bottom
        except Exception as e:
            self.log(f"WARNING: automatic black-border trimming failed: {e}")
            return None

    def _take_android_screenshot(self) -> tuple[bytes, str]:
        serial, device = self._connect_android("source")
        adb = self._find_or_install_adb()
        cp = self._run_binary(
            [str(adb), "-s", serial, "exec-out", "screencap", "-p"],
            timeout=30,
        )
        if cp.returncode != 0:
            raise TransferError(f"Android screenshot capture failed (ADB exit code {cp.returncode}).")
        data = cp.stdout or b""
        if not data.startswith(b"\x89PNG\r\n\x1a\n"):
            raise TransferError("Android screenshot capture did not return a valid PNG image.")
        label = " ".join(x for x in (device.get("manufacturer", ""), device.get("model", "")) if x).strip()
        self.log(f"Android screenshot captured from {label or serial}.")
        return data, (label or "Android")

    def _take_libreelec_screenshot(self) -> tuple[bytes, str]:
        client = self._ssh_client("source")
        remote = f"/tmp/jjs-kodi-screenshot-{os.getpid()}-{int(time.time() * 1000)}.png"
        sftp = None
        try:
            code, _, _ = self._ssh_exec(
                client,
                "command -v kodi-send >/dev/null 2>&1",
                timeout=20,
            )
            if code != 0:
                raise TransferError("LibreELEC does not provide the kodi-send command.")

            action = f"TakeScreenshot({remote},sync)"
            code, _, err = self._ssh_exec(
                client,
                f"kodi-send --host=127.0.0.1 --action={shlex.quote(action)}",
                timeout=30,
            )
            if code != 0:
                raise TransferError(
                    f"Kodi screenshot command failed.{(' ' + err) if err else ''}"
                )

            sftp = client.open_sftp()
            deadline = time.monotonic() + 10
            size = 0
            while time.monotonic() < deadline:
                try:
                    size = int(sftp.stat(remote).st_size)
                    if size > 8:
                        break
                except OSError:
                    pass
                time.sleep(0.2)
            if size <= 8:
                raise TransferError(
                    "Kodi did not create a screenshot on LibreELEC. "
                    "The active Kodi display backend may not support screenshots."
                )

            with sftp.open(remote, "rb") as handle:
                data = handle.read()
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                raise TransferError("LibreELEC screenshot capture did not return a valid PNG image.")
            self.log(f"LibreELEC screenshot captured via temporary file {remote}.")
            return data, "LibreELEC"
        finally:
            if sftp is not None:
                try:
                    sftp.remove(remote)
                    self.log("Temporary LibreELEC screenshot removed.")
                except OSError:
                    self.log(f"WARNING: temporary screenshot could not be removed: {remote}")
                try:
                    sftp.close()
                except Exception:
                    pass
            else:
                try:
                    self._ssh_exec(client, f"rm -f {shlex.quote(remote)}", timeout=10)
                except Exception:
                    pass
            client.close()

    def _take_screenshot(self) -> None:
        self._set_progress(10, "Connecting")
        self._set_status("screenshot", "Connecting …")
        is_android = str(self._endpoint_vars["source"]["type"].get()).startswith("Android")
        ip, _port = self._validate_ip_port("source")
        self._set_progress(25, "Capturing screen")
        if is_android:
            data, device_name = self._take_android_screenshot()
        else:
            data, device_name = self._take_libreelec_screenshot()

        self._set_progress(75, "Saving PNG")
        destination = self._screenshot_destination(device_name, ip)
        try:
            destination.write_bytes(data)
        except Exception as e:
            raise TransferError(f"Screenshot could not be saved: {destination}: {e}") from e

        self._set_progress(88, "Checking borders")
        margins = self._trim_black_screenshot_borders(destination)
        if margins:
            left, top, right, bottom = margins
            self.log(
                "Removed solid-black screenshot border "
                f"(left {left}px, top {top}px, right {right}px, bottom {bottom}px)."
            )

        self._set_progress(96, "Screenshot saved")
        size_kib = destination.stat().st_size / 1024
        self.log(f"Screenshot saved locally: {destination} ({size_kib:.0f} KiB)")
        self._set_status("screenshot", f"Saved: {destination}")

    # ---------- database backup / restore ----------
    def _database_remote_path(self, info: dict, relative: str) -> str:
        return str(PurePosixPath(info["profile_root"]) / PurePosixPath(relative))

    def _database_read_remote_bytes(self, info: dict, remote_path: str) -> bytes | None:
        if info["platform"] == "android":
            cp = self._run_binary(
                [str(self._find_or_install_adb()), "-s", info["serial"], "exec-out", "cat", remote_path],
                timeout=30,
            )
            if cp.returncode != 0:
                return None
            return bytes(cp.stdout or b"")

        client = self._ssh_client("source")
        sftp = None
        try:
            sftp = client.open_sftp()
            try:
                with sftp.open(remote_path, "rb") as handle:
                    return bytes(handle.read())
            except OSError:
                return None
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def _database_list_sqlite_files(self, info: dict) -> list[str]:
        database_dir = self._database_remote_path(info, "userdata/Database")
        if info["platform"] == "android":
            command = f"ls -1 {shlex.quote(database_dir)}/*.db 2>/dev/null"
            cp = self._adb(info["serial"], "shell", command, timeout=30)
            if cp.returncode != 0 and not (cp.stdout or "").strip():
                return []
            return [
                PurePosixPath(line.strip()).name
                for line in (cp.stdout or "").splitlines()
                if line.strip().lower().endswith(".db")
            ]

        client = self._ssh_client("source")
        sftp = None
        try:
            sftp = client.open_sftp()
            try:
                return [name for name in sftp.listdir(database_dir) if str(name).lower().endswith(".db")]
            except OSError:
                return []
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def _database_download_remote(self, info: dict, remote_path: str, local_path: Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if info["platform"] == "android":
            cp = self._run(
                [str(self._find_or_install_adb()), "-s", info["serial"], "pull", remote_path, str(local_path)],
                timeout=180,
            )
            if cp.returncode != 0 or not local_path.is_file():
                raise TransferError(f"Could not download SQLite database: {remote_path}")
            return

        client = self._ssh_client("source")
        sftp = None
        try:
            sftp = client.open_sftp()
            try:
                size = int(sftp.stat(remote_path).st_size)
            except OSError as exc:
                raise TransferError(f"SQLite database does not exist: {remote_path}") from exc

            def callback(done, total):
                self._set_progress_fraction(12, 35, int(done), int(total or size), "Downloading SQLite DB")

            sftp.get(remote_path, str(local_path), callback=callback)
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def _database_upload_sqlite(self, info: dict, local_path: Path, remote_path: str) -> None:
        remote_tmp = remote_path + ".jjs-toolbox-new"
        wal = remote_path + "-wal"
        shm = remote_path + "-shm"
        if info["platform"] == "android":
            cp = self._run(
                [str(self._find_or_install_adb()), "-s", info["serial"], "push", str(local_path), remote_tmp],
                timeout=180,
            )
            if cp.returncode != 0:
                raise TransferError("Could not upload restored SQLite database.")
            command = (
                f"rm -f {shlex.quote(wal)} {shlex.quote(shm)} && "
                f"mv -f {shlex.quote(remote_tmp)} {shlex.quote(remote_path)}"
            )
            cp = self._adb(info["serial"], "shell", command, timeout=60)
            if cp.returncode != 0:
                self._adb(info["serial"], "shell", f"rm -f {shlex.quote(remote_tmp)}", timeout=20)
                raise TransferError("Could not replace the active SQLite database.")
            return

        client = self._ssh_client("source")
        sftp = None
        try:
            sftp = client.open_sftp()

            def callback(done, total):
                self._set_progress_fraction(82, 94, int(done), int(total), "Uploading restored SQLite DB")

            sftp.put(str(local_path), remote_tmp, callback=callback)
            for sidecar in (wal, shm):
                try:
                    sftp.remove(sidecar)
                except OSError:
                    pass
            try:
                sftp.remove(remote_path)
            except OSError:
                pass
            sftp.rename(remote_tmp, remote_path)
        except Exception:
            if sftp is not None:
                try:
                    sftp.remove(remote_tmp)
                except OSError:
                    pass
            raise
        finally:
            if sftp is not None:
                sftp.close()
            client.close()

    def _database_stop_kodi(self, info: dict) -> None:
        if info["platform"] == "android":
            cp = self._adb(
                info["serial"], "shell", "am", "force-stop", info["identifier"], timeout=30
            )
            if cp.returncode != 0:
                raise TransferError(f"Could not stop {info['identifier']} before database operation.")
            self.log(f"Kodi stopped: {info['identifier']}")
            return

        client = self._ssh_client("source")
        try:
            code, _out, err = self._ssh_exec(client, "systemctl stop kodi", timeout=60)
            if code != 0:
                raise TransferError(f"Could not stop Kodi on LibreELEC.{(' ' + err) if err else ''}")
            self.log("Kodi stopped on LibreELEC.")
        finally:
            client.close()

    def _database_start_kodi(self, info: dict) -> None:
        if info["platform"] == "android":
            cp = self._adb(
                info["serial"],
                "shell",
                "monkey",
                "-p",
                info["identifier"],
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
                timeout=30,
            )
            if cp.returncode == 0:
                self.log(f"Kodi restarted: {info['identifier']}")
            else:
                self.log(
                    f"NOTE: {info['identifier']} could not be relaunched automatically; start Kodi manually."
                )
            return

        client = self._ssh_client("source")
        try:
            code, _out, err = self._ssh_exec(client, "systemctl start kodi", timeout=60)
            if code != 0:
                raise TransferError(f"Could not restart Kodi on LibreELEC.{(' ' + err) if err else ''}")
            self.log("Kodi restarted on LibreELEC.")
        finally:
            client.close()

    def _direct_database_config(self, kind: str) -> dict:
        host = self.database_host_var.get().strip()
        user = self.database_user_var.get().strip()
        password = self.database_password_var.get()
        prefix = (
            self.database_music_prefix_var.get().strip()
            if kind == "music"
            else self.database_video_prefix_var.get().strip()
        )
        if not host:
            raise TransferError("MariaDB server is missing.")
        if not user:
            raise TransferError("MariaDB user is missing.")
        if not prefix:
            raise TransferError(f"{kind.title()}DB prefix is missing.")
        try:
            port = int(self.database_port_var.get().strip() or "3306")
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError as exc:
            raise TransferError("MariaDB port is invalid.") from exc
        return {
            "engine": "mariadb",
            "config": {
                "host": host,
                "port": port,
                "user": user,
                "password": password,
                "prefix": prefix,
                "timeout": 5,
                "ssl_ca": "",
                "ssl_cert": "",
                "ssl_key": "",
            },
        }

    def _database_source(self) -> tuple[dict | None, str]:
        if self.database_source_mode_var.get().strip() == "MariaDB server":
            host = self.database_host_var.get().strip() or "?"
            port = self.database_port_var.get().strip() or "3306"
            return None, f"MariaDB server | {host}:{port}"
        info = self._inspect_endpoint("source")
        return info, f"{info['device']} | {info['name']} | {info['identifier']}"

    def _database_config(self, info: dict | None, kind: str) -> dict:
        if self.database_source_mode_var.get().strip() == "MariaDB server":
            return self._direct_database_config(kind)
        if info is None:
            raise TransferError("Kodi source is not available.")

        advanced = self._database_remote_path(info, "userdata/advancedsettings.xml")
        raw = self._database_read_remote_bytes(info, advanced)
        if raw:
            try:
                xml_text = raw.decode("utf-8-sig", errors="replace")
                cfg = kodi_db.parse_advancedsettings(xml_text, kind)
            except Exception as exc:
                raise TransferError(f"Could not parse advancedsettings.xml: {exc}") from exc
            if cfg is not None:
                return {"engine": "mariadb", "config": cfg}

        names = self._database_list_sqlite_files(info)
        try:
            filename = kodi_db.discover_sqlite_filename(names, kind)
        except Exception as exc:
            raise TransferError(str(exc)) from exc
        return {
            "engine": "sqlite",
            "filename": filename,
            "remote_path": self._database_remote_path(info, f"userdata/Database/{filename}"),
        }

    def _database_describe(self, info: dict | None, kind: str) -> dict:
        context = self._database_config(info, kind)
        if context["engine"] == "mariadb":
            try:
                db_name, version = kodi_db.discover_mariadb(context["config"], kind)
            except Exception as exc:
                raise TransferError(f"{kind.title()}DB MariaDB discovery failed: {exc}") from exc
            return {
                **context,
                "database": db_name,
                "schema_version": version,
                "text": (
                    f"MariaDB | {context['config']['host']}:{context['config']['port']} | "
                    f"{db_name} | schema {version}"
                ),
            }

        filename = context["filename"]
        match = re.search(r"(\d+)\.db$", filename, flags=re.IGNORECASE)
        suffix = match.group(1) if match else "?"
        return {
            **context,
            "database": Path(filename).stem,
            "schema_version": int(suffix) if suffix.isdigit() else -1,
            "text": f"SQLite | {filename}",
        }

    def _check_databases(self) -> None:
        self._set_progress(5, "Checking source")
        info, source_text = self._database_source()
        self._set_status("database_source", source_text)
        self.log(f"Database source: {source_text}")
        for idx, kind in enumerate(("music", "video")):
            self._set_progress(25 + idx * 32, f"Checking {kind.title()}DB")
            try:
                db = self._database_describe(info, kind)
                self._set_status(f"{kind}_db", db["text"])
                self.log(f"{kind.title()}DB: {db['text']}")
            except Exception as exc:
                self._set_status(f"{kind}_db", f"Not available: {exc}")
                self.log(f"{kind.title()}DB: not available – {exc}")
        self._set_progress(95, "Database check complete")
        self._set_status("database", "Check complete")

    def _database_backup(self, kind: str) -> None:
        label = "MusicDB" if kind == "music" else "VideoDB"
        self._set_progress(3, "Checking source")
        info, source_text = self._database_source()
        self._set_status("database_source", source_text)
        context = self._database_describe(info, kind)
        self._set_status(f"{kind}_db", context["text"])

        destination = Path(
            normalize_windows_unc_path(
                self.database_backup_dir_var.get().strip() or str(default_database_backup_dir())
            )
        )
        try:
            destination.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            raise TransferError(f"Database backup folder could not be created: {destination}: {exc}") from exc

        self._set_status("database", f"Backing up {label} …")
        self.log(f"{label} backup: {context['text']}")
        if context["engine"] == "mariadb":
            try:
                result = kodi_db.backup_mariadb(
                    kind,
                    context["config"],
                    destination,
                    kodi_version=(info or {}).get("version", ""),
                    source_id=str(context["config"].get("host") or ""),
                    progress=lambda value, text: self._set_progress(value, text),
                    log=self.log,
                )
            except Exception as exc:
                raise TransferError(f"{label} backup failed: {exc}") from exc
        else:
            if info is None:
                raise TransferError("SQLite backup requires a Kodi source device.")
            stopped = False
            try:
                self._set_progress(8, "Stopping Kodi for SQLite snapshot")
                self._database_stop_kodi(info)
                stopped = True
                with tempfile.TemporaryDirectory(prefix=f"jjs-{kind}db-") as td:
                    local_db = Path(td) / context["filename"]
                    self._database_download_remote(info, context["remote_path"], local_db)
                    try:
                        result = kodi_db.backup_sqlite(
                            kind,
                            local_db,
                            context["filename"],
                            destination,
                            kodi_version=info.get("version", ""),
                            source_id=str(info.get("ip") or ""),
                            progress=lambda value, text: self._set_progress(35 + value * 0.62, text),
                            log=self.log,
                        )
                    except Exception as exc:
                        raise TransferError(f"{label} backup failed: {exc}") from exc
            finally:
                if stopped:
                    self._database_start_kodi(info)

        self.database_restore_file_var.set(str(result["path"]))
        self._set_status(
            "database",
            f"Backup complete: {result['engine']} | {result['database']} | schema {result['schema_version']}",
        )
        self.log(f"{label} backup written: {result['path']}")

    def _database_restore(self, kind: str) -> None:
        label = "MusicDB" if kind == "music" else "VideoDB"
        source = Path(normalize_windows_unc_path(self.database_restore_file_var.get().strip()))
        if not source.is_file():
            raise TransferError("Select an existing JJS database backup ZIP first.")

        try:
            manifest, _schema = kodi_db.validate_backup(source, kind)
        except Exception as exc:
            raise TransferError(f"Backup validation failed: {exc}") from exc

        self._set_progress(4, "Checking restore target")
        info, source_text = self._database_source()
        self._set_status("database_source", source_text)
        context = self._database_config(info, kind)
        backup_engine = kodi_db.backup_engine(manifest)
        if backup_engine != context["engine"]:
            raise TransferError(
                f"Backup uses {backup_engine.upper()}, but the configured {label} uses {context['engine'].upper()}."
            )

        backup_db = str(manifest.get("source_database") or "?")
        backup_version = int(manifest.get("schema_version") or -1)

        if context["engine"] == "mariadb":
            try:
                target = kodi_db.resolve_mariadb_restore_target(
                    context["config"], kind, backup_version
                )
            except Exception as exc:
                raise TransferError(f"{label} restore target check failed: {exc}") from exc
            context = {
                **context,
                "database": target["database"],
                "schema_version": target["schema_version"],
                "text": (
                    f"MariaDB | {context['config']['host']}:{context['config']['port']} | "
                    f"{target['database']} | restore schema {backup_version}"
                ),
            }
        else:
            context = self._database_describe(info, kind)

        self._set_status(f"{kind}_db", context["text"])
        if info is None:
            runtime_note = (
                "No Kodi instance is controlled in direct-server mode.\n"
                "Make sure NO Kodi instance is using this MariaDB during the restore."
            )
        else:
            runtime_note = (
                "Kodi on this device will be stopped during the restore.\n"
                "Other Kodi instances must not use the same MariaDB during restore."
            )
        if not self._ask_yes_no(
            f"Restore {label}",
            f"The active {label} will be completely replaced.\n\n"
            f"Backup: {backup_db} | {backup_engine.upper()} | schema {backup_version}\n"
            f"Target: {context['database']} | {context['engine'].upper()}\n\n"
            f"{runtime_note}\n\n"
            "Continue?",
        ):
            raise TransferError("Database restore cancelled.")

        self._set_status("database", f"Restoring {label} …")
        stopped = False
        try:
            if info is not None:
                self._set_progress(8, "Stopping Kodi")
                self._database_stop_kodi(info)
                stopped = True

            if context["engine"] == "mariadb":
                try:
                    result = kodi_db.restore_mariadb(
                        kind,
                        context["config"],
                        source,
                        progress=lambda value, text: self._set_progress(
                            (10 + value * 0.85) if info is not None else value,
                            text,
                        ),
                        log=self.log,
                    )
                except Exception as exc:
                    raise TransferError(f"{label} restore failed: {exc}") from exc
            else:
                if info is None:
                    raise TransferError("SQLite restore requires a Kodi source device.")
                with tempfile.TemporaryDirectory(prefix=f"jjs-{kind}db-restore-") as td:
                    current_db = Path(td) / ("current-" + context["filename"])
                    restored_db = Path(td) / ("restored-" + context["filename"])
                    self._database_download_remote(info, context["remote_path"], current_db)
                    try:
                        result = kodi_db.restore_sqlite(
                            kind,
                            source,
                            current_db,
                            restored_db,
                            progress=lambda value, text: self._set_progress(35 + value * 0.45, text),
                            log=self.log,
                        )
                    except Exception as exc:
                        raise TransferError(f"{label} restore failed: {exc}") from exc
                    self._set_progress(82, "Installing restored SQLite DB")
                    self._database_upload_sqlite(info, restored_db, context["remote_path"])

            skipped_rows = int(result.get("skipped_rows") or 0)
            suffix = f" | WARNING: {skipped_rows} row(s) skipped" if skipped_rows else ""
            self._set_status(
                "database",
                f"Restore complete: {result['engine']} | {context['database']} | "
                f"schema {result['schema_version']}{suffix}",
            )
            if skipped_rows:
                self.log(
                    f"WARNING: {label} restore completed with {skipped_rows} skipped row(s); "
                    "all remaining data and database structure were verified."
                )
            else:
                self.log(f"{label} restore completed and verified.")
        finally:
            if stopped and info is not None:
                cancel_enabled = self._cancel_enabled
                self._cancel_enabled = False
                try:
                    self._set_progress(97, "Restarting Kodi")
                    self._database_start_kodi(info)
                finally:
                    self._cancel_enabled = cancel_enabled

    # ---------- endpoint discovery ----------
    def _profile_display(self, profile: dict) -> str:
        version = profile.get("version", "").strip()
        if version:
            return f"{profile['name']} {version} — {profile['identifier']}"
        return f"{profile['name']} — {profile['identifier']}"

    def _choose_profile(self, role: str, profiles: list[dict]) -> dict:
        if not profiles:
            raise TransferError("No Kodi installation found.")

        mapping = {self._profile_display(p): p for p in profiles}
        self._endpoint_profiles[role] = mapping

        selected_text = str(self._endpoint_vars[role]["profile"].get()).strip()
        if selected_text not in mapping:
            if selected_text:
                for display, profile in mapping.items():
                    if profile["identifier"] == selected_text or display.endswith(" — " + selected_text):
                        selected_text = display
                        break
            if selected_text not in mapping:
                selected_text = next(iter(mapping))

        values = list(mapping.keys())
        if threading.current_thread() is threading.main_thread():
            self._endpoint_widgets[role]["profile"].configure(values=values)
            if role == "source" and "screenshot" in self._endpoint_widgets:
                self._endpoint_widgets["screenshot"]["profile"].configure(values=values)
            if role == "source" and "database" in self._endpoint_widgets:
                self._endpoint_widgets["database"]["profile"].configure(values=values)
            self._endpoint_vars[role]["profile"].set(selected_text)
        else:
            done = threading.Event()
            self._ui_queue.put(("profiles", (role, values, selected_text, done)))
            done.wait()

        return mapping[selected_text]

    def _inspect_android(self, role: str) -> dict:
        ip, port = self._validate_ip_port(role)
        serial, device = self._connect_android(role)
        profiles = self._discover_android_profiles(serial)

        typed = str(self._endpoint_vars[role]["profile"].get()).strip()
        if typed and " — " not in typed and all(p["identifier"] != typed for p in profiles):
            installed = self._adb(serial, "shell", "pm", "path", typed, timeout=15).stdout or ""
            if "package:" in installed:
                root = f"/sdcard/Android/data/{typed}/files/.kodi"
                exists = self._adb(serial, "shell", f"test -d {shlex.quote(root)}").returncode == 0
                profiles.append(
                    {
                        "name": KNOWN_ANDROID_LABELS.get(typed, typed),
                        "identifier": typed,
                        "profile_root": root,
                        "profile_exists": exists,
                        "version": self._android_package_version(serial, typed),
                    }
                )

        profile = self._choose_profile(role, profiles)
        info = {
            "platform": "android",
            "ip": ip,
            "port": port,
            "name": profile["name"],
            "identifier": profile["identifier"],
            "profile_root": profile["profile_root"],
            "profile_exists": profile["profile_exists"],
            "arch": device["arch"],
            "arch_family": arch_family(device["arch"]),
            "version": profile["version"],
            "serial": serial,
            "device": f"{device['manufacturer']} {device['model']}".strip(),
        }
        return info

    def _inspect_libreelec(self, role: str) -> dict:
        ip, port = self._validate_ip_port(role)
        client = self._ssh_client(role)
        try:
            code, os_release, _ = self._ssh_exec(client, "cat /etc/os-release 2>/dev/null", timeout=20)
            if code != 0:
                raise TransferError("The target system could not be identified via SSH.")
            code, arch, _ = self._ssh_exec(client, "uname -m", timeout=20)
            if code != 0:
                raise TransferError("CPU architecture could not be determined.")
            _, version, _ = self._ssh_exec(client, "kodi --version 2>/dev/null | head -1", timeout=20)
            code, _, _ = self._ssh_exec(client, "test -d /storage/.kodi", timeout=20)
            exists = code == 0
        finally:
            client.close()

        if "libreelec" not in os_release.lower():
            self.log("Note: The SSH system does not clearly identify as LibreELEC; /storage/.kodi will still be used.")

        profile = {
            "name": "Kodi",
            "identifier": "/storage/.kodi",
            "profile_root": "/storage/.kodi",
            "profile_exists": exists,
        }
        self._choose_profile(role, [profile])
        return {
            "platform": "libreelec",
            "ip": ip,
            "port": port,
            "name": "Kodi",
            "identifier": "/storage/.kodi",
            "profile_root": "/storage/.kodi",
            "profile_exists": exists,
            "arch": arch.strip(),
            "arch_family": arch_family(arch),
            "version": version.strip(),
            "serial": "",
            "device": "LibreELEC",
        }

    def _inspect_endpoint(self, role: str) -> dict:
        kind = str(self._endpoint_vars[role]["type"].get())
        if kind.startswith("Android"):
            info = self._inspect_android(role)
        else:
            info = self._inspect_libreelec(role)

        label = (
            f"{info['device']} | {info['name']} | {info['identifier']} | "
            f"{info['arch']} | Profile {'present' if info['profile_exists'] else 'not initialized'}"
        )
        self._set_status(role, label)
        self.log(f"{'Source' if role == 'source' else 'Target'}: {label}")
        return info

    def _check_endpoint(self, role: str) -> None:
        self._set_progress(10, f"Checking {role}")
        self._set_status("result", "Check in progress …")
        info = self._inspect_endpoint(role)
        self._set_progress(80, "Device identified")
        if role == "target":
            self._sync_checked_target_to_install(info)
        self._set_progress(95, "Check OK")
        self._set_status("result", "Check OK")

    def _sync_checked_target_to_install(self, info: dict) -> None:
        """Expose a checked Target B immediately in the Install / Update tab."""
        if info["platform"] == "android":
            profiles = self._discover_android_profiles(info["serial"])
            mapping = {self._install_profile_display(p): p for p in profiles}
            self._install_profile_map = mapping

            selected = str(self._endpoint_vars["target"]["profile"].get()).strip()
            if selected not in mapping:
                for display, profile in mapping.items():
                    if profile["identifier"] == info["identifier"]:
                        selected = display
                        break

            done = threading.Event()
            self._ui_queue.put(("install_profiles", (list(mapping.keys()), selected, done)))
            done.wait()
            self._set_status(
                "install_device",
                f"{info['device']} | Android | {info['arch']}",
            )
            if len(profiles) == 1:
                self._set_status("install_kodi", self._install_profile_display(profiles[0]))
            else:
                self._set_status(
                    "install_kodi",
                    f"{len(profiles)} Kodi installations found – selected: {info['name']}",
                )
        else:
            self._install_profile_map = {}
            self._set_status(
                "install_device",
                f"{info['device']} | {info['arch']}",
            )
            self._set_status("install_kodi", info.get("version", "") or "Kodi")
        self._set_status("install", "Target B already checked")

    # ---------- install / update ----------
    def _install_profile_display(self, profile: dict) -> str:
        return self._profile_display(profile)

    def _publish_install_profiles(self, profiles: list[dict]) -> None:
        mapping = {self._install_profile_display(p): p for p in profiles}
        self._install_profile_map = mapping
        current = str(self._endpoint_vars["install"]["profile"].get()).strip()

        if current not in mapping:
            current = next(iter(mapping)) if len(mapping) == 1 else ""

        done = threading.Event()
        self._ui_queue.put(("install_profiles", (list(mapping.keys()), current, done)))
        done.wait()

        if not profiles:
            summary = "No Kodi installation found"
        elif len(profiles) == 1:
            summary = self._install_profile_display(profiles[0])
        else:
            summary = f"{len(profiles)} Kodi installations found – select one for uninstall"
        self._set_status("install_kodi", summary)

    def _inspect_install_device(self) -> dict:
        kind = str(self._endpoint_vars["install"]["type"].get())
        if kind.startswith("Android"):
            ip, port = self._validate_ip_port("install")
            serial, device = self._connect_android("install")
            profiles = self._discover_android_profiles(serial)
            self._publish_install_profiles(profiles)
            info = {
                "platform": "android",
                "ip": ip,
                "port": port,
                "serial": serial,
                "device": f"{device['manufacturer']} {device['model']}".strip(),
                "arch": device["arch"],
                "arch_family": arch_family(device["arch"]),
                "android": device["android"],
                "profiles": profiles,
            }
            label = f"{info['device']} | Android {info['android']} | {info['arch']}"
            self._set_status("install_device", label)
            self.log(f"Install target: {label}")
            return info

        ip, port = self._validate_ip_port("install")
        client = self._ssh_client("install")
        try:
            code, os_release, _ = self._ssh_exec(client, "cat /etc/os-release 2>/dev/null", timeout=20)
            if code != 0 or "libreelec" not in os_release.lower():
                raise TransferError("The SSH target does not identify itself as LibreELEC.")
            code, arch, _ = self._ssh_exec(client, "uname -m", timeout=20)
            if code != 0:
                raise TransferError("CPU architecture could not be determined.")
            _, kodi_version, _ = self._ssh_exec(client, "kodi --version 2>/dev/null | head -1", timeout=20)
            pretty = ""
            m = re.search(r'^PRETTY_NAME=["\']?([^"\'\n]+)', os_release, flags=re.MULTILINE)
            if m:
                pretty = m.group(1).strip()
        finally:
            client.close()

        self._publish_install_profiles([])
        label = f"{pretty or 'LibreELEC'} | {arch.strip()}"
        self._set_status("install_device", label)
        self._set_status("install_kodi", kodi_version.strip() or "Kodi version not reported")
        self.log(f"Install target: {label}")
        return {
            "platform": "libreelec",
            "ip": ip,
            "port": port,
            "device": pretty or "LibreELEC",
            "arch": arch.strip(),
            "arch_family": arch_family(arch),
            "version": kodi_version.strip(),
            "profiles": [],
        }

    def _check_install_target(self) -> None:
        self._set_progress(10, "Checking device")
        self._set_status("install", "Checking device …")
        info = self._inspect_install_device()
        self._set_progress(80, "Device identified")
        self._sync_checked_install_to_target(info)
        self._set_progress(95, "Check OK")
        self._set_status("install", "Check OK")

    def _sync_checked_install_to_target(self, info: dict) -> None:
        """Expose an Install / Update device check immediately as Target B."""
        if info["platform"] == "android":
            profiles = info["profiles"]
            mapping = {self._profile_display(p): p for p in profiles}
            self._endpoint_profiles["target"] = mapping
            selected_install = str(self._endpoint_vars["install"]["profile"].get()).strip()
            selected_identifier = ""
            selected_profile = self._install_profile_map.get(selected_install)
            if selected_profile is not None:
                selected_identifier = selected_profile["identifier"]

            selected_target = ""
            for display, profile in mapping.items():
                if profile["identifier"] == selected_identifier:
                    selected_target = display
                    break
            if not selected_target and len(mapping) == 1:
                selected_target = next(iter(mapping))

            done = threading.Event()
            self._ui_queue.put(("profiles", ("target", list(mapping.keys()), selected_target, done)))
            done.wait()

            target_name = "Kodi"
            if selected_target in mapping:
                target_name = mapping[selected_target]["name"]
            self._set_status(
                "target",
                f"{info['device']} | {target_name} | {info['arch']} | checked via Install / Update",
            )
        else:
            self._endpoint_profiles["target"] = {
                "Kodi — /storage/.kodi": {
                    "name": "Kodi",
                    "identifier": "/storage/.kodi",
                    "profile_root": "/storage/.kodi",
                    "profile_exists": True,
                }
            }
            done = threading.Event()
            self._ui_queue.put(("profiles", ("target", ["Kodi — /storage/.kodi"], "Kodi — /storage/.kodi", done)))
            done.wait()
            self._set_status(
                "target",
                f"{info['device']} | Kodi | /storage/.kodi | {info['arch']} | checked via Install / Update",
            )

    def _selected_install_profile(self) -> dict:
        selected = str(self._endpoint_vars["install"]["profile"].get()).strip()
        profile = self._install_profile_map.get(selected)
        if profile is None:
            raise TransferError("Select the Kodi installation to uninstall.")
        return profile

    def _install_or_update(self) -> None:
        self._set_progress(5, "Checking installation file")
        path = Path(self.install_file_var.get().strip())
        if not path.is_file():
            raise TransferError(f"Installation file not found: {path}")

        self._set_progress(12, "Checking target")
        info = self._inspect_install_device()
        self._set_progress(22, "Target ready")
        if info["platform"] == "android":
            if path.suffix.lower() != ".apk":
                raise TransferError("Android installation requires a local .apk file.")
            self._install_android_apk(path, info)
            return

        if path.suffix.lower() != ".tar":
            raise TransferError("LibreELEC update requires a local .tar file.")
        self._upload_libreelec_update(path, info)

    def _configure_fresh_android_kodi_permissions(
        self,
        serial: str,
        package: str,
        android_version: str,
    ) -> None:
        """Grant Kodi's required Android permissions after a fresh installation."""
        self.log(f"Configuring persistent Android permissions for {package} …")

        failures: list[str] = []

        mic = self._adb(
            serial,
            "shell",
            "pm",
            "grant",
            package,
            "android.permission.RECORD_AUDIO",
            timeout=30,
        )
        if mic.returncode != 0:
            failures.append("Microphone permission could not be granted")

        storage = self._adb(
            serial,
            "shell",
            "appops",
            "set",
            "--uid",
            package,
            "MANAGE_EXTERNAL_STORAGE",
            "allow",
            timeout=30,
        )
        if storage.returncode != 0:
            failures.append('"All files" access could not be enabled')

        # Android 11+ can automatically revoke sensitive runtime permissions when
        # an app is unused for a long period. Disable that behavior for this Kodi
        # package so RECORD_AUDIO remains granted across normal long-term use.
        auto_revoke = self._adb(
            serial,
            "shell",
            "appops",
            "set",
            package,
            "AUTO_REVOKE_PERMISSIONS_IF_UNUSED",
            "ignore",
            timeout=30,
        )
        try:
            android_major = int((android_version or "0").split(".", 1)[0])
        except ValueError:
            android_major = 0

        auto_revoke_ok = auto_revoke.returncode == 0
        if auto_revoke_ok:
            auto_revoke_check = self._adb(
                serial,
                "shell",
                "appops",
                "get",
                package,
                "AUTO_REVOKE_PERMISSIONS_IF_UNUSED",
                timeout=30,
            )
            auto_revoke_text = (auto_revoke_check.stdout or "").lower()
            auto_revoke_ok = (
                auto_revoke_check.returncode == 0
                and "ignore" in auto_revoke_text
            )

        if android_major >= 11 and not auto_revoke_ok:
            failures.append(
                'Android "remove permissions if app is unused" could not be disabled'
            )
        elif not auto_revoke_ok:
            self.log(
                "Note: This Android version/device does not expose "
                "AUTO_REVOKE_PERMISSIONS_IF_UNUSED."
            )

        dump = self._adb(serial, "shell", "dumpsys", "package", package, timeout=30)
        dump_text = dump.stdout or ""
        mic_ok = bool(
            re.search(
                r"android\.permission\.RECORD_AUDIO:.*granted=true",
                dump_text,
            )
        )
        if not mic_ok and "Microphone permission could not be granted" not in failures:
            failures.append("Microphone permission could not be verified")

        storage_check = self._adb(
            serial,
            "shell",
            "appops",
            "get",
            "--uid",
            package,
            "MANAGE_EXTERNAL_STORAGE",
            timeout=30,
        )
        storage_text = (storage_check.stdout or "").lower()
        if storage_check.returncode != 0 or "allow" not in storage_text:
            if '"All files" access could not be enabled' not in failures:
                failures.append('"All files" access could not be verified')

        if failures:
            raise TransferError(
                "Kodi was installed, but Android permission setup is incomplete:\n\n"
                + "\n".join(f"• {item}" for item in failures)
            )

        self.log("Android permissions OK: microphone + all files.")
        if auto_revoke_ok:
            self.log("Android unused-app permission revocation disabled for this Kodi package.")

    def _install_android_apk(self, path: Path, info: dict) -> None:
        before = {p["identifier"]: p for p in info["profiles"]}
        installed_text = "\n".join(
            f"  {p['name']} {p.get('version', '')}  ({p['identifier']})".rstrip()
            for p in info["profiles"]
        ) or "  No Kodi installation currently found."

        if not self._ask_yes_no(
            "Install / update Kodi",
            f"Device:\n{info['device']} ({info['ip']})\n\n"
            f"Local APK:\n{path}\n\n"
            f"Installed Kodi packages:\n{installed_text}\n\n"
            "Android will use the package ID embedded in the APK. "
            "A matching package will be updated; otherwise it will be installed as a new app.\n\n"
            "Continue?",
        ):
            raise TransferError("Installation was cancelled.")

        self._set_progress(30, "Starting Android install")
        self._set_status("install", f"Installing {path.name} …")
        adb = self._find_or_install_adb()
        self._set_progress(38, "Installing APK")
        cp = self._run(
            [str(adb), "-s", info["serial"], "install", "-r", str(path)],
            timeout=None,
        )
        output = (cp.stdout or "").strip()
        if cp.returncode != 0 or "success" not in output.lower():
            if "INSTALL_FAILED_UPDATE_INCOMPATIBLE" in output or "signatures do not match" in output.lower():
                raise TransferError(
                    "Android rejected the update because the APK signature does not match the installed app. "
                    "The existing app was NOT uninstalled."
                )
            raise TransferError(f"APK installation failed.{(' Device: ' + output) if output else ''}")

        self._set_progress(78, "Verifying installation")
        after = self._discover_android_profiles(info["serial"])
        self._publish_install_profiles(after)
        after_map = {p["identifier"]: p for p in after}

        new_packages = [p for package, p in after_map.items() if package not in before]
        changed_packages = [
            p
            for package, p in after_map.items()
            if package in before and p.get("version", "") != before[package].get("version", "")
        ]

        if len(new_packages) == 1:
            p = new_packages[0]
            self._set_progress(88, "Configuring Android permissions")
            self._configure_fresh_android_kodi_permissions(
                info["serial"],
                p["identifier"],
                info.get("android", ""),
            )
            result = f"Installed {p['name']} {p.get('version', '')}".strip()
        elif len(changed_packages) == 1:
            p = changed_packages[0]
            old = before[p["identifier"]].get("version", "")
            new = p.get("version", "")
            result = f"Updated {p['name']} {old} → {new}".strip()
        else:
            result = f"APK installed successfully: {path.name}"

        self._set_progress(96, "Installation verified")
        self.log(result)
        self._set_status("install", result)
        self._ui_queue.put(("message", ("info", APP_TITLE, result)))

    def _uninstall_android_kodi(self) -> None:
        if not str(self._endpoint_vars["install"]["type"].get()).startswith("Android"):
            raise TransferError("Uninstall is available only for Android.")

        self._set_progress(8, "Checking Android device")
        selected_text = str(self._endpoint_vars["install"]["profile"].get()).strip()
        info = self._inspect_install_device()
        if selected_text:
            self._endpoint_vars["install"]["profile"].set(selected_text)
        profile = self._selected_install_profile()

        backup_requested = bool(self.uninstall_backup_var.get())
        backup_note = (
            "A profile backup will be created before uninstalling."
            if backup_requested and profile["profile_exists"]
            else "No profile backup will be created before uninstalling."
        )
        if not self._ask_yes_no(
            "Uninstall Kodi",
            f"Device:\n{info['device']} ({info['ip']})\n\n"
            f"Kodi:\n{profile['name']} {profile.get('version', '')}\n"
            f"Package: {profile['identifier']}\n\n"
            f"{backup_note}\n\n"
            "Android will remove this app and its app data. Continue?",
        ):
            raise TransferError("Uninstall was cancelled.")

        backup_path: Path | None = None
        target = {
            **info,
            "name": profile["name"],
            "identifier": profile["identifier"],
            "profile_root": profile["profile_root"],
            "profile_exists": profile["profile_exists"],
            "version": profile.get("version", ""),
        }

        if backup_requested and profile["profile_exists"]:
            self.log("Creating profile backup before uninstall …")
            backup_path, _ = self._create_backup(
                target,
                "install",
                progress_range=(18, 58),
            )

        self._set_progress(68, f"Uninstalling {profile['name']}")
        self._set_status("install", f"Uninstalling {profile['name']} …")
        cp = self._adb(info["serial"], "uninstall", profile["identifier"], timeout=120)
        output = (cp.stdout or "").strip()
        if cp.returncode != 0 or "success" not in output.lower():
            raise TransferError(f"Android uninstall failed.{(' Device: ' + output) if output else ''}")

        self._set_progress(88, "Verifying uninstall")
        remaining = self._discover_android_profiles(info["serial"])
        self._publish_install_profiles(remaining)
        result = f"Uninstalled {profile['name']} ({profile['identifier']})"
        if backup_path:
            result += f"\n\nProfile backup:\n{backup_path}"
        self.log(result.replace("\n", " | "))
        self._set_status("install", f"Uninstalled {profile['name']}")
        self._ui_queue.put(("message", ("info", APP_TITLE, result)))

    def _upload_libreelec_update(self, path: Path, info: dict) -> None:
        if not self._ask_yes_no(
            "Transfer LibreELEC update",
            f"Target:\n{info['device']} ({info['ip']})\n\n"
            f"Local update TAR:\n{path}\n\n"
            "The TAR will be uploaded to /storage/.update/. "
            "The existing /storage data, including the Kodi profile, is not intentionally removed.\n\n"
            "Continue?",
        ):
            raise TransferError("Update transfer was cancelled.")

        client = self._ssh_client("install")
        remote_final = f"/storage/.update/{path.name}"
        remote_temp = f"/storage/.update/.jjs-upload-{int(time.time())}.tmp"
        sftp = None
        try:
            code, _, err = self._ssh_exec(client, "mkdir -p /storage/.update", timeout=30)
            if code != 0:
                raise TransferError(f"Could not create LibreELEC update folder: {err}")

            self._set_progress(30, "Preparing LibreELEC update")
            self._set_status("install", f"Uploading {path.name} …")
            self.log(f"Uploading update TAR to temporary file: {remote_temp}")
            sftp = client.open_sftp()

            def upload_progress(transferred: int, total: int) -> None:
                self._set_progress_fraction(
                    35,
                    88,
                    transferred,
                    total,
                    "Uploading update",
                )

            sftp.put(str(path), remote_temp, callback=upload_progress)
            self._set_progress(90, "Verifying upload")
            remote_size = sftp.stat(remote_temp).st_size
            local_size = path.stat().st_size
            if remote_size != local_size:
                raise TransferError(
                    f"Uploaded TAR size mismatch: local {local_size} bytes, remote {remote_size} bytes."
                )

            self._set_progress(94, "Activating update")
            command = (
                f"rm -f {shlex.quote(remote_final)} && "
                f"mv {shlex.quote(remote_temp)} {shlex.quote(remote_final)}"
            )
            code, _, err = self._ssh_exec(client, command, timeout=30)
            if code != 0:
                raise TransferError(f"Could not activate LibreELEC update TAR: {err}")
        except Exception:
            try:
                if sftp is not None:
                    sftp.remove(remote_temp)
            except Exception:
                pass
            client.close()
            raise
        finally:
            if sftp is not None:
                try:
                    sftp.close()
                except Exception:
                    pass

        self.log(f"LibreELEC update uploaded: {remote_final}")
        reboot = self._ask_yes_no(
            "LibreELEC update ready",
            f"Update uploaded successfully:\n{remote_final}\n\n"
            "Restart LibreELEC now to install the update?",
        )
        if reboot:
            self.log("$ ssh: systemctl reboot")
            try:
                client.exec_command("systemctl reboot")
                time.sleep(0.5)
            except Exception as e:
                self.log(f"Reboot command sent; connection closed with: {e}")
            self._set_status("install", "Update uploaded – reboot requested")
        else:
            self._set_status("install", "Update uploaded – reboot later to install")
        client.close()

    # ---------- Kodi process handling ----------
    def _is_kodi_running(self, info: dict, role: str) -> bool:
        if info["platform"] == "android":
            out = self._adb(info["serial"], "shell", "pidof", info["identifier"], timeout=15).stdout.strip()
            return bool(out)

        client = self._ssh_client(role)
        try:
            code, out, _ = self._ssh_exec(client, "systemctl is-active kodi", timeout=20)
            return code == 0 and out.strip() == "active"
        finally:
            client.close()

    def _stop_kodi(self, info: dict, role: str) -> None:
        if info["platform"] == "android":
            self._adb(info["serial"], "shell", "am", "force-stop", info["identifier"], timeout=30)
            return
        client = self._ssh_client(role)
        try:
            code, _, _ = self._ssh_exec(client, "systemctl stop kodi", timeout=60)
            if code != 0:
                raise TransferError("Kodi could not be stopped on LibreELEC.")
        finally:
            client.close()

    def _start_kodi(self, info: dict, role: str) -> None:
        if info["platform"] == "android":
            self._adb(
                info["serial"],
                "shell",
                "monkey",
                "-p",
                info["identifier"],
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
                timeout=30,
            )
            return
        client = self._ssh_client(role)
        try:
            code, _, _ = self._ssh_exec(client, "systemctl start kodi", timeout=60)
            if code != 0:
                raise TransferError("Kodi could not be started on LibreELEC.")
        finally:
            client.close()

    def _profile_nonempty(self, info: dict, role: str) -> bool:
        root = shlex.quote(info["profile_root"])
        cmd = f"test -d {root} && test -n \"$(ls -A {root} 2>/dev/null)\""
        if info["platform"] == "android":
            return self._adb(info["serial"], "shell", cmd, timeout=20).returncode == 0
        client = self._ssh_client(role)
        try:
            code, _, _ = self._ssh_exec(client, cmd, timeout=20)
            return code == 0
        finally:
            client.close()

    def _ensure_target_profile(self, info: dict, role: str) -> None:
        root = shlex.quote(info["profile_root"])
        if info["platform"] == "android":
            if not info["profile_exists"]:
                self.log("Initializing the target Kodi installation once …")
                self._start_kodi(info, role)
                time.sleep(3)
                self._stop_kodi(info, role)
            cp = self._adb(info["serial"], "shell", f"mkdir -p {root}", timeout=30)
            if cp.returncode != 0:
                raise TransferError("Target profile directory could not be created on Android.")
            return

        client = self._ssh_client(role)
        try:
            code, _, _ = self._ssh_exec(client, f"mkdir -p {root}", timeout=30)
            if code != 0:
                raise TransferError("Target profile directory could not be created on LibreELEC.")
        finally:
            client.close()

    # ---------- backup ----------
    def _backup_destination(self, info: dict) -> Path:
        root = Path(self.backup_dir_var.get().strip() or str(default_backup_dir()))
        try:
            root.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise TransferError(f"Backup destination folder could not be created: {root}: {e}") from e

        ip = safe_filename_part(info["ip"])
        name = safe_filename_part(info["name"])
        stamp = dt.datetime.now().strftime("%y%m%d-%H%M")
        candidate = root / f"{ip}-{name}-{stamp}.tar"
        n = 2
        while candidate.exists():
            candidate = root / f"{ip}-{name}-{stamp}-{n}.tar"
            n += 1
        return candidate

    def _stream_android_backup(self, info: dict, destination: Path) -> None:
        adb = self._find_or_install_adb()
        cmd = [
            str(adb),
            "-s",
            info["serial"],
            "exec-out",
            "tar",
            "-cf",
            "-",
            "-C",
            info["profile_root"],
            ".",
        ]
        self.log("$ " + subprocess.list2cmdline(cmd[:-1] + ["."]))
        with tempfile.TemporaryFile() as err, destination.open("wb") as out:
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=err,
                    creationflags=CREATE_NO_WINDOW,
                )
                assert proc.stdout is not None
                shutil.copyfileobj(proc.stdout, out, length=4 * 1024 * 1024)
                proc.stdout.close()
                code = proc.wait()
            except Exception as e:
                raise TransferError(f"ADB backup stream failed: {e}") from e
            if code != 0:
                err.seek(0)
                msg = err.read().decode("utf-8", errors="replace").strip()
                raise TransferError(f"TAR backup over ADB failed: {msg or 'Exit Code ' + str(code)}")

    def _stream_ssh_backup(self, info: dict, role: str, destination: Path) -> None:
        client = self._ssh_client(role)
        root = shlex.quote(info["profile_root"])
        try:
            self.log(f"$ ssh: tar -cf - -C {root} .")
            _stdin, stdout, stderr = client.exec_command(f"tar -cf - -C {root} .")
            with destination.open("wb") as out:
                while True:
                    chunk = stdout.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
            code = stdout.channel.recv_exit_status()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            if code != 0:
                raise TransferError(f"TAR backup over SSH failed: {err or 'Exit Code ' + str(code)}")
        finally:
            client.close()

    def _append_metadata(self, path: Path, info: dict) -> None:
        try:
            with tarfile.open(path, "r:") as tf:
                members = tf.getmembers()
                if not members:
                    raise TransferError("Backup TAR is empty.")
                for member in members:
                    validate_tar_path(member.name)
                    if member.issym() or member.islnk():
                        validate_tar_path(member.linkname)
        except TransferError:
            raise
        except Exception as e:
            raise TransferError(f"Generated TAR backup is invalid: {e}") from e

        meta = {
            "format": "JJS-Kodi-Profile-Transfer",
            "format_version": 1,
            "created_local": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
            "source": {
                "platform": info["platform"],
                "ip": info["ip"],
                "name": info["name"],
                "identifier": info["identifier"],
                "profile_root": info["profile_root"],
                "arch": info["arch"],
                "arch_family": info["arch_family"],
                "version": info.get("version", ""),
            },
        }
        data = json.dumps(meta, indent=2, ensure_ascii=False).encode("utf-8")
        ti = tarfile.TarInfo(META_NAME)
        ti.size = len(data)
        ti.mtime = int(time.time())
        ti.mode = 0o644
        with tarfile.open(path, "a:") as tf:
            tf.addfile(ti, io.BytesIO(data))

    def _create_backup(
        self,
        info: dict,
        role: str,
        leave_stopped: bool = False,
        progress_range: tuple[float, float] | None = None,
    ) -> tuple[Path, bool]:
        progress_start, progress_end = progress_range or (15.0, 92.0)

        def progress(fraction: float, text: str) -> None:
            value = progress_start + (progress_end - progress_start) * fraction
            self._set_progress(value, text)

        progress(0.02, "Checking profile")
        if not info["profile_exists"] and not self._profile_nonempty(info, role):
            raise TransferError("The selected Kodi installation does not have a profile to back up yet.")

        destination = self._backup_destination(info)
        progress(0.08, "Preparing backup")
        was_running = self._is_kodi_running(info, role)
        if was_running:
            progress(0.14, "Stopping Kodi")
            self.log(f"Stopping {info['name']} for a consistent backup …")
            self._stop_kodi(info, role)
            time.sleep(1)

        try:
            progress(0.20, "Transferring profile")
            self.log(f"Backing up complete Kodi profile directly to: {destination}")
            if info["platform"] == "android":
                self._stream_android_backup(info, destination)
            else:
                self._stream_ssh_backup(info, role, destination)
            progress(0.88, "Finalizing backup")
            self._append_metadata(destination, info)
        except Exception:
            try:
                if destination.exists():
                    destination.unlink()
            except Exception:
                pass
            if was_running and not leave_stopped:
                try:
                    self._start_kodi(info, role)
                except Exception:
                    pass
            raise

        if was_running and not leave_stopped:
            progress(0.94, "Starting Kodi")
            self._start_kodi(info, role)

        progress(1.0, "Backup complete")
        size_mb = destination.stat().st_size / (1024 * 1024)
        self.log(f"Backup complete: {destination} ({size_mb:.1f} MiB)")
        self._set_status("backup", str(destination))
        return destination, was_running

    # ---------- backup parsing / smart restore ----------
    def _read_backup(self, path: Path) -> tuple[dict | None, bool]:
        if not path.is_file():
            raise TransferError(f"Backup not found: {path}")
        try:
            with tarfile.open(path, "r:") as tf:
                members = tf.getmembers()
                if not members:
                    raise TransferError("Backup TAR is empty.")
                for member in members:
                    validate_tar_path(member.name)
                    if member.issym() or member.islnk():
                        validate_tar_path(member.linkname)

                names = [normalize_tar_name(m.name) for m in members]
                has_wrapped = any(n == ".kodi" or n.startswith(".kodi/") for n in names)
                has_direct = any(n.startswith("userdata/") or n.startswith("addons/") for n in names)
                legacy_wrapped = has_wrapped and not has_direct

                meta = None
                try:
                    member = tf.getmember(META_NAME)
                    f = tf.extractfile(member)
                    if f is not None:
                        meta = json.loads(f.read().decode("utf-8"))
                except KeyError:
                    pass
                except Exception as e:
                    raise TransferError(f"Backup metadata is invalid: {e}") from e
        except TransferError:
            raise
        except Exception as e:
            raise TransferError(f"Backup could not be read: {e}") from e

        return meta, legacy_wrapped

    def _detect_binary_addons(self, tf: tarfile.TarFile, legacy_wrapped: bool) -> set[str]:
        binary: set[str] = set()
        addon_xml_members = []

        for member in tf.getmembers():
            name = normalize_tar_name(member.name, legacy_wrapped)
            parts = PurePosixPath(name).parts
            if len(parts) >= 3 and parts[0] == "addons":
                addon_id = parts[1]
                if member.isfile() and Path(parts[-1]).suffix.lower() in NATIVE_EXTENSIONS:
                    binary.add(addon_id)
                if member.isfile() and parts[-1].lower() == "addon.xml":
                    addon_xml_members.append((addon_id, member))

        for addon_id, member in addon_xml_members:
            if addon_id in binary:
                continue
            try:
                f = tf.extractfile(member)
                if f is None:
                    continue
                data = f.read(1024 * 1024).decode("utf-8", errors="ignore").lower()
            except Exception:
                continue
            if "library_android" in data or "library_linux" in data or "kodi.binary." in data:
                binary.add(addon_id)

        return binary

    def _compatibility_mode(self, meta: dict | None, target: dict) -> tuple[bool, str]:
        if not meta or meta.get("format") != "JJS-Kodi-Profile-Transfer":
            return False, "backup without platform metadata"
        source = meta.get("source", {})
        same_platform = source.get("platform") == target["platform"]
        if same_platform:
            return True, "same platform - full restore"
        return False, (
            f"cross-platform: {source.get('platform', '?')}/{source.get('arch', '?')} "
            f"→ {target['platform']}/{target['arch']}"
        )

    def _member_allowed(
        self,
        member: tarfile.TarInfo,
        target_name: str,
        full_restore: bool,
        binary_addons: set[str],
        target: dict,
    ) -> tuple[bool, str]:
        if not target_name or target_name == META_NAME:
            return False, "metadata/root"

        parts = PurePosixPath(target_name).parts
        if not parts:
            return False, "root"

        if member.ischr() or member.isblk() or member.isfifo():
            return False, "special file"

        if (member.issym() or member.islnk()) and target["platform"] == "android":
            return False, "link not supported on Android"

        if full_restore:
            return True, ""

        if parts[0] == "temp":
            return False, "temporary data"

        if len(parts) >= 2 and parts[0] == "addons" and parts[1] == "packages":
            return False, "addon package cache"

        if len(parts) >= 2 and parts[0] == "addons" and parts[1] in binary_addons:
            return False, "binary addon"

        if (
            len(parts) >= 3
            and parts[0] == "userdata"
            and parts[1] == "addon_data"
            and parts[2] in binary_addons
        ):
            return False, "binary addon settings"

        if len(parts) >= 3 and parts[0] == "userdata" and parts[1] == "Database":
            base = parts[-1].lower()
            if re.fullmatch(r"addons\d+\.db", base):
                return False, "addon database"

        return True, ""

    def _clear_target_profile(self, info: dict, role: str) -> None:
        root = shlex.quote(info["profile_root"])
        cmd = f"rm -rf {root} && mkdir -p {root}"
        if info["platform"] == "android":
            cp = self._adb(info["serial"], "shell", cmd, timeout=120)
            if cp.returncode != 0:
                raise TransferError("Target profile could not be cleared on Android.")
            return
        client = self._ssh_client(role)
        try:
            code, _, _ = self._ssh_exec(client, cmd, timeout=120)
            if code != 0:
                raise TransferError("Target profile could not be cleared on LibreELEC.")
        finally:
            client.close()

    def _build_filtered_restore_archive(
        self,
        backup: Path,
        target: dict,
        full_restore: bool,
        legacy_wrapped: bool,
    ) -> tuple[Path, dict]:
        skipped_binary: set[str] = set()
        skipped_reasons: dict[str, int] = {}

        fd, tmp_name = tempfile.mkstemp(prefix="jjs-kodi-restore-", suffix=".tar")
        os.close(fd)
        temp_path = Path(tmp_name)

        try:
            with tarfile.open(backup, "r:") as src, tarfile.open(temp_path, "w:") as dst:
                binary_addons = set() if full_restore else self._detect_binary_addons(src, legacy_wrapped)
                source_addons: set[str] = set()
                if not full_restore:
                    for item in src.getmembers():
                        item_name = normalize_tar_name(item.name, legacy_wrapped)
                        item_parts = PurePosixPath(item_name).parts
                        if len(item_parts) >= 2 and item_parts[0] == "addons":
                            addon_id = item_parts[1]
                            if addon_id != "packages":
                                source_addons.add(addon_id)
                portable_addons = source_addons - binary_addons

                for member in src.getmembers():
                    target_name = normalize_tar_name(member.name, legacy_wrapped)
                    validate_tar_path(target_name or ".")
                    allowed, reason = self._member_allowed(
                        member,
                        target_name,
                        full_restore,
                        binary_addons,
                        target,
                    )
                    if not allowed:
                        skipped_reasons[reason] = skipped_reasons.get(reason, 0) + 1
                        parts = PurePosixPath(target_name).parts
                        if reason == "binary addon" and len(parts) >= 2:
                            skipped_binary.add(parts[1])
                        continue

                    ti = copy.copy(member)
                    ti.name = target_name
                    fileobj = src.extractfile(member) if member.isfile() else None
                    dst.addfile(ti, fileobj)

            with tarfile.open(temp_path, "r:") as check:
                if not check.getmembers():
                    raise TransferError("Filtered restore archive is empty.")

            return temp_path, {
                "binary_addons": sorted(skipped_binary),
                "portable_addons": sorted(portable_addons),
                "reasons": skipped_reasons,
            }
        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    def _target_exec(
        self,
        info: dict,
        role: str,
        command: str,
        timeout: int = 120,
    ) -> tuple[int, str, str]:
        if info["platform"] == "android":
            cp = self._adb(info["serial"], "shell", command, timeout=timeout)
            return cp.returncode, cp.stdout or "", cp.stderr or ""

        client = self._ssh_client(role)
        try:
            return self._ssh_exec(client, command, timeout=timeout)
        finally:
            client.close()

    def _restore_stage_paths(self, target: dict) -> tuple[str, str, str]:
        root = target["profile_root"]
        return root, root + ".jjs_restore_new", root + ".jjs_restore_old"

    def _prepare_restore_stage(self, target: dict, role: str) -> str:
        root, stage, rollback = self._restore_stage_paths(target)
        qroot = shlex.quote(root)
        qstage = shlex.quote(stage)
        qrollback = shlex.quote(rollback)

        command = (
            f"if [ ! -e {qroot} ] && [ -e {qrollback} ]; then mv {qrollback} {qroot}; fi; "
            f"rm -rf {qstage}; "
            f"if [ -e {qrollback} ]; then rm -rf {qrollback}; fi; "
            f"mkdir -p {qstage}"
        )
        if target["platform"] == "android":
            command += f"; rm -f {shlex.quote(root + '.jjs_restore_payload.tar')}"
        code, _, err = self._target_exec(target, role, command, timeout=120)
        if code != 0:
            raise TransferError(f"Restore staging directory could not be created: {err.strip()}")
        return stage

    def _seed_cross_platform_addon_state(self, target: dict, role: str, stage: str) -> None:
        """Keep the target add-on registry/add-ons/settings, then source portable add-ons overlay them."""
        root = target["profile_root"].rstrip("/")
        stage_root = stage.rstrip("/")

        pairs = (
            ("addons", "addons"),
            ("userdata/addon_data", "userdata/addon_data"),
        )
        commands: list[str] = []
        for source_rel, stage_rel in pairs:
            source_path = f"{root}/{source_rel}"
            stage_path = f"{stage_root}/{stage_rel}"
            commands.append(
                f"if [ -d {shlex.quote(source_path)} ]; then "
                f"mkdir -p {shlex.quote(stage_path)} && "
                f"cp -a {shlex.quote(source_path + '/.')} {shlex.quote(stage_path + '/')}; fi"
            )

        source_db = f"{root}/userdata/Database"
        stage_db = f"{stage_root}/userdata/Database"
        commands.append(
            f"mkdir -p {shlex.quote(stage_db)}; "
            f"for f in {shlex.quote(source_db)}/Addons*.db; do "
            f"if [ -f \"$f\" ]; then cp -a \"$f\" {shlex.quote(stage_db + '/')}; fi; "
            f"done"
        )

        code, _, err = self._target_exec(target, role, "; ".join(commands), timeout=300)
        if code != 0:
            raise TransferError(
                "Existing target add-on state could not be preserved for cross-platform restore: "
                + err.strip()
            )
        self.log("Preserved target Addons*.db, installed add-ons, and add-on settings.")

    def _remove_stage_portable_addons(
        self,
        target: dict,
        role: str,
        stage: str,
        addon_ids: list[str],
    ) -> None:
        """Remove target copies so restored portable source add-ons/settings replace them exactly."""
        if not addon_ids:
            return

        stage_root = stage.rstrip("/")
        for start in range(0, len(addon_ids), 40):
            chunk = addon_ids[start : start + 40]
            paths: list[str] = []
            for addon_id in chunk:
                paths.append(f"{stage_root}/addons/{addon_id}")
                paths.append(f"{stage_root}/userdata/addon_data/{addon_id}")
            command = "rm -rf " + " ".join(shlex.quote(path) for path in paths)
            code, _, err = self._target_exec(target, role, command, timeout=180)
            if code != 0:
                raise TransferError(
                    "Existing portable add-on copies could not be cleared from restore staging: "
                    + err.strip()
                )

    def _cleanup_restore_stage(self, target: dict, role: str) -> None:
        _, stage, _ = self._restore_stage_paths(target)
        self._target_exec(target, role, f"rm -rf {shlex.quote(stage)}", timeout=120)

    def _extract_archive_locally_for_android(
        self,
        archive: Path,
        destination: Path,
    ) -> list[tuple[str, str, str]]:
        """Extract regular files locally and return links to recreate on Android."""
        links: list[tuple[str, str, str]] = []
        try:
            with tarfile.open(archive, "r:") as tf:
                for member in tf.getmembers():
                    validate_tar_path(member.name)
                    if member.issym() or member.islnk():
                        validate_tar_path(member.linkname)

                    name = normalize_tar_name(member.name)
                    if not name or name == META_NAME:
                        continue

                    parts = PurePosixPath(name).parts
                    local_path = destination.joinpath(*parts)

                    if member.isdir():
                        local_path.mkdir(parents=True, exist_ok=True)
                    elif member.isfile():
                        local_path.parent.mkdir(parents=True, exist_ok=True)
                        src = tf.extractfile(member)
                        if src is None:
                            raise TransferError(f"Could not read file from backup: {member.name}")
                        with src, local_path.open("wb") as out:
                            shutil.copyfileobj(src, out, length=4 * 1024 * 1024)
                    elif member.issym():
                        links.append(("symlink", name, member.linkname))
                    elif member.islnk():
                        links.append(("hardlink", name, normalize_tar_name(member.linkname)))
                    else:
                        raise TransferError(f"Unsupported entry in Android restore backup: {member.name}")
        except TransferError:
            raise
        except Exception as e:
            raise TransferError(f"Backup could not be extracted locally for Android restore: {e}") from e

        return links

    def _extract_archive_to_dir(
        self,
        archive: Path,
        target: dict,
        role: str,
        destination_root: str,
        progress_range: tuple[float, float] | None = None,
    ) -> None:
        progress_start, progress_end = progress_range or (45.0, 85.0)
        if target["platform"] == "android":
            adb = self._find_or_install_adb()
            self.log("Extracting restore archive locally on Windows …")

            try:
                with tempfile.TemporaryDirectory(prefix="jjs-kodi-android-restore-") as td:
                    payload = Path(td) / "payload"
                    payload.mkdir(parents=True, exist_ok=True)
                    links = self._extract_archive_locally_for_android(archive, payload)
                    children = sorted(payload.iterdir(), key=lambda p: p.name.lower())

                    if not children and not links:
                        raise TransferError("Restore archive contains no Kodi profile data.")

                    self.log(
                        f"Transferring extracted profile directly to Android staging "
                        f"({len(children)} top-level items) …"
                    )

                    def local_data_size(path: Path) -> int:
                        if path.is_file():
                            return path.stat().st_size
                        total = 0
                        for item in path.rglob("*"):
                            if item.is_file():
                                total += item.stat().st_size
                        return total

                    child_sizes = {child: local_data_size(child) for child in children}
                    total_bytes = sum(child_sizes.values())
                    transferred_bytes = 0
                    remote_root = destination_root.rstrip("/") + "/"
                    for child in children:
                        self._set_progress_fraction(
                            progress_start,
                            progress_end,
                            transferred_bytes,
                            total_bytes,
                            f"Transferring {child.name}",
                        )
                        cp = self._run(
                            [str(adb), "-s", target["serial"], "push", str(child), remote_root],
                            timeout=None,
                        )
                        if cp.returncode != 0:
                            detail = (cp.stdout or "").strip()
                            raise TransferError(
                                f"ADB push failed while transferring {child.name}."
                                + (f" Device: {detail}" if detail else "")
                            )
                        transferred_bytes += child_sizes[child]
                        self._set_progress_fraction(
                            progress_start,
                            progress_end,
                            transferred_bytes,
                            total_bytes,
                            "Transferring profile",
                        )

                    for link_type, name, link_target in links:
                        remote_path = destination_root.rstrip("/") + "/" + name
                        remote_parent = str(PurePosixPath(remote_path).parent)
                        if link_type == "symlink":
                            command = (
                                f"mkdir -p {shlex.quote(remote_parent)}; "
                                f"ln -s {shlex.quote(link_target)} {shlex.quote(remote_path)}"
                            )
                        else:
                            target_path = destination_root.rstrip("/") + "/" + link_target
                            command = (
                                f"mkdir -p {shlex.quote(remote_parent)}; "
                                f"ln {shlex.quote(target_path)} {shlex.quote(remote_path)}"
                            )
                        cp = self._adb(target["serial"], "shell", command, timeout=60)
                        if cp.returncode != 0:
                            detail = (cp.stdout or "").strip()
                            raise TransferError(
                                f"Could not recreate {link_type} from backup: {name}"
                                + (f" Device: {detail}" if detail else "")
                            )
            except TransferError:
                raise
            except Exception as e:
                raise TransferError(f"Direct Android restore transfer failed: {e}") from e

            self.log("Direct Android profile transfer completed.")
            return

        client = self._ssh_client(role)
        root = shlex.quote(destination_root)
        total_bytes = archive.stat().st_size
        transferred_bytes = 0
        try:
            self.log(f"$ ssh: tar -xf - -C {root}")
            stdin, stdout, stderr = client.exec_command(f"tar -xf - -C {root}")
            stream_error: Exception | None = None
            try:
                with archive.open("rb") as src:
                    while True:
                        chunk = src.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        stdin.write(chunk)
                        transferred_bytes += len(chunk)
                        self._set_progress_fraction(
                            progress_start,
                            progress_end,
                            transferred_bytes,
                            total_bytes,
                            "Transferring restore",
                        )
            except Exception as e:
                stream_error = e
            finally:
                try:
                    stdin.close()
                except Exception as e:
                    if stream_error is None:
                        stream_error = e

            code = stdout.channel.recv_exit_status()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            if stream_error is not None:
                raise TransferError(
                    f"Restore stream over SSH failed: {stream_error}"
                    + (f" | Device: {err}" if err else "")
                ) from stream_error
            if code != 0:
                raise TransferError(f"Restore over SSH failed: {err or 'Exit Code ' + str(code)}")
        finally:
            client.close()

    def _validate_restore_stage(self, target: dict, role: str, stage: str) -> None:
        qstage = shlex.quote(stage)
        command = f"test -d {qstage} && test -n \"$(ls -A {qstage} 2>/dev/null)\""
        code, _, err = self._target_exec(target, role, command, timeout=60)
        if code != 0:
            raise TransferError(f"Restore staging directory is empty or invalid: {err.strip()}")

    def _activate_restore_stage(self, target: dict, role: str) -> None:
        root, stage, rollback = self._restore_stage_paths(target)
        qroot = shlex.quote(root)
        qstage = shlex.quote(stage)
        qrollback = shlex.quote(rollback)

        command = (
            f"rm -rf {qrollback}; "
            f"if [ -e {qroot} ]; then mv {qroot} {qrollback} || exit 31; fi; "
            f"if mv {qstage} {qroot}; then exit 0; fi; "
            f"rm -rf {qroot}; "
            f"if [ -e {qrollback} ]; then mv {qrollback} {qroot}; fi; "
            f"exit 32"
        )
        code, _, err = self._target_exec(target, role, command, timeout=120)
        if code != 0:
            raise TransferError(f"Restore profile could not be activated (code {code}): {err.strip()}")

    def _commit_restore_stage(self, target: dict, role: str) -> None:
        _, _, rollback = self._restore_stage_paths(target)
        code, _, err = self._target_exec(
            target,
            role,
            f"rm -rf {shlex.quote(rollback)}",
            timeout=120,
        )
        if code != 0:
            self.log(f"Warning: Temporary rollback profile could not be removed: {err.strip()}")

    def _rollback_restore_stage(self, target: dict, role: str) -> None:
        root, stage, rollback = self._restore_stage_paths(target)
        qroot = shlex.quote(root)
        qstage = shlex.quote(stage)
        qrollback = shlex.quote(rollback)
        command = (
            f"rm -rf {qstage}; "
            f"if [ -e {qrollback} ]; then rm -rf {qroot}; mv {qrollback} {qroot}; fi"
        )
        self._target_exec(target, role, command, timeout=120)

    def _localize_restore_source(self, backup: Path) -> tuple[Path, Path | None]:
        raw = str(backup)
        is_unc = os.name == "nt" and (raw.startswith("\\\\") or raw.startswith("//"))
        if not is_unc:
            return backup, None

        native_source = normalize_windows_unc_path(raw)
        sources = [native_source]
        for candidate in unc_ip_fallback_paths(native_source):
            if candidate not in sources:
                sources.append(candidate)

        fd, tmp_name = tempfile.mkstemp(prefix="jjs-kodi-network-restore-", suffix=".tar")
        os.close(fd)
        temp_path = Path(tmp_name)

        copy_file = ctypes.WinDLL("kernel32", use_last_error=True).CopyFileW
        copy_file.argtypes = (ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_bool)
        copy_file.restype = ctypes.c_bool

        errors: list[str] = []
        try:
            self.log(f"Copying network backup to local temporary storage: {backup}")
            for index, source in enumerate(sources):
                if index == 0:
                    self.log(f"Trying UNC path: {source}")
                else:
                    self.log(f"Retrying UNC path via resolved server IP: {source}")

                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass

                if copy_file(source, str(temp_path), False):
                    copied_size = temp_path.stat().st_size
                    if copied_size <= 0:
                        raise TransferError("The locally copied network backup is empty.")
                    self.log(f"Network backup copied locally ({copied_size} bytes).")
                    return temp_path, temp_path

                error = ctypes.get_last_error()
                win_error = ctypes.WinError(error)
                errors.append(f"{source}: {win_error}")
                self.log(f"Network copy attempt failed: {win_error}")

            raise TransferError(
                "Network backup could not be copied locally. "
                + " | ".join(errors)
            )
        except TransferError:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise
        except Exception as e:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise TransferError(f"Network backup could not be copied locally: {e}") from e

    def _restore_backup(
        self,
        backup: Path,
        target: dict,
        role: str,
        confirm: bool = True,
        display_backup: Path | None = None,
        progress_range: tuple[float, float] | None = None,
    ) -> Path | None:
        progress_start, progress_end = progress_range or (15.0, 94.0)

        def progress(fraction: float, text: str) -> None:
            value = progress_start + (progress_end - progress_start) * fraction
            self._set_progress(value, text)

        def progress_value(fraction: float) -> float:
            return progress_start + (progress_end - progress_start) * fraction

        progress(0.02, "Reading backup")
        shown_backup = display_backup or backup
        meta, legacy_wrapped = self._read_backup(backup)
        full_restore, mode = self._compatibility_mode(meta, target)
        self.log(f"Restore mode: {mode}.")
        if full_restore:
            self.log("Full restore: Platform and architecture are compatible.")
        else:
            self.log(
                "Cross-platform restore: target Addons*.db remains intact; portable source add-ons "
                "and their settings replace/add to the target; hardware-dependent source add-ons are skipped."
            )

        if confirm:
            if not self._ask_yes_no(
                "Confirm restore",
                f"The Kodi profile on\n{target['ip']} – {target['name']}\n"
                f"will be replaced by\n{shown_backup}.\n\nContinue?",
            ):
                raise TransferError("Restore was cancelled.")

        progress(0.08, "Preparing target")
        self._ensure_target_profile(target, role)
        was_running = self._is_kodi_running(target, role)
        safety_path: Path | None = None
        staged = False
        swapped = False
        prepared_archive: Path | None = None
        prepared_is_temp = False
        details = {"binary_addons": [], "portable_addons": [], "reasons": {}}

        try:
            if self.safety_backup_var.get() and self._profile_nonempty(target, role):
                self.log("Creating a safety backup of the existing target profile …")
                safety_path, safety_was_running = self._create_backup(
                    target,
                    role,
                    leave_stopped=True,
                    progress_range=(progress_value(0.10), progress_value(0.34)),
                )
                was_running = was_running or safety_was_running
            elif was_running:
                self._stop_kodi(target, role)
                time.sleep(1)

            progress(0.36, "Preparing restore staging")
            stage = self._prepare_restore_stage(target, role)
            staged = True

            if full_restore and not legacy_wrapped:
                prepared_archive = backup
                self.log("Same-platform restore: restoring the complete profile …")
            else:
                self._seed_cross_platform_addon_state(target, role, stage)
                self.log("Classifying source add-ons for cross-platform restore …")
                prepared_archive, details = self._build_filtered_restore_archive(
                    backup,
                    target,
                    full_restore,
                    legacy_wrapped,
                )
                prepared_is_temp = True
                progress(0.45, "Preparing portable add-ons")
                self._remove_stage_portable_addons(
                    target,
                    role,
                    stage,
                    details["portable_addons"],
                )
                self.log(
                    f"Portable source add-ons to restore: {len(details['portable_addons'])}; "
                    f"hardware-dependent source add-ons skipped: {len(details['binary_addons'])}."
                )

            self._extract_archive_to_dir(
                prepared_archive,
                target,
                role,
                stage,
                progress_range=(progress_value(0.48), progress_value(0.82)),
            )

            progress(0.84, "Validating restored profile")
            # New-format backups contain metadata at archive root. It is useful in the
            # backup file, but must not become part of Kodi's live profile.
            self._target_exec(
                target,
                role,
                f"rm -f {shlex.quote(stage + '/' + META_NAME)}",
                timeout=30,
            )
            self._validate_restore_stage(target, role, stage)

            progress(0.89, "Activating restored profile")
            self.log("Restore transferred completely. Activating new profile …")
            self._activate_restore_stage(target, role)
            swapped = True
            staged = False

            progress(0.94, "Starting Kodi")
            self._start_kodi(target, role)
            time.sleep(3)
            if not self._is_kodi_running(target, role):
                raise TransferError("Kodi did not start with the restored profile.")

            progress(0.98, "Committing restore")
            self._commit_restore_stage(target, role)
            swapped = False
            progress(1.0, "Restore complete")

            if details["binary_addons"]:
                self.log("Not copied (hardware-dependent source add-ons): " + ", ".join(details["binary_addons"]))
            if not full_restore:
                self.log(
                    "Target Addons*.db was retained; Kodi will register any newly added portable add-ons on startup."
                )
            self.log("Keymaps and library nodes were restored with the userdata profile.")

            self._set_status("restore", f"OK – {shown_backup.name} → {target['name']}")
            return safety_path
        except Exception:
            if swapped:
                try:
                    self._stop_kodi(target, role)
                except Exception:
                    pass
                try:
                    self._rollback_restore_stage(target, role)
                    self.log("Restore failed: Previous target profile was rolled back automatically.")
                except Exception as rollback_error:
                    self.log(f"CRITICAL: Automatic rollback failed: {rollback_error}")
            elif staged:
                try:
                    self._cleanup_restore_stage(target, role)
                except Exception:
                    pass

            if was_running:
                try:
                    self._start_kodi(target, role)
                except Exception:
                    pass
            if safety_path:
                self.log(f"Safety backup of the target profile is retained: {safety_path}")
            raise
        finally:
            if prepared_is_temp and prepared_archive is not None:
                try:
                    prepared_archive.unlink(missing_ok=True)
                except Exception:
                    pass

    # ---------- workflows ----------
    def _backup_only(self) -> None:
        self._set_progress(5, "Checking source")
        self._set_status("result", "Backup in progress …")
        source = self._inspect_endpoint("source")
        path, _ = self._create_backup(
            source,
            "source",
            progress_range=(15, 95),
        )
        self.backup_file_var.set(str(path))
        self._save_config()
        self._set_status("result", "SUCCESS – Backup created")
        self._ui_queue.put(("message", ("info", APP_TITLE, f"Backup created:\n\n{path}")))

    def _restore_only(self) -> None:
        self._set_progress(5, "Checking target")
        self._set_status("result", "Restore in progress …")
        backup = Path(self.backup_file_var.get().strip())
        target = self._inspect_endpoint("target")
        self._set_progress(12, "Preparing backup")
        local_backup, temp_copy = self._localize_restore_source(backup)
        try:
            safety = self._restore_backup(
                local_backup,
                target,
                "target",
                confirm=True,
                display_backup=backup,
                progress_range=(15, 96),
            )
        finally:
            if temp_copy is not None:
                try:
                    temp_copy.unlink(missing_ok=True)
                except Exception:
                    pass
        self._set_status("result", "SUCCESS – Restore completed")
        msg = f"Restore completed:\n\n{backup}\n→ {target['ip']} – {target['name']}"
        if safety:
            msg += f"\n\nSafety backup of the previous target profile:\n{safety}"
        self._ui_queue.put(("message", ("info", APP_TITLE, msg)))

    def _same_endpoint(self, a: dict, b: dict) -> bool:
        return (
            a["platform"] == b["platform"]
            and a["ip"] == b["ip"]
            and str(a["identifier"]) == str(b["identifier"])
        )

    def _transfer(self) -> None:
        self._set_progress(4, "Checking source")
        self._set_status("result", "Transfer A → B in progress …")
        source = self._inspect_endpoint("source")
        self._set_progress(8, "Checking target")
        target = self._inspect_endpoint("target")
        if self._same_endpoint(source, target):
            raise TransferError("Source and target are the same Kodi installation.")

        if not self._ask_yes_no(
            "Transfer A → B",
            f"Source:\n{source['ip']} – {source['name']} ({source['identifier']})\n\n"
            f"Target:\n{target['ip']} – {target['name']} ({target['identifier']})\n\n"
            "Create a backup of the source and then transfer it to the target?",
        ):
            raise TransferError("Transfer was cancelled.")

        backup, _ = self._create_backup(
            source,
            "source",
            progress_range=(12, 40),
        )
        self.backup_file_var.set(str(backup))
        self._save_config()
        local_backup, temp_copy = self._localize_restore_source(backup)
        try:
            safety = self._restore_backup(
                local_backup,
                target,
                "target",
                confirm=False,
                display_backup=backup,
                progress_range=(42, 96),
            )
        finally:
            if temp_copy is not None:
                try:
                    temp_copy.unlink(missing_ok=True)
                except Exception:
                    pass

        self._set_status("result", "SUCCESS – Transfer A → B completed")
        msg = (
            f"Transfer completed.\n\n"
            f"Backup:\n{backup}\n\n"
            f"Target:\n{target['ip']} – {target['name']}"
        )
        if safety:
            msg += f"\n\nSafety backup of the previous target profile:\n{safety}"
        self._ui_queue.put(("message", ("info", APP_TITLE, msg)))

    def _on_close(self) -> None:
        if self._busy:
            if self._operation_dialog is not None and self._operation_dialog.winfo_exists():
                self._operation_dialog.lift()
                return
        self._save_config()
        self.destroy()


if __name__ == "__main__":
    TransferApp().mainloop()
