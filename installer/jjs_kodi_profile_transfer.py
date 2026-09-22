#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JJS KODI Profile Backup/Restore, Transfer & Install - Windows GUI.

The tool backs up, restores, and transfers complete Kodi profiles between Android
(ADB) and LibreELEC (SSH). It can also install or update a local Kodi APK on Android,
uninstall a selected Android Kodi package, and stage a local LibreELEC update TAR.

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


APP_TITLE = "JJS KODI Profile Backup/Restore, Transfer & Install"
APP_VERSION = "1.11"
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
    root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "JJSKodiProfileTransfer"
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
        self._progress_bars: list[ttk.Progressbar] = []
        self._log_widgets: list[tk.Text] = []

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

        v = self._endpoint_vars.get("install", {})
        if v:
            cfg["install"] = {
                "type": str(v["type"].get()),
                "ip": str(v["ip"].get()).strip(),
                "port": str(v["port"].get()).strip(),
                "user": str(v["user"].get()).strip(),
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
            text="Manage Kodi profiles and install or update Kodi on Android/ADB and LibreELEC/SSH.",
        ).pack(anchor="w", pady=(2, 10))

        self.adb_dir_var = tk.StringVar(value=str(self._cfg.get("adb_dir", DEFAULT_ADB_DIR)))
        self.backup_dir_var = tk.StringVar(value=str(self._cfg.get("backup_dir", default_backup_dir())))
        self.backup_file_var = tk.StringVar(value=str(self._cfg.get("backup_file", "")))
        self.safety_backup_var = tk.BooleanVar(value=bool(self._cfg.get("safety_backup", True)))
        self.install_file_var = tk.StringVar(value=str(self._cfg.get("install_file", "")))
        self.uninstall_backup_var = tk.BooleanVar(value=bool(self._cfg.get("uninstall_backup", True)))

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        profile_tab = ttk.Frame(notebook, padding=10)
        install_tab = ttk.Frame(notebook, padding=10)
        notebook.add(profile_tab, text="Profile Backup / Restore / Transfer")
        notebook.add(install_tab, text="Kodi Install / Update")

        self._build_profile_tab(profile_tab)
        self._build_install_tab(install_tab)

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
            ("Check source", lambda: self._start_worker(lambda: self._check_endpoint("source"))),
            ("Check target", lambda: self._start_worker(lambda: self._check_endpoint("target"))),
            ("BACKUP", lambda: self._start_worker(self._backup_only)),
            ("RESTORE", lambda: self._start_worker(self._restore_only)),
            ("TRANSFER A → B", lambda: self._start_worker(self._transfer)),
        ):
            b = ttk.Button(actions, text=text, command=fn)
            b.pack(side="left", padx=(0, 8))
            self._action_buttons.append(b)

        self.profile_progress = ttk.Progressbar(actions, mode="indeterminate", length=220)
        self.profile_progress.pack(side="right")
        self._progress_bars.append(self.profile_progress)

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
            command=lambda: self._start_worker(self._check_install_target, "install"),
        )
        self.install_check_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.install_check_button)

        self.install_action_button = ttk.Button(
            actions,
            text="INSTALL / UPDATE",
            command=lambda: self._start_worker(self._install_or_update, "install"),
        )
        self.install_action_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.install_action_button)

        self.uninstall_button = ttk.Button(
            actions,
            text="UNINSTALL",
            command=lambda: self._start_worker(self._uninstall_android_kodi, "install"),
        )
        self.uninstall_button.pack(side="left", padx=(0, 8))
        self._action_buttons.append(self.uninstall_button)

        self.install_progress = ttk.Progressbar(actions, mode="indeterminate", length=220)
        self.install_progress.pack(side="right")
        self._progress_bars.append(self.install_progress)

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

    def _build_install_endpoint(self, frame) -> None:
        saved = self._cfg.get("install", {})
        type_var = tk.StringVar(value=str(saved.get("type", "Android (ADB)")))
        ip_var = tk.StringVar(value=str(saved.get("ip", "")))
        default_port = DEFAULT_ADB_PORT if type_var.get().startswith("Android") else DEFAULT_SSH_PORT
        port_var = tk.StringVar(value=str(saved.get("port", default_port)))
        user_var = tk.StringVar(value=str(saved.get("user", "root")))
        password_var = tk.StringVar(value="")
        profile_var = tk.StringVar(value="")

        self._endpoint_vars["install"] = {
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

        for widget in self._endpoint_widgets["install"]["ssh_rows"]:
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

        self._install_profile_map = {}
        v["profile"].set("")
        self._endpoint_widgets["install"]["profile"].configure(values=())

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
                self.uninstall_button.pack(side="left", padx=(0, 8), before=self.install_progress)
                self.uninstall_backup_check.pack(
                    anchor="w",
                    pady=(0, 8),
                    before=self.install_status_frame,
                )
            else:
                self.uninstall_button.pack_forget()
                self.uninstall_backup_check.pack_forget()

        if hasattr(self, "status_vars"):
            if "install_device" in self.status_vars:
                self.status_vars["install_device"].set("—")
            if "install_kodi" in self.status_vars:
                self.status_vars["install_kodi"].set("—")
            if "install" in self.status_vars:
                self.status_vars["install"].set("—")
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

        for widget in self._endpoint_widgets[role]["ssh_rows"]:
            if is_android:
                widget.grid_remove()
            else:
                widget.grid()

        if not is_android and not str(v["user"].get()).strip():
            v["user"].set("root")
        self._endpoint_profiles[role] = {}

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
                elif kind == "profiles":
                    role, values, selected_text, done = payload
                    try:
                        self._endpoint_widgets[role]["profile"].configure(values=values)
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
                    fn = {
                        "info": messagebox.showinfo,
                        "warning": messagebox.showwarning,
                        "error": messagebox.showerror,
                    }[level]
                    fn(title, msg, parent=self)
        except queue.Empty:
            pass
        self.after(100, self._drain_ui_queue)

    def _apply_busy(self, busy: bool) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for button in self._action_buttons:
            button.configure(state=state)
        for progress in self._progress_bars:
            if busy:
                progress.start(12)
            else:
                progress.stop()
        if not busy:
            self._refresh_install_controls()

    def _start_worker(self, fn, error_status_key: str = "result") -> None:
        if self._busy:
            return
        self._save_config()
        self._ui_queue.put(("busy", True))
        threading.Thread(
            target=self._worker_wrapper,
            args=(fn, error_status_key),
            daemon=True,
        ).start()

    def _worker_wrapper(self, fn, error_status_key: str) -> None:
        try:
            self._prepare_log_file()
            fn()
        except TransferError as e:
            self.log(f"ERROR: {e}")
            if error_status_key in self.status_vars:
                self._set_status(error_status_key, f"ERROR: {e}")
            self._ui_queue.put(("message", ("error", APP_TITLE, str(e))))
        except Exception as e:
            self.log(f"UNEXPECTED ERROR: {type(e).__name__}: {e}")
            if error_status_key in self.status_vars:
                self._set_status(error_status_key, f"ERROR: {type(e).__name__}: {e}")
            self._ui_queue.put(
                ("message", ("error", APP_TITLE, f"Unexpected error:\n\n{type(e).__name__}: {e}"))
            )
        finally:
            self._ui_queue.put(("busy", False))

    def _prepare_log_file(self) -> None:
        root = app_root() / "Logs"
        root.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self._log_file = root / f"profile-transfer-{stamp}.log"
        self.log(f"{APP_TITLE} {APP_VERSION}")

    def _ask_yes_no(self, title: str, message: str) -> bool:
        done = threading.Event()
        answer = {"value": False}

        def ask() -> None:
            try:
                answer["value"] = bool(messagebox.askyesno(title, message, parent=self))
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

    # ---------- endpoint discovery ----------
    def _profile_display(self, profile: dict) -> str:
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
        self._set_status("result", "Check in progress …")
        self._inspect_endpoint(role)
        self._set_status("result", "Check OK")

    # ---------- install / update ----------
    def _install_profile_display(self, profile: dict) -> str:
        version = profile.get("version", "").strip()
        if version:
            return f"{profile['name']} {version} — {profile['identifier']}"
        return f"{profile['name']} — {profile['identifier']}"

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
        self._set_status("install", "Checking device …")
        self._inspect_install_device()
        self._set_status("install", "Check OK")

    def _selected_install_profile(self) -> dict:
        selected = str(self._endpoint_vars["install"]["profile"].get()).strip()
        profile = self._install_profile_map.get(selected)
        if profile is None:
            raise TransferError("Select the Kodi installation to uninstall.")
        return profile

    def _install_or_update(self) -> None:
        path = Path(self.install_file_var.get().strip())
        if not path.is_file():
            raise TransferError(f"Installation file not found: {path}")

        info = self._inspect_install_device()
        if info["platform"] == "android":
            if path.suffix.lower() != ".apk":
                raise TransferError("Android installation requires a local .apk file.")
            self._install_android_apk(path, info)
            return

        if path.suffix.lower() != ".tar":
            raise TransferError("LibreELEC update requires a local .tar file.")
        self._upload_libreelec_update(path, info)

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

        self._set_status("install", f"Installing {path.name} …")
        adb = self._find_or_install_adb()
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
            result = f"Installed {p['name']} {p.get('version', '')}".strip()
        elif len(changed_packages) == 1:
            p = changed_packages[0]
            old = before[p["identifier"]].get("version", "")
            new = p.get("version", "")
            result = f"Updated {p['name']} {old} → {new}".strip()
        else:
            result = f"APK installed successfully: {path.name}"

        self.log(result)
        self._set_status("install", result)
        self._ui_queue.put(("message", ("info", APP_TITLE, result)))

    def _uninstall_android_kodi(self) -> None:
        if not str(self._endpoint_vars["install"]["type"].get()).startswith("Android"):
            raise TransferError("Uninstall is available only for Android.")

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
            backup_path, _ = self._create_backup(target, "install")

        self._set_status("install", f"Uninstalling {profile['name']} …")
        cp = self._adb(info["serial"], "uninstall", profile["identifier"], timeout=120)
        output = (cp.stdout or "").strip()
        if cp.returncode != 0 or "success" not in output.lower():
            raise TransferError(f"Android uninstall failed.{(' Device: ' + output) if output else ''}")

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

            self._set_status("install", f"Uploading {path.name} …")
            self.log(f"Uploading update TAR to temporary file: {remote_temp}")
            sftp = client.open_sftp()
            sftp.put(str(path), remote_temp)
            remote_size = sftp.stat(remote_temp).st_size
            local_size = path.stat().st_size
            if remote_size != local_size:
                raise TransferError(
                    f"Uploaded TAR size mismatch: local {local_size} bytes, remote {remote_size} bytes."
                )

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

    def _create_backup(self, info: dict, role: str, leave_stopped: bool = False) -> tuple[Path, bool]:
        if not info["profile_exists"] and not self._profile_nonempty(info, role):
            raise TransferError("The selected Kodi installation does not have a profile to back up yet.")

        destination = self._backup_destination(info)
        was_running = self._is_kodi_running(info, role)
        if was_running:
            self.log(f"Stopping {info['name']} for a consistent backup …")
            self._stop_kodi(info, role)
            time.sleep(1)

        try:
            self.log(f"Backing up complete Kodi profile directly to: {destination}")
            if info["platform"] == "android":
                self._stream_android_backup(info, destination)
            else:
                self._stream_ssh_backup(info, role, destination)
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
            self._start_kodi(info, role)

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
    ) -> None:
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
                    remote_root = destination_root.rstrip("/") + "/"
                    for child in children:
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
    ) -> Path | None:
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
                safety_path, safety_was_running = self._create_backup(target, role, leave_stopped=True)
                was_running = was_running or safety_was_running
            elif was_running:
                self._stop_kodi(target, role)
                time.sleep(1)

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

            self._extract_archive_to_dir(prepared_archive, target, role, stage)

            # New-format backups contain metadata at archive root. It is useful in the
            # backup file, but must not become part of Kodi's live profile.
            self._target_exec(
                target,
                role,
                f"rm -f {shlex.quote(stage + '/' + META_NAME)}",
                timeout=30,
            )
            self._validate_restore_stage(target, role, stage)

            self.log("Restore transferred completely. Activating new profile …")
            self._activate_restore_stage(target, role)
            swapped = True
            staged = False

            self._start_kodi(target, role)
            time.sleep(3)
            if not self._is_kodi_running(target, role):
                raise TransferError("Kodi did not start with the restored profile.")

            self._commit_restore_stage(target, role)
            swapped = False

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
        self._set_status("result", "Backup in progress …")
        source = self._inspect_endpoint("source")
        path, _ = self._create_backup(source, "source")
        self.backup_file_var.set(str(path))
        self._save_config()
        self._set_status("result", "SUCCESS – Backup created")
        self._ui_queue.put(("message", ("info", APP_TITLE, f"Backup created:\n\n{path}")))

    def _restore_only(self) -> None:
        self._set_status("result", "Restore in progress …")
        backup = Path(self.backup_file_var.get().strip())
        target = self._inspect_endpoint("target")
        local_backup, temp_copy = self._localize_restore_source(backup)
        try:
            safety = self._restore_backup(
                local_backup,
                target,
                "target",
                confirm=True,
                display_backup=backup,
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
        self._set_status("result", "Transfer A → B in progress …")
        source = self._inspect_endpoint("source")
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

        backup, _ = self._create_backup(source, "source")
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
            if not messagebox.askyesno(APP_TITLE, "An operation is currently running. Close the window anyway?", parent=self):
                return
        self._save_config()
        self.destroy()


if __name__ == "__main__":
    TransferApp().mainloop()
