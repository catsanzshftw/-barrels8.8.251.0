#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BarrelsClient — Single File (MVP)
---------------------------------
A clean, minimal Minecraft launcher UI in one file.
- Dark theme Tkinter UI
- Version list refresh via minecraft-launcher-lib (if present) or Mojang manifest
- Offline auth (username)
- Optional Adoptium JRE 17 download (OS/arch aware)
- Resumable downloader + SHA1 verification
- Launch selected version (minecraft-launcher-lib required for launch)

License: MIT
"""

import os, sys, platform, subprocess, threading, queue, time, json, shutil, zipfile, tarfile, hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception as e:
    print("Tkinter is required to run this UI.", e)
    sys.exit(1)

try:
    import requests
except Exception:
    requests = None

# Optional: minecraft-launcher-lib
try:
    import minecraft_launcher_lib as mll
except Exception:
    mll = None

# ---------------------------- Constants --------------------------------

THEME = {
    "bg": "#161616",
    "panel": "#1f1f1f",
    "fg": "#eaeaea",
    "muted": "#b0b0b0",
    "accent": "#6A1B9A"
}

VERSION_MANIFEST_URL = "https://piston-meta.mojang.com/mc/game/version_manifest.json"

APP_NAME = "BarrelsClient (Single File)"
DEFAULT_DIR = os.path.join(os.path.expanduser("~"), ".minecraft")
MANAGED_DIR = os.path.join(DEFAULT_DIR, "barrelsclient")
JAVA_DIR = os.path.join(MANAGED_DIR, "java")
VERSIONS_DIR = os.path.join(DEFAULT_DIR, "versions")
ASSETS_DIR = os.path.join(DEFAULT_DIR, "assets")

os.makedirs(MANAGED_DIR, exist_ok=True)
os.makedirs(JAVA_DIR, exist_ok=True)

# ---------------------------- Helpers ----------------------------------

def log(ts=True, *parts):
    s = " ".join(str(p) for p in parts)
    if ts:
        t = time.strftime("%H:%M:%S")
        print(f"[{t}] {s}")
    else:
        print(s)

def sha1sum(path: str) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ensure_requests():
    if requests is None:
        raise RuntimeError("The 'requests' package is required. Try: pip install requests")

# --------------------- Resumable Downloader ----------------------------

class Downloader:
    def __init__(self, session=None):
        self.session = session or (requests and requests.Session())

    def get(self, url, **kwargs):
        ensure_requests()
        return self.session.get(url, **kwargs)

    def head(self, url, **kwargs):
        ensure_requests()
        return self.session.head(url, **kwargs)

    def download(self, url: str, dest: str, expected_sha1: Optional[str] = None, progress_cb=None) -> str:
        """
        Resumable HTTP download with Range support and optional SHA1 verify.
        Returns dest path.
        """
        ensure_requests()
        os.makedirs(os.path.dirname(dest), exist_ok=True)

        temp = dest + ".part"
        mode = "ab" if os.path.exists(temp) else "wb"
        resume_pos = os.path.getsize(temp) if os.path.exists(temp) else 0

        headers = {}
        if resume_pos > 0:
            headers["Range"] = f"bytes={resume_pos}-"

        with self.session.get(url, stream=True, headers=headers, timeout=30) as r:
            r.raise_for_status()
            total = int(r.headers.get("Content-Length", "0"))
            # If ranged, try to estimate full size
            if "Content-Range" in r.headers:
                cr = r.headers["Content-Range"]
                # Content-Range: bytes start-end/total
                try:
                    total = int(cr.split("/")[-1])
                except Exception:
                    pass

            done = resume_pos
            chunk_size = 1024 * 256
            with open(temp, mode) as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if not chunk:
                        continue
                    f.write(chunk)
                    done += len(chunk)
                    if progress_cb and total:
                        progress_cb(done, total)

        # Move temp into place
        if os.path.exists(dest):
            os.remove(dest)
        os.rename(temp, dest)

        if expected_sha1:
            actual = sha1sum(dest)
            if actual != expected_sha1:
                raise RuntimeError(f"SHA1 mismatch for {dest}: {actual} != {expected_sha1}")
        return dest

# ----------------------- Adoptium Java Manager -------------------------

def detect_system_java() -> Optional[str]:
    try:
        out = subprocess.run(["java", "-version"], capture_output=True, text=True)
        if out.returncode == 0:
            return "java"
    except Exception:
        return None
    return None

def current_os_arch() -> Tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system.startswith("darwin"):
        os_name = "mac"
    elif system.startswith("windows"):
        os_name = "windows"
    else:
        os_name = "linux"

    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif "aarch64" in machine or "arm64" in machine:
        arch = "aarch64"
    else:
        arch = "x64"
    return os_name, arch

def adoptium_asset(os_name: str, arch: str) -> Dict[str, Any]:
    """
    Query Adoptium API for latest JRE 17 hotspot build for this OS/arch.
    """
    ensure_requests()
    img = "zip" if os_name == "windows" else "tar.gz"
    url = f"https://api.adoptium.net/v3/assets/latest/17/hotspot"
    params = {
        "image_type": "jre",
        "architecture": arch,
        "os": "mac" if os_name == "mac" else os_name,
        "vendor": "eclipse",
        "heap_size": "normal",
        "jvm_impl": "hotspot",
    }
    r = requests.get(url, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    if not data:
        raise RuntimeError("No Adoptium assets found for this platform.")
    asset = data[0]  # latest
    # Extract download info
    binary = asset.get("binary", {})
    pkg = binary.get("package", {})
    dl = {
        "link": pkg.get("link"),
        "checksum": pkg.get("checksum"),  # sha256 in text file; we'll skip strict verify
        "name": pkg.get("name"),
    }
    return dl

def extract_archive(archive_path: str, dest_dir: str) -> str:
    os.makedirs(dest_dir, exist_ok=True)
    base = None
    if archive_path.endswith(".zip"):
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(dest_dir)
            # infer base dir
            tops = set(p.split("/")[0] for p in z.namelist() if "/" in p)
            base = sorted(list(tops))[0] if tops else dest_dir
    elif archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(dest_dir)
            tops = set(p.split("/")[0] for p in t.getnames() if "/" in p)
            base = sorted(list(tops))[0] if tops else dest_dir
    else:
        raise RuntimeError("Unsupported archive format: " + archive_path)
    return os.path.join(dest_dir, base or "")

def ensure_managed_java(progress_cb=None) -> str:
    """
    Ensure we have a managed JRE installed. Returns java executable path.
    """
    os_name, arch = current_os_arch()
    target_root = os.path.join(JAVA_DIR, f"jre17-{os_name}-{arch}")
    java_bin = os.path.join(target_root, "bin", "java.exe" if os_name == "windows" else "java")
    if os.path.exists(java_bin):
        return java_bin

    dl_info = adoptium_asset(os_name, arch)
    url = dl_info["link"]
    fname = os.path.join(MANAGED_DIR, dl_info.get("name") or os.path.basename(url).split("?")[0])
    d = Downloader()
    def _cb(done, total):
        if progress_cb:
            progress_cb(done, total)
    log(True, "Downloading Adoptium JRE 17:", url)
    d.download(url, fname, expected_sha1=None, progress_cb=_cb)
    log(True, "Extracting:", fname)
    extracted = extract_archive(fname, target_root)
    # If extracted path isn't exactly our root, move contents up
    if extracted != target_root and os.path.isdir(extracted):
        for item in os.listdir(extracted):
            shutil.move(os.path.join(extracted, item), target_root)
        shutil.rmtree(extracted, ignore_errors=True)
    log(True, "Java ready at:", java_bin)
    return java_bin

# ----------------------- Version Manifest ------------------------------

def fetch_version_manifest() -> Dict[str, Any]:
    ensure_requests()
    r = requests.get(VERSION_MANIFEST_URL, timeout=30)
    r.raise_for_status()
    return r.json()

def list_versions() -> list:
    if mll:
        try:
            return [v["id"] for v in mll.utils.get_version_list()]
        except Exception:
            pass
    # Fallback: direct manifest
    data = fetch_version_manifest()
    return [v["id"] for v in data.get("versions", [])]

# --------------------------- Launcher ----------------------------------

def launch_offline(username: str, version: str, java_path: Optional[str], log_func=log):
    if not mll:
        raise RuntimeError("minecraft-launcher-lib not installed. Install with: pip install minecraft-launcher-lib")

    game_dir = DEFAULT_DIR
    opts = {
        "username": username or "Player",
        "uuid": "00000000-0000-0000-0000-000000000000",
        "token": "",
        "jvmArguments": ["-Xmx2G"],
        "gameDirectory": game_dir,
    }

    # Ensure Java
    jpath = java_path or detect_system_java() or ensure_managed_java()
    log_func(True, "Using Java:", jpath)

    callback = {
        "setStatus": lambda s: log_func(True, s),
        "setProgress": lambda p: None,
        "setMax": lambda m: None,
    }

    # Install/prepare the version if needed
    log_func(True, f"Preparing {version} ...")
    mll.install.install_minecraft_version(version, game_dir, callback=callback)

    # Build command
    log_func(True, "Building command ...")
    cmd = mll.command.get_minecraft_command(version, game_dir, opts)
    if jpath and jpath != "java":
        cmd = [jpath] + cmd[1:]  # replace java executable

    log_func(True, "Launching Minecraft...")
    subprocess.Popen(cmd, cwd=game_dir)
    log_func(True, "Process started. You can close this window.")

# ----------------------------- UI -------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("900x600")
        self.configure(bg=THEME["bg"])
        self.resizable(True, True)

        self.username_var = tk.StringVar(value="Player")
        self.java_path_var = tk.StringVar(value="(auto)")
        self.version_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready.")
        self.progress_var = tk.DoubleVar(value=0.0)

        self._make_style()
        self._build_ui()
        self._log_queue = queue.Queue()
        self.after(100, self._drain_log_queue)

        self._thread = None
        self.refresh_versions()

    def _make_style(self):
        style = ttk.Style()
        # On some platforms, "clam" looks clean
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=THEME["bg"], foreground=THEME["fg"])
        style.configure("TLabel", background=THEME["bg"], foreground=THEME["fg"])
        style.configure("TButton", background=THEME["panel"], foreground=THEME["fg"])
        style.configure("Accent.TButton", background=THEME["accent"], foreground="white")
        style.configure("TEntry", fieldbackground=THEME["panel"], foreground=THEME["fg"])
        style.configure("Horizontal.TProgressbar", troughcolor=THEME["panel"], background=THEME["accent"])

    def _build_ui(self):
        top = ttk.Frame(self); top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Username").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.username_var, width=20).grid(row=0, column=1, sticky="w", padx=6)

        ttk.Label(top, text="Java").grid(row=0, column=2, sticky="e", padx=(20, 0))
        ttk.Entry(top, textvariable=self.java_path_var, width=40).grid(row=0, column=3, sticky="we", padx=6)
        ttk.Button(top, text="Browse...", command=self.choose_java).grid(row=0, column=4, padx=4)
        ttk.Button(top, text="Install JRE 17", style="Accent.TButton", command=self.install_java).grid(row=0, column=5, padx=4)

        top.grid_columnconfigure(3, weight=1)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=12, pady=(0,10))
        left = ttk.Frame(mid); left.pack(side="left", fill="y")
        right = ttk.Frame(mid); right.pack(side="right", fill="both", expand=True)

        ttk.Label(left, text="Versions").pack(anchor="w")
        self.versions_list = tk.Listbox(left, height=20, bg=THEME["panel"], fg=THEME["fg"])
        self.versions_list.pack(fill="y", expand=False)
        btns = ttk.Frame(left); btns.pack(fill="x", pady=6)
        ttk.Button(btns, text="Refresh", command=self.refresh_versions).pack(side="left")
        ttk.Button(btns, text="Launch", style="Accent.TButton", command=self.launch).pack(side="right")

        ttk.Label(right, text="Log").pack(anchor="w")
        self.log_text = tk.Text(right, height=20, bg=THEME["panel"], fg=THEME["fg"], insertbackground=THEME["fg"])
        self.log_text.pack(fill="both", expand=True)

        bottom = ttk.Frame(self); bottom.pack(fill="x", padx=12, pady=(0,12))
        self.status_label = ttk.Label(bottom, textvariable=self.status_var)
        self.status_label.pack(side="left")
        self.progress = ttk.Progressbar(bottom, orient="horizontal", variable=self.progress_var, mode="determinate")
        self.progress.pack(side="right", fill="x", expand=True, padx=(12,0))

    def _drain_log_queue(self):
        try:
            while True:
                line = self._log_queue.get_nowait()
                self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain_log_queue)

    def _log(self, *parts):
        s = " ".join(str(p) for p in parts)
        t = time.strftime("%H:%M:%S")
        self._log_queue.put(f"[{t}] {s}")
        self.status_var.set(parts[-1] if parts else "")

    def _set_progress(self, done, total):
        try:
            self.progress_var.set((done / max(1,total)) * 100.0)
        except Exception:
            pass

    def choose_java(self):
        path = filedialog.askopenfilename(title="Select Java executable")
        if path:
            self.java_path_var.set(path)

    def install_java(self):
        if self._thread and self._thread.is_alive():
            messagebox.showinfo(APP_NAME, "Another task is running.")
            return
        def worker():
            try:
                self._log("Resolving Adoptium JRE 17...")
                java_path = ensure_managed_java(progress_cb=self._set_progress)
                self.java_path_var.set(java_path)
                self._log("Java installed at", java_path)
            except Exception as e:
                self._log("Java install failed:", repr(e))
                messagebox.showerror(APP_NAME, f"Java install failed:\n{e}")
            finally:
                self.progress_var.set(0.0)
        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def refresh_versions(self):
        if self._thread and self._thread.is_alive():
            messagebox.showinfo(APP_NAME, "Another task is running.")
            return
        def worker():
            try:
                self._log("Refreshing version list...")
                versions = list_versions()
                self.versions_list.delete(0, "end")
                for vid in versions:
                    self.versions_list.insert("end", vid)
                self._log(f"Found {len(versions)} versions.")
            except Exception as e:
                self._log("Version refresh failed:", repr(e))
                messagebox.showerror(APP_NAME, f"Failed to load versions:\n{e}")
        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def selected_version(self) -> Optional[str]:
        try:
            idx = self.versions_list.curselection()
            if not idx:
                return None
            return self.versions_list.get(idx[0])
        except Exception:
            return None

    def launch(self):
        version = self.selected_version()
        if not version:
            messagebox.showinfo(APP_NAME, "Pick a version first.")
            return
        username = self.username_var.get().strip() or "Player"
        java_path = None if self.java_path_var.get().strip() in ("", "(auto)") else self.java_path_var.get().strip()

        if self._thread and self._thread.is_alive():
            messagebox.showinfo(APP_NAME, "Another task is running.")
            return

        def worker():
            try:
                self._log("Launching", version, "for", username, "...")
                launch_offline(username, version, java_path, log_func=self._log)
                self._log("Launch command executed.")
            except Exception as e:
                self._log("Launch failed:", repr(e))
                messagebox.showerror(APP_NAME, f"Launch failed:\n{e}")
        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

def main():
    app = App()
    # Prefill Java path if detected
    j = detect_system_java()
    if j:
        app.java_path_var.set(j)
    app.mainloop()

if __name__ == "__main__":
    main()
