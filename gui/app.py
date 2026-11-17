"""
BruteForce Attack Detector - Premium Cyberpunk Desktop Application
Academic DSA Demonstration Project (C Core Backend + Python Tkinter GUI)
Version: 2.0 (Redesigned Authentication & Premium Cyberpunk UI)

Features:
  - Dedicated Authentication Flow (Login & Registration)
  - Salted PBKDF2-HMAC-SHA256 password security (stored in database/users.txt)
  - Active Route-Based Local IP Detection & Public IP Lookup
  - Pure C Backend Source of Truth for Queue (FIFO), Stack (LIFO), and Detection
  - Premium Cyberpunk UI with restrained accents and modern typography
"""

import os
import sys
import json
import time
import socket
import secrets
import hashlib
import urllib.request
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

# ==============================================================================
# DESIGN SYSTEM: PREMIUM CYBERPUNK PALETTE & TYPOGRAPHY
# ==============================================================================
THEME = {
    "bg_root": "#0B0D13",        # Deep near-black charcoal
    "bg_surface": "#131622",     # Secondary container & panel surface
    "bg_card": "#181C2C",        # Metric cards & elevated elements
    "bg_input": "#0F121D",       # Form input fields
    "border": "#23283E",         # Subtle crisp border
    "border_focus": "#00E5FF",   # Primary accent border highlight
    "cyan": "#00E5FF",           # Muted electric cyan (Primary accent)
    "violet": "#8B5CF6",         # Subtle violet (Secondary accent)
    "alert": "#EF4444",          # Restrained alert red/pink
    "alert_bg": "#2A1117",       # Alert container surface
    "success": "#10B981",        # Clean emerald green
    "success_bg": "#0D241E",     # Success container surface
    "warning": "#F59E0B",        # Amber warning
    "text_primary": "#F1F5F9",   # Crisp readable white
    "text_secondary": "#94A3B8", # Clean slate secondary
    "text_dim": "#64748B",       # Subtle metadata / labels
    "font_ui": "Segoe UI",       # Modern clean UI font
    "font_mono": "Consolas",     # Monospaced font for technical data
}

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(BASE_DIR, "src")
DB_DIR = os.path.join(BASE_DIR, "database")
USERS_FILE = os.path.join(DB_DIR, "users.txt")
LOGIN_DB_FILE = os.path.join(DB_DIR, "login_database.txt")
EXE_NAME = "bruteforce_detector.exe" if os.name == "nt" else "bruteforce_detector"
EXE_PATH = os.path.join(BASE_DIR, EXE_NAME)


# ==============================================================================
# 1. USER AUTHENTICATION & CREDENTIAL MANAGEMENT (database/users.txt)
# Salted PBKDF2-HMAC-SHA256 (100,000 iterations, 16-byte individual salt)
# ==============================================================================
class UserManager:
    """Manages user registration and password hashing."""

    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple[str, str]:
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return salt.hex(), key.hex()

    @staticmethod
    def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
        try:
            salt = bytes.fromhex(salt_hex)
            key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
            return secrets.compare_digest(key.hex(), hash_hex)
        except Exception:
            return False

    @classmethod
    def ensure_storage(cls):
        os.makedirs(DB_DIR, exist_ok=True)
        if not os.path.isfile(USERS_FILE) or os.path.getsize(USERS_FILE) == 0:
            # Pre-populate default demo accounts so existing viva test credentials work
            defaults = [
                ("admin", "System Administrator", "cyber2026!"),
                ("advait", "Advait Sharma", "matrix99"),
                ("student", "DSA Student", "dsa123"),
            ]
            with open(USERS_FILE, "w", encoding="utf-8") as f:
                for uname, fname, pwd in defaults:
                    salt, phash = cls.hash_password(pwd)
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"Username: {uname}\n")
                    f.write(f"FullName: {fname}\n")
                    f.write(f"Salt: {salt}\n")
                    f.write(f"PasswordHash: {phash}\n")
                    f.write(f"CreatedAt: {now_str}\n")
                    f.write("--------------------------------\n")

    @classmethod
    def load_users(cls) -> dict:
        cls.ensure_storage()
        users = {}
        if not os.path.isfile(USERS_FILE):
            return users

        current = {}
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Username: "):
                    current["username"] = line[10:].strip()
                elif line.startswith("FullName: "):
                    current["fullname"] = line[10:].strip()
                elif line.startswith("Salt: "):
                    current["salt"] = line[6:].strip()
                elif line.startswith("PasswordHash: "):
                    current["hash"] = line[14:].strip()
                elif line.startswith("CreatedAt: "):
                    current["created_at"] = line[11:].strip()
                elif line.startswith("--------------------------------"):
                    if "username" in current and "hash" in current:
                        users[current["username"].lower()] = current
                    current = {}
        return users

    @classmethod
    def register_user(cls, full_name: str, username: str, password: str) -> tuple[bool, str]:
        full_name = full_name.strip()
        username = username.strip()

        if not full_name:
            return False, "Full name cannot be empty."
        if not username:
            return False, "Username cannot be empty."
        if len(username) < 3 or len(username) > 24:
            return False, "Username must be between 3 and 24 characters."
        if not username.replace("_", "").replace("-", "").isalnum():
            return False, "Username can only contain letters, numbers, hyphens, and underscores."
        if len(password) < 6:
            return False, "Password must be at least 6 characters long."

        users = cls.load_users()
        if username.lower() in users:
            return False, f"Username '{username}' is already registered."

        salt, phash = cls.hash_password(password)
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(USERS_FILE, "a", encoding="utf-8") as f:
            f.write(f"Username: {username}\n")
            f.write(f"FullName: {full_name}\n")
            f.write(f"Salt: {salt}\n")
            f.write(f"PasswordHash: {phash}\n")
            f.write(f"CreatedAt: {now_str}\n")
            f.write("--------------------------------\n")

        return True, "Account registered successfully! You can now sign in."

    @classmethod
    def authenticate(cls, username: str, password: str) -> tuple[bool, dict]:
        users = cls.load_users()
        u_record = users.get(username.strip().lower())
        if not u_record:
            return False, {}

        valid = cls.verify_password(password, u_record.get("salt", ""), u_record.get("hash", ""))
        return valid, u_record if valid else {}


# ==============================================================================
# 2. ACCURATE IP DETECTION (Active Route & Public WAN)
# ==============================================================================
class NetworkManager:
    """Accurately detects active network IP and public WAN IP."""

    _cached_local_ip = None
    _cached_public_ip = None

    @classmethod
    def get_active_local_ip(cls, force_refresh=False) -> str:
        """
        Determines the local IP address on the active routing interface.
        Uses a UDP route query to determine which network adapter owns the default route.
        Avoids loopback (127.0.0.1), APIPA (169.254.x.x), and inactive virtual adapters.
        """
        if cls._cached_local_ip and not force_refresh:
            return cls._cached_local_ip

        # Probes external public DNS to query the kernel routing table
        endpoints = [("8.8.8.8", 80), ("1.1.1.1", 80), ("9.9.9.9", 80)]
        for host, port in endpoints:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.6)
                s.connect((host, port))
                ip = s.getsockname()[0]
                s.close()
                if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                    cls._cached_local_ip = ip
                    return ip
            except Exception:
                continue

        # Fallback inspection of host addresses
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                cand = info[4][0]
                if not cand.startswith("127.") and not cand.startswith("169.254."):
                    cls._cached_local_ip = cand
                    return cand
        except Exception:
            pass

        cls._cached_local_ip = "127.0.0.1"
        return cls._cached_local_ip

    @classmethod
    def get_public_ip(cls, timeout=1.8, force_refresh=False) -> str:
        """
        Retrieves the public gateway IP via reputable HTTPS providers.
        Falls back gracefully if offline or request times out.
        """
        if cls._cached_public_ip and not force_refresh:
            return cls._cached_public_ip

        endpoints = [
            "https://api.ipify.org?format=json",
            "https://icanhazip.com",
            "https://checkip.amazonaws.com"
        ]
        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64)"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8").strip()
                    if "json" in url:
                        ip = json.loads(raw).get("ip")
                    else:
                        ip = raw
                    if ip and "." in ip:
                        cls._cached_public_ip = ip
                        return ip
            except Exception:
                continue

        return "Unavailable (Offline or Private Network)"


# ==============================================================================
# 3. C BACKEND CLIENT (Subprocess Execution)
# Single source of truth for Stack (LIFO), Queue (FIFO), and Detection
# ==============================================================================
class CBackendClient:
    def __init__(self):
        self.exe_path = EXE_PATH

    def ensure_binary(self):
        if not os.path.isfile(self.exe_path):
            # Attempt compilation if missing
            gcc_path = "gcc"
            c_sources = [
                os.path.join(SRC_DIR, "main.c"),
                os.path.join(SRC_DIR, "database.c"),
                os.path.join(SRC_DIR, "stack.c"),
                os.path.join(SRC_DIR, "queue.c"),
                os.path.join(SRC_DIR, "detector.c"),
            ]
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            subprocess.run(
                [gcc_path, "-Wall", "-Wextra", "-std=c11", "-O2", "-I" + SRC_DIR, *c_sources, "-o", self.exe_path],
                cwd=BASE_DIR,
                creationflags=flags
            )

    def execute(self, *args):
        self.ensure_binary()
        if not os.path.isfile(self.exe_path):
            return {
                "status": "error",
                "error": f"C backend '{EXE_NAME}' not found.",
                "stats": {"total_attempts": 0, "successful_logins": 0, "failed_logins": 0, "suspicious_ips_count": 0},
                "queue": [],
                "stack": [],
                "suspicious_ips": []
            }

        cmd = [self.exe_path] + list(args)
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            proc = subprocess.run(
                cmd,
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=creationflags
            )
            stdout = proc.stdout.strip()
            s_idx = stdout.find("{")
            e_idx = stdout.rfind("}")
            if s_idx != -1 and e_idx != -1:
                return json.loads(stdout[s_idx:e_idx + 1])
            return {"status": "raw", "output": stdout, "stderr": proc.stderr}
        except Exception as ex:
            return {"status": "error", "error": str(ex)}

    def record_attempt(self, username: str, status_success: bool, ip: str, source: str):
        st_val = "1" if status_success else "0"
        return self.execute("record-attempt", username, st_val, ip, source)

    def get_state(self):
        return self.execute("get-state")

    def enqueue(self, username, password, ip, source):
        return self.execute("enqueue", username, password, ip, source)

    def process_next(self):
        return self.execute("process-next")

    def pop_stack(self):
        return self.execute("stack-pop")


# ==============================================================================
# 4. MAIN APPLICATION WINDOW
# ==============================================================================
class BruteForceApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BruteForce Detector")
        self.geometry("1120x740")
        self.minsize(980, 660)
        self.configure(bg=THEME["bg_root"])

        self.backend = CBackendClient()
        self.current_user = None  # Populated upon successful login
        self.current_state = {}

        # Initialize databases
        UserManager.ensure_storage()
        os.makedirs(DB_DIR, exist_ok=True)
        if not os.path.isfile(LOGIN_DB_FILE):
            open(LOGIN_DB_FILE, "a").close()

        self._configure_ttk_styles()

        # Root Container: Holds either Auth View or Dashboard View
        self.main_container = tk.Frame(self, bg=THEME["bg_root"])
        self.main_container.pack(fill=tk.BOTH, expand=True)

        # Start with the dedicated authentication screen (No dashboard visible)
        self.auth_view = AuthContainer(self.main_container, self)
        self.auth_view.pack(fill=tk.BOTH, expand=True)

        self.dashboard_view = None

    def _configure_ttk_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Treeview styling for data tables
        style.configure(
            "Cyber.Treeview",
            background=THEME["bg_input"],
            foreground=THEME["text_primary"],
            fieldbackground=THEME["bg_input"],
            font=(THEME["font_mono"], 9),
            rowheight=28,
            borderwidth=0,
            relief="flat"
        )
        style.configure(
            "Cyber.Treeview.Heading",
            background=THEME["bg_card"],
            foreground=THEME["cyan"],
            font=(THEME["font_ui"], 9, "bold"),
            relief="flat",
            borderwidth=1
        )
        style.map(
            "Cyber.Treeview.Heading",
            background=[("active", THEME["violet"])],
            foreground=[("active", "#FFFFFF")]
        )
        style.map(
            "Cyber.Treeview",
            background=[("selected", THEME["violet"])],
            foreground=[("selected", "#FFFFFF")]
        )

    def on_login_success(self, user_record: dict):
        """Called when user successfully authenticates. Transitions to Dashboard."""
        self.current_user = user_record

        # Destroy Auth View
        if self.auth_view:
            self.auth_view.destroy()
            self.auth_view = None

        # Build & show Dashboard View
        self.dashboard_view = DashboardContainer(self.main_container, self)
        self.dashboard_view.pack(fill=tk.BOTH, expand=True)
        self.refresh_backend_state()

    def on_logout(self):
        """Clears user session and returns to login view."""
        self.current_user = None

        if self.dashboard_view:
            self.dashboard_view.destroy()
            self.dashboard_view = None

        self.auth_view = AuthContainer(self.main_container, self)
        self.auth_view.pack(fill=tk.BOTH, expand=True)

    def refresh_backend_state(self):
        state = self.backend.get_state()
        self.current_state = state
        if self.dashboard_view:
            self.dashboard_view.update_state(state)


# ==============================================================================
# 5. DEDICATED AUTHENTICATION VIEW (Login & Registration)
# ==============================================================================
class AuthContainer(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Center container
        center_frame = tk.Frame(self, bg=THEME["bg_root"])
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Brand Header
        header = tk.Frame(center_frame, bg=THEME["bg_root"])
        header.pack(pady=(0, 20))

        badge = tk.Label(
            header,
            text="SHIELD // ACTIVE DEFENSE",
            font=(THEME["font_mono"], 8, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_root"]
        )
        badge.pack()

        title = tk.Label(
            header,
            text="BruteForce Detector",
            font=(THEME["font_ui"], 22, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_root"]
        )
        title.pack(pady=(4, 2))

        sub = tk.Label(
            header,
            text="Cybersecurity Threat Monitoring & DSA Architecture",
            font=(THEME["font_ui"], 9),
            fg=THEME["text_secondary"],
            bg=THEME["bg_root"]
        )
        sub.pack()

        # Auth Card
        self.card = tk.Frame(
            center_frame,
            bg=THEME["bg_surface"],
            padx=32,
            pady=28,
            highlightthickness=1,
            highlightbackground=THEME["border"],
            width=420
        )
        self.card.pack(fill=tk.BOTH, expand=True)

        self.active_tab = "login"
        self._show_login_form()

    def _clear_card(self):
        for widget in self.card.winfo_children():
            widget.destroy()

    def _show_login_form(self):
        self._clear_card()
        self.active_tab = "login"

        # Card Title
        tk.Label(
            self.card,
            text="Account Sign In",
            font=(THEME["font_ui"], 13, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"]
        ).pack(anchor="w", pady=(0, 2))

        tk.Label(
            self.card,
            text="Enter your credentials to access the security dashboard",
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"]
        ).pack(anchor="w", pady=(0, 16))

        # Username Field
        tk.Label(self.card, text="USERNAME", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.login_user = tk.Entry(
            self.card,
            font=(THEME["font_ui"], 10),
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["border"]
        )
        self.login_user.pack(fill=tk.X, pady=(4, 12), ipady=5)
        self.login_user.insert(0, "admin")

        # Password Field
        tk.Label(self.card, text="PASSWORD", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.login_pass = tk.Entry(
            self.card,
            show="•",
            font=(THEME["font_ui"], 10),
            bg=THEME["bg_input"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["border"]
        )
        self.login_pass.pack(fill=tk.X, pady=(4, 6), ipady=5)
        self.login_pass.insert(0, "cyber2026!")

        # Password Options Row
        opt_row = tk.Frame(self.card, bg=THEME["bg_surface"])
        opt_row.pack(fill=tk.X, pady=(0, 12))

        self.show_pass_var = tk.BooleanVar(value=False)
        show_cb = tk.Checkbutton(
            opt_row,
            text="Show password",
            variable=self.show_pass_var,
            command=self._toggle_password_visibility,
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            activebackground=THEME["bg_surface"],
            activeforeground=THEME["cyan"],
            selectcolor=THEME["bg_input"],
            bd=0
        )
        show_cb.pack(side=tk.LEFT)

        # IP Detection & Testing Selector
        tk.Label(self.card, text="ORIGINATING IP FOR ATTEMPT TRACKING", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")

        local_ip = NetworkManager.get_active_local_ip()
        self.ip_mode = tk.StringVar(value="local")

        ip_box = tk.Frame(self.card, bg=THEME["bg_input"], padx=10, pady=8, highlightthickness=1, highlightbackground=THEME["border"])
        ip_box.pack(fill=tk.X, pady=(4, 14))

        self.ip_display = tk.Label(
            ip_box,
            text=f"Active Local IP: {local_ip}",
            font=(THEME["font_mono"], 8),
            fg=THEME["cyan"],
            bg=THEME["bg_input"]
        )
        self.ip_display.pack(anchor="w")

        ip_btns = tk.Frame(ip_box, bg=THEME["bg_input"])
        ip_btns.pack(fill=tk.X, pady=(4, 0))

        tk.Radiobutton(
            ip_btns,
            text="Local Network IP",
            variable=self.ip_mode,
            value="local",
            command=self._update_ip_mode,
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_input"],
            activebackground=THEME["bg_input"],
            activeforeground=THEME["cyan"],
            selectcolor=THEME["bg_root"]
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Radiobutton(
            ip_btns,
            text="Simulated Test IP",
            variable=self.ip_mode,
            value="custom",
            command=self._update_ip_mode,
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_input"],
            activebackground=THEME["bg_input"],
            activeforeground=THEME["cyan"],
            selectcolor=THEME["bg_root"]
        ).pack(side=tk.LEFT)

        self.custom_ip_entry = tk.Entry(
            ip_box,
            font=(THEME["font_mono"], 8),
            bg=THEME["bg_card"],
            fg=THEME["text_primary"],
            insertbackground=THEME["cyan"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=THEME["border"]
        )
        self.custom_ip_entry.insert(0, "192.168.1.100")

        # Feedback & Alert Banner
        self.login_msg = tk.Label(
            self.card,
            text="",
            font=(THEME["font_ui"], 8, "bold"),
            fg=THEME["alert"],
            bg=THEME["bg_surface"],
            wraplength=350,
            justify="left"
        )
        self.login_msg.pack(anchor="w", pady=(0, 8))

        # Sign In Button
        sign_in_btn = tk.Button(
            self.card,
            text="Sign In",
            font=(THEME["font_ui"], 10, "bold"),
            bg=THEME["cyan"],
            fg=THEME["bg_root"],
            activebackground=THEME["violet"],
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_sign_in_clicked
        )
        sign_in_btn.pack(fill=tk.X, pady=(4, 12))

        # Switch to Registration Link
        switch_row = tk.Frame(self.card, bg=THEME["bg_surface"])
        switch_row.pack(fill=tk.X)

        tk.Label(switch_row, text="Don't have an account?", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(side=tk.LEFT)
        create_btn = tk.Button(
            switch_row,
            text="Create an account",
            font=(THEME["font_ui"], 8, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_surface"],
            activebackground=THEME["bg_surface"],
            activeforeground=THEME["violet"],
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._show_registration_form
        )
        create_btn.pack(side=tk.LEFT, padx=(4, 0))

    def _show_registration_form(self):
        self._clear_card()
        self.active_tab = "register"

        # Card Title
        tk.Label(
            self.card,
            text="Create New Account",
            font=(THEME["font_ui"], 13, "bold"),
            fg=THEME["text_primary"],
            bg=THEME["bg_surface"]
        ).pack(anchor="w", pady=(0, 2))

        tk.Label(
            self.card,
            text="Credentials are encrypted with salted PBKDF2-HMAC",
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"]
        ).pack(anchor="w", pady=(0, 14))

        # Full Name
        tk.Label(self.card, text="FULL NAME", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.reg_fullname = tk.Entry(self.card, font=(THEME["font_ui"], 9), bg=THEME["bg_input"], fg=THEME["text_primary"], insertbackground=THEME["cyan"], relief="flat", highlightthickness=1, highlightbackground=THEME["border"])
        self.reg_fullname.pack(fill=tk.X, pady=(2, 8), ipady=4)

        # Username
        tk.Label(self.card, text="USERNAME", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.reg_user = tk.Entry(self.card, font=(THEME["font_ui"], 9), bg=THEME["bg_input"], fg=THEME["text_primary"], insertbackground=THEME["cyan"], relief="flat", highlightthickness=1, highlightbackground=THEME["border"])
        self.reg_user.pack(fill=tk.X, pady=(2, 8), ipady=4)

        # Password
        tk.Label(self.card, text="PASSWORD (MIN 6 CHARACTERS)", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.reg_pass = tk.Entry(self.card, show="•", font=(THEME["font_ui"], 9), bg=THEME["bg_input"], fg=THEME["text_primary"], insertbackground=THEME["cyan"], relief="flat", highlightthickness=1, highlightbackground=THEME["border"])
        self.reg_pass.pack(fill=tk.X, pady=(2, 8), ipady=4)

        # Confirm Password
        tk.Label(self.card, text="CONFIRM PASSWORD", font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        self.reg_pass_confirm = tk.Entry(self.card, show="•", font=(THEME["font_ui"], 9), bg=THEME["bg_input"], fg=THEME["text_primary"], insertbackground=THEME["cyan"], relief="flat", highlightthickness=1, highlightbackground=THEME["border"])
        self.reg_pass_confirm.pack(fill=tk.X, pady=(2, 8), ipady=4)

        # Show passwords option
        self.reg_show_var = tk.BooleanVar(value=False)
        show_cb = tk.Checkbutton(
            self.card,
            text="Show passwords",
            variable=self.reg_show_var,
            command=self._toggle_reg_password_visibility,
            font=(THEME["font_ui"], 8),
            fg=THEME["text_secondary"],
            bg=THEME["bg_surface"],
            activebackground=THEME["bg_surface"],
            activeforeground=THEME["cyan"],
            selectcolor=THEME["bg_input"],
            bd=0
        )
        show_cb.pack(anchor="w", pady=(0, 10))

        # Feedback Message
        self.reg_msg = tk.Label(
            self.card,
            text="",
            font=(THEME["font_ui"], 8, "bold"),
            fg=THEME["alert"],
            bg=THEME["bg_surface"],
            wraplength=350,
            justify="left"
        )
        self.reg_msg.pack(anchor="w", pady=(0, 8))

        # Submit Button
        create_btn = tk.Button(
            self.card,
            text="Create Account",
            font=(THEME["font_ui"], 10, "bold"),
            bg=THEME["violet"],
            fg="#FFFFFF",
            activebackground=THEME["cyan"],
            activeforeground=THEME["bg_root"],
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            command=self._on_register_clicked
        )
        create_btn.pack(fill=tk.X, pady=(4, 12))

        # Back to Login
        switch_row = tk.Frame(self.card, bg=THEME["bg_surface"])
        switch_row.pack(fill=tk.X)

        tk.Label(switch_row, text="Already have an account?", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(side=tk.LEFT)
        back_btn = tk.Button(
            switch_row,
            text="Sign in",
            font=(THEME["font_ui"], 8, "bold"),
            fg=THEME["cyan"],
            bg=THEME["bg_surface"],
            activebackground=THEME["bg_surface"],
            activeforeground=THEME["violet"],
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._show_login_form
        )
        back_btn.pack(side=tk.LEFT, padx=(4, 0))

    def _toggle_password_visibility(self):
        if self.show_pass_var.get():
            self.login_pass.config(show="")
        else:
            self.login_pass.config(show="•")

    def _toggle_reg_password_visibility(self):
        if self.reg_show_var.get():
            self.reg_pass.config(show="")
            self.reg_pass_confirm.config(show="")
        else:
            self.reg_pass.config(show="•")
            self.reg_pass_confirm.config(show="•")

    def _update_ip_mode(self):
        mode = self.ip_mode.get()
        if mode == "local":
            self.custom_ip_entry.pack_forget()
            local_ip = NetworkManager.get_active_local_ip()
            self.ip_display.config(text=f"Active Local IP: {local_ip}")
        else:
            self.custom_ip_entry.pack(fill=tk.X, pady=(4, 0), ipady=3)
            self.ip_display.config(text="Simulated Test IP (Manual):")

    def _get_current_attempt_ip(self) -> tuple[str, str]:
        mode = self.ip_mode.get()
        if mode == "local":
            return NetworkManager.get_active_local_ip(), "Local (Auto)"
        else:
            c_ip = self.custom_ip_entry.get().strip()
            return (c_ip if c_ip else "192.168.1.100"), "Manual (Simulated)"

    def _on_sign_in_clicked(self):
        u = self.login_user.get().strip()
        p = self.login_pass.get().strip()
        ip, source = self._get_current_attempt_ip()

        if not u or not p:
            self.login_msg.config(text="Please enter both username and password.", fg=THEME["alert"])
            return

        # 1. Verify credentials against salted PBKDF2 hashes in database/users.txt
        auth_success, user_record = UserManager.authenticate(u, p)

        # 2. Process attempt through C backend (Queue -> Detector -> Database TXT -> Stack)
        c_res = self.app.backend.record_attempt(u, auth_success, ip, source)
        alert_msg = c_res.get("alert")

        if auth_success:
            self.login_msg.config(text="Authentication successful! Redirecting...", fg=THEME["success"])
            self.app.after(350, lambda: self.app.on_login_success(user_record))
        else:
            if alert_msg:
                self.login_msg.config(
                    text=f"Authentication Failed!\n[BRUTE-FORCE ALERT] {alert_msg}",
                    fg=THEME["alert"]
                )
            else:
                self.login_msg.config(
                    text="Invalid username or password. Please verify your credentials.",
                    fg=THEME["alert"]
                )

    def _on_register_clicked(self):
        fname = self.reg_fullname.get().strip()
        uname = self.reg_user.get().strip()
        pwd = self.reg_pass.get().strip()
        pwd2 = self.reg_pass_confirm.get().strip()

        if pwd != pwd2:
            self.reg_msg.config(text="Passwords do not match.", fg=THEME["alert"])
            return

        ok, msg = UserManager.register_user(fname, uname, pwd)
        if ok:
            self.reg_msg.config(text=msg, fg=THEME["success"])
            self.app.after(1200, self._show_login_form)
        else:
            self.reg_msg.config(text=msg, fg=THEME["alert"])


# ==============================================================================
# 6. POST-LOGIN DASHBOARD CONTAINER & SUB-SCREENS
# ==============================================================================
class DashboardContainer(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Left Sidebar Navigation
        self.sidebar = tk.Frame(self, bg=THEME["bg_surface"], width=230, highlightthickness=1, highlightbackground=THEME["border"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        # Sidebar Header Brand
        brand_box = tk.Frame(self.sidebar, bg=THEME["bg_surface"], padx=16, pady=20)
        brand_box.pack(fill=tk.X)

        tk.Label(brand_box, text="SHIELD CONSOLE", font=(THEME["font_mono"], 7, "bold"), fg=THEME["cyan"], bg=THEME["bg_surface"]).pack(anchor="w")
        tk.Label(brand_box, text="BruteForce Detector", font=(THEME["font_ui"], 13, "bold"), fg=THEME["text_primary"], bg=THEME["bg_surface"]).pack(anchor="w")

        # Nav Buttons Frame
        self.nav_frame = tk.Frame(self.sidebar, bg=THEME["bg_surface"], padx=10, pady=10)
        self.nav_frame.pack(fill=tk.X)

        self.nav_btns = {}
        items = [
            ("dashboard", "Dashboard"),
            ("history", "Login History"),
            ("dsa", "DSA Visualization"),
            ("settings", "Settings"),
        ]
        for key, label in items:
            btn = tk.Button(
                self.nav_frame,
                text=label,
                font=(THEME["font_ui"], 9, "bold"),
                bg=THEME["bg_surface"],
                fg=THEME["text_secondary"],
                activebackground=THEME["bg_card"],
                activeforeground=THEME["cyan"],
                relief="flat",
                bd=0,
                padx=12,
                pady=9,
                anchor="w",
                cursor="hand2",
                command=lambda k=key: self.show_view(k)
            )
            btn.pack(fill=tk.X, pady=2)
            self.nav_btns[key] = btn

        # Bottom Profile & Logout Box
        profile_box = tk.Frame(self.sidebar, bg=THEME["bg_card"], padx=14, pady=14, highlightthickness=1, highlightbackground=THEME["border"])
        profile_box.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=12)

        u_info = self.app.current_user or {}
        tk.Label(profile_box, text=u_info.get("fullname", "User"), font=(THEME["font_ui"], 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"]).pack(anchor="w")
        tk.Label(profile_box, text=f"@{u_info.get('username', 'user')}", font=(THEME["font_mono"], 8), fg=THEME["cyan"], bg=THEME["bg_card"]).pack(anchor="w", pady=(1, 8))

        logout_btn = tk.Button(
            profile_box,
            text="Sign Out",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["bg_surface"],
            fg=THEME["alert"],
            relief="flat",
            bd=0,
            pady=4,
            cursor="hand2",
            command=self.app.on_logout
        )
        logout_btn.pack(fill=tk.X)

        # Right Content Area
        self.content_area = tk.Frame(self, bg=THEME["bg_root"], padx=24, pady=20)
        self.content_area.grid(row=0, column=1, sticky="nsew")
        self.content_area.grid_rowconfigure(0, weight=1)
        self.content_area.grid_columnconfigure(0, weight=1)

        # Sub-views
        self.views = {
            "dashboard": DashboardView(self.content_area, self.app),
            "history": HistoryView(self.content_area, self.app),
            "dsa": DsaView(self.content_area, self.app),
            "settings": SettingsView(self.content_area, self.app),
        }

        for v in self.views.values():
            v.grid(row=0, column=0, sticky="nsew")

        self.show_view("dashboard")

    def show_view(self, key):
        for k, btn in self.nav_btns.items():
            if k == key:
                btn.configure(bg=THEME["bg_card"], fg=THEME["cyan"])
            else:
                btn.configure(bg=THEME["bg_surface"], fg=THEME["text_secondary"])

        view = self.views[key]
        view.tkraise()
        if hasattr(view, "on_activate"):
            view.on_activate()

    def update_state(self, state):
        for v in self.views.values():
            if hasattr(v, "update_state"):
                v.update_state(state)


# ==============================================================================
# 7. SUB-VIEW 1: MAIN DASHBOARD
# ==============================================================================
class DashboardView(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        top_bar = tk.Frame(self, bg=THEME["bg_root"])
        top_bar.pack(fill=tk.X, pady=(0, 16))

        u_name = (self.app.current_user or {}).get("fullname", "User")
        tk.Label(top_bar, text="System Overview", font=(THEME["font_ui"], 18, "bold"), fg=THEME["text_primary"], bg=THEME["bg_root"]).pack(anchor="w")
        tk.Label(top_bar, text=f"Active threat monitoring for {u_name}", font=(THEME["font_ui"], 9), fg=THEME["text_secondary"], bg=THEME["bg_root"]).pack(anchor="w")

        # Active Alert Banner (Hidden by default, shown when threat detected)
        self.alert_banner = tk.Frame(self, bg=THEME["alert_bg"], padx=16, pady=12, highlightthickness=1, highlightbackground=THEME["alert"])

        self.alert_title = tk.Label(self.alert_banner, text="SECURITY ALERT: Brute-Force Pattern Detected", font=(THEME["font_ui"], 9, "bold"), fg=THEME["alert"], bg=THEME["alert_bg"])
        self.alert_title.pack(anchor="w")
        self.alert_detail = tk.Label(self.alert_banner, text="", font=(THEME["font_mono"], 8), fg=THEME["text_primary"], bg=THEME["alert_bg"])
        self.alert_detail.pack(anchor="w", pady=(2, 0))

        # 4 Metric Cards
        cards_row = tk.Frame(self, bg=THEME["bg_root"])
        cards_row.pack(fill=tk.X, pady=(0, 16))

        self.card_total = self._create_metric_card(cards_row, "Total Login Attempts", "0", THEME["cyan"], 0)
        self.card_success = self._create_metric_card(cards_row, "Successful Logins", "0", THEME["success"], 1)
        self.card_failed = self._create_metric_card(cards_row, "Failed Attempts", "0", THEME["alert"], 2)
        self.card_suspicious = self._create_metric_card(cards_row, "Suspicious IPs Flagged", "0", THEME["violet"], 3)

        # Two Columns: Left = Suspicious IPs, Right = Recent Activity
        body = tk.Frame(self, bg=THEME["bg_root"])
        body.pack(fill=tk.BOTH, expand=True)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # Left: Suspicious IPs Table
        left_card = tk.Frame(body, bg=THEME["bg_surface"], padx=18, pady=16, highlightthickness=1, highlightbackground=THEME["border"])
        left_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        tk.Label(left_card, text="Detected Suspicious IP Addresses", font=(THEME["font_ui"], 11, "bold"), fg=THEME["text_primary"], bg=THEME["bg_surface"]).pack(anchor="w")
        tk.Label(left_card, text="IP addresses that exceeded the threshold of 3 consecutive failed attempts", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(anchor="w", pady=(2, 10))

        cols = ("ip", "consec", "fails", "status")
        self.tree_susp = ttk.Treeview(left_card, columns=cols, show="headings", style="Cyber.Treeview")
        self.tree_susp.heading("ip", text="IP ADDRESS")
        self.tree_susp.heading("consec", text="CONSEC. FAILS")
        self.tree_susp.heading("fails", text="TOTAL FAILS")
        self.tree_susp.heading("status", text="THREAT STATUS")

        self.tree_susp.column("ip", width=140)
        self.tree_susp.column("consec", width=95, anchor="center")
        self.tree_susp.column("fails", width=85, anchor="center")
        self.tree_susp.column("status", width=110, anchor="center")

        self.tree_susp.pack(fill=tk.BOTH, expand=True)

        # Right: Recent Activity Snapshot
        right_card = tk.Frame(body, bg=THEME["bg_surface"], padx=18, pady=16, highlightthickness=1, highlightbackground=THEME["border"])
        right_card.grid(row=0, column=1, sticky="nsew")

        tk.Label(right_card, text="Recent Login Activity", font=(THEME["font_ui"], 11, "bold"), fg=THEME["text_primary"], bg=THEME["bg_surface"]).pack(anchor="w")
        tk.Label(right_card, text="Retrieved live from C Activity Stack (LIFO)", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(anchor="w", pady=(2, 10))

        self.recent_list = tk.Frame(right_card, bg=THEME["bg_surface"])
        self.recent_list.pack(fill=tk.BOTH, expand=True)

    def _create_metric_card(self, parent, title, value, color, col_idx):
        card = tk.Frame(parent, bg=THEME["bg_surface"], padx=16, pady=14, highlightthickness=1, highlightbackground=THEME["border"])
        card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if col_idx == 0 else 8, 0))

        tk.Label(card, text=title, font=(THEME["font_ui"], 8, "bold"), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(anchor="w")
        val_lbl = tk.Label(card, text=value, font=(THEME["font_ui"], 18, "bold"), fg=color, bg=THEME["bg_surface"])
        val_lbl.pack(anchor="w", pady=(2, 0))
        return val_lbl

    def update_state(self, state):
        stats = state.get("stats", {})
        self.card_total.config(text=str(stats.get("total_attempts", 0)))
        self.card_success.config(text=str(stats.get("successful_logins", 0)))
        self.card_failed.config(text=str(stats.get("failed_logins", 0)))

        susp_count = stats.get("suspicious_ips_count", 0)
        self.card_suspicious.config(text=str(susp_count))

        # Alert Banner Update
        if susp_count > 0:
            self.alert_banner.pack(fill=tk.X, pady=(0, 16), after=self.card_total.master)
            self.alert_detail.config(text=f"{susp_count} IP address(es) currently flagged for suspicious brute-force activity.")
        else:
            self.alert_banner.pack_forget()

        # Update Suspicious IPs Table
        for r in self.tree_susp.get_children():
            self.tree_susp.delete(r)

        for item in state.get("suspicious_ips", []):
            st = "FLAGGED" if item.get("is_suspicious") else "Normal"
            self.tree_susp.insert("", tk.END, values=(
                item.get("ip_address"),
                item.get("consecutive_failures"),
                item.get("total_failures"),
                st
            ))

        # Update Recent Activity List
        for widget in self.recent_list.winfo_children():
            widget.destroy()

        stack_items = state.get("stack", [])
        if not stack_items:
            tk.Label(self.recent_list, text="No recent login activity recorded.", font=(THEME["font_ui"], 9), fg=THEME["text_dim"], bg=THEME["bg_surface"]).pack(pady=20)
            return

        for item in stack_items[:6]:
            is_succ = item.get("status") == "Success"
            row = tk.Frame(self.recent_list, bg=THEME["bg_card"], padx=10, pady=7, highlightthickness=1, highlightbackground=THEME["border"])
            row.pack(fill=tk.X, pady=3)

            u_lbl = tk.Label(row, text=item.get("username", "unknown"), font=(THEME["font_ui"], 9, "bold"), fg=THEME["text_primary"], bg=THEME["bg_card"])
            u_lbl.pack(side=tk.LEFT)

            st_chip = tk.Label(
                row,
                text="SUCCESS" if is_succ else "FAILED",
                font=(THEME["font_mono"], 7, "bold"),
                fg=THEME["success"] if is_succ else THEME["alert"],
                bg=THEME["success_bg"] if is_succ else THEME["alert_bg"],
                padx=6,
                pady=1
            )
            st_chip.pack(side=tk.LEFT, padx=8)

            ip_lbl = tk.Label(row, text=item.get("ip_address"), font=(THEME["font_mono"], 8), fg=THEME["text_secondary"], bg=THEME["bg_card"])
            ip_lbl.pack(side=tk.RIGHT)


# ==============================================================================
# 8. SUB-VIEW 2: LOGIN HISTORY (database/login_database.txt)
# ==============================================================================
class HistoryView(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        top_bar = tk.Frame(self, bg=THEME["bg_root"])
        top_bar.pack(fill=tk.X, pady=(0, 14))

        left = tk.Frame(top_bar, bg=THEME["bg_root"])
        left.pack(side=tk.LEFT)

        tk.Label(left, text="Login History & Audit Log", font=(THEME["font_ui"], 18, "bold"), fg=THEME["text_primary"], bg=THEME["bg_root"]).pack(anchor="w")
        tk.Label(left, text="Persistent historical records loaded from database/login_database.txt", font=(THEME["font_ui"], 9), fg=THEME["text_secondary"], bg=THEME["bg_root"]).pack(anchor="w")

        refresh_btn = tk.Button(
            top_bar,
            text="Refresh Audit Log",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["bg_surface"],
            fg=THEME["cyan"],
            relief="flat",
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
            command=self.app.refresh_backend_state
        )
        refresh_btn.pack(side=tk.RIGHT)

        # Table Container
        card = tk.Frame(self, bg=THEME["bg_surface"], padx=16, pady=16, highlightthickness=1, highlightbackground=THEME["border"])
        card.pack(fill=tk.BOTH, expand=True)

        cols = ("user", "ip", "status", "time", "source")
        self.tree = ttk.Treeview(card, columns=cols, show="headings", style="Cyber.Treeview")
        self.tree.heading("user", text="USERNAME")
        self.tree.heading("ip", text="IP ADDRESS")
        self.tree.heading("status", text="AUTH RESULT")
        self.tree.heading("time", text="TIMESTAMP")
        self.tree.heading("source", text="DETECTION SOURCE")

        self.tree.column("user", width=140)
        self.tree.column("ip", width=160)
        self.tree.column("status", width=110, anchor="center")
        self.tree.column("time", width=180, anchor="center")
        self.tree.column("source", width=140, anchor="center")

        scroll = ttk.Scrollbar(card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def update_state(self, state):
        for r in self.tree.get_children():
            self.tree.delete(r)

        # Stack holds reverse chronological attempts
        records = state.get("stack", [])
        for rec in records:
            self.tree.insert("", tk.END, values=(
                rec.get("username"),
                rec.get("ip_address"),
                rec.get("status"),
                rec.get("timestamp"),
                rec.get("ip_source")
            ))


# ==============================================================================
# 9. SUB-VIEW 3: STACK & QUEUE DSA VISUALIZATION
# ==============================================================================
class DsaView(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        top_bar = tk.Frame(self, bg=THEME["bg_root"])
        top_bar.pack(fill=tk.X, pady=(0, 14))

        tk.Label(top_bar, text="Data Structures & Algorithms Verification", font=(THEME["font_ui"], 18, "bold"), fg=THEME["text_primary"], bg=THEME["bg_root"]).pack(anchor="w")
        tk.Label(top_bar, text="Real-time inspection of C11 Queue (FIFO) and Stack (LIFO) in memory", font=(THEME["font_ui"], 9), fg=THEME["text_secondary"], bg=THEME["bg_root"]).pack(anchor="w")

        # Two Columns
        body = tk.Frame(self, bg=THEME["bg_root"])
        body.pack(fill=tk.BOTH, expand=True)
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        # --- LEFT: QUEUE (FIFO) ---
        q_card = tk.Frame(body, bg=THEME["bg_surface"], padx=18, pady=16, highlightthickness=1, highlightbackground=THEME["border"])
        q_card.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        q_head = tk.Frame(q_card, bg=THEME["bg_surface"])
        q_head.pack(fill=tk.X)
        tk.Label(q_head, text="Queue (FIFO - First In, First Out)", font=(THEME["font_ui"], 11, "bold"), fg=THEME["cyan"], bg=THEME["bg_surface"]).pack(side=tk.LEFT)
        self.q_badge = tk.Label(q_head, text="Count: 0", font=(THEME["font_mono"], 8, "bold"), fg=THEME["bg_root"], bg=THEME["cyan"], padx=6)
        self.q_badge.pack(side=tk.RIGHT)

        tk.Label(q_card, text="Incoming attempts enter at REAR; processed from FRONT", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(anchor="w", pady=(2, 8))

        # Canvas for Queue visualization
        self.q_canvas = tk.Canvas(q_card, bg=THEME["bg_input"], highlightthickness=1, highlightbackground=THEME["border"], height=320)
        self.q_canvas.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Queue controls
        q_ctrls = tk.Frame(q_card, bg=THEME["bg_surface"])
        q_ctrls.pack(fill=tk.X)

        tk.Button(
            q_ctrls,
            text="Enqueue Test Attempt",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["bg_card"],
            fg=THEME["cyan"],
            relief="flat",
            bd=0,
            pady=6,
            cursor="hand2",
            command=self._on_enqueue_test
        ).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))

        tk.Button(
            q_ctrls,
            text="Dequeue & Process Next (FIFO)",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["cyan"],
            fg=THEME["bg_root"],
            relief="flat",
            bd=0,
            pady=6,
            cursor="hand2",
            command=self._on_dequeue_click
        ).pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(4, 0))

        # --- RIGHT: STACK (LIFO) ---
        s_card = tk.Frame(body, bg=THEME["bg_surface"], padx=18, pady=16, highlightthickness=1, highlightbackground=THEME["border"])
        s_card.grid(row=0, column=1, sticky="nsew")

        s_head = tk.Frame(s_card, bg=THEME["bg_surface"])
        s_head.pack(fill=tk.X)
        tk.Label(s_head, text="Stack (LIFO - Last In, First Out)", font=(THEME["font_ui"], 11, "bold"), fg=THEME["violet"], bg=THEME["bg_surface"]).pack(side=tk.LEFT)
        self.s_badge = tk.Label(s_head, text="Count: 0", font=(THEME["font_mono"], 8, "bold"), fg=THEME["bg_root"], bg=THEME["violet"], padx=6)
        self.s_badge.pack(side=tk.RIGHT)

        tk.Label(s_card, text="Processed attempts pushed to TOP; latest attempt at TOP", font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_surface"]).pack(anchor="w", pady=(2, 8))

        # Canvas for Stack visualization
        self.s_canvas = tk.Canvas(s_card, bg=THEME["bg_input"], highlightthickness=1, highlightbackground=THEME["border"], height=320)
        self.s_canvas.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # Stack controls
        s_ctrls = tk.Frame(s_card, bg=THEME["bg_surface"])
        s_ctrls.pack(fill=tk.X)

        tk.Button(
            s_ctrls,
            text="Pop Top Element from Stack (LIFO)",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["violet"],
            fg="#FFFFFF",
            relief="flat",
            bd=0,
            pady=6,
            cursor="hand2",
            command=self._on_pop_click
        ).pack(fill=tk.X)

    def _on_enqueue_test(self):
        u = "test_user_" + secrets.token_hex(2)
        ip = "192.168.1.150"
        self.app.backend.enqueue(u, "sample_pwd", ip, "Manual")
        self.app.refresh_backend_state()

    def _on_dequeue_click(self):
        res = self.app.backend.process_next()
        self.app.refresh_backend_state()
        alert = res.get("alert")
        if alert:
            messagebox.showwarning("Brute-Force Alert", alert)

    def _on_pop_click(self):
        self.app.backend.pop_stack()
        self.app.refresh_backend_state()

    def update_state(self, state):
        q_items = state.get("queue", [])
        s_items = state.get("stack", [])

        self.q_badge.config(text=f"Count: {len(q_items)}")
        self.s_badge.config(text=f"Count: {len(s_items)}")

        self._render_queue(q_items)
        self._render_stack(s_items)

    def _render_queue(self, items):
        self.q_canvas.delete("all")
        w = self.q_canvas.winfo_width() or 380
        h = self.q_canvas.winfo_height() or 320

        if not items:
            self.q_canvas.create_text(
                w / 2, h / 2,
                text="Queue is currently empty.\n\nUse 'Enqueue Test Attempt' above to add\nincoming login attempts in FIFO order.",
                font=(THEME["font_ui"], 9),
                fill=THEME["text_dim"],
                justify="center"
            )
            return

        box_h = 42
        gap = 8
        y = 16

        self.q_canvas.create_text(20, y, text="▲ FRONT (NEXT IN LINE TO DEQUEUE)", font=(THEME["font_ui"], 8, "bold"), fill=THEME["success"], anchor="w")
        y += 18

        max_display = min(len(items), 6)
        for i in range(max_display):
            item = items[i]
            is_front = (i == 0)
            is_rear = (i == len(items) - 1)

            border_c = THEME["cyan"] if is_front else THEME["border"]
            fill_c = THEME["bg_card"] if is_front else THEME["bg_surface"]

            self.q_canvas.create_rectangle(16, y, w - 16, y + box_h, fill=fill_c, outline=border_c, width=1.5 if is_front else 1)

            tag = ""
            if is_front and is_rear:
                tag = " [FRONT & REAR]"
            elif is_front:
                tag = " [FRONT]"
            elif is_rear:
                tag = " [REAR]"

            self.q_canvas.create_text(26, y + 13, text=f"Item #{i}: {item.get('username')}{tag}", font=(THEME["font_ui"], 9, "bold"), fill=THEME["cyan"] if is_front else THEME["text_primary"], anchor="w")
            self.q_canvas.create_text(26, y + 29, text=f"IP: {item.get('ip_address')} | Source: {item.get('ip_source')}", font=(THEME["font_mono"], 8), fill=THEME["text_secondary"], anchor="w")
            y += box_h + gap

        if len(items) > max_display:
            self.q_canvas.create_text(w / 2, y + 10, text=f"... +{len(items) - max_display} more attempts in queue ...", font=(THEME["font_ui"], 8), fill=THEME["text_dim"])
        else:
            self.q_canvas.create_text(20, y + 6, text="▼ REAR (NEW ATTEMPTS ENTER HERE)", font=(THEME["font_ui"], 8, "bold"), fill=THEME["cyan"], anchor="w")

    def _render_stack(self, items):
        self.s_canvas.delete("all")
        w = self.s_canvas.winfo_width() or 380
        h = self.s_canvas.winfo_height() or 320

        if not items:
            self.s_canvas.create_text(
                w / 2, h / 2,
                text="Stack is currently empty.\n\nProcessed attempts are pushed to the top\nof this LIFO history stack.",
                font=(THEME["font_ui"], 9),
                fill=THEME["text_dim"],
                justify="center"
            )
            return

        box_h = 42
        gap = 8
        y = 16

        self.s_canvas.create_text(20, y, text="▼ TOP (MOST RECENT / POP TARGET)", font=(THEME["font_ui"], 8, "bold"), fill=THEME["violet"], anchor="w")
        y += 18

        max_display = min(len(items), 6)
        for i in range(max_display):
            item = items[i]
            is_top = (i == 0)
            is_succ = item.get("status") == "Success"

            border_c = THEME["violet"] if is_top else THEME["border"]
            fill_c = THEME["bg_card"] if is_top else THEME["bg_surface"]

            self.s_canvas.create_rectangle(16, y, w - 16, y + box_h, fill=fill_c, outline=border_c, width=1.5 if is_top else 1)

            top_tag = " [TOP]" if is_top else ""
            self.s_canvas.create_text(26, y + 13, text=f"Top-{i}: {item.get('username')}{top_tag} -> [{item.get('status')}]", font=(THEME["font_ui"], 9, "bold"), fill=THEME["success"] if is_succ else THEME["alert"], anchor="w")
            self.s_canvas.create_text(26, y + 29, text=f"IP: {item.get('ip_address')} | Time: {item.get('timestamp')}", font=(THEME["font_mono"], 8), fill=THEME["text_secondary"], anchor="w")
            y += box_h + gap

        if len(items) > max_display:
            self.s_canvas.create_text(w / 2, y + 10, text=f"... +{len(items) - max_display} earlier records at bottom ...", font=(THEME["font_ui"], 8), fill=THEME["text_dim"])


# ==============================================================================
# 10. SUB-VIEW 4: SETTINGS & NETWORK DIAGNOSTICS
# ==============================================================================
class SettingsView(tk.Frame):
    def __init__(self, parent, app: BruteForceApp):
        super().__init__(parent, bg=THEME["bg_root"])
        self.app = app
        self._build_ui()

    def _build_ui(self):
        top_bar = tk.Frame(self, bg=THEME["bg_root"])
        top_bar.pack(fill=tk.X, pady=(0, 16))

        tk.Label(top_bar, text="Settings & Network Diagnostics", font=(THEME["font_ui"], 18, "bold"), fg=THEME["text_primary"], bg=THEME["bg_root"]).pack(anchor="w")
        tk.Label(top_bar, text="Interface configuration and architectural diagnostic details", font=(THEME["font_ui"], 9), fg=THEME["text_secondary"], bg=THEME["bg_root"]).pack(anchor="w")

        scroll_card = tk.Frame(self, bg=THEME["bg_surface"], padx=20, pady=20, highlightthickness=1, highlightbackground=THEME["border"])
        scroll_card.pack(fill=tk.BOTH, expand=True)

        # 1. Network Diagnostics Section
        tk.Label(scroll_card, text="Network Interface Diagnostics", font=(THEME["font_ui"], 11, "bold"), fg=THEME["cyan"], bg=THEME["bg_surface"]).pack(anchor="w")

        local_ip = NetworkManager.get_active_local_ip()
        public_ip = NetworkManager.get_public_ip()

        diag_box = tk.Frame(scroll_card, bg=THEME["bg_card"], padx=14, pady=12, highlightthickness=1, highlightbackground=THEME["border"])
        diag_box.pack(fill=tk.X, pady=(6, 16))

        self.lbl_local = tk.Label(diag_box, text=f"• Active Local IP (Active Routing Interface): {local_ip}", font=(THEME["font_mono"], 9), fg=THEME["text_primary"], bg=THEME["bg_card"])
        self.lbl_local.pack(anchor="w")

        self.lbl_pub = tk.Label(diag_box, text=f"• Public WAN Gateway IP (HTTPS Resolved): {public_ip}", font=(THEME["font_mono"], 9), fg=THEME["text_primary"], bg=THEME["bg_card"])
        self.lbl_pub.pack(anchor="w", pady=(4, 6))

        refresh_net_btn = tk.Button(
            diag_box,
            text="Re-check Active Interfaces",
            font=(THEME["font_ui"], 8, "bold"),
            bg=THEME["bg_surface"],
            fg=THEME["cyan"],
            relief="flat",
            bd=0,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._refresh_network
        )
        refresh_net_btn.pack(anchor="w")

        # 2. Architectural Limitation Notice
        tk.Label(scroll_card, text="Architectural Operating Principles", font=(THEME["font_ui"], 11, "bold"), fg=THEME["violet"], bg=THEME["bg_surface"]).pack(anchor="w")

        notice_box = tk.Frame(scroll_card, bg=THEME["bg_card"], padx=14, pady=12, highlightthickness=1, highlightbackground=THEME["border"])
        notice_box.pack(fill=tk.X, pady=(6, 16))

        notice_text = (
            "This application operates as a standalone local desktop program.\n"
            "• Automatically detected IP addresses represent the host computer running this app.\n"
            "• A remote web server is required to capture actual client IP addresses over the internet.\n"
            "• To test brute-force protection from simulated external clients, use the 'Simulated Test IP' option."
        )
        tk.Label(notice_box, text=notice_text, font=(THEME["font_ui"], 8), fg=THEME["text_secondary"], bg=THEME["bg_card"], justify="left").pack(anchor="w")

        # 3. Account Details
        tk.Label(scroll_card, text="Authentication Storage Security", font=(THEME["font_ui"], 11, "bold"), fg=THEME["success"], bg=THEME["bg_surface"]).pack(anchor="w")

        sec_box = tk.Frame(scroll_card, bg=THEME["bg_card"], padx=14, pady=12, highlightthickness=1, highlightbackground=THEME["border"])
        sec_box.pack(fill=tk.X, pady=(6, 0))

        sec_text = (
            f"• User Accounts Database: database/users.txt\n"
            f"• Password Hashing: PBKDF2-HMAC-SHA256 (100,000 iterations)\n"
            f"• Salt: 16-byte cryptographically secure individual salt per account\n"
            f"• Login Audit Database: database/login_database.txt (Zero password leakage)"
        )
        tk.Label(sec_box, text=sec_text, font=(THEME["font_mono"], 8), fg=THEME["text_primary"], bg=THEME["bg_card"], justify="left").pack(anchor="w")

    def _refresh_network(self):
        local_ip = NetworkManager.get_active_local_ip(force_refresh=True)
        public_ip = NetworkManager.get_public_ip(force_refresh=True)
        self.lbl_local.config(text=f"• Active Local IP (Active Routing Interface): {local_ip}")
        self.lbl_pub.config(text=f"• Public WAN Gateway IP (HTTPS Resolved): {public_ip}")
        messagebox.showinfo("Network Status", "Active network interfaces refreshed successfully.")


# ==============================================================================
# MAIN ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    app = BruteForceApp()
    app.mainloop()
