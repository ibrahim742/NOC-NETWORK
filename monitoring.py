import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess, threading, time, json, os, sys, re, queue, socket, csv
import hashlib, hmac, base64
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import winsound
except ImportError:
    winsound = None

# ── Loader .env (Tanpa Library Tambahan) ───────────────
def _env_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def load_env(filename=".env"):
    path = os.path.join(_env_dir(), filename)
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    "# Format akun: username:password (pisah koma jika lebih dari 1)\n"
                    "AUTH_USERS=admin:ssc2026\n"
                    "DATA_SECRET_KEY=NOC-SSC-SECRET-KEY-2026\n"
                )
        except Exception:
            pass

    env = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return env

def _parse_users(raw):
    users = {}
    for pair in raw.split(","):
        if ":" in pair:
            u, p = pair.split(":", 1)
            u = u.strip()
            if u:
                users[u] = p.strip()
    return users or {"admin": "ssc2026"}

_ENV = load_env()
AUTH_USERS = _parse_users(_ENV.get("AUTH_USERS", "admin:ssc2026"))
DATA_SECRET_KEY = _ENV.get("DATA_SECRET_KEY", "NOC-SSC-SECRET-KEY-2026")


INTERVAL              = 5
CONFIG_NAME           = "hosts.json"
HINTS_NAME            = "scan_hints.json"
SETTINGS_NAME         = "settings.json"
ICON_NAME             = "icon.ico"
SLOW_THRESHOLD        = 150
PING_TIMEOUT_MS       = 2000
PING_SEQUENCE_COUNT   = 4
TRACERT_THROTTLE      = 60
RTO_THRESHOLD_MINUTES = 20
RTO_REPEAT_SECONDS    = 10
SCAN_TIMEOUT_MS       = 500
SCAN_RETRY_TIMEOUT_MS = 2000
SCAN_WORKERS          = 100
MAX_SCAN_IPS          = 30000
HISTORY_LEN           = 20
RTO_STATUSES          = {"timeout", "offline", "unreachable"}
NO_WINDOW             = getattr(subprocess, "CREATE_NO_WINDOW", 0)

DEVICE_ICONS = {"PC": "💻", "Printer": "🖨", "Aplikasi": "⚙", "SDWAN": "🌐"}
DEVICE_LIST  = ["PC", "Printer", "Aplikasi", "SDWAN"]

TAB_STYLES = {
    "PC":       {"bg_inactive": "#e3f2fd", "bg_active": "#1976d2",
                 "fg_inactive": "#0d47a1", "fg_active": "#ffffff"},
    "Printer":  {"bg_inactive": "#fff3e0", "bg_active": "#f57c00",
                 "fg_inactive": "#e65100", "fg_active": "#ffffff"},
    "Aplikasi": {"bg_inactive": "#f3e5f5", "bg_active": "#7b1fa2",
                 "fg_inactive": "#4a148c", "fg_active": "#ffffff"},
    "SDWAN":    {"bg_inactive": "#e8f5e9", "bg_active": "#00796b",
                 "fg_inactive": "#1b5e20", "fg_active": "#ffffff"},
}

COL_DEFS = [
    ("aktif",   "Aktif",                     62,  "center"),
    ("ikon",    "",                          56,  "center"),
    ("nama",    "Nama",                      185, "w"),
    ("ip",      "IP / Hostname",             135, "w"),
    ("status",  "Status",                    130, "center"),
    ("latency", f"Latency + Tren ({HISTORY_LEN}x)", 200, "w"),
    ("pesan",   "Keterangan",                175, "w"),
]
COL_NAMES   = [c[0] for c in COL_DEFS]
COL_WIDTHS  = [c[2] for c in COL_DEFS]
AKTIF_INDEX = COL_NAMES.index("aktif")

STATUS_LABEL = {"online": "Online", "slow": "Lambat", "timeout": "Timeout",
    "offline": "Offline", "unreachable": "Unreachable",
    "error": "Error", "checking": "Checking...", "disabled": "Nonaktif"}
STATUS_EMOJI = {"online": "🟢", "slow": "🟡", "timeout": "🟠",
    "offline": "🔴", "unreachable": "⚫", "error": "⚪",
    "checking": "🔵", "disabled": "⏸"}
STATUS_TAG = {"online": "st_online", "slow": "st_slow", "timeout": "st_timeout",
    "offline": "st_offline", "unreachable": "st_unreach",
    "error": "st_error", "checking": "st_check", "disabled": "st_disabled"}
TAG_COLOR = {"st_online": "#c8e6c9", "st_slow": "#fff9c4",
    "st_timeout": "#ffe0b2", "st_offline": "#ffcdd2",
    "st_unreach": "#e0e0e0", "st_error": "#e0e0e0",
    "st_check": "#bbdefb", "st_disabled": "#eceff1"}
PESAN_MAP = {"online": "Reply normal", "slow": "Latensi tinggi",
    "timeout": "Tidak ada balasan (RTO)", "offline": "Request gagal",
    "unreachable": "Host tidak terjangkau",
    "error": "ping gagal dijalankan", "disabled": "Ping dinonaktifkan"}

# ── Enkripsi JSON (Standard Library Only) ──────────────
def _keystream(key_bytes, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        blk = hashlib.sha256(
            key_bytes + nonce + counter.to_bytes(4, "big")
        ).digest()
        out.extend(blk)
        counter += 1
    return bytes(out[:length])

def encrypt_text(plaintext, secret):
    raw = plaintext.encode("utf-8")
    salt = os.urandom(16)
    nonce = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000, dklen=32)
    ks = _keystream(key, nonce, len(raw))
    cipher = bytes(a ^ b for a, b in zip(raw, ks))
    mac = hmac.new(key, salt + nonce + cipher, hashlib.sha256).digest()
    return base64.b64encode(salt + nonce + mac + cipher).decode("ascii")

def decrypt_text(token, secret):
    blob = base64.b64decode(token.encode("ascii"))
    if len(blob) < 64:
        raise ValueError("Format data tidak valid")
    salt, nonce, mac, cipher = blob[:16], blob[16:32], blob[32:64], blob[64:]
    key = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 100000, dklen=32)
    expected = hmac.new(key, salt + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("Kunci salah atau file rusak")
    ks = _keystream(key, nonce, len(cipher))
    return bytes(a ^ b for a, b in zip(cipher, ks)).decode("utf-8")

def verify_credentials(username, password):
    expected = AUTH_USERS.get(username.strip())
    if expected is None:
        return False
    return hmac.compare_digest(password, expected)

# ── Helper tombol berwarna ─────────────────────────────
def _darken(hex_color, factor=0.82):
    try:
        c = hex_color.lstrip("#")
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        return f"#{int(r*factor):02x}{int(g*factor):02x}{int(b*factor):02x}"
    except Exception:
        return hex_color

def make_btn(parent, text, bg, fg="white", font_size=9,
             padx=10, pady=4, cmd=None, **kw):
    return tk.Button(
        parent, text=text, bg=bg, fg=fg, relief="flat", bd=0,
        font=("Segoe UI", font_size, "bold"),
        padx=padx, pady=pady,
        activebackground=_darken(bg), activeforeground=fg,
        cursor="hand2", command=cmd, **kw)

# ── Sparkline ──────────────────────────────────────────
SPARK_CHARS = "▁▂▃▄▅▆▇█"
SPARK_TIMEOUT = "✕"

def latency_to_spark(lat):
    if lat is None: return SPARK_TIMEOUT
    if lat < 10: return SPARK_CHARS[0]
    elif lat < 30: return SPARK_CHARS[1]
    elif lat < 60: return SPARK_CHARS[2]
    elif lat < 100: return SPARK_CHARS[3]
    elif lat < 200: return SPARK_CHARS[4]
    elif lat < 400: return SPARK_CHARS[5]
    elif lat < 800: return SPARK_CHARS[6]
    else: return SPARK_CHARS[7]

def make_sparkline(hist, width=HISTORY_LEN):
    out = "".join(latency_to_spark(lat) for lat in hist)
    if len(out) < width: out = "·" * (width - len(out)) + out
    elif len(out) > width: out = out[-width:]
    return out

# ── Util & Resource ───────────────────────────────────
def base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def resource_path(filename):
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        bundled = os.path.join(sys._MEIPASS, filename)
        if os.path.exists(bundled):
            return bundled
    return os.path.join(base_dir(), filename)

def apply_icon(win):
    try:
        ico = resource_path(ICON_NAME)
        if not os.path.exists(ico):
            return
        win.iconbitmap(ico)
        if isinstance(win, tk.Tk):
            win.iconbitmap(default=ico)
        if sys.platform == "win32":
            win.update_idletasks()
            import ctypes
            user32 = ctypes.windll.user32
            hwnd = user32.GetParent(win.winfo_id()) or win.winfo_id()
            # 1 = IMAGE_ICON, 0x0010 = LR_LOADFROMFILE, 0x0080 = WM_SETICON
            hicon_big = user32.LoadImageW(0, ico, 1, 32, 32, 0x0010)
            hicon_small = user32.LoadImageW(0, ico, 1, 16, 16, 0x0010)
            if hicon_big:
                user32.SendMessageW(hwnd, 0x0080, 1, hicon_big)   # Ikon Taskbar
            if hicon_small:
                user32.SendMessageW(hwnd, 0x0080, 0, hicon_small) # Ikon Titlebar
    except Exception:
        pass

def center_on_parent(win, parent=None):
    """Posisikan jendela popup presisi di tengah parent atau layar."""
    win.update_idletasks()
    w = win.winfo_width()
    h = win.winfo_height()
    if w <= 1:
        w = win.winfo_reqwidth()
    if h <= 1:
        h = win.winfo_reqheight()
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    try:
        if parent is None or not parent.winfo_viewable():
            raise ValueError("center on screen")
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        if pw < 100 or ph < 100:
            raise ValueError("parent belum tampil")
        x = px + (pw - w) // 2
        y = py + (ph - h) // 2
    except Exception:
        x = (sw - w) // 2
        y = (sh - h) // 2
    x = max(0, min(x, sw - w))
    y = max(0, min(y, sh - h))
    win.geometry(f"+{x}+{y}")

def play_alert_sound(sound_path=""):
    if sound_path and os.path.exists(sound_path):
        ext = os.path.splitext(sound_path)[1].lower()
        if ext == ".wav" and winsound:
            try:
                winsound.PlaySound(
                    sound_path, winsound.SND_FILENAME | winsound.SND_ASYNC)
                return
            except Exception:
                pass
        if sys.platform == "win32":
            try:
                import ctypes
                winmm = ctypes.windll.winmm
                winmm.mciSendStringW("close noc_alert", None, 0, None)
                winmm.mciSendStringW(
                    f'open "{sound_path}" alias noc_alert', None, 0, None)
                winmm.mciSendStringW("play noc_alert", None, 0, None)
                return
            except Exception:
                pass
    if winsound:
        try:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass

CONFIG_PATH   = os.path.join(base_dir(), CONFIG_NAME)
HINTS_PATH    = os.path.join(base_dir(), HINTS_NAME)
SETTINGS_PATH = os.path.join(base_dir(), SETTINGS_NAME)

def load_hosts():
    if not os.path.exists(CONFIG_PATH): return []
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict) and raw.get("protected") and "data" in raw:
            plain = decrypt_text(raw["data"], DATA_SECRET_KEY)
            data = json.loads(plain)
            return data if isinstance(data, list) else []
        if isinstance(raw, list):
            save_hosts(raw)
            return raw
        return []
    except Exception:
        return []

def save_hosts(h):
    payload = {
        "protected": True,
        "v": 1,
        "data": encrypt_text(json.dumps(h, ensure_ascii=False), DATA_SECRET_KEY),
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def load_hints():
    if not os.path.exists(HINTS_PATH): return []
    try:
        with open(HINTS_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("subnets", [])
    except Exception: return []

def save_hints(s):
    with open(HINTS_PATH, "w", encoding="utf-8") as f:
        json.dump({"subnets": s}, f, indent=2)

def load_settings():
    if not os.path.exists(SETTINGS_PATH): return {}
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception: return {}

def save_settings(s):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2, ensure_ascii=False)
    except Exception: pass

def valid_target(s):
    return bool(re.match(r"^[a-zA-Z0-9\.\-_]+$", s))

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80)); return s.getsockname()[0]
    except Exception: return "192.168.1.1"
    finally:
        try: s.close()
        except Exception: pass

def resolve_hostname(ip, timeout=2.0):
    r = [None]
    def w():
        try: r[0] = socket.gethostbyaddr(ip)[0]
        except Exception: pass
    t = threading.Thread(target=w, daemon=True); t.start(); t.join(timeout)
    return r[0] or ""

def expand_cidr(cidr):
    try:
        net, prefix = cidr.split("/")
        prefix = int(prefix)
        if prefix < 20 or prefix > 32: return []
        parts = [int(x) for x in net.split(".")]
        base = (parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3]
        total = 2**(32-prefix)
        start, end = (0, total) if prefix >= 31 else (1, total-1)
        return [f"{(base+i>>24)&0xFF}.{(base+i>>16)&0xFF}."
                f"{(base+i>>8)&0xFF}.{(base+i)&0xFF}"
                for i in range(start, end)]
    except Exception: return []

def parse_range_line(s):
    s = s.strip()
    if not s: return []
    m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$", s)
    if m:
        pre, a, b = m.group(1), int(m.group(2)), int(m.group(3))
        a, b = min(a, b), max(a, b)
        return [f"{pre}.{i}" for i in range(a, b + 1)]
    if re.match(r"^(\d+\.\d+\.\d+\.\d+)/(\d+)$", s):
        return expand_cidr(s)
    return []

# ── Login Dialog ───────────────────────────────────────
class LoginDialog(tk.Toplevel):
    def __init__(self, master, title="Login - NOC NETWORK SSC",
                 subtitle="Silakan masuk dengan akun Anda untuk melanjutkan",
                 btn_text="Masuk"):
        super().__init__(master)
        apply_icon(self)
        self.title(title)
        self.configure(bg="white")
        self.resizable(False, False)
        self.authenticated = False
        self.username = ""
        self._logo_img = None
        self._show_pw = False

        if master.winfo_viewable():
            self.transient(master)
        self.grab_set()

        # Garis aksen biru di atas
        tk.Frame(self, bg="#1565c0", height=5).pack(fill="x")

        container = tk.Frame(self, bg="white", padx=34, pady=24)
        container.pack(fill="both", expand=True)

        # ── Logo SCC ──
        logo_loaded = self._load_logo(size=96)
        if logo_loaded is not None:
            self._logo_img = logo_loaded
            tk.Label(container, image=self._logo_img, bg="white").pack(pady=(0, 10))
        else:
            badge = tk.Frame(container, bg="#1565c0", width=84, height=84)
            badge.pack(pady=(0, 10))
            badge.pack_propagate(False)
            tk.Label(badge, text="SCC", bg="#1565c0", fg="white",
                     font=("Segoe UI", 24, "bold")).pack(expand=True)

        # ── Judul & Keterangan ──
        tk.Label(container, text="NOC NETWORK SSC",
                 bg="white", fg="#1565c0",
                 font=("Segoe UI", 14, "bold")).pack()
        tk.Label(container, text=subtitle,
                 bg="white", fg="#607d8b",
                 font=("Segoe UI", 9), wraplength=330,
                 justify="center").pack(pady=(2, 18))

        # ── Username ──
        tk.Label(container, text="Username", bg="white", fg="#37474f",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        u_box = tk.Frame(container, bg="#cfd8dc", padx=1, pady=1)
        u_box.pack(fill="x", pady=(0, 12))
        u_inner = tk.Frame(u_box, bg="#fafafa")
        u_inner.pack(fill="x")
        self.e_user = tk.Entry(u_inner, font=("Segoe UI", 10), bg="#fafafa",
                               fg="#263238", relief="flat", bd=0,
                               insertbackground="#1565c0")
        self.e_user.pack(fill="x", padx=10, pady=8)
        self.e_user.bind("<FocusIn>", lambda e: u_box.config(bg="#1976d2"))
        self.e_user.bind("<FocusOut>", lambda e: u_box.config(bg="#cfd8dc"))

        # ── Password ──
        tk.Label(container, text="Password", bg="white", fg="#37474f",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        p_box = tk.Frame(container, bg="#cfd8dc", padx=1, pady=1)
        p_box.pack(fill="x", pady=(0, 4))
        p_inner = tk.Frame(p_box, bg="#fafafa")
        p_inner.pack(fill="x")
        self.e_pass = tk.Entry(p_inner, font=("Segoe UI", 10), bg="#fafafa",
                               fg="#263238", relief="flat", bd=0, show="•",
                               insertbackground="#1565c0")
        self.e_pass.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=8)
        self.btn_eye = tk.Button(p_inner, text="Lihat", bg="#fafafa", fg="#607d8b",
                                 activebackground="#fafafa", activeforeground="#1565c0",
                                 relief="flat", bd=0, cursor="hand2",
                                 font=("Segoe UI", 8, "bold"), padx=8,
                                 command=self._toggle_pw)
        self.btn_eye.pack(side="right", pady=4)
        self.e_pass.bind("<FocusIn>", lambda e: p_box.config(bg="#1976d2"))
        self.e_pass.bind("<FocusOut>", lambda e: p_box.config(bg="#cfd8dc"))

        # ── Pesan Error ──
        self.lbl_err = tk.Label(container, text="", bg="white", fg="#d32f2f",
                                font=("Segoe UI", 8), height=1)
        self.lbl_err.pack(anchor="w", pady=(2, 12))

        # ── Tombol ──
        fb = tk.Frame(container, bg="white")
        fb.pack(fill="x")
        make_btn(fb, btn_text, "#1976d2", font_size=10, padx=16, pady=9,
                 cmd=self._submit).pack(side="left", fill="x", expand=True, padx=(0, 8))
        make_btn(fb, "Batal", "#eceff1", fg="#455a64", font_size=10, padx=18, pady=9,
                 cmd=self._cancel).pack(side="right")

        self.e_user.bind("<Return>", lambda e: self.e_pass.focus())
        self.e_pass.bind("<Return>", lambda e: self._submit())
        self.bind("<Escape>", lambda e: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)

        # Ukuran otomatis pas dengan isi (lebar 400px)
        self.update_idletasks()
        self.geometry(f"400x{self.winfo_reqheight()}")
        center_on_parent(self, master if master.winfo_viewable() else None)
        self.e_user.focus_force()

    def _toggle_pw(self):
        self._show_pw = not self._show_pw
        self.e_pass.config(show="" if self._show_pw else "•")
        self.btn_eye.config(text="Tutup" if self._show_pw else "Lihat")

    def _load_logo(self, size=96):
        candidates = ["logo.png", "logo.jpg", "logo.jpeg", ICON_NAME]
        img_path = None
        for name in candidates:
            p = resource_path(name)
            if os.path.exists(p):
                img_path = p
                break
        if not img_path:
            return None

        try:
            from PIL import Image, ImageTk
            im = Image.open(img_path)
            im.thumbnail((size, size), Image.LANCZOS)
            return ImageTk.PhotoImage(im)
        except Exception:
            pass

        if img_path.lower().endswith(".png"):
            try:
                img = tk.PhotoImage(file=img_path)
                w, h = img.width(), img.height()
                if max(w, h) > size:
                    scale = max(1, int(max(w, h) // size))
                    img = img.subsample(scale, scale)
                return img
            except Exception:
                pass
        return None

    def _submit(self):
        u = self.e_user.get().strip()
        p = self.e_pass.get()
        if not u or not p:
            self.lbl_err.config(text="Username dan password wajib diisi.")
            return
        if verify_credentials(u, p):
            self.authenticated = True
            self.username = u
            self.destroy()
        else:
            self.lbl_err.config(text="Username atau password salah!")
            self.e_pass.delete(0, "end")
            self.e_pass.focus()

    def _cancel(self):
        self.authenticated = False
        self.destroy()

# ── Ping ──────────────────────────────────────────────
UNREACHABLE_KEYS = ("unreachable", "tidak dapat dijangkau",
                    "ttl expired", "ttl kedaluwarsa", "destination host")

def _ping_once(ip, timeout_ms):
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]; f = NO_WINDOW
        else:
            cmd = ["ping", "-c", "1", "-W",
                   str(max(1, timeout_ms // 1000)), ip]; f = 0
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout_ms / 1000 + 4, creationflags=f)
        out = ((r.stdout or "") + " " + (r.stderr or "")).lower()
        if any(k in out for k in UNREACHABLE_KEYS):
            return False, out
        if "ttl=" in out or "ttl =" in out:
            return True, out
        return False, out
    except subprocess.TimeoutExpired: return False, "(timeout)"
    except FileNotFoundError: return False, "(ping.exe tidak ada)"
    except Exception as e: return False, f"(error: {e})"

def ping_full(t):
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT_MS), t]; f = NO_WINDOW
        else:
            cmd = ["ping", "-c", "1", "-W", "2", t]; f = 0
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=PING_TIMEOUT_MS / 1000 + 4, creationflags=f)
        raw = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
        out = (r.stdout or "").lower()
        if any(k in out for k in UNREACHABLE_KEYS):
            return "unreachable", None, raw
        if r.returncode == 0 and ("ttl=" in out or "ttl =" in out):
            m = (re.search(r"time[=<]\s*([\d\.]+)\s*ms", out)
                 or re.search(r"time[=<]([\d\.]+)", out))
            lat = float(m.group(1)) if m else None
            if lat is None: return "online", None, raw
            return ("slow" if lat > SLOW_THRESHOLD else "online"), lat, raw
        if ("timed out" in out or "request timed out" in out
                or "waktu permintaan habis" in out):
            return "timeout", None, raw
        return "offline", None, raw
    except subprocess.TimeoutExpired: return "timeout", None, "(ping timeout)"
    except FileNotFoundError: return "error", None, "(ping.exe tidak ada)"
    except Exception as e: return "error", None, f"(ping error: {e})"

def ping_sequence(target, count=PING_SEQUENCE_COUNT):
    try:
        if sys.platform == "win32":
            cmd = ["ping", "-n", str(count), "-w", str(PING_TIMEOUT_MS), target]
            f = NO_WINDOW
        else:
            cmd = ["ping", "-c", str(count), "-W", "2", target]
            f = 0
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=count * (PING_TIMEOUT_MS / 1000 + 2) + 10,
                           creationflags=f)
        return (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
    except subprocess.TimeoutExpired: return "(ping sequence timeout)"
    except FileNotFoundError: return "(ping.exe tidak ditemukan)"
    except Exception as e: return f"(ping sequence error: {e})"

def quick_scan_ip(ip, stop=lambda: False):
    if stop(): return None
    alive, _ = _ping_once(ip, SCAN_TIMEOUT_MS)
    if not alive and not stop():
        alive, _ = _ping_once(ip, SCAN_RETRY_TIMEOUT_MS)
    if not alive: return None
    hn = resolve_hostname(ip)
    if hn:
        return {"ip": ip, "nama": hn.split(".")[0], "hostname": hn, "tipe": "PC"}
    return {"ip": ip, "nama": f"Device-{ip.split('.')[-1]}",
            "hostname": "", "tipe": "Printer"}

def run_tracert(t):
    try:
        if sys.platform == "win32":
            cmd = ["tracert", "-d", "-h", "10", "-w", "500", t]; f = NO_WINDOW
        else:
            cmd = ["traceroute", "-n", "-m", "10", "-w", "1", t]; f = 0
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=45, creationflags=f)
        return (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr else "")
    except subprocess.TimeoutExpired: return "(tracert timeout)"
    except FileNotFoundError: return "(tracert.exe tidak tersedia)"
    except Exception as e: return f"(tracert error: {e})"

# ── Auto-detect ───────────────────────────────────────
def collect_all_targets():
    ips = set(); subnets = set(); sources = {}
    def add_24(prefix):
        if prefix in subnets: return False
        subnets.add(prefix)
        for i in range(1, 255): ips.add(f"{prefix}.{i}")
        return True
    def add_ip(ip):
        if ip.startswith(("127.", "0.", "224.", "239.", "255.", "169.254.")): return
        ips.add(ip)
    hints = load_hints()
    if hints:
        hint_n = 0
        for h in hints:
            expanded = expand_cidr(h)
            for ip in expanded: ips.add(ip)
            if expanded: hint_n += 1
        if hint_n: sources["Hints tersimpan"] = hint_n
    try:
        p = ".".join(get_local_ip().split(".")[:3])
        if add_24(p): sources["Subnet lokal"] = 1
    except Exception: pass
    route_n = 0
    try:
        r = subprocess.run(["route", "print", "-4"], capture_output=True,
                           text=True, timeout=5, creationflags=NO_WINDOW)
        in_t = False
        for line in r.stdout.split("\n"):
            if "IPv4 Route Table" in line: in_t = True; continue
            if not in_t: continue
            if line.strip().startswith("==="): in_t = False; continue
            parts = line.split()
            if len(parts) >= 3 and len(parts[0].split(".")) == 4:
                dest = parts[0]
                if dest in ("0.0.0.0", "127.0.0.0", "255.255.255.255",
                            "224.0.0.0", "239.0.0.0"): continue
                if dest.startswith(("127.", "224.", "239.", "255.")): continue
                try:
                    mask = parts[1]
                    pl = sum(bin(int(x)).count("1") for x in mask.split("."))
                except Exception: continue
                dp = dest.split(".")
                if pl >= 24:
                    if add_24(f"{dp[0]}.{dp[1]}.{dp[2]}"): route_n += 1
                elif pl >= 16:
                    for x in range(1, min(6, 255)):
                        if add_24(f"{dp[0]}.{dp[1]}.{x}"): route_n += 1
    except Exception: pass
    if route_n: sources["Route table"] = route_n
    arp_n = 0
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           timeout=5, creationflags=NO_WINDOW)
        for line in r.stdout.split("\n"):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{14,17})", line)
            if m:
                ip = m.group(1)
                if ip.startswith(("224.", "239.", "255.", "169.254.")): continue
                add_ip(ip)
                parts = ip.split(".")
                add_24(f"{parts[0]}.{parts[1]}.{parts[2]}")
                arp_n += 1
    except Exception: pass
    if arp_n: sources["ARP cache"] = arp_n
    dns_n = 0
    try:
        r = subprocess.run(["ipconfig", "/displaydns"], capture_output=True,
                           text=True, timeout=5, creationflags=NO_WINDOW)
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)", r.stdout):
            ip = m.group(1)
            if ip.startswith(("127.", "0.", "224.", "239.", "255.", "169.254.")):
                continue
            add_ip(ip); dns_n += 1
    except Exception: pass
    if dns_n: sources["DNS cache"] = dns_n
    net_n = 0
    try:
        r = subprocess.run(["netstat", "-n"], capture_output=True, text=True,
                           timeout=5, creationflags=NO_WINDOW)
        for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+):\d+", r.stdout):
            ip = m.group(1)
            if ip.startswith(("127.", "0.", "224.", "239.", "255.", "169.254.")):
                continue
            add_ip(ip); net_n += 1
    except Exception: pass
    if net_n: sources["Netstat"] = net_n
    nv_n = 0
    try:
        r = subprocess.run(["net", "view"], capture_output=True, text=True,
                           timeout=10, creationflags=NO_WINDOW)
        for line in r.stdout.split("\n"):
            m = re.match(r"^\s*\\\\([A-Za-z0-9_\-]+)", line)
            if m:
                try:
                    ip = socket.gethostbyname(m.group(1))
                    if ip and not ip.startswith(("127.", "0.", "169.254.")):
                        add_ip(ip)
                        parts = ip.split(".")
                        add_24(f"{parts[0]}.{parts[1]}.{parts[2]}")
                        nv_n += 1
                except Exception: pass
    except Exception: pass
    if nv_n: sources["net view (domain)"] = nv_n
    if len(subnets) < 5:
        try:
            p = get_local_ip().split(".")
            base_3rd = int(p[2]); added = 0
            for i in range(max(1, base_3rd - 10), min(255, base_3rd + 11)):
                if add_24(f"{p[0]}.{p[1]}.{i}"): added += 1
            if added: sources["Heuristik (tetangga /24)"] = added
        except Exception: pass
    return sorted(ips), sources

# ── ColorTabBar ────────────────────────────────────────
class ColorTabBar(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.tabs_data = {}
        self.frames = {}
        self.buttons = {}
        self.active = None

        self.bar = tk.Frame(self, bg="#f5f5f5")
        self.bar.pack(fill="x")

        self.sep = tk.Frame(self, bg="#cfd8dc", height=2)
        self.sep.pack(fill="x")

        self.content = tk.Frame(self, bg="white")
        self.content.pack(fill="both", expand=True)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

    def add_tab(self, key, label, style, frame):
        self.tabs_data[key] = {"style": style, "label": label}
        self.frames[key] = frame
        btn = tk.Button(
            self.bar, text=label,
            bg=style["bg_inactive"], fg=style["fg_inactive"],
            relief="flat", bd=0,
            font=("Segoe UI", 10, "bold"),
            padx=16, pady=8,
            activebackground=style["bg_active"],
            activeforeground=style["fg_active"],
            cursor="hand2",
            command=lambda k=key: self.select(k))
        btn.pack(side="left", padx=(0, 3), pady=(6, 0))
        self.buttons[key] = btn
        frame.grid(row=0, column=0, sticky="nsew")
        if self.active is None:
            self.select(key)
        else:
            self.frames[self.active].tkraise()

    def select(self, key):
        if self.active == key: return
        self.active = key
        for k, btn in self.buttons.items():
            style = self.tabs_data[k]["style"]
            if k == key:
                btn.config(bg=style["bg_active"], fg=style["fg_active"])
            else:
                btn.config(bg=style["bg_inactive"], fg=style["fg_inactive"])
        self.frames[key].tkraise()

    def get_active(self):
        return self.active or "PC"

# ── ToggleOverlay ─────────────────────────────────────
class ToggleOverlay:
    def __init__(self, app, tree, col_index, col_widths,
                 on_color="#4caf50", off_color="#bdbdbd"):
        self.app = app
        self.tree = tree
        self.col_index = col_index
        self.col_widths = col_widths
        self.col_names = list(tree["columns"])
        self.on_color = on_color
        self.off_color = off_color
        self._dirty = True
        self._last_yview = None
        self._last_click = {}

        col_w = col_widths[col_index]
        self.canvas = tk.Canvas(tree, highlightthickness=0, bd=0,
                                 bg="white", width=col_w, height=1)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<Button-4>", self._on_wheel)
        self.canvas.bind("<Button-5>", self._on_wheel)
        self.canvas.bind("<Enter>", lambda e: self.canvas.config(cursor="hand2"))
        self.canvas.bind("<Leave>", lambda e: self.canvas.config(cursor=""))

        tree.bind("<Configure>", lambda e: self.mark_dirty(), add="+")
        tree.bind("<MouseWheel>", lambda e: self._schedule_redraw(), add="+")

        self._place_overlay()
        tree.after(100, self._poll)

    def _place_overlay(self):
        try:
            col_x = 0
            for i in range(self.col_index):
                col_x += int(self.tree.column(self.col_names[i], "width"))
            col_w = int(self.tree.column(self.col_names[self.col_index], "width"))
            tree_h = self.tree.winfo_height()
            header_h = self._get_header_height()
            self.canvas.place(x=col_x, y=header_h,
                              width=col_w, height=max(1, tree_h - header_h))
        except Exception: pass

    def _get_header_height(self):
        if not self.tree.get_children(): return 28
        for y in range(0, 100, 2):
            try:
                if self.tree.identify_region(10, y) == "cell":
                    return y
            except Exception: pass
        return 28

    def mark_dirty(self):
        self._dirty = True

    def _schedule_redraw(self):
        try: self.tree.after(10, self._redraw)
        except Exception: pass

    def _poll(self):
        try:
            yv = self.tree.yview()
            if self._dirty or yv != self._last_yview:
                self._dirty = False
                self._last_yview = yv
                self._redraw()
        except Exception: pass
        try: self.tree.after(100, self._poll)
        except Exception: pass

    def _redraw(self):
        try:
            self._place_overlay()
            c = self.canvas
            c.delete("all")
            header_h = self._get_header_height()
            col_w = int(self.tree.column(self.col_names[self.col_index], "width"))
            ch = c.winfo_height()
            if ch <= 1: return

            for iid in self.tree.get_children():
                try:
                    bbox = self.tree.bbox(iid, self.col_index)
                except Exception: continue
                if not bbox: continue
                try: _, y, _, h = bbox
                except Exception: continue
                cy = y - header_h
                if cy + h < 0 or cy > ch: continue

                vals = self.tree.item(iid, "values")
                if len(vals) < 4: continue
                ip = vals[3]
                state = self.app.state.get(ip, {}).get("enabled", True)

                tags = self.tree.item(iid, "tags")
                tag = tags[0] if tags else ""
                bg = TAG_COLOR.get(tag, "#ffffff")

                c.create_rectangle(0, cy, col_w, cy + h, fill=bg, outline=bg)
                self._draw_toggle(c, col_w // 2, cy + h // 2, state)

            c.lift()
        except Exception: pass

    def _draw_toggle(self, c, cx, cy, state):
        w, h = 34, 18
        x1 = cx - w // 2
        y1 = cy - h // 2
        x2 = x1 + w
        y2 = y1 + h
        r = h // 2
        color = self.on_color if state else self.off_color
        c.create_oval(x1, y1, x1 + h, y2, fill=color, outline=color)
        c.create_oval(x2 - h, y1, x2, y2, fill=color, outline=color)
        c.create_rectangle(x1 + r, y1, x2 - r, y2, fill=color, outline=color)
        if state:
            kx1 = x2 - h + 2
        else:
            kx1 = x1 + 2
        kx2 = kx1 + h - 4
        c.create_oval(kx1, y1 + 2, kx2, y2 - 2,
                      fill="white", outline="#9e9e9e")

    def _find_row_at(self, y):
        header_h = self._get_header_height()
        for iid in self.tree.get_children():
            try:
                bbox = self.tree.bbox(iid, self.col_index)
            except Exception: continue
            if not bbox: continue
            try: _, ry, _, rh = bbox
            except Exception: continue
            if ry - header_h <= y <= ry - header_h + rh:
                return iid
        return None

    def _on_release(self, e):
        iid = self._find_row_at(e.y)
        if not iid: return
        now = time.time()
        if now - self._last_click.get(iid, 0) < 0.3: return
        self._last_click[iid] = now
        try:
            vals = self.tree.item(iid, "values")
            ip = vals[3]
            self.app._toggle_enabled(ip)
        except Exception: pass

    def _on_wheel(self, e):
        try:
            if getattr(e, "num", 0) == 4: delta = -1
            elif getattr(e, "num", 0) == 5: delta = 1
            else: delta = int(-1 * (e.delta / 120))
            self.tree.yview_scroll(delta, "units")
            self._schedule_redraw()
        except Exception: pass
        return "break"

# ── Info Dialog (?) ────────────────────────────────────
class InfoDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        apply_icon(self)
        self.title("Informasi Penting")
        self.geometry("580x430")
        self.transient(master)
        self.resizable(False, False)
        self.grab_set()

        if winsound:
            try: winsound.MessageBeep(winsound.MB_ICONWARNING)
            except Exception: pass

        header = tk.Frame(self, bg="#1565c0", height=78)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(header, text="ℹ", bg="#1565c0", fg="white",
                 font=("Segoe UI", 30, "bold"))\
            .pack(side="left", padx=(20, 8), pady=8)

        frm_head = tk.Frame(header, bg="#1565c0")
        frm_head.pack(side="left", fill="y", pady=14)
        tk.Label(frm_head, text="INFORMASI PENTING",
                 bg="#1565c0", fg="white",
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(frm_head,
                 text="Mohon dibaca sebelum menggunakan aplikasi",
                 bg="#1565c0", fg="#e3f2fd",
                 font=("Segoe UI", 9)).pack(anchor="w")

        body = tk.Frame(self, bg="white", padx=24, pady=18)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Hallo, TIM SSC 👋",
                 bg="white", fg="#1565c0",
                 font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 12))

        warn_outer = tk.Frame(body, bg="#ffe0b2")
        warn_outer.pack(fill="x", pady=(0, 14))

        warn_inner = tk.Frame(warn_outer, bg="#fff3e0", padx=14, pady=12)
        warn_inner.pack(fill="x", padx=2, pady=2)

        tk.Label(warn_inner, text="🔒  JAGA KERAHASIAAN DATA",
                 bg="#fff3e0", fg="#e65100",
                 font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 6))

        msg = (
            "Informasi topologi, IP address, dan data jaringan "
            "bersifat RAHASIA dan TIDAK BOLEH disebarluaskan "
            "kepada pihak yang tidak berwenang."
        )
        tk.Label(warn_inner, text=msg, bg="#fff3e0", fg="#5d4037",
                 font=("Segoe UI", 10), justify="left",
                 wraplength=480, anchor="w").pack(anchor="w")

        tk.Label(body, text="Terima kasih atas kerja sama Anda.",
                 bg="white", fg="#546e7a",
                 font=("Segoe UI", 9, "italic")).pack(anchor="w")

        btn_frame = tk.Frame(body, bg="white")
        btn_frame.pack(fill="x", side="bottom", pady=(12, 0))
        make_btn(btn_frame, "Mengerti", "#388e3c", font_size=10,
                 padx=20, pady=8, cmd=self.destroy).pack(side="right")

        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self.destroy())

        center_on_parent(self, master)

# ── Toast alert ───────────────────────────────────────
class ToastAlert(tk.Toplevel):
    def __init__(self, master, app, nama, ip, status):
        super().__init__(master)
        self.app = app
        self.overrideredirect(True)
        try: self.attributes("-topmost", True)
        except Exception: pass
        self.entries = [(nama, ip, status)]
        self._timer = None
        self._build(); self._place(); self._schedule()
    def _build(self):
        self.configure(bg="#b71c1c")
        inner = tk.Frame(self, bg="#b71c1c", padx=14, pady=10)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text="⚠  HOST DOWN (RTO)", bg="#b71c1c", fg="white",
                 font=("Segoe UI", 10, "bold")).pack(anchor="w")
        self.body = tk.Label(inner, text="", bg="#b71c1c", fg="white",
                             font=("Consolas", 9), justify="left")
        self.body.pack(anchor="w", pady=(6, 0))
        tk.Label(inner, text="Klik untuk lihat detail", bg="#b71c1c",
                 fg="#ffcdd2", font=("Segoe UI", 8)).pack(anchor="w", pady=(6, 0))
        for w in (self, inner, self.body): w.bind("<Button-1>", self._click)
        self._refresh()
    def _refresh(self):
        self.body.config(text="\n".join(
            f"• {n} ({ip}) — {STATUS_LABEL.get(s, s)}" for n, ip, s in self.entries))
    def _place(self):
        self.update_idletasks()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"+{sw-w-20}+{sh-h-60}")
    def add_entry(self, n, ip, s):
        for i, (_, ipp, _) in enumerate(self.entries):
            if ipp == ip: self.entries[i] = (n, ip, s); break
        else: self.entries.append((n, ip, s))
        self._refresh(); self._place(); self._schedule()
    def remove_entry(self, ip):
        self.entries = [e for e in self.entries if e[1] != ip]
        if not self.entries: self._close(); return
        self._refresh(); self._place(); self._schedule()
    def _click(self, _):
        if self.entries: self.app.open_detail(self.entries[0][1])
        self._close()
    def _schedule(self):
        if self._timer:
            try: self.after_cancel(self._timer)
            except Exception: pass
        self._timer = self.after(10000, self._close)
    def _close(self):
        if self._timer:
            try: self.after_cancel(self._timer)
            except Exception: pass
        try: self.app._toast = None; self.destroy()
        except Exception: pass

# ── Detail Window ─────────────────────────────────────
class DetailWindow(tk.Toplevel):
    def __init__(self, app, ip, nama, tipe):
        super().__init__(app.root)
        apply_icon(self)
        self.app, self.ip, self.nama, self.tipe = app, ip, nama, tipe
        self.title(f"{DEVICE_ICONS.get(tipe, '💻')} Detail: {nama} ({ip})")
        self.geometry("800x620"); self.transient(app.root)
        self._closed = False; self._lp = None; self._lt = None
        self._manual_hold_until = 0.0
        self._cont_running = False
        self._cont_mode = ""
        self._cont_proc = None
        self._cont_stats = {"sent": 0, "recv": 0,
                            "min": None, "max": None, "sum": 0.0}
        self.header = ttk.Label(self, text="", font=("Segoe UI", 10, "bold"))
        self.header.pack(fill="x", padx=10, pady=(8, 4))
        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=10, pady=4)
        f1 = ttk.Frame(nb); nb.add(f1, text="Hasil Ping")
        f1_inner = ttk.Frame(f1); f1_inner.pack(fill="both", expand=True)
        self.txt_p = tk.Text(f1_inner, wrap="word", font=("Consolas", 9),
                              bg="#1e1e1e", fg="#d4d4d4")
        self.txt_p.pack(side="left", fill="both", expand=True)
        s1 = ttk.Scrollbar(f1_inner, command=self.txt_p.yview)
        s1.pack(side="right", fill="y")
        self.txt_p.configure(yscrollcommand=s1.set, state="disabled")
        self.stats_lbl = ttk.Label(f1, text="",
            font=("Consolas", 9), foreground="#37474f",
            background="#eceff1", anchor="w")
        self.stats_lbl.pack(fill="x", padx=2, pady=(2, 2))
        f2 = ttk.Frame(nb); nb.add(f2, text="Hasil Tracert")
        self.txt_t = tk.Text(f2, wrap="word", font=("Consolas", 9), bg="#fafafa")
        self.txt_t.pack(side="left", fill="both", expand=True)
        s2 = ttk.Scrollbar(f2, command=self.txt_t.yview)
        s2.pack(side="right", fill="y")
        self.txt_t.configure(yscrollcommand=s2.set, state="disabled")
        fb = ttk.Frame(self); fb.pack(fill="x", padx=10, pady=8)
        self.btn_4x = make_btn(fb, "Ping", "#0288d1", cmd=self._ping_4x)
        self.btn_4x.pack(side="left", padx=2)
        self.btn_cont = make_btn(fb, "Ping -t",
                                 "#388e3c", cmd=self._toggle_continuous)
        self.btn_cont.pack(side="left", padx=2)
        self.btn_stop_cont = make_btn(fb, "Stop", "#d32f2f",
                                       cmd=self._stop_continuous)
        self.btn_stop_cont.config(state="disabled")
        self.btn_stop_cont.pack(side="left", padx=2)
        make_btn(fb, "Tracert Ulang", "#7b1fa2",
                 cmd=lambda: app.trigger_tracert(ip, True)).pack(side="left", padx=2)
        make_btn(fb, "Tutup", "#757575",
                 cmd=self._close).pack(side="right", padx=2)
        self.protocol("WM_DELETE_WINDOW", self._close)
        center_on_parent(self, app.root)
        self._tick()

    def _set(self, w, c):
        w.configure(state="normal"); w.delete("1.0", "end")
        w.insert("1.0", c); w.configure(state="disabled")

    def _ping_4x(self):
        if self._cont_running:
            messagebox.showinfo("Info",
                "Stop proses ping yang sedang berjalan dulu.",
                parent=self); return
        self._start_stream_ping(continuous=False)

    def _toggle_continuous(self):
        if self._cont_running: self._stop_continuous()
        else: self._start_stream_ping(continuous=True)

    def _start_stream_ping(self, continuous=True):
        if self._cont_running: return
        self._cont_running = True
        self._cont_mode = "-t" if continuous else ""
        self._cont_stats = {"sent": 0, "recv": 0,
                            "min": None, "max": None, "sum": 0.0}
        self._manual_hold_until = time.time() + 999999
        self.btn_cont.config(state="disabled")
        self.btn_4x.config(state="disabled")
        self.btn_stop_cont.config(state="normal")
        self.stats_lbl.config(text="Menjalankan ping...")
        header_txt = (
            f"=== PING -t: {self.ip} ===\n"
            f"(Tekan Stop untuk berhenti)\n\n"
            if continuous else
            f"=== PING: {self.ip} ===\n\n"
        )
        try:
            self.txt_p.configure(state="normal")
            self.txt_p.delete("1.0", "end")
            self.txt_p.insert("1.0", header_txt)
            self.txt_p.configure(state="disabled")
        except Exception: pass
        threading.Thread(
            target=self._run_stream_ping, args=(continuous,), daemon=True
        ).start()

    def _run_stream_ping(self, continuous):
        try:
            if sys.platform == "win32":
                if continuous:
                    cmd = ["ping", "-t", "-w", str(PING_TIMEOUT_MS), self.ip]
                else:
                    cmd = ["ping", "-n", str(PING_SEQUENCE_COUNT),
                           "-w", str(PING_TIMEOUT_MS), self.ip]
                f = NO_WINDOW
            else:
                cmd = (["ping", self.ip] if continuous
                       else ["ping", "-c", str(PING_SEQUENCE_COUNT), "-W", "2", self.ip])
                f = 0
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1, creationflags=f)
            self._cont_proc = proc
            for line in iter(proc.stdout.readline, ""):
                if not self._cont_running: break
                stripped = line.rstrip()
                if not stripped: continue
                self._update_cont_stats(stripped)
                self.app.ui_queue.put(
                    lambda l=stripped: self._append_continuous(l))
            if not self._cont_running:
                try: proc.terminate()
                except Exception: pass
            else:
                try: proc.wait(timeout=5)
                except Exception: pass
        except Exception as e:
            self.app.ui_queue.put(
                lambda: self._append_continuous(f"[error: {e}]"))
        finally:
            self.app.ui_queue.put(
                lambda c=continuous: self._finish_continuous(c))

    def _update_cont_stats(self, line):
        ll = line.lower()
        is_reply = ("ttl=" in ll or "ttl =" in ll)
        is_fail = any(k in ll for k in (
            "timed out", "waktu permintaan habis",
            "unreachable", "tidak dapat dijangkau",
            "host tidak terjangkau", "destination host"))
        if is_reply or is_fail: self._cont_stats["sent"] += 1
        if is_reply:
            self._cont_stats["recv"] += 1
            m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", ll)
            if m:
                try:
                    lat = float(m.group(1))
                    s = self._cont_stats
                    s["min"] = lat if s["min"] is None else min(s["min"], lat)
                    s["max"] = lat if s["max"] is None else max(s["max"], lat)
                    s["sum"] += lat
                except Exception: pass

    def _append_continuous(self, line):
        try:
            self.txt_p.configure(state="normal")
            self.txt_p.insert("end", line + "\n")
            cur = int(self.txt_p.index("end-1c").split(".")[0])
            if cur > 600:
                self.txt_p.delete("1.0", f"{cur - 500}.0")
            self.txt_p.see("end")
            self.txt_p.configure(state="disabled")
            self._render_cont_stats()
        except Exception: pass

    def _render_cont_stats(self):
        s = self._cont_stats
        sent = s["sent"]; recv = s["recv"]
        lost = sent - recv
        loss = (lost / sent * 100) if sent > 0 else 0.0
        avg = (s["sum"] / recv) if recv > 0 else 0.0
        mn = s["min"] if s["min"] is not None else 0.0
        mx = s["max"] if s["max"] is not None else 0.0
        try:
            self.stats_lbl.config(
                text=f"Sent={sent}  Recv={recv}  Lost={lost} ({loss:.1f}%)"
                     f"    Min={mn:.0f}  Avg={avg:.0f}  Max={mx:.0f} ms")
        except Exception: pass

    def _stop_continuous(self):
        if not self._cont_running: return
        self._cont_running = False
        p = self._cont_proc
        if p:
            try: p.terminate()
            except Exception: pass
            try: p.kill()
            except Exception: pass
        self.btn_stop_cont.config(state="disabled")
        try: self._append_continuous("\n=== DIHENTIKAN ===")
        except Exception: pass
        self._render_cont_stats()

    def _finish_continuous(self, was_continuous=True):
        self._cont_running = False
        self._cont_mode = ""
        self._cont_proc = None
        try:
            self.btn_cont.config(state="normal")
            self.btn_4x.config(state="normal")
            self.btn_stop_cont.config(state="disabled")
        except Exception: pass
        self._manual_hold_until = time.time() + (6 if was_continuous else 15)
        self._lp = None
        if not was_continuous:
            self.app.force_ping(self.ip)

    def _tick(self):
        if self._closed: return
        st = self.app.state.get(self.ip)
        if not st: self._close(); return
        h = (f"{DEVICE_ICONS.get(self.tipe, '💻')} {self.tipe}  |  "
             f"Status: {STATUS_LABEL.get(st.get('status', '?'), '?')}")
        if st.get("latency") is not None: h += f"   |   Latency: {int(st['latency'])} ms"
        if st.get("last_check"): h += f"   |   Cek: {st['last_check']}"
        if self._cont_running:
            mode_txt = f" {self._cont_mode}" if self._cont_mode else ""
            h += f"   |   🔴 Ping{mode_txt} berjalan"
        self.header.config(text=h)
        if time.time() >= self._manual_hold_until and not self._cont_running:
            p = st.get("raw_ping") or "(belum ada)"
            if p != self._lp: self._set(self.txt_p, p); self._lp = p
        t = st.get("tracert_text") or "(belum dijalankan — otomatis saat RTO)"
        if t != self._lt: self._set(self.txt_t, t); self._lt = t
        try: self.after(500, self._tick)
        except Exception: pass

    def _close(self):
        if self._closed: return
        self._closed = True
        self._cont_running = False
        if self._cont_proc:
            try: self._cont_proc.terminate()
            except Exception: pass
            try: self._cont_proc.kill()
            except Exception: pass
            self._cont_proc = None
        self.app.popups.pop(self.ip, None)
        try: self.destroy()
        except Exception: pass

# ── Manual Ping Window ────────────────────────────────
class ManualPingWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        apply_icon(self)
        self.app = app
        self.title("Ping Manual (seperti CMD)")
        self.geometry("820x620"); self.transient(app.root)
        self._closed = False
        self._cont_running = False
        self._cont_proc = None
        self._cont_stats = {"sent": 0, "recv": 0,
                            "min": None, "max": None, "sum": 0.0}
        frm = ttk.Frame(self); frm.pack(fill="x", padx=10, pady=10)
        ttk.Label(frm, text="IP / Hostname:").pack(side="left")
        self.e_target = ttk.Entry(frm, width=28, font=("Consolas", 11))
        self.e_target.pack(side="left", padx=5)
        self.e_target.insert(0, "8.8.8.8")
        self.btn_4x = make_btn(frm, "Ping", "#0288d1", cmd=self._ping_4x)
        self.btn_4x.pack(side="left", padx=2)
        self.btn_cont = make_btn(frm, "Ping -t",
                                  "#388e3c", cmd=self._toggle_continuous)
        self.btn_cont.pack(side="left", padx=2)
        self.btn_stop = make_btn(frm, "Stop", "#d32f2f",
                                  cmd=self._stop_continuous)
        self.btn_stop.config(state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        make_btn(frm, "Bersihkan", "#757575",
                 cmd=self._clear).pack(side="right", padx=2)
        txt_frame = ttk.Frame(self)
        txt_frame.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.txt = tk.Text(txt_frame, wrap="word", font=("Consolas", 10),
                            bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        self.txt.pack(side="left", fill="both", expand=True)
        sc = ttk.Scrollbar(txt_frame, orient="vertical", command=self.txt.yview)
        sc.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=sc.set)
        self.stats_lbl = ttk.Label(self, text="",
            font=("Consolas", 9), foreground="#37474f",
            background="#eceff1", anchor="w")
        self.stats_lbl.pack(fill="x", padx=10, pady=(0, 10))
        self.e_target.bind("<Return>", lambda e: self._ping_4x())
        self.protocol("WM_DELETE_WINDOW", self._close)
        center_on_parent(self, app.root)

    def _target(self):
        t = self.e_target.get().strip()
        if not t:
            messagebox.showerror("Error", "Target kosong", parent=self)
            return None
        if not valid_target(t):
            messagebox.showerror("Error", "Target tidak valid", parent=self)
            return None
        return t

    def _clear(self):
        self.txt.configure(state="normal")
        self.txt.delete("1.0", "end")

    def _append(self, text):
        try:
            self.txt.insert("end", text + "\n")
            self.txt.see("end")
        except Exception: pass

    def _set_all(self, text):
        try:
            self.txt.configure(state="normal")
            self.txt.delete("1.0", "end")
            self.txt.insert("1.0", text)
        except Exception: pass

    def _ping_4x(self):
        if self._cont_running:
            messagebox.showinfo("Info", "Stop proses ping yang sedang berjalan dulu.",
                                parent=self); return
        self._start_stream_ping(continuous=False)

    def _toggle_continuous(self):
        if self._cont_running: self._stop_continuous()
        else: self._start_stream_ping(continuous=True)

    def _start_stream_ping(self, continuous=True):
        if self._cont_running: return
        target = self._target()
        if not target: return
        self._cont_running = True
        self._cont_stats = {"sent": 0, "recv": 0,
                            "min": None, "max": None, "sum": 0.0}
        self.btn_4x.config(state="disabled")
        self.btn_cont.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.stats_lbl.config(text="Menjalankan ping...")
        header = (f"=== PING -t ke {target} ===\n\n" if continuous
                  else f"=== PING ke {target} ===\n\n")
        self._set_all(header)
        threading.Thread(target=self._run_stream_ping,
                         args=(target, continuous), daemon=True).start()

    def _run_stream_ping(self, target, continuous):
        try:
            if sys.platform == "win32":
                if continuous:
                    cmd = ["ping", "-t", "-w", str(PING_TIMEOUT_MS), target]
                else:
                    cmd = ["ping", "-n", str(PING_SEQUENCE_COUNT),
                           "-w", str(PING_TIMEOUT_MS), target]
                f = NO_WINDOW
            else:
                cmd = (["ping", target] if continuous
                       else ["ping", "-c", str(PING_SEQUENCE_COUNT), "-W", "2", target])
                f = 0
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1, creationflags=f)
            self._cont_proc = proc
            for line in iter(proc.stdout.readline, ""):
                if not self._cont_running: break
                stripped = line.rstrip()
                if not stripped: continue
                self._update_stats(stripped)
                self.app.ui_queue.put(lambda l=stripped: self._append(l))
                self.app.ui_queue.put(self._render_stats)
            if not self._cont_running:
                try: proc.terminate()
                except Exception: pass
            else:
                try: proc.wait(timeout=5)
                except Exception: pass
        except Exception as e:
            self.app.ui_queue.put(lambda: self._append(f"[error: {e}]"))
        finally:
            self.app.ui_queue.put(self._finish_continuous)

    def _update_stats(self, line):
        ll = line.lower()
        is_reply = ("ttl=" in ll or "ttl =" in ll)
        is_fail = any(k in ll for k in (
            "timed out", "waktu permintaan habis",
            "unreachable", "tidak dapat dijangkau",
            "host tidak terjangkau", "destination host"))
        if is_reply or is_fail: self._cont_stats["sent"] += 1
        if is_reply:
            self._cont_stats["recv"] += 1
            m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", ll)
            if m:
                try:
                    lat = float(m.group(1))
                    s = self._cont_stats
                    s["min"] = lat if s["min"] is None else min(s["min"], lat)
                    s["max"] = lat if s["max"] is None else max(s["max"], lat)
                    s["sum"] += lat
                except Exception: pass

    def _render_stats(self):
        s = self._cont_stats
        sent = s["sent"]; recv = s["recv"]
        lost = sent - recv
        loss = (lost / sent * 100) if sent > 0 else 0.0
        avg = (s["sum"] / recv) if recv > 0 else 0.0
        mn = s["min"] if s["min"] is not None else 0.0
        mx = s["max"] if s["max"] is not None else 0.0
        try:
            self.stats_lbl.config(
                text=f"Sent={sent}  Recv={recv}  Lost={lost} ({loss:.1f}%)"
                     f"    Min={mn:.0f}  Avg={avg:.0f}  Max={mx:.0f} ms")
        except Exception: pass

    def _stop_continuous(self):
        if not self._cont_running: return
        self._cont_running = False
        p = self._cont_proc
        if p:
            try: p.terminate()
            except Exception: pass
            try: p.kill()
            except Exception: pass
        self.btn_stop.config(state="disabled")
        try: self._append("\n=== DIHENTIKAN ===")
        except Exception: pass
        self._render_stats()

    def _finish_continuous(self):
        self._cont_running = False
        self._cont_proc = None
        try:
            self.btn_4x.config(state="normal")
            self.btn_cont.config(state="normal")
            self.btn_stop.config(state="disabled")
        except Exception: pass

    def _close(self):
        if self._closed: return
        self._closed = True
        self._cont_running = False
        if self._cont_proc:
            try: self._cont_proc.terminate()
            except Exception: pass
            try: self._cont_proc.kill()
            except Exception: pass
            self._cont_proc = None
        try: self.destroy()
        except Exception: pass

# ── Test IP ───────────────────────────────────────────
class TestIPDialog(tk.Toplevel):
    def __init__(self, master, app):
        super().__init__(master)
        apply_icon(self)
        self.app = app
        self.title("Test IP (Diagnostik)")
        self.geometry("740x600"); self.transient(master)
        self._hint_frm = None
        frm = ttk.Frame(self); frm.pack(fill="x", padx=10, pady=10)
        ttk.Label(frm, text="IP:").pack(side="left")
        self.e_ip = ttk.Entry(frm, width=25, font=("Consolas", 11))
        self.e_ip.pack(side="left", padx=5)
        self.e_ip.insert(0, "172.17.93.184")
        make_btn(frm, "Test", "#0288d1",
                 cmd=self._test).pack(side="left", padx=5)
        make_btn(frm, "Tutup", "#757575",
                 cmd=self.destroy).pack(side="right", padx=2)
        self.e_ip.bind("<Return>", lambda e: self._test())
        self.txt = tk.Text(self, wrap="word", font=("Consolas", 9), bg="#fafafa")
        self.txt.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.e_ip.focus()
        center_on_parent(self, master)
    def _test(self):
        ip = self.e_ip.get().strip()
        if not valid_target(ip):
            messagebox.showerror("Error", "IP tidak valid", parent=self); return
        self.txt.delete("1.0", "end"); self.txt.insert("end", f"🔍 Menguji {ip}...\n")
        if self._hint_frm:
            try: self._hint_frm.destroy()
            except Exception: pass
            self._hint_frm = None
        threading.Thread(target=self._worker, args=(ip,), daemon=True).start()
    def _worker(self, ip):
        lines = []; need_hint = False
        subnet = ".".join(ip.split(".")[:3]) + ".0/24"
        try:
            targets, sources = collect_all_targets()
            in_t = ip in targets
            lines.append("═══ 1. Target Detection ═══")
            lines.append(f"IP dalam target: {'✓ YA' if in_t else '✗ TIDAK'}")
            lines.append(f"Total target: {len(targets):,}".replace(",", "."))
            lines.append(f"Sumber: {' | '.join(f'{k}: {v}' for k,v in sources.items()) or '(kosong)'}")
            lines.append("")
            lines.append(f"═══ 2. Ping Cepat ({SCAN_TIMEOUT_MS}ms) ═══")
            alive1, raw1 = _ping_once(ip, SCAN_TIMEOUT_MS)
            lines.append(f"Hasil: {'✓ REPLY' if alive1 else '✗ TIMEOUT'}")
            if raw1 and len(raw1) < 400: lines.append(f"Output:\n{raw1.strip()}")
            alive2 = alive1
            if not alive1:
                lines.append("")
                lines.append(f"═══ 3. Ping Retry ({SCAN_RETRY_TIMEOUT_MS}ms) ═══")
                alive2, raw2 = _ping_once(ip, SCAN_RETRY_TIMEOUT_MS)
                lines.append(f"Hasil: {'✓ REPLY' if alive2 else '✗ TIMEOUT'}")
                if raw2 and len(raw2) < 400: lines.append(f"Output:\n{raw2.strip()}")
            hn = resolve_hostname(ip)
            lines.append("")
            lines.append("═══ 4. Reverse DNS ═══")
            lines.append(f"Hostname: {hn or '(tidak ada)'}")
            lines.append("")
            lines.append(f"═══ 5. Ping Berurutan ({PING_SEQUENCE_COUNT}x) ═══")
            lines.append(ping_sequence(ip, PING_SEQUENCE_COUNT))
            lines.append("")
            lines.append("═══ 6. Simulasi Scan ═══")
            r = quick_scan_ip(ip)
            if r: lines.append(f"✓ AKAN DITAMBAHKAN: {r['nama']} ({r['tipe']})")
            else: lines.append("✗ AKAN DILEWATI (tidak merespon)")
            lines.append(""); lines.append("═══ Kesimpulan ═══")
            if not in_t and (alive1 or alive2):
                lines.append(f"🐛 Penyebab: subnet {subnet} tidak terdeteksi")
                lines.append(f"💡 Solusi: tambahkan hint subnet {subnet}")
                need_hint = True
            elif in_t and not (alive1 or alive2):
                lines.append("⚠ IP dalam target tapi tidak merespon → cek firewall")
            elif in_t and (alive1 or alive2):
                lines.append("✓ Normal: akan muncul di scan")
            else:
                lines.append("⚠ IP tidak dalam target dan tidak merespon → cek koneksi")
        except Exception as e:
            lines.append(f"ERROR: {e}")
        self.app.ui_queue.put(lambda: self._show("\n".join(lines)))
        if need_hint:
            self.app.ui_queue.put(lambda: self._show_hint(subnet))
    def _show(self, text):
        try: self.txt.delete("1.0", "end"); self.txt.insert("1.0", text)
        except Exception: pass
    def _show_hint(self, subnet):
        if self._hint_frm:
            try: self._hint_frm.destroy()
            except Exception: pass
        self._hint_frm = ttk.Frame(self)
        self._hint_frm.pack(fill="x", padx=10, pady=(0, 10))
        def add():
            hints = load_hints()
            if subnet not in hints: hints.append(subnet); save_hints(hints)
            messagebox.showinfo("Berhasil", f"Subnet {subnet} ditambahkan.",
                                parent=self)
            try: self._hint_frm.destroy()
            except Exception: pass
            self._hint_frm = None
        make_btn(self._hint_frm, f"Simpan hint {subnet}", "#388e3c",
                 cmd=add).pack(side="left", padx=2)

# ── Scan Window ───────────────────────────────────────
class ScanWindow(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app.root)
        apply_icon(self)
        self.app = app
        self.title("Scan Jaringan")
        self.geometry("1020x880"); self.transient(app.root)
        self.results = []; self.scanning = False; self._stop = False
        self._auto_targets = []; self._auto_sources = {}
        nb = ttk.Notebook(self); nb.pack(fill="x", padx=10, pady=(10, 5))
        frm_auto = ttk.Frame(nb); nb.add(frm_auto, text="Scan Otomatis")
        ttk.Label(frm_auto,
            text="Deteksi otomatis dari route table, ARP, DNS cache, netstat, net view, hints.",
            foreground="#607d8b", font=("Segoe UI", 9))\
            .pack(anchor="w", padx=8, pady=(8, 4))
        self.lbl_sources = ttk.Label(frm_auto, text="Mendeteksi sumber...",
                                     foreground="#455a64", font=("Segoe UI", 9))
        self.lbl_sources.pack(fill="x", padx=8, pady=(0, 6))
        frm_auto_btn = ttk.Frame(frm_auto)
        frm_auto_btn.pack(fill="x", padx=8, pady=(0, 8))
        make_btn(frm_auto_btn, "Deteksi Ulang", "#f57c00",
                 cmd=self._detect_auto).pack(side="left", padx=2)
        make_btn(frm_auto_btn, "Mulai Scan Otomatis", "#1976d2",
                 cmd=self._scan_auto).pack(side="left", padx=2)
        make_btn(frm_auto_btn, "Test IP", "#7b1fa2",
                 cmd=lambda: TestIPDialog(self, self.app)).pack(side="left", padx=2)
        make_btn(frm_auto_btn, "Kelola Hints", "#00796b",
                 cmd=self._manage_hints).pack(side="left", padx=2)
        frm_manual = ttk.Frame(nb); nb.add(frm_manual, text="Scan Manual Range")
        ttk.Label(frm_manual, text="Masukkan range IP (satu per baris):",
                  font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(8, 2))
        ttk.Label(frm_manual, text="Format: 10.1.1.1-254  atau  10.1.1.0/24",
                  foreground="#666", font=("Segoe UI", 8)).pack(anchor="w", padx=8)
        self.txt_range = tk.Text(frm_manual, height=5, font=("Consolas", 10))
        self.txt_range.pack(fill="x", padx=8, pady=4)
        self.txt_range.insert("1.0", "10.1.1.1-254\n10.2.1.0/24\n10.3.5.1-100")
        frm_mb = ttk.Frame(frm_manual); frm_mb.pack(fill="x", padx=8, pady=(4, 8))
        make_btn(frm_mb, "Mulai Scan Manual", "#1976d2",
                 cmd=self._scan_manual).pack(side="left", padx=2)
        make_btn(frm_mb, "Bersihkan", "#757575",
                 cmd=lambda: self.txt_range.delete("1.0", "end"))\
            .pack(side="left", padx=2)
        frm_prog = ttk.Frame(self); frm_prog.pack(fill="x", padx=10, pady=(5, 3))
        self.progress = ttk.Progressbar(frm_prog, mode="determinate")
        self.progress.pack(fill="x")
        self.lbl_status = ttk.Label(frm_prog, text="Bersiap...")
        self.lbl_status.pack(fill="x", pady=(3, 0))
        frm_filter = ttk.LabelFrame(self, text="Filter Hasil Scan")
        frm_filter.pack(fill="x", padx=10, pady=(5, 0))
        row1 = ttk.Frame(frm_filter); row1.pack(fill="x", padx=6, pady=4)
        ttk.Label(row1, text="Subnet:").pack(side="left")
        self.subnet_var = tk.StringVar(value="Semua")
        self.subnet_combo = ttk.Combobox(row1, textvariable=self.subnet_var,
                                          values=["Semua"], width=22,
                                          state="readonly")
        self.subnet_combo.pack(side="left", padx=5)
        self.subnet_combo.bind("<<ComboboxSelected>>",
                                lambda e: self._apply_filters())
        make_btn(row1, "Refresh", "#607d8b", padx=8,
                 cmd=self._refresh_subnet_combo).pack(side="left", padx=2)
        ttk.Label(row1, text="Cari:").pack(side="left", padx=(15, 0))
        self.text_filter_var = tk.StringVar()
        self.text_filter_var.trace_add("write", lambda *a: self._apply_filters())
        ttk.Entry(row1, textvariable=self.text_filter_var,
                  width=22).pack(side="left", padx=5)
        make_btn(row1, "Search", "#757575", padx=8,
                 cmd=lambda: self.text_filter_var.set(""))\
            .pack(side="left", padx=2)
        ttk.Label(self, text="Hasil (otomatis + manual digabung):",
                  foreground="#37474f", font=("Segoe UI", 9, "bold"))\
            .pack(anchor="w", padx=10, pady=(8, 0))
        ttk.Label(self, text="Klik kanan baris hasil → ubah tipe",
                  foreground="#888", font=("Segoe UI", 8)).pack(anchor="w", padx=10)
        frm_tree = ttk.Frame(self); frm_tree.pack(fill="both", expand=True,
                                                   padx=10, pady=5)
        cols = ("sel", "tipe", "nama", "ip", "hostname")
        self.tree = ttk.Treeview(frm_tree, columns=cols, show="headings")
        for c, t, w, a in [("sel", "✓", 40, "center"),
                           ("tipe", "Tipe", 70, "center"),
                           ("nama", "Nama", 200, "w"),
                           ("ip", "IP", 140, "w"),
                           ("hostname", "Hostname", 280, "w")]:
            self.tree.heading(c, text=t); self.tree.column(c, width=w, anchor=a)
        sc = ttk.Scrollbar(frm_tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sc.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sc.pack(side="right", fill="y")
        self.tree.bind("<Button-1>", self._res_click)
        self.tree.bind("<Button-3>", self._res_right_click)
        frm_btn = ttk.Frame(self); frm_btn.pack(fill="x", padx=10, pady=(5, 10))
        make_btn(frm_btn, "Pilih Semua", "#607d8b",
                 cmd=self._sel_all).pack(side="left", padx=2)
        make_btn(frm_btn, "Kosongkan", "#607d8b",
                 cmd=self._desel_all).pack(side="left", padx=2)
        self.btn_stop = make_btn(frm_btn, "Stop", "#d32f2f",
                                  cmd=self._stop_scan)
        self.btn_stop.config(state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        make_btn(frm_btn, "Tutup", "#757575",
                 cmd=self._close).pack(side="right", padx=2)
        make_btn(frm_btn, "Tambah Ke Monitor", "#388e3c",
                 cmd=self._add_sel).pack(side="right", padx=2)
        self.protocol("WM_DELETE_WINDOW", self._close)
        center_on_parent(self, app.root)
        self.after(300, self._detect_auto)

    def _detect_auto(self):
        if self.scanning: return
        self.lbl_sources.config(text="Mendeteksi sumber...")
        threading.Thread(target=self._run_detect, daemon=True).start()
    def _run_detect(self):
        try:
            targets, sources = collect_all_targets()
            self._auto_targets = targets
            self._auto_sources = sources
            src = " | ".join(f"{k}: {v}" for k, v in sources.items()) or "tidak ada"
            self.app.ui_queue.put(lambda: self.lbl_sources.config(
                text=f"📍 {len(targets):,} IP dari: {src}".replace(",", ".")))
            self.app.ui_queue.put(self._refresh_subnet_combo)
        except Exception as e:
            self._auto_targets = []
            self.app.ui_queue.put(lambda: self.lbl_sources.config(text=f"⚠ {e}"))
    def _scan_auto(self):
        if self.scanning:
            messagebox.showinfo("Info", "Scan sedang berjalan", parent=self); return
        if not self._auto_targets:
            self._detect_auto()
            messagebox.showinfo("Info",
                "Sedang mendeteksi target, klik lagi sebentar.", parent=self); return
        self._start_scan(self._auto_targets, "otomatis")
    def _scan_manual(self):
        if self.scanning:
            messagebox.showinfo("Info", "Scan sedang berjalan", parent=self); return
        content = self.txt_range.get("1.0", "end").strip()
        if not content:
            messagebox.showerror("Error", "Range kosong", parent=self); return
        ips = []; invalid = []
        for line in content.split("\n"):
            line = line.strip()
            if not line: continue
            r = parse_range_line(line)
            if r: ips.extend(r)
            else: invalid.append(line)
        ips = list(dict.fromkeys(ips))
        if not ips:
            messagebox.showerror("Error",
                "Tidak ada IP valid.\nContoh: 10.1.1.1-254 atau 10.1.1.0/24",
                parent=self); return
        if invalid:
            msg = (f"{len(invalid)} baris invalid:\n" + "\n".join(invalid[:5]) +
                   ("..." if len(invalid) > 5 else "") +
                   f"\n\nLanjut scan {len(ips):,} IP?".replace(",", "."))
            if not messagebox.askyesno("Peringatan", msg, parent=self): return
        self._start_scan(ips, "manual")
    def _start_scan(self, ips, mode):
        if len(ips) > MAX_SCAN_IPS:
            messagebox.showerror("Error",
                f"Terlalu banyak: {len(ips):,} IP (maks {MAX_SCAN_IPS:,})."
                .replace(",", "."), parent=self); return
        for iid in self.tree.get_children(): self.tree.delete(iid)
        self.results.clear()
        self.scanning = True; self._stop = False
        self.btn_stop.config(state="normal", text="Stop")
        self.progress["maximum"] = len(ips); self.progress["value"] = 0
        self.lbl_status.config(
            text=f"Scanning ({mode}): {len(ips):,} IP...".replace(",", "."))
        threading.Thread(target=self._run_scan, args=(ips, mode),
                         daemon=True).start()
    def _stop_scan(self):
        self._stop = True
        self.btn_stop.config(state="disabled", text="Stopping...")
    def _run_scan(self, ips, mode):
        n = len(ips); done = found = 0
        try:
            with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
                futs = {ex.submit(quick_scan_ip, ip, lambda: self._stop): ip
                        for ip in ips}
                for fut in as_completed(futs):
                    if self._stop: break
                    done += 1
                    try: r = fut.result()
                    except Exception: r = None
                    if r:
                        found += 1
                        self.app.ui_queue.put(lambda rr=r: self._add_result(rr))
                    if done % 20 == 0 or done == n:
                        self.app.ui_queue.put(
                            lambda d=done, t=n, f=found: self._upd_prog(d, t, f))
        except Exception: pass
        self.app.ui_queue.put(self._done)
    def _upd_prog(self, d, t, f):
        try:
            self.progress["value"] = d
            self.lbl_status.config(
                text=f"Scan: {d:,}/{t:,} — ditemukan {f} host".replace(",", "."))
        except Exception: pass
    def _done(self):
        self.scanning = False; self._stop = False
        try:
            self.btn_stop.config(state="disabled", text="Stop")
            self.lbl_status.config(
                text=f"Selesai. Total di tabel: {len(self.results)} host.")
            self._refresh_subnet_combo()
        except Exception: pass
    def _add_result(self, r):
        if any(x["ip"] == r["ip"] for x in self.results): return
        self.results.append(r)
        try:
            iid = self.tree.insert("", "end",
                values=("☐", DEVICE_ICONS.get(r["tipe"], "💻"),
                        r["nama"], r["ip"], r.get("hostname") or "-"))
            if not self._row_matches(iid, r["ip"]):
                self.tree.detach(iid)
        except Exception: pass
    def _row_matches(self, iid, ip):
        sf = self.subnet_var.get()
        tf = self.text_filter_var.get().lower().strip()
        if sf and sf != "Semua":
            prefix = sf.rsplit(".", 1)[0] + "."
            if not ip.startswith(prefix): return False
        if tf:
            try:
                text = " ".join(str(x) for x in self.tree.item(iid, "values")).lower()
                if tf not in text: return False
            except Exception: return True
        return True
    def _apply_filters(self):
        for iid in self.tree.get_children():
            try:
                v = self.tree.item(iid, "values")
                ip = v[3] if len(v) > 3 else ""
                if self._row_matches(iid, ip):
                    self.tree.reattach(iid, "", "end")
                else:
                    self.tree.detach(iid)
            except Exception: pass
    def _refresh_subnet_combo(self):
        prefixes = set()
        for r in self.results:
            prefixes.add(".".join(r["ip"].split(".")[:3]) + ".0/24")
        for ip in self._auto_targets[:3000]:
            prefixes.add(".".join(ip.split(".")[:3]) + ".0/24")
        vals = ["Semua"] + sorted(prefixes)
        try:
            self.subnet_combo["values"] = vals
            if self.subnet_var.get() not in vals:
                self.subnet_var.set("Semua")
        except Exception: pass
    def _res_click(self, e):
        if self.tree.identify_region(e.x, e.y) != "cell": return
        if self.tree.identify_column(e.x) != "#1": return
        row = self.tree.identify_row(e.y)
        if not row: return
        v = list(self.tree.item(row, "values"))
        for rr in self.results:
            if rr["ip"] == v[3]:
                rr["selected"] = not rr.get("selected", False)
                v[0] = "☑" if rr["selected"] else "☐"
                self.tree.item(row, values=v); return
    def _res_right_click(self, e):
        row = self.tree.identify_row(e.y)
        if not row: return
        self.tree.selection_set(row)
        menu = tk.Menu(self, tearoff=0)
        for tipe in DEVICE_LIST:
            menu.add_command(
                label=f"Tandai: {DEVICE_ICONS[tipe]} {tipe}",
                command=lambda t=tipe, r=row: self._change_type(r, t))
        menu.tk_popup(e.x_root, e.y_root)
    def _change_type(self, iid, tipe):
        try: v = list(self.tree.item(iid, "values"))
        except Exception: return
        for rr in self.results:
            if rr["ip"] == v[3]:
                rr["tipe"] = tipe
                v[1] = DEVICE_ICONS.get(tipe, "💻")
                self.tree.item(iid, values=v)
                return
    def _sel_all(self):
        for iid in self.tree.get_children():
            v = list(self.tree.item(iid, "values"))
            for rr in self.results:
                if rr["ip"] == v[3]:
                    rr["selected"] = True; v[0] = "☑"
                    self.tree.item(iid, values=v)
    def _desel_all(self):
        for iid in self.tree.get_children():
            v = list(self.tree.item(iid, "values"))
            for rr in self.results:
                if rr["ip"] == v[3]:
                    rr["selected"] = False; v[0] = "☐"
                    self.tree.item(iid, values=v)
    def _add_sel(self):
        sel = [r for r in self.results if r.get("selected")]
        if not sel:
            messagebox.showinfo("Info", "Pilih minimal 1 host", parent=self); return
        added = skipped = 0
        with self.app.lock:
            existing = {h["ip"] for h in self.app.hosts}
            for r in sel:
                if r["ip"] in existing: skipped += 1; continue
                self.app.hosts.append(
                    {"nama": r["nama"], "ip": r["ip"], "tipe": r["tipe"],
                     "enabled": True})
                existing.add(r["ip"]); added += 1
            if added: save_hosts(self.app.hosts)
        for r in sel:
            if r["ip"] in self.app.rows: continue
            if not any(h["ip"] == r["ip"] for h in self.app.hosts): continue
            self.app._init_state(r["ip"], r["tipe"], True)
            self.app._insert_row(r["nama"], r["ip"], r["tipe"], True)
        self.app._apply_search(); self.app._queue_summary()
        messagebox.showinfo("Selesai",
            f"{added} ditambahkan, {skipped} duplikat dilewati.", parent=self)
    def _manage_hints(self):
        dlg = tk.Toplevel(self)
        apply_icon(dlg)
        dlg.title("Kelola Subnet Hints"); dlg.geometry("520x420")
        dlg.transient(self); dlg.grab_set()
        ttk.Label(dlg, text="Subnet yang selalu di-scan (satu per baris):",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=(10, 3))
        ttk.Label(dlg, text="Format: 172.17.93.0/24",
                  foreground="#666").pack(anchor="w", padx=10)
        txt = tk.Text(dlg, height=12, font=("Consolas", 10))
        txt.pack(fill="both", expand=True, padx=10, pady=8)
        txt.insert("1.0", "\n".join(load_hints())); txt.focus()
        def save():
            valid = []; invalid = []
            for line in txt.get("1.0", "end").split("\n"):
                line = line.strip()
                if not line: continue
                m = re.match(r"^(\d+\.\d+\.\d+\.\d+)/(\d+)$", line)
                if m and 20 <= int(m.group(2)) <= 32: valid.append(line)
                else: invalid.append(line)
            save_hints(valid)
            msg = f"✓ {len(valid)} hint disimpan."
            if invalid: msg += f"\n⚠ {len(invalid)} baris invalid"
            messagebox.showinfo("Hasil", msg, parent=dlg); dlg.destroy()
        frm = ttk.Frame(dlg); frm.pack(pady=8)
        make_btn(frm, "Simpan", "#388e3c",
                 cmd=save).pack(side="left", padx=5)
        make_btn(frm, "Batal", "#757575",
                 cmd=dlg.destroy).pack(side="left", padx=5)
        center_on_parent(dlg, self)
    def _close(self):
        self._stop = True
        self.app.scan_window = None
        try: self.destroy()
        except Exception: pass

# ── Aplikasi utama ─────────────────────────────────────
class App:
    def __init__(self, root):
        self.root = root
        apply_icon(root)
        root.title("NOC NETWORK SSC")
        root.geometry("1180x840")
        self.lock = threading.Lock()
        self.hosts = load_hosts()
        self.settings = load_settings()
        self.trees = {}
        self.rows = {}
        self.state = {}; self.popups = {}
        self.ui_queue = queue.Queue()
        self.running = True; self._toast = None
        self.scan_window = None
        self.manual_ping_window = None
        self.overlays = {}

        # Form tambah + tombol Naik/Turun di pojok kanan sejajar toolbar bawah
        frm = ttk.LabelFrame(root, text="Tambah Host Baru")
        frm.pack(fill="x", padx=10, pady=(10, 5))
        frm.grid_columnconfigure(7, weight=1)

        ttk.Label(frm, text="Nama:").grid(row=0, column=0, padx=5, pady=6, sticky="e")
        self.e_nama = ttk.Entry(frm, width=20, font=("Segoe UI", 10))
        self.e_nama.grid(row=0, column=1, padx=5, pady=6)
        ttk.Label(frm, text="IP:").grid(row=0, column=2, padx=5, pady=6, sticky="e")
        self.e_ip = ttk.Entry(frm, width=16, font=("Segoe UI", 10))
        self.e_ip.grid(row=0, column=3, padx=5, pady=6)
        ttk.Label(frm, text="Tipe:").grid(row=0, column=4, padx=5, pady=6, sticky="e")
        self.cb_tipe = ttk.Combobox(frm, values=DEVICE_LIST, width=10,
                                     state="readonly", font=("Segoe UI", 10))
        self.cb_tipe.set("PC"); self.cb_tipe.grid(row=0, column=5, padx=5, pady=6)
        make_btn(frm, "+ Tambah", "#388e3c",
                 cmd=self.add_host).grid(row=0, column=6, padx=5, pady=6)

        make_btn(frm, "▲ Naik", "#546e7a", padx=10,
                 cmd=lambda: self.move_selected(-1))\
            .grid(row=0, column=8, padx=2, pady=6, sticky="e")
        make_btn(frm, "▼ Turun", "#546e7a", padx=10,
                 cmd=lambda: self.move_selected(1))\
            .grid(row=0, column=9, padx=(2, 2), pady=6, sticky="e")

        self.e_nama.bind("<Return>", lambda e: self.e_ip.focus())
        self.e_ip.bind("<Return>", lambda e: self.add_host())
        self.e_nama.focus()

        # Toolbar atas
        frm_s = ttk.Frame(root); frm_s.pack(fill="x", padx=10, pady=(0, 5))
        ttk.Label(frm_s, text="Cari:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *a: self._apply_search())
        ttk.Entry(frm_s, textvariable=self.search_var, width=22)\
            .pack(side="left", padx=5)
        make_btn(frm_s, "Search", "#757575", padx=8,
                 cmd=lambda: self.search_var.set("")).pack(side="left", padx=2)
        make_btn(frm_s, "Scan Jaringan", "#1976d2",
                 cmd=self.open_scan).pack(side="right", padx=2)
        make_btn(frm_s, "Ping Manual", "#0288d1",
                 cmd=self.open_manual_ping).pack(side="right", padx=2)
        make_btn(frm_s, "Import", "#f57c00",
                 cmd=self.import_hosts).pack(side="right", padx=2)
        make_btn(frm_s, "Export", "#7b1fa2",
                 cmd=self.export_hosts).pack(side="right", padx=2)
        make_btn(frm_s, "Info", "#455a64",
                 cmd=lambda: InfoDialog(self.root)).pack(side="right", padx=2)

        # ColorTabBar
        self.tab_bar = ColorTabBar(root)
        self.tab_bar.pack(fill="both", expand=True, padx=10, pady=(0, 5))

        for tipe in DEVICE_LIST:
            frame = tk.Frame(self.tab_bar.content, bg="white")
            inner = tk.Frame(frame, bg="white")
            inner.pack(fill="both", expand=True)

            tree = ttk.Treeview(inner, columns=COL_NAMES, show="headings")
            for c, t, w, a in COL_DEFS:
                heading_text = tipe if c == "ikon" else t
                tree.heading(c, text=heading_text, anchor="center")
                tree.column(c, width=w,
                            anchor="center" if c in ("aktif", "ikon", "status") else "w")

            sc = ttk.Scrollbar(inner, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=sc.set)
            tree.pack(side="left", fill="both", expand=True)
            sc.pack(side="right", fill="y")
            for tag, color in TAG_COLOR.items():
                tree.tag_configure(tag, background=color)
            tree.bind("<Double-1>", self._on_dbl)
            tree.bind("<Button-1>", self._on_tree_click)
            tree.bind("<Delete>", lambda e: self.del_selected())

            self.tab_bar.add_tab(tipe, f"{DEVICE_ICONS.get(tipe, '')} {tipe}",
                                 TAB_STYLES[tipe], frame)
            self.trees[tipe] = tree

        self.root.after(500, self._init_overlays)

        ttk.Label(root,
            text="Tips: Klik toggle di kolom 'Aktif' untuk enable/disable ping. "
                 "Gunakan ▲ Naik / ▼ Turun untuk urutkan target. Klik kanan tombol 'Suara' untuk reset ke default.",
            foreground="#607d8b").pack(fill="x", padx=12, pady=(4, 0))

        frm_b = ttk.Frame(root); frm_b.pack(fill="x", padx=10, pady=8)
        make_btn(frm_b, "Detail", "#0288d1",
                 cmd=self.detail_selected).pack(side="left", padx=2)
        make_btn(frm_b, "Edit", "#f57c00",
                 cmd=self.edit_selected).pack(side="left", padx=2)
        make_btn(frm_b, "Hapus", "#d32f2f",
                 cmd=self.del_selected).pack(side="left", padx=2)
        self.alerts_on = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm_b, text="Alert suara",
                        variable=self.alerts_on).pack(side="left", padx=(8, 2))
        self.btn_sound = make_btn(frm_b, self._sound_btn_label(), "#00897b",
                                  padx=10, cmd=self.choose_alert_sound)
        self.btn_sound.pack(side="left", padx=2)
        self.btn_sound.bind("<Button-3>", lambda e: self.reset_alert_sound())

        self.info = ttk.Label(frm_b, text="Memuat..."); self.info.pack(side="right")
        self.summary = ttk.Label(root, text="", foreground="#37474f")
        self.summary.pack(fill="x", padx=12, pady=(0, 8))

        for h in self.hosts:
            tipe = h.get("tipe", "PC")
            if tipe not in DEVICE_LIST: tipe = "PC"
            enabled = h.get("enabled", True)
            self._init_state(h["ip"], tipe, enabled)
            self._insert_row(h["nama"], h["ip"], tipe, enabled)

        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(80, self._drain)
        threading.Thread(target=self._loop, daemon=True).start()

        self.root.after(600, self._show_startup_info)

    def _sound_btn_label(self):
        p = self.settings.get("alert_sound", "")
        if p and os.path.exists(p):
            name = os.path.basename(p)
            if len(name) > 14: name = name[:11] + "..."
            return f"Browse Files: {name}"
        return "Browse Files"

    def choose_alert_sound(self):
        path = filedialog.askopenfilename(
            title="Pilih Suara Alert (.wav / .mp3)",
            filetypes=[("Audio Files", "*.wav *.mp3"),
                       ("WAV", "*.wav"), ("MP3", "*.mp3"), ("All files", "*.*")])
        if not path: return
        self.settings["alert_sound"] = path
        save_settings(self.settings)
        self.btn_sound.config(text=self._sound_btn_label())
        play_alert_sound(path)

    def reset_alert_sound(self):
        if not self.settings.get("alert_sound"): return
        if messagebox.askyesno("Reset Suara",
                               "Kembalikan suara alert ke bunyi default Windows?"):
            self.settings.pop("alert_sound", None)
            save_settings(self.settings)
            self.btn_sound.config(text=self._sound_btn_label())
            play_alert_sound("")

    def move_selected(self, direction):
        tipe, tree = self._active_tree()
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Pilih baris IP Monitor yang ingin dipindahkan")
            return
        iid = sel[0]
        children = list(tree.get_children())
        if iid not in children: return
        idx = children.index(iid)
        target_idx = idx + direction
        if target_idx < 0 or target_idx >= len(children): return

        other_iid = children[target_idx]
        v1 = tree.item(iid, "values")
        v2 = tree.item(other_iid, "values")
        if len(v1) < 4 or len(v2) < 4: return
        ip1, ip2 = v1[3], v2[3]

        with self.lock:
            i1 = next((i for i, h in enumerate(self.hosts) if h["ip"] == ip1), None)
            i2 = next((i for i, h in enumerate(self.hosts) if h["ip"] == ip2), None)
            if i1 is not None and i2 is not None:
                self.hosts[i1], self.hosts[i2] = self.hosts[i2], self.hosts[i1]
                save_hosts(self.hosts)

        tree.move(iid, "", target_idx)
        tree.selection_set(iid)
        tree.see(iid)
        self._mark_overlay(tipe)

    def _show_startup_info(self):
        try:
            self.root.lift()
            self.root.focus_force()
        except Exception: pass
        try:
            InfoDialog(self.root)
        except Exception as e:
            print(f"Startup info error: {e}")

    def _init_overlays(self):
        try:
            for tipe, tree in self.trees.items():
                ov = ToggleOverlay(self, tree, col_index=AKTIF_INDEX,
                                    col_widths=COL_WIDTHS)
                self.overlays[tipe] = ov
        except Exception as e:
            print(f"Overlay init error: {e}")

    def _mark_overlay(self, tipe=None):
        if tipe and tipe in self.overlays:
            try: self.overlays[tipe].mark_dirty()
            except Exception: pass
        else:
            for ov in self.overlays.values():
                try: ov.mark_dirty()
                except Exception: pass

    def _init_state(self, ip, tipe="PC", enabled=True):
        with self.lock:
            self.state[ip] = {"status": "checking", "latency": None,
                "raw_ping": "", "pesan": "Menunggu", "last_check": "",
                "tracert_text": "", "tracert_running": False,
                "last_tracert_trigger": 0.0, "tipe": tipe,
                "prev_status": "checking",
                "rto_start": 0.0, "last_rto_alert_time": 0.0,
                "latency_history": [], "enabled": enabled}

    def _insert_row(self, nama, ip, tipe="PC", enabled=True):
        if tipe not in self.trees: tipe = "PC"
        tree = self.trees[tipe]
        empty_spark = "·" * HISTORY_LEN
        tag = "st_check" if enabled else "st_disabled"
        status_str = "🔵 Checking..." if enabled else "⏸ Nonaktif"
        iid = tree.insert("", "end",
            values=("", DEVICE_ICONS.get(tipe, "💻"), nama, ip,
                    status_str, f"-  {empty_spark}",
                    "Menunggu" if enabled else "Ping dinonaktifkan"),
            tags=(tag,))
        self.rows[ip] = (tipe, iid)
        self._mark_overlay(tipe)
        return iid

    def _active_tree(self):
        try:
            tipe = self.tab_bar.get_active()
            return tipe, self.trees[tipe]
        except Exception:
            return "PC", self.trees["PC"]

    def _drain(self):
        try:
            for _ in range(200):
                try: fn = self.ui_queue.get_nowait()
                except queue.Empty: break
                try: fn()
                except Exception: pass
        finally:
            if self.running:
                try: self.root.after(80, self._drain)
                except Exception: pass

    def _on_tree_click(self, event):
        tree = event.widget
        region = tree.identify_region(event.x, event.y)
        if region != "cell": return
        col = tree.identify_column(event.x)
        if col != "#1": return
        row = tree.identify_row(event.y)
        if not row: return
        vals = tree.item(row, "values")
        if len(vals) < 4: return
        ip = vals[3]
        self._toggle_enabled(ip)

    def _toggle_enabled(self, ip):
        new_enabled = None
        with self.lock:
            for h in self.hosts:
                if h["ip"] == ip:
                    cur = h.get("enabled", True)
                    new_enabled = not cur
                    h["enabled"] = new_enabled
                    break
            if new_enabled is None: return
            save_hosts(self.hosts)
            st = self.state.get(ip)
            if st:
                st["enabled"] = new_enabled
                if not new_enabled:
                    st["status"] = "disabled"
                    st["pesan"] = "Ping dinonaktifkan"
                    st["latency"] = None
                    st["rto_start"] = 0.0
                    st["last_rto_alert_time"] = 0.0
                else:
                    if st.get("status") == "disabled":
                        st["status"] = "checking"
                        st["pesan"] = "Menunggu"
        if ip in self.rows:
            tipe, iid = self.rows[ip]
            tree = self.trees.get(tipe)
            if tree:
                try:
                    v = list(tree.item(iid, "values"))
                    v[0] = ""
                    if not new_enabled:
                        v[4] = "⏸ Nonaktif"
                        v[5] = "-"
                        v[6] = "Ping dinonaktifkan"
                        tag = "st_disabled"
                    else:
                        v[4] = "🔵 Checking..."
                        v[5] = "-  " + ("·" * HISTORY_LEN)
                        v[6] = "Menunggu"
                        tag = "st_check"
                    tree.item(iid, values=v, tags=(tag,))
                    self._mark_overlay(tipe)
                except Exception: pass
        if new_enabled:
            self.force_ping(ip)
        self._queue_summary()

    def _update_row(self, ip):
        def do():
            with self.lock:
                st = self.state.get(ip)
                if not st: return
                s = dict(st)
                hist = list(st.get("latency_history", []))
                enabled = st.get("enabled", True)
            if ip not in self.rows: return
            tipe, iid = self.rows[ip]
            tree = self.trees.get(tipe)
            if not tree: return
            try:
                v = tree.item(iid, "values")
                icon, nama, hip = v[1], v[2], v[3]
            except Exception: return
            status = s["status"]
            lat_ms = s.get("latency")
            lat_str = f"{int(lat_ms)} ms" if lat_ms is not None else "-"
            spark = make_sparkline(hist, HISTORY_LEN)
            lat_display = f"{lat_str}  {spark}"
            pesan = s.get("pesan", "")
            if s.get("tracert_running"):
                pesan = (pesan + "  • tracert...") if pesan else "tracert..."
            tag = STATUS_TAG.get(status, "st_check")
            if not enabled: tag = "st_disabled"
            try:
                tree.item(iid, values=("", icon, nama, hip,
                    f"{STATUS_EMOJI.get(status, '?')} {STATUS_LABEL.get(status, '?')}",
                    lat_display, pesan), tags=(tag,))
                self._mark_overlay(tipe)
            except Exception: return

            prev = s.get("prev_status", "checking")
            with self.lock:
                if ip in self.state:
                    self.state[ip]["prev_status"] = status
            now = time.time()

            if enabled and status in RTO_STATUSES:
                rto_start = s.get("rto_start", 0.0)
                last_alert = s.get("last_rto_alert_time", 0.0)
                if rto_start == 0.0 or prev not in RTO_STATUSES:
                    # Baru mulai RTO: catat waktunya saja, belum bunyikan alert
                    with self.lock:
                        if ip in self.state:
                            self.state[ip]["rto_start"] = now
                            self.state[ip]["last_rto_alert_time"] = 0.0
                else:
                    rto_duration = now - rto_start
                    if rto_duration >= RTO_THRESHOLD_MINUTES * 60:
                        if last_alert == 0.0 or (now - last_alert) >= RTO_REPEAT_SECONDS:
                            self._alert(nama, ip, status)
                            with self.lock:
                                if ip in self.state:
                                    self.state[ip]["last_rto_alert_time"] = now
            elif status not in RTO_STATUSES:
                with self.lock:
                    if ip in self.state:
                        self.state[ip]["rto_start"] = 0.0
                        self.state[ip]["last_rto_alert_time"] = 0.0
                if prev in RTO_STATUSES:
                    if self._toast and self._toast.winfo_exists():
                        try: self._toast.remove_entry(ip)
                        except Exception: pass
        self.ui_queue.put(do)

    def _queue_summary(self):
        def do():
            with self.lock:
                c = {}
                for s in self.state.values():
                    k = s.get("status", "checking"); c[k] = c.get(k, 0) + 1
                tc = {t: 0 for t in DEVICE_LIST}
                for s in self.state.values():
                    t = s.get("tipe", "PC")
                    if t in tc: tc[t] += 1
                disabled = sum(1 for s in self.state.values() if not s.get("enabled", True))
            self.summary.config(text=(
                f"🟢 {c.get('online',0)}  🟡 {c.get('slow',0)}  "
                f"🟠 {c.get('timeout',0)}  🔴 {c.get('offline',0)}  "
                f"⚫ {c.get('unreachable',0)}  ⚪ {c.get('error',0)}  "
                f"⏸ {disabled}  "
                f"| 💻 {tc['PC']}  🖨 {tc['Printer']}  ⚙ {tc['Aplikasi']}  "
                f"🌐 {tc['SDWAN']}  | Total: {len(self.state)}"))
            self.info.config(text=f"Update: {time.strftime('%H:%M:%S')}")
        self.ui_queue.put(do)

    def _alert(self, nama, ip, status):
        if not self.alerts_on.get(): return
        play_alert_sound(self.settings.get("alert_sound", ""))
        if self._toast and self._toast.winfo_exists():
            try: self._toast.add_entry(nama, ip, status)
            except Exception: pass
        else:
            try: self._toast = ToastAlert(self.root, self, nama, ip, status)
            except Exception: pass

    def _apply_search(self):
        q = self.search_var.get().lower().strip()
        for tree in self.trees.values():
            for iid in tree.get_children():
                try: tree.detach(iid)
                except Exception: pass
        for h in self.hosts:
            if h["ip"] not in self.rows: continue
            tipe, iid = self.rows[h["ip"]]
            tree = self.trees.get(tipe)
            if not tree: continue
            try:
                vals = tree.item(iid, "values")
                if not q or q in " ".join(str(x) for x in vals).lower():
                    tree.reattach(iid, "", "end")
            except Exception: pass
        self._mark_overlay()

    def open_scan(self):
        if self.scan_window and self.scan_window.winfo_exists():
            try:
                self.scan_window.lift(); self.scan_window.focus_force(); return
            except Exception: self.scan_window = None
        self.scan_window = ScanWindow(self)

    def open_manual_ping(self):
        if self.manual_ping_window and self.manual_ping_window.winfo_exists():
            try:
                self.manual_ping_window.lift()
                self.manual_ping_window.focus_force()
                return
            except Exception: self.manual_ping_window = None
        self.manual_ping_window = ManualPingWindow(self)

    def _on_dbl(self, event):
        tree = event.widget
        sel = tree.selection()
        if not sel: return
        v = tree.item(sel[0], "values")
        if len(v) >= 4: self.open_detail(v[3])

    def open_detail(self, ip):
        if ip in self.popups:
            try:
                self.popups[ip].lift(); self.popups[ip].focus_force(); return
            except Exception: self.popups.pop(ip, None)
        n, t = ip, "PC"
        for h in self.hosts:
            if h["ip"] == ip:
                n = h["nama"]; t = h.get("tipe", "PC"); break
        try: self.popups[ip] = DetailWindow(self, ip, n, t)
        except Exception: pass

    def detail_selected(self):
        _, tree = self._active_tree()
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Pilih baris IP Monitor"); return
        v = tree.item(sel[0], "values")
        if len(v) >= 4: self.open_detail(v[3])

    def add_host(self):
        n, ip = self.e_nama.get().strip(), self.e_ip.get().strip()
        t = self.cb_tipe.get() or "PC"
        if t not in DEVICE_LIST: t = "PC"
        if not n:
            messagebox.showerror("Error", "Nama kosong"); return
        if not ip:
            messagebox.showerror("Error", "IP kosong"); return
        if not valid_target(ip):
            messagebox.showerror("Error", "Format IP tidak valid"); return
        with self.lock:
            if any(h["ip"] == ip for h in self.hosts):
                messagebox.showerror("Error", f"IP {ip} sudah ada"); return
            self.hosts.append({"nama": n, "ip": ip, "tipe": t, "enabled": True})
            save_hosts(self.hosts)
        self._init_state(ip, t, True); self._insert_row(n, ip, t, True)
        self.e_nama.delete(0, "end"); self.e_ip.delete(0, "end")
        self.e_nama.focus()
        self._apply_search(); self._queue_summary()

    def del_selected(self):
        _, tree = self._active_tree()
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Pilih baris IP Monitor"); return
        iid = sel[0]; v = tree.item(iid, "values")
        if len(v) < 4: return
        n, ip = v[2], v[3]
        if not messagebox.askyesno("Konfirmasi", f"Hapus {n} ({ip})?"): return
        with self.lock:
            self.hosts = [h for h in self.hosts if h["ip"] != ip]
            save_hosts(self.hosts)
            self.state.pop(ip, None); self.rows.pop(ip, None)
        p = self.popups.pop(ip, None)
        if p:
            try: p._close()
            except Exception: pass
        if self._toast and self._toast.winfo_exists():
            try: self._toast.remove_entry(ip)
            except Exception: pass
        try: tree.delete(iid)
        except Exception: pass
        self._mark_overlay()
        self._queue_summary()

    def edit_selected(self):
        _, tree = self._active_tree()
        sel = tree.selection()
        if not sel:
            messagebox.showinfo("Info", "Pilih baris IP Monitor"); return
        v = tree.item(sel[0], "values")
        if len(v) < 4: return
        self._edit(sel[0], v[2], v[3])

    def _edit(self, iid, on, oip):
        ot = "PC"; oen = True
        for h in self.hosts:
            if h["ip"] == oip:
                ot = h.get("tipe", "PC")
                oen = h.get("enabled", True)
                break
        dlg = tk.Toplevel(self.root)
        apply_icon(dlg)
        dlg.title("Edit Host"); dlg.transient(self.root)
        dlg.resizable(False, False); dlg.grab_set()
        ttk.Label(dlg, text="Nama:").grid(row=0, column=0, padx=8, pady=8, sticky="e")
        e1 = ttk.Entry(dlg, width=25); e1.insert(0, on)
        e1.grid(row=0, column=1, padx=8, pady=8)
        ttk.Label(dlg, text="IP:").grid(row=1, column=0, padx=8, pady=8, sticky="e")
        e2 = ttk.Entry(dlg, width=25); e2.insert(0, oip)
        e2.grid(row=1, column=1, padx=8, pady=8)
        ttk.Label(dlg, text="Tipe:").grid(row=2, column=0, padx=8, pady=8, sticky="e")
        cb = ttk.Combobox(dlg, values=DEVICE_LIST, width=22, state="readonly")
        cb.set(ot); cb.grid(row=2, column=1, padx=8, pady=8)
        en_var = tk.BooleanVar(value=oen)
        ttk.Checkbutton(dlg, text="Aktif (ping berjalan)",
                         variable=en_var).grid(row=3, column=1, sticky="w", padx=8)

        def save():
            nn, ni, nt, nen = (e1.get().strip(), e2.get().strip(),
                                cb.get() or "PC", en_var.get())
            if nt not in DEVICE_LIST: nt = "PC"
            if not nn or not ni:
                messagebox.showerror("Error", "Wajib", parent=dlg); return
            if not valid_target(ni):
                messagebox.showerror("Error", "IP tidak valid", parent=dlg); return
            with self.lock:
                if ni != oip and any(h["ip"] == ni for h in self.hosts):
                    messagebox.showerror("Error",
                        f"IP {ni} sudah ada", parent=dlg); return
                for h in self.hosts:
                    if h["ip"] == oip and h["nama"] == on:
                        h["nama"], h["ip"], h["tipe"], h["enabled"] = nn, ni, nt, nen
                        break
                save_hosts(self.hosts)
                old_tipe = self.state.get(oip, {}).get("tipe", "PC")
                if ni != oip:
                    self.state[ni] = self.state.pop(oip, {})
                    self.rows.pop(oip, None)
                    p = self.popups.pop(oip, None)
                    if p:
                        try: p._close()
                        except Exception: pass
                self.state[ni]["status"] = "checking" if nen else "disabled"
                self.state[ni]["pesan"] = "Menunggu" if nen else "Ping dinonaktifkan"
                self.state[ni]["tipe"] = nt
                self.state[ni]["prev_status"] = "checking"
                self.state[ni]["enabled"] = nen
                self.state[ni]["rto_start"] = 0.0
                self.state[ni]["last_rto_alert_time"] = 0.0
            try:
                if old_tipe in self.trees:
                    self.trees[old_tipe].delete(iid)
            except Exception: pass
            self.rows.pop(oip, None)
            self._insert_row(nn, ni, nt, nen)
            dlg.destroy(); self._apply_search(); self._queue_summary()
            if nen: self.force_ping(ni)

        f = ttk.Frame(dlg); f.grid(row=4, column=0, columnspan=2, pady=(8, 10))
        make_btn(f, "Simpan", "#388e3c",
                 cmd=save).pack(side="left", padx=5)
        make_btn(f, "Batal", "#757575",
                 cmd=dlg.destroy).pack(side="left", padx=5)
        e1.focus(); e2.bind("<Return>", lambda e: save())
        center_on_parent(dlg, self.root)

    # ── Import / Export ──────────────────────────────
    def import_hosts(self):
        path = filedialog.askopenfilename(
            title="Import Host",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv"), ("All files", "*.*")])
        if not path: return
        new_hosts = []
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext == ".json":
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict) and data.get("protected") and "data" in data:
                    plain = decrypt_text(data["data"], DATA_SECRET_KEY)
                    data = json.loads(plain)
                elif isinstance(data, dict) and "hosts" in data:
                    data = data["hosts"]
                for item in data:
                    if not isinstance(item, dict): continue
                    n = str(item.get("nama") or item.get("name") or "").strip()
                    ip = str(item.get("ip") or "").strip()
                    t = str(item.get("tipe") or item.get("type") or "PC").strip()
                    en = bool(item.get("enabled", True))
                    if not n or not ip or not valid_target(ip): continue
                    if t not in DEVICE_LIST: t = "PC"
                    new_hosts.append({"nama": n, "ip": ip, "tipe": t, "enabled": en})
            elif ext == ".csv":
                with open(path, "r", encoding="utf-8-sig", newline="") as f:
                    reader = csv.reader(f)
                    rows = list(reader)
                if not rows: return
                start = 1 if any(x.strip().lower() in ("nama", "name", "ip")
                                  for x in rows[0]) else 0
                for row in rows[start:]:
                    if len(row) < 2: continue
                    n = row[0].strip()
                    ip = row[1].strip()
                    t = row[2].strip() if len(row) > 2 else "PC"
                    en = True
                    if len(row) > 3:
                        v = row[3].strip().lower()
                        en = v in ("1", "true", "yes", "y", "aktif", "enabled")
                    if not n or not ip or not valid_target(ip): continue
                    if t not in DEVICE_LIST: t = "PC"
                    new_hosts.append({"nama": n, "ip": ip, "tipe": t, "enabled": en})
            else:
                messagebox.showerror("Error",
                    "Format tidak didukung. Gunakan .json atau .csv"); return
        except Exception as e:
            messagebox.showerror("Error", f"Gagal membaca file:\n{e}"); return

        if not new_hosts:
            messagebox.showinfo("Info", "Tidak ada data valid di file"); return

        added = skipped = 0
        with self.lock:
            existing = {h["ip"] for h in self.hosts}
            for h in new_hosts:
                if h["ip"] in existing:
                    skipped += 1; continue
                self.hosts.append(h)
                existing.add(h["ip"]); added += 1
            if added: save_hosts(self.hosts)
        for h in new_hosts:
            if h["ip"] in self.rows: continue
            if not any(x["ip"] == h["ip"] for x in self.hosts): continue
            self._init_state(h["ip"], h["tipe"], h["enabled"])
            self._insert_row(h["nama"], h["ip"], h["tipe"], h["enabled"])
        self._apply_search(); self._queue_summary()
        messagebox.showinfo("Import Selesai",
            f"✓ {added} host ditambahkan\n⚠ {skipped} duplikat dilewati")

    def export_hosts(self):
        dlg = LoginDialog(
            self.root,
            title="Verifikasi Export",
            subtitle="Masukkan username & password untuk export data",
            btn_text="Verifikasi"
        )
        self.root.wait_window(dlg)
        if not dlg.authenticated:
            return

        path = filedialog.asksaveasfilename(
            title="Export Host",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("CSV", "*.csv")])
        if not path: return
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == ".json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.hosts, f, indent=2, ensure_ascii=False)
            elif ext == ".csv":
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["nama", "ip", "tipe", "enabled"])
                    for h in self.hosts:
                        w.writerow([h.get("nama", ""), h.get("ip", ""),
                                    h.get("tipe", "PC"),
                                    "1" if h.get("enabled", True) else "0"])
            else:
                messagebox.showerror("Error", "Pilih .json atau .csv"); return
            messagebox.showinfo("Export Selesai",
                f"✓ {len(self.hosts)} host disimpan ke:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", f"Gagal menyimpan:\n{e}")

    def on_close(self):
        self.running = False
        if self.scan_window and self.scan_window.winfo_exists():
            try: self.scan_window._close()
            except Exception: pass
        if self.manual_ping_window and self.manual_ping_window.winfo_exists():
            try: self.manual_ping_window._close()
            except Exception: pass
        if self._toast and self._toast.winfo_exists():
            try: self._toast._close()
            except Exception: pass
        for p in list(self.popups.values()):
            try: p._close()
            except Exception: pass
        try: self.root.destroy()
        except Exception: pass

    def force_ping(self, ip):
        def w():
            with self.lock:
                st = self.state.get(ip)
                if not st or not st.get("enabled", True): return
            s, lat, raw = ping_full(ip)
            with self.lock:
                st = self.state.get(ip)
                if st:
                    st["status"] = s; st["latency"] = lat; st["raw_ping"] = raw
                    st["pesan"] = PESAN_MAP.get(s, "")
                    st["last_check"] = time.strftime("%H:%M:%S")
                    hist = st.setdefault("latency_history", [])
                    hist.append(lat)
                    if len(hist) > HISTORY_LEN: del hist[:-HISTORY_LEN]
            self._update_row(ip); self._maybe_tracert(ip, s); self._queue_summary()
        threading.Thread(target=w, daemon=True).start()

    def _loop(self):
        while self.running:
            try: self.check_all()
            except Exception: pass
            for _ in range(INTERVAL):
                if not self.running: return
                time.sleep(1)

    def check_all(self):
        with self.lock:
            snap = [(h["nama"], h["ip"], h.get("enabled", True))
                    for h in self.hosts]
        ts = []
        for n, ip, en in snap:
            if ip not in self.rows: continue
            if not en: continue
            t = threading.Thread(target=self._check_one, args=(n, ip), daemon=True)
            t.start(); ts.append(t)
        for t in ts: t.join(timeout=10)
        self._queue_summary()

    def _check_one(self, n, ip):
        with self.lock:
            st = self.state.get(ip)
            if not st or not st.get("enabled", True): return
        s, lat, raw = ping_full(ip)
        with self.lock:
            st = self.state.get(ip) or {}
            self.state[ip] = st
            st["status"] = s; st["latency"] = lat; st["raw_ping"] = raw
            st["pesan"] = PESAN_MAP.get(s, "")
            st["last_check"] = time.strftime("%H:%M:%S")
            hist = st.setdefault("latency_history", [])
            hist.append(lat)
            if len(hist) > HISTORY_LEN: del hist[:-HISTORY_LEN]
        self._update_row(ip); self._maybe_tracert(ip, s)

    def _maybe_tracert(self, ip, s):
        if s not in RTO_STATUSES: return
        with self.lock:
            st = self.state.get(ip)
            if not st or not st.get("enabled", True): return
            if st.get("tracert_running"): return
            if (time.time() - st.get("last_tracert_trigger", 0)) < TRACERT_THROTTLE:
                return
        self.trigger_tracert(ip)

    def trigger_tracert(self, ip, force=False):
        with self.lock:
            st = self.state.get(ip)
            if not st or st.get("tracert_running"): return
            if not st.get("enabled", True): return
            if (not force and
                (time.time() - st.get("last_tracert_trigger", 0)) < TRACERT_THROTTLE):
                return
            st["tracert_running"] = True
            st["last_tracert_trigger"] = time.time()
            st["tracert_text"] = "(tracert berjalan...)"
        self._update_row(ip)
        threading.Thread(target=self._do_tr, args=(ip,), daemon=True).start()

    def _do_tr(self, ip):
        txt = run_tracert(ip)
        with self.lock:
            st = self.state.get(ip)
            if st:
                st["tracert_text"] = txt; st["tracert_running"] = False
        self._update_row(ip)


if __name__ == "__main__":
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "noc.network.ssc.monitor")
        except Exception:
            pass
    root = tk.Tk()
    apply_icon(root)
    style = ttk.Style()
    try: style.theme_use("clam")
    except Exception: pass
    style.configure("Treeview", rowheight=38, font=("Segoe UI", 10))
    style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))

    root.withdraw()
    login = LoginDialog(root)
    root.wait_window(login)
    if login.authenticated:
        root.deiconify()
        App(root)
        root.mainloop()
    else:
        root.destroy()