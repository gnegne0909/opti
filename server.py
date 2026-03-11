"""
server.py — WinOptimizer Pro v4.0
Panel admin : /admin  |  API : /api/...

NOUVEAU v4.0 :
  - 🖥️ Remote Control : viewer live WebSocket depuis le panel admin
  - 👥 Panel Staff++ : analytics live, alert center, notes système, actions rapides
  - 👤 Panel User++ : profil enrichi, historique logins, sessions actives, hardware map
  - 📊 Dashboard v2 : graphiques temps réel, top IPs, activité par pays
  - 🔔 Système de notifications admin en temps réel
  - 🗂️ Gestion notes & tags utilisateurs
  - 🔍 Recherche avancée full-text
"""

from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for, Response
import hmac, hashlib, json, time, os, sqlite3, secrets, string, random
import re, urllib.request, threading, struct, zlib, base64, io
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ─── CONFIG ───────────────────────────────────────────────────────────────────
MASTER_SECRET   = os.environ.get("MASTER_SECRET", "WinOpt_k7#Xm2@pQ9_zR4wN8_2025!").encode()
DB_PATH         = "licenses.db"
DISCORD_BOT_URL = "http://localhost:8080"
DEFAULT_ADMIN   = {"username": "xywez", "password": "Admin2025!", "role": "owner"}
APP_VERSION     = "4.0"

# Remote control sessions {session_id: {username, socket, active, frames_sent}}
_remote_sessions = {}
_remote_lock = threading.Lock()

# SSE clients pour notifications live {admin: queue}
_sse_clients = []
_sse_lock = threading.Lock()

# ─── IP HELPER ────────────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _is_ipv4(ip: str) -> bool:
    return bool(_IPV4_RE.match(ip or ""))

def get_real_ip() -> str:
    candidates = [
        request.headers.get("CF-Connecting-IP", ""),
        request.headers.get("X-Real-IP", ""),
        (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()),
        request.remote_addr or "",
    ]
    for ip in candidates:
        ip = ip.strip()
        if _is_ipv4(ip) and ip not in ("127.0.0.1", "0.0.0.0"):
            return ip
    return candidates[-1] or "?"

# ─── GEOIP ────────────────────────────────────────────────────────────────────
_geoip_cache = {}
GEOIP_TTL = 3600

def get_geoip(ip: str) -> dict:
    if not ip or not _is_ipv4(ip) or ip in ("127.0.0.1",):
        return {"country": "Local", "city": "Localhost", "flag": "🖥", "isp": "Local"}
    now = time.time()
    if ip in _geoip_cache and now - _geoip_cache[ip].get("ts", 0) < GEOIP_TTL:
        return _geoip_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,proxy,hosting"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            cc = data.get("countryCode", "")
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) if len(cc) == 2 else "🌐"
            result = {
                "country": data.get("country", "?"), "city": data.get("city", "?"),
                "flag": flag, "isp": data.get("isp", "?"),
                "proxy": data.get("proxy", False), "hosting": data.get("hosting", False), "ts": now,
            }
        else:
            result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "proxy": False, "hosting": False, "ts": now}
    except Exception:
        result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "proxy": False, "hosting": False, "ts": now}
    _geoip_cache[ip] = result
    return result

# ─── DB ───────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY, plan TEXT DEFAULT 'NORMAL',
        status TEXT DEFAULT 'active', created_at INTEGER, note TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        license_key TEXT, plan TEXT DEFAULT 'NORMAL',
        discord_id TEXT, hwid TEXT, ip TEXT,
        os_info TEXT, cpu_info TEXT, gpu_info TEXT, ram_info TEXT,
        motherboard_info TEXT, disk_info TEXT,
        status TEXT DEFAULT 'active',
        created_at INTEGER, last_login INTEGER,
        connections INTEGER DEFAULT 0,
        first_login_done INTEGER DEFAULT 0,
        must_change_pass INTEGER DEFAULT 0, temp_password TEXT, note TEXT,
        session_token TEXT, tags TEXT,
        FOREIGN KEY (license_key) REFERENCES licenses(key)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, ip TEXT, ts INTEGER, country TEXT, city TEXT, flag TEXT,
        success INTEGER DEFAULT 1, reason TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admin_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, note TEXT, author TEXT, ts INTEGER, color TEXT DEFAULT 'gray'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'staff', created_at INTEGER, created_by TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER, level TEXT, type TEXT, msg TEXT, user TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_rules (
        ip TEXT PRIMARY KEY, rule TEXT, note TEXT, added_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, discord_id TEXT,
        subject TEXT, message TEXT, status TEXT DEFAULT 'open',
        response TEXT, created_at INTEGER, updated_at INTEGER, priority TEXT DEFAULT 'normal'
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS reset_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, discord_id TEXT,
        type TEXT, status TEXT DEFAULT 'pending', temp_pass TEXT,
        requested_at INTEGER, resolved_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS hwid_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, hwid TEXT, ip TEXT, ts INTEGER, note TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS remote_sessions (
        id TEXT PRIMARY KEY, username TEXT, admin_user TEXT,
        started_at INTEGER, ended_at INTEGER, status TEXT DEFAULT 'pending',
        frames_sent INTEGER DEFAULT 0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS addon_licenses (
        key TEXT PRIMARY KEY, addon_key TEXT, plan TEXT DEFAULT 'NORMAL',
        status TEXT DEFAULT 'active', created_at INTEGER, note TEXT
    )""")
    # Table liaison addons <-> users (FIX ADDONS)
    c.execute("""CREATE TABLE IF NOT EXISTS user_addons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        addon_key TEXT NOT NULL,
        source TEXT DEFAULT 'key',
        activated_at INTEGER,
        UNIQUE(username, addon_key)
    )""")
    # Migrations colonnes
    for col, typ in [
        ("os_info","TEXT"),("cpu_info","TEXT"),("gpu_info","TEXT"),
        ("ram_info","TEXT"),("motherboard_info","TEXT"),("disk_info","TEXT"),
        ("session_token","TEXT"),("tags","TEXT"),
    ]:
        try: c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        except: pass
    try: c.execute("ALTER TABLE tickets ADD COLUMN priority TEXT DEFAULT 'normal'")
    except: pass
    # Migration: LIFETIME supprimé → tout devient PRO
    try: c.execute("UPDATE users SET plan='PRO' WHERE plan='LIFETIME'")
    except: pass
    try: c.execute("UPDATE licenses SET plan='PRO' WHERE plan='LIFETIME'")
    except: pass
    conn.commit()
    if not conn.execute("SELECT 1 FROM admins WHERE username=?", (DEFAULT_ADMIN["username"],)).fetchone():
        conn.execute("INSERT INTO admins (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                     (DEFAULT_ADMIN["username"], _hash_password(DEFAULT_ADMIN["password"]), DEFAULT_ADMIN["role"], int(time.time())))
    for k, v in [("maintenance","0"),("vpn_block","0"),
                 ("maintenance_msg","Maintenance en cours. Revenez dans quelques minutes."),
                 ("offline_mode","0"),("announce",""),("announce_color","blue")]:
        conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k,v))
    conn.commit(); conn.close()

_db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn

def add_log(level, type_, msg, user=""):
    try:
        with _db_lock:
            conn = get_db()
            conn.execute("INSERT INTO logs (ts,level,type,msg,user) VALUES (?,?,?,?,?)",
                         (int(time.time()), level, type_, msg, user))
            conn.commit()
            conn.close()
    except Exception as e:
        print(f"[add_log ERROR] {e}")
    _push_sse({"type":"log","level":level,"msg":msg,"user":user,"ts":int(time.time())})

def _hash_password(pwd: str) -> str:
    return hashlib.sha256((pwd + "WinOpt_SALT_2025").encode()).hexdigest()

def _gen_temp_password(n=10) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))

def get_setting(key, default="0"):
    conn = get_db(); row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone(); conn.close()
    return row["value"] if row else default

def set_setting(key, value):
    conn = get_db(); conn.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value)); conn.commit(); conn.close()

def generate_key(plan="NORMAL"):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    lid = "".join(random.choices(chars, k=12))
    sig = hmac.new(MASTER_SECRET, lid.encode(), hashlib.sha256).hexdigest()[:8].upper()
    combined = (lid + sig)[:20]
    return "-".join([combined[i:i+5] for i in range(0, 20, 5)])

def generate_addon_key(addon_key):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    lid = "".join(random.choices(chars, k=12))
    sig = hmac.new(MASTER_SECRET, (lid + addon_key).encode(), hashlib.sha256).hexdigest()[:8].upper()
    combined = (lid + sig)[:20]
    return "-".join([combined[i:i+5] for i in range(0, 20, 5)])

# ─── SSE PUSH ────────────────────────────────────────────────────────────────
def _push_sse(data: dict):
    msg = f"data: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try: q.append(msg)
            except: dead.append(q)
        for q in dead: _sse_clients.remove(q)

@app.route("/admin/events")
def admin_sse():
    if not session.get("admin_logged"): return "Unauthorized", 401
    q = []
    with _sse_lock: _sse_clients.append(q)
    def gen():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            if q:
                yield q.pop(0)
            else:
                time.sleep(0.5)
                yield ": heartbeat\n\n"
    return Response(gen(), content_type="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ─── AUTH ─────────────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged"): return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

# ─── ANTI-CRACK / ANTI-LEAK ───────────────────────────────────────────────────
def check_anti_leak(username: str, hwid: str, ip: str) -> dict:
    conn = get_db()
    hwid_users = conn.execute(
        "SELECT username FROM users WHERE hwid=? AND username!=? AND status='active'",
        (hwid, username)).fetchall() if hwid else []
    ip_users = conn.execute(
        "SELECT COUNT(DISTINCT username) as cnt FROM users WHERE ip=? AND username!=?",
        (ip, username)).fetchone() if ip else None
    conn.close()
    warnings = []
    if hwid_users:
        others = [r["username"] for r in hwid_users]
        warnings.append(f"HWID partagé avec: {', '.join(others)}")
        add_log("WARN", "ANTI-LEAK", f"HWID {hwid[:16]}… partagé entre {username} et {', '.join(others)}", username)
        try:
            with _db_lock:
                conn2 = get_db()
                conn2.execute("INSERT INTO hwid_alerts (username,hwid,ip,ts,note) VALUES (?,?,?,?,?)",
                              (username, hwid, ip, int(time.time()), f"Partagé avec {', '.join(others)}"))
                conn2.commit(); conn2.close()
        except Exception as e:
            print(f"[hwid_alert ERROR] {e}")
        _push_sse({"type":"alert","level":"warn","msg":f"⚠ HWID partagé: {username}"})
    if ip_users and ip_users["cnt"] > 3:
        warnings.append(f"IP {ip} utilisée par {ip_users['cnt']+1} comptes")
        add_log("WARN", "ANTI-LEAK", f"IP {ip} sur {ip_users['cnt']+1} comptes (suspect)", username)
    return {"warnings": warnings, "flagged": len(warnings) > 0}

# ─── LOGIN HISTORY ────────────────────────────────────────────────────────────
def record_login(username, ip, success=True, reason=""):
    geo = get_geoip(ip)
    try:
        with _db_lock:
            conn = get_db()
            conn.execute("INSERT INTO login_history (username,ip,ts,country,city,flag,success,reason) VALUES (?,?,?,?,?,?,?,?)",
                         (username, ip, int(time.time()), geo.get("country","?"), geo.get("city","?"),
                          geo.get("flag","🌐"), 1 if success else 0, reason))
            conn.commit(); conn.close()
    except Exception as e:
        print(f"[record_login ERROR] {e}")

# ════════════════════════════════════════════════════════════════════════════════
#  API PUBLIQUES
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/ping")
def ping():
    maintenance = get_setting("maintenance") == "1"
    msg = get_setting("maintenance_msg")
    return jsonify({"status": "maintenance" if maintenance else "ok",
                    "message": msg if maintenance else "Serveur opérationnel",
                    "version": APP_VERSION, "ts": int(time.time())}), 200

@app.route("/api/status")
def api_status():
    maintenance = get_setting("maintenance") == "1"
    announce = get_setting("announce")
    return jsonify({"online": True, "maintenance": maintenance,
                    "maintenance_msg": get_setting("maintenance_msg") if maintenance else "",
                    "announce": announce, "announce_color": get_setting("announce_color"),
                    "version": APP_VERSION, "ts": int(time.time())}), 200

@app.route("/api/register", methods=["POST"])
def api_register():
    if get_setting("maintenance") == "1":
        return jsonify({"success": False, "reason": get_setting("maintenance_msg")})
    data = request.get_json(silent=True) or {}
    username    = data.get("username", "").strip().lower()
    password    = data.get("password", "").strip()
    license_key = data.get("license_key", "").strip().upper()
    discord_id  = data.get("discord_id", "").strip()
    os_info     = data.get("os_info", "")[:100]
    cpu_info    = data.get("cpu_info", "")[:150]
    gpu_info    = data.get("gpu_info", "")[:150]
    ram_info    = data.get("ram_info", "")[:150]
    mb_info     = data.get("motherboard_info", "")[:150]
    disk_info   = data.get("disk_info", "")[:200]
    ip          = get_real_ip()

    if not username or not password or not license_key:
        return jsonify({"success": False, "reason": "Champs manquants"})
    if len(username) < 3 or len(username) > 20 or not re.match(r'^[a-z0-9_]+$', username):
        return jsonify({"success": False, "reason": "Username invalide (3-20 chars, lettres/chiffres/_)"})
    if len(password) < 6:
        return jsonify({"success": False, "reason": "Mot de passe trop court (6 min)"})

    conn = get_db()
    ip_rule = conn.execute("SELECT rule FROM ip_rules WHERE ip=?", (ip,)).fetchone()
    if ip_rule and ip_rule["rule"] == "blacklist":
        conn.close(); return jsonify({"success": False, "reason": "Accès refusé"})
    if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        conn.close(); return jsonify({"success": False, "reason": "Username déjà pris"})
    if not re.match(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$', license_key):
        conn.close(); return jsonify({"success": False, "reason": "Format de clé invalide"})

    raw = license_key.replace("-", "")
    sig_expected = hmac.new(MASTER_SECRET, raw[:12].encode(), hashlib.sha256).hexdigest()[:8].upper()
    if not hmac.compare_digest(raw[12:20], sig_expected):
        conn.close(); return jsonify({"success": False, "reason": "Clé de licence invalide"})

    lic = conn.execute("SELECT * FROM licenses WHERE key=?", (license_key,)).fetchone()
    if not lic: conn.close(); return jsonify({"success": False, "reason": "Clé non trouvée"})
    if lic["status"] != "active": conn.close(); return jsonify({"success": False, "reason": f"Clé {lic['status']}"})
    if conn.execute("SELECT 1 FROM users WHERE license_key=?", (license_key,)).fetchone():
        conn.close(); return jsonify({"success": False, "reason": "Clé déjà utilisée"})

    plan = lic["plan"]
    conn.execute("""INSERT INTO users
        (username,password_hash,license_key,plan,discord_id,ip,os_info,cpu_info,gpu_info,ram_info,motherboard_info,disk_info,status,created_at,first_login_done)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (username, _hash_password(password), license_key, plan, discord_id, ip,
         os_info, cpu_info, gpu_info, ram_info, mb_info, disk_info, "active", int(time.time()), 0))
    conn.commit(); conn.close()
    add_log("OK","REGISTER",f"Nouveau: {username} plan={plan} IP={ip} CPU={cpu_info[:40]}", username)
    record_login(username, ip, success=True, reason="register")
    _push_sse({"type":"new_user","username":username,"plan":plan})
    return jsonify({"success": True, "plan": plan, "username": username})

@app.route("/api/login", methods=["POST"])
def api_login():
    if get_setting("maintenance") == "1":
        return jsonify({"success": False, "reason": get_setting("maintenance_msg"), "maintenance": True})
    data = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip().lower()
    password   = data.get("password", "").strip()
    machine_id = data.get("machine_id", "").strip()
    os_info    = data.get("os_info", "")[:100]
    cpu_info   = data.get("cpu_info", "")[:150]
    gpu_info   = data.get("gpu_info", "")[:150]
    ram_info   = data.get("ram_info", "")[:150]
    mb_info    = data.get("motherboard_info", "")[:150]
    disk_info  = data.get("disk_info", "")[:200]
    ip         = get_real_ip()

    if not username or not password:
        return jsonify({"success": False, "reason": "Champs manquants"})

    conn = get_db()
    ip_rule = conn.execute("SELECT rule FROM ip_rules WHERE ip=?", (ip,)).fetchone()
    if ip_rule and ip_rule["rule"] == "blacklist":
        conn.close(); record_login(username, ip, False, "IP blacklistée")
        return jsonify({"success": False, "reason": "Accès refusé depuis cette IP"})
    whitelist_count = conn.execute("SELECT COUNT(*) FROM ip_rules WHERE rule='whitelist'").fetchone()[0]
    if whitelist_count > 0:
        is_whitelisted = conn.execute("SELECT 1 FROM ip_rules WHERE ip=? AND rule='whitelist'", (ip,)).fetchone()
        if not is_whitelisted:
            conn.close(); return jsonify({"success": False, "reason": "IP non autorisée"})

    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close(); record_login(username, ip, False, "Compte inconnu")
        add_log("WARN","LOGIN",f"Compte inconnu: {username} IP={ip}")
        return jsonify({"success": False, "reason": "Identifiants incorrects"})

    if row["status"] == "banned":
        conn.close(); return jsonify({"success": False, "reason": "Compte suspendu. Contactez le support."})
    if row["status"] == "suspended":
        conn.close(); return jsonify({"success": False, "reason": "Compte suspendu temporairement."})

    ph = _hash_password(password)
    must_change = False
    if ph == row["password_hash"]:
        pass
    elif row["must_change_pass"] and row["temp_password"] and password == row["temp_password"]:
        must_change = True
    else:
        conn.close(); record_login(username, ip, False, "Mauvais MDP")
        add_log("WARN","LOGIN",f"Mauvais MDP: {username} IP={ip}")
        return jsonify({"success": False, "reason": "Identifiants incorrects"})

    if row["hwid"] and machine_id and row["hwid"] != machine_id:
        add_log("WARN","ANTI-CRACK",f"HWID mismatch: {username}")
        conn.close(); return jsonify({"success": False, "reason": "Machine non autorisée. Contactez le support."})
    if not row["hwid"] and machine_id:
        conn.execute("UPDATE users SET hwid=? WHERE username=?", (machine_id, username))

    check_anti_leak(username, machine_id, ip)
    session_token = secrets.token_hex(32)
    first_login = row["first_login_done"] == 0

    conn.execute("""UPDATE users SET
        connections=connections+1, last_login=?, ip=?,
        os_info=COALESCE(NULLIF(?,''), os_info),
        cpu_info=COALESCE(NULLIF(?,''), cpu_info),
        gpu_info=COALESCE(NULLIF(?,''), gpu_info),
        ram_info=COALESCE(NULLIF(?,''), ram_info),
        motherboard_info=COALESCE(NULLIF(?,''), motherboard_info),
        disk_info=COALESCE(NULLIF(?,''), disk_info),
        session_token=?, first_login_done=1
        WHERE username=?""",
        (int(time.time()), ip, os_info, cpu_info, gpu_info, ram_info, mb_info, disk_info, session_token, username))
    conn.commit(); conn.close()
    record_login(username, ip, True)
    add_log("OK","LOGIN",f"Connexion: {username} plan={row['plan']} IP={ip}", username)
    _push_sse({"type":"login","username":username,"plan":row["plan"],"ip":ip})

    # Normaliser le plan (plus de LIFETIME)
    plan_final = row["plan"] if row["plan"] in ("NORMAL","PRO") else "PRO"
    # Récupérer les addons activés
    conn2 = get_db()
    addon_rows = conn2.execute("SELECT addon_key FROM user_addons WHERE username=?", (username,)).fetchall()
    conn2.close()
    active_addons = [r["addon_key"] for r in addon_rows]
    if plan_final == "PRO":
        for a in PRO_FREE_ADDONS:
            if a not in active_addons:
                active_addons.append(a)
    return jsonify({
        "success": True, "username": username, "plan": plan_final,
        "discord_id": row["discord_id"] or "", "first_login": first_login,
        "must_change_pass": must_change, "license_key": row["license_key"],
        "session_token": session_token, "addons": active_addons,
    })

@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    old_pass = data.get("old_password", "").strip()
    new_pass = data.get("new_password", "").strip()
    if len(new_pass) < 6: return jsonify({"success": False, "reason": "MDP trop court"})
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row: conn.close(); return jsonify({"success": False, "reason": "Utilisateur inconnu"})
    valid = (_hash_password(old_pass) == row["password_hash"]) or (row["temp_password"] and old_pass == row["temp_password"])
    if not valid: conn.close(); return jsonify({"success": False, "reason": "Ancien MDP incorrect"})
    conn.execute("UPDATE users SET password_hash=?,must_change_pass=0,temp_password=NULL WHERE username=?",
                 (_hash_password(new_pass), username))
    conn.commit(); conn.close()
    add_log("OK","ACCOUNT",f"MDP changé: {username}", username)
    return jsonify({"success": True})

@app.route("/api/request_reset", methods=["POST"])
def api_request_reset():
    data = request.get_json(silent=True) or {}
    req_type   = data.get("type", "password")
    username   = data.get("username", "").strip().lower()
    discord_id = data.get("discord_id", "").strip()
    if not discord_id: return jsonify({"success": False, "reason": "Discord ID requis"})
    conn = get_db()
    if req_type == "password":
        if not username: conn.close(); return jsonify({"success": False, "reason": "Username requis"})
        if not conn.execute("SELECT 1 FROM users WHERE username=? AND discord_id=?", (username, discord_id)).fetchone():
            conn.close(); return jsonify({"success": False, "reason": "Compte introuvable"})
    elif req_type == "username":
        row = conn.execute("SELECT username FROM users WHERE discord_id=?", (discord_id,)).fetchone()
        if not row: conn.close(); return jsonify({"success": False, "reason": "Aucun compte lié à ce Discord"})
        username = row["username"]
    if conn.execute("SELECT 1 FROM reset_requests WHERE username=? AND status='pending' AND type=?", (username, req_type)).fetchone():
        conn.close(); return jsonify({"success": False, "reason": "Demande déjà en attente"})
    conn.execute("INSERT INTO reset_requests (username,discord_id,type,status,requested_at) VALUES (?,?,?,?,?)",
                 (username, discord_id, req_type, "pending", int(time.time())))
    conn.commit(); conn.close()
    add_log("OK","RESET",f"Reset {req_type}: {username}")
    _push_sse({"type":"reset_request","username":username,"req_type":req_type})
    return jsonify({"success": True})

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip().lower()
    machine_id = data.get("machine_id", "")
    ip = get_real_ip()
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or row["status"] != "active": conn.close(); return jsonify({"valid": False})
    if row["hwid"] and machine_id and row["hwid"] != machine_id:
        conn.close(); return jsonify({"valid": False, "reason": "HWID mismatch"})
    plan_final = row["plan"] if row["plan"] in ("NORMAL","PRO") else "PRO"
    conn.execute("UPDATE users SET last_login=?,ip=?,connections=connections+1 WHERE username=?",
                 (int(time.time()), ip, username))
    addon_rows = conn.execute("SELECT addon_key FROM user_addons WHERE username=?", (username,)).fetchall()
    active_addons = [r["addon_key"] for r in addon_rows]
    if plan_final == "PRO":
        for a in PRO_FREE_ADDONS:
            if a not in active_addons:
                active_addons.append(a)
    conn.commit(); conn.close()
    return jsonify({"valid": True, "plan": plan_final, "username": username, "addons": active_addons})

@app.route("/api/ticket", methods=["POST"])
def api_create_ticket():
    data = request.get_json(silent=True) or {}
    subject = data.get("subject", "").strip(); message = data.get("message", "").strip()
    priority = data.get("priority", "normal")
    if not subject or not message: return jsonify({"success": False, "reason": "Champs manquants"})
    conn = get_db()
    conn.execute("INSERT INTO tickets (user,discord_id,subject,message,status,priority,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                 (data.get("username",""), data.get("discord_id",""), subject[:100], message[:1000], "open", priority, int(time.time()), int(time.time())))
    conn.commit(); conn.close()
    _push_sse({"type":"new_ticket","user":data.get("username",""),"subject":subject[:40]})
    return jsonify({"success": True})

# ─── REMOTE CONTROL API ───────────────────────────────────────────────────────
@app.route("/api/support/request", methods=["POST"])
def api_support_request():
    data = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip()
    machine_id = data.get("machine_id", "")
    ip         = get_real_ip()
    session_id = secrets.token_hex(16)
    with _remote_lock:
        _remote_sessions[session_id] = {
            "username": username, "machine_id": machine_id, "ip": ip,
            "status": "pending", "started_at": int(time.time()),
            "frames": [], "commands": [], "admin_user": None
        }
    conn = get_db()
    conn.execute("INSERT OR IGNORE INTO remote_sessions (id,username,started_at,status) VALUES (?,?,?,?)",
                 (session_id, username, int(time.time()), "pending"))
    conn.commit(); conn.close()
    add_log("OK","REMOTE",f"Support demandé: {username} IP={ip}", username)
    _push_sse({"type":"support_request","username":username,"ip":ip,"session_id":session_id})
    return jsonify({"success": True, "session_id": session_id})

@app.route("/api/support/frame", methods=["POST"])
def api_support_frame():
    """Reçoit une frame JPEG compressée du logiciel client."""
    data = request.get_json(silent=True) or {}
    session_id = data.get("session_id","")
    frame_b64  = data.get("frame","")
    with _remote_lock:
        sess = _remote_sessions.get(session_id)
        if not sess: return jsonify({"success": False, "reason": "Session inconnue"})
        if sess.get("status") not in ("active","pending"):
            return jsonify({"success": False, "reason": "Session inactive"})
        # Garder seulement les 3 dernières frames
        sess["frames"] = sess["frames"][-2:] + [frame_b64]
        # Retourner les commandes en attente
        cmds = list(sess.get("commands", []))
        sess["commands"] = []
    return jsonify({"success": True, "commands": cmds})

@app.route("/api/support/end", methods=["POST"])
def api_support_end():
    data = request.get_json(silent=True) or {}
    username   = data.get("username","")
    session_id = data.get("session_id","")
    with _remote_lock:
        # Trouver la session par username si pas d'ID
        if not session_id:
            for sid, s in _remote_sessions.items():
                if s["username"] == username: session_id = sid; break
        if session_id in _remote_sessions:
            _remote_sessions[session_id]["status"] = "ended"
    conn = get_db()
    conn.execute("UPDATE remote_sessions SET status='ended',ended_at=? WHERE id=?",
                 (int(time.time()), session_id))
    conn.commit(); conn.close()
    _push_sse({"type":"support_ended","username":username})
    return jsonify({"success": True})

# Addons PRO gratuits automatiques
PRO_FREE_ADDONS = ["fps_counter", "vibrance", "ram_cleaner", "overclock", "antilag", "process_boost"]

@app.route("/api/addon/activate", methods=["POST"])
def api_addon_activate():
    """
    Active un addon et le lie au compte utilisateur dans user_addons.
    Payload: { username, addon_key, addon_license_key }
    Les PRO activent leurs addons gratuits sans clé (source='pro_free').
    """
    data = request.get_json(silent=True) or {}
    username          = data.get("username","").strip().lower()
    addon_name        = data.get("addon_key","").strip().lower()
    addon_license_key = data.get("addon_license_key","").strip().upper()

    if not username or not addon_name:
        return jsonify({"success": False, "reason": "Paramètres manquants"})

    conn = get_db()
    user = conn.execute("SELECT plan FROM users WHERE username=? AND status='active'", (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "reason": "Utilisateur introuvable ou inactif"})

    plan = user["plan"]

    # Vérifier si déjà activé
    already = conn.execute("SELECT 1 FROM user_addons WHERE username=? AND addon_key=?", (username, addon_name)).fetchone()
    if already:
        conn.close()
        return jsonify({"success": True, "addon_key": addon_name, "already": True})

    # Addon PRO gratuit — pas besoin de clé
    if plan == "PRO" and addon_name in PRO_FREE_ADDONS and not addon_license_key:
        conn.execute("INSERT OR IGNORE INTO user_addons (username,addon_key,source,activated_at) VALUES (?,?,?,?)",
                     (username, addon_name, "pro_free", int(time.time())))
        conn.commit(); conn.close()
        add_log("OK","ADDON",f"Addon PRO gratuit '{addon_name}' activé: {username}", username)
        return jsonify({"success": True, "addon_key": addon_name, "free": True})

    # Activation par clé
    if not addon_license_key:
        conn.close()
        return jsonify({"success": False, "reason": "Clé addon requise pour cet addon"})

    row = conn.execute(
        "SELECT * FROM addon_licenses WHERE key=? AND addon_key=?",
        (addon_license_key, addon_name)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "reason": "Clé invalide ou mauvais addon"})
    if row["status"] == "used":
        conn.close()
        return jsonify({"success": False, "reason": "Clé déjà utilisée"})
    if row["status"] != "active":
        conn.close()
        return jsonify({"success": False, "reason": f"Clé {row['status']}"})

    conn.execute("UPDATE addon_licenses SET status='used' WHERE key=?", (addon_license_key,))
    conn.execute("INSERT OR IGNORE INTO user_addons (username,addon_key,source,activated_at) VALUES (?,?,?,?)",
                 (username, addon_name, "key", int(time.time())))
    conn.commit(); conn.close()
    add_log("OK","ADDON",f"Addon '{addon_name}' activé par {username} (clé:{addon_license_key[:8]}…)", username)
    return jsonify({"success": True, "addon_key": addon_name})

@app.route("/api/addon/list", methods=["POST"])
def api_addon_list():
    """Retourne la liste des addons activés pour un user (inclut les PRO gratuits)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username","").strip().lower()
    if not username:
        return jsonify({"success": False, "reason": "Username requis"})
    conn = get_db()
    user = conn.execute("SELECT plan FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "reason": "Utilisateur inconnu"})
    rows = conn.execute("SELECT addon_key, source, activated_at FROM user_addons WHERE username=?", (username,)).fetchall()
    conn.close()
    addons = [{"key": r["addon_key"], "source": r["source"]} for r in rows]
    # Inclure les PRO gratuits pas encore activés
    if user["plan"] == "PRO":
        activated_keys = {a["key"] for a in addons}
        for a in PRO_FREE_ADDONS:
            if a not in activated_keys:
                addons.append({"key": a, "source": "pro_free_auto"})
    return jsonify({"success": True, "addons": addons, "plan": user["plan"]})

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN AUTH
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username",""); p = request.form.get("password","")
        conn = get_db(); row = conn.execute("SELECT * FROM admins WHERE username=?", (u,)).fetchone(); conn.close()
        if row and row["password_hash"] == _hash_password(p):
            session["admin_logged"] = True; session["admin_user"] = row["username"]; session["admin_role"] = row["role"]
            add_log("OK","ADMIN",f"Login admin: {u}")
            return redirect("/admin")
        error = "Identifiants incorrects"
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/admin/logout")
def admin_logout():
    session.clear(); return redirect("/admin/login")

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — DASHBOARD
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db()
    today = int(time.time()) - 86400
    stats = {
        "total":         conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":        conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":        conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":           conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "normal":        conn.execute("SELECT COUNT(*) FROM users WHERE plan='NORMAL'").fetchone()[0],
        "total_lic":     conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "pending_reset": conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets":  conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "today_logins":  conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "new_today":     conn.execute("SELECT COUNT(*) FROM users WHERE created_at>?", (today,)).fetchone()[0],
        "hwid_alerts":   conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "remote_active": len([s for s in _remote_sessions.values() if s.get("status")=="active"]),
        "remote_pending":len([s for s in _remote_sessions.values() if s.get("status")=="pending"]),
        "maintenance":   get_setting("maintenance") == "1",
    }
    hourly = []
    for i in range(24):
        ts = int(time.time()) - (i+1)*3600; te = int(time.time()) - i*3600
        hourly.append(conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (ts,te)).fetchone()[0])
    hourly.reverse(); stats["hourly"] = hourly
    recent_users = conn.execute("SELECT username,plan,status,last_login,ip,connections,os_info,gpu_info FROM users ORDER BY last_login DESC LIMIT 8").fetchall()
    recent_logs = conn.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT 8").fetchall()
    # Top countries
    top_ips = conn.execute("SELECT ip, COUNT(*) as cnt FROM users WHERE ip IS NOT NULL AND ip!='' GROUP BY ip ORDER BY cnt DESC LIMIT 10").fetchall()
    conn.close()
    return _page_dashboard(stats, recent_users, recent_logs, top_ips, session["admin_user"], session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — USERS
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q",""); plan_f = request.args.get("plan",""); status_f = request.args.get("status","")
    tag_f = request.args.get("tag","")
    conn = get_db()
    sql = "SELECT * FROM users WHERE 1=1"; params = []
    if q: sql += " AND (username LIKE ? OR discord_id LIKE ? OR ip LIKE ? OR license_key LIKE ? OR cpu_info LIKE ? OR gpu_info LIKE ?)"; params += [f"%{q}%"]*6
    if plan_f: sql += " AND plan=?"; params.append(plan_f)
    if status_f: sql += " AND status=?"; params.append(status_f)
    if tag_f: sql += " AND tags LIKE ?"; params.append(f"%{tag_f}%")
    sql += " ORDER BY last_login DESC LIMIT 200"
    rows = conn.execute(sql, params).fetchall(); conn.close()
    return _page_users(rows, q, plan_f, status_f, session["admin_user"], session["admin_role"])

@app.route("/admin/user/<username>")
@admin_required
def admin_user_detail(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user: conn.close(); return "Introuvable", 404
    logs = conn.execute("SELECT * FROM logs WHERE user=? ORDER BY ts DESC LIMIT 50", (username,)).fetchall()
    alerts = conn.execute("SELECT * FROM hwid_alerts WHERE username=? ORDER BY ts DESC LIMIT 10", (username,)).fetchall()
    login_hist = conn.execute("SELECT * FROM login_history WHERE username=? ORDER BY ts DESC LIMIT 20", (username,)).fetchall()
    notes = conn.execute("SELECT * FROM admin_notes WHERE username=? ORDER BY ts DESC", (username,)).fetchall()
    remote_hist = conn.execute("SELECT * FROM remote_sessions WHERE username=? ORDER BY started_at DESC LIMIT 5", (username,)).fetchall()
    conn.close()
    geo = get_geoip(user["ip"]) if user["ip"] else {}
    msg = request.args.get("msg","")
    return _page_user_detail(user, logs, alerts, login_hist, notes, remote_hist, geo, msg,
                             session["admin_user"], session["admin_role"])

@app.route("/admin/user/<username>/action", methods=["POST"])
@admin_required
def admin_user_action(username):
    action = request.form.get("action"); conn = get_db()
    if action == "suspend":
        conn.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
        add_log("WARN","ADMIN",f"Suspendu: {username}", session["admin_user"])
    elif action == "ban":
        conn.execute("UPDATE users SET status='banned' WHERE username=?", (username,))
        add_log("WARN","ADMIN",f"Banni: {username}", session["admin_user"])
    elif action == "reactivate":
        conn.execute("UPDATE users SET status='active' WHERE username=?", (username,))
        add_log("OK","ADMIN",f"Réactivé: {username}", session["admin_user"])
    elif action == "reset_hwid":
        conn.execute("UPDATE users SET hwid='' WHERE username=?", (username,))
        add_log("OK","ADMIN",f"HWID reset: {username}", session["admin_user"])
    elif action == "reset_password":
        temp = _gen_temp_password()
        conn.execute("UPDATE users SET password_hash=?,must_change_pass=1,temp_password=? WHERE username=?",
                     (_hash_password(temp), temp, username))
        conn.commit(); conn.close()
        ur = get_db().execute("SELECT discord_id FROM users WHERE username=?", (username,)).fetchone()
        if ur and ur["discord_id"]: _notify_discord(ur["discord_id"], f"🔑 MDP temporaire: `{temp}` — Change-le à la connexion!")
        add_log("OK","ADMIN",f"MDP reset: {username} temp={temp}", session["admin_user"])
        return redirect(f"/admin/user/{username}?msg=MDP+temp:+{temp}")
    elif action == "upgrade_pro":
        conn.execute("UPDATE users SET plan='PRO' WHERE username=?", (username,))
        add_log("OK","ADMIN",f"Upgrade PRO: {username}", session["admin_user"])
    elif action == "upgrade_lifetime":
        conn.execute("UPDATE users SET plan='PRO' WHERE username=?", (username,))
        add_log("OK","ADMIN",f"Upgrade PRO: {username}", session["admin_user"])
    elif action == "downgrade_normal":
        conn.execute("UPDATE users SET plan='NORMAL' WHERE username=?", (username,))
        add_log("OK","ADMIN",f"Downgrade NORMAL: {username}", session["admin_user"])
    conn.commit(); conn.close()
    return redirect(f"/admin/user/{username}")

@app.route("/admin/user/<username>/edit", methods=["POST"])
@admin_required
def admin_user_edit(username):
    conn = get_db()
    conn.execute("UPDATE users SET plan=?,note=?,discord_id=?,tags=? WHERE username=?",
                 (request.form.get("plan","NORMAL"), request.form.get("note",""),
                  request.form.get("discord_id",""), request.form.get("tags",""), username))
    conn.commit(); conn.close()
    add_log("OK","ADMIN",f"User {username} modifié", session["admin_user"])
    return redirect(f"/admin/user/{username}?msg=Sauvegardé")

@app.route("/admin/user/<username>/note", methods=["POST"])
@admin_required
def admin_add_note(username):
    note = request.form.get("note","").strip()
    color = request.form.get("color","gray")
    if note:
        conn = get_db()
        conn.execute("INSERT INTO admin_notes (username,note,author,ts,color) VALUES (?,?,?,?,?)",
                     (username, note, session["admin_user"], int(time.time()), color))
        conn.commit(); conn.close()
    return redirect(f"/admin/user/{username}#notes")

@app.route("/admin/user/<username>/note/<int:nid>/delete", methods=["POST"])
@admin_required
def admin_delete_note(username, nid):
    conn = get_db()
    conn.execute("DELETE FROM admin_notes WHERE id=? AND username=?", (nid, username))
    conn.commit(); conn.close()
    return redirect(f"/admin/user/{username}#notes")

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — REMOTE CONTROL PANEL
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/remote")
@admin_required
def admin_remote():
    conn = get_db()
    sessions_db = conn.execute("SELECT * FROM remote_sessions ORDER BY started_at DESC LIMIT 30").fetchall()
    conn.close()
    active = {sid: s for sid, s in _remote_sessions.items() if s.get("status") in ("pending","active")}
    return _page_remote(active, sessions_db, session["admin_user"], session["admin_role"])

@app.route("/admin/remote/<session_id>")
@admin_required
def admin_remote_viewer(session_id):
    with _remote_lock:
        sess = _remote_sessions.get(session_id)
    if not sess:
        return redirect("/admin/remote")
    return _page_remote_viewer(session_id, sess, session["admin_user"], session["admin_role"])

@app.route("/admin/remote/<session_id>/connect", methods=["POST"])
@admin_required
def admin_remote_connect(session_id):
    with _remote_lock:
        if session_id in _remote_sessions:
            _remote_sessions[session_id]["status"] = "active"
            _remote_sessions[session_id]["admin_user"] = session["admin_user"]
    conn = get_db()
    conn.execute("UPDATE remote_sessions SET status='active',admin_user=? WHERE id=?",
                 (session["admin_user"], session_id))
    conn.commit(); conn.close()
    add_log("OK","REMOTE",f"Admin {session['admin_user']} connecté à {_remote_sessions.get(session_id,{}).get('username','?')}", session["admin_user"])
    _push_sse({"type":"remote_connected","session_id":session_id,"admin":session["admin_user"]})
    return jsonify({"success": True})

@app.route("/admin/remote/<session_id>/frame")
@admin_required
def admin_remote_frame(session_id):
    """Retourne la dernière frame disponible."""
    with _remote_lock:
        sess = _remote_sessions.get(session_id)
        if not sess or not sess.get("frames"):
            return jsonify({"frame": None, "status": sess["status"] if sess else "unknown"})
        frame = sess["frames"][-1] if sess["frames"] else None
    return jsonify({"frame": frame, "status": sess.get("status","unknown"),
                    "username": sess.get("username","?")})

@app.route("/admin/remote/<session_id>/command", methods=["POST"])
@admin_required
def admin_remote_command(session_id):
    """Envoie une commande souris/clavier au client."""
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd","")
    with _remote_lock:
        sess = _remote_sessions.get(session_id)
        if sess and sess.get("status") == "active":
            if "commands" not in sess: sess["commands"] = []
            sess["commands"].append(cmd)
    return jsonify({"success": True})

@app.route("/admin/remote/<session_id>/disconnect", methods=["POST"])
@admin_required
def admin_remote_disconnect(session_id):
    with _remote_lock:
        if session_id in _remote_sessions:
            _remote_sessions[session_id]["status"] = "ended"
    conn = get_db()
    conn.execute("UPDATE remote_sessions SET status='ended',ended_at=? WHERE id=?",
                 (int(time.time()), session_id))
    conn.commit(); conn.close()
    _push_sse({"type":"remote_ended","session_id":session_id})
    return redirect("/admin/remote")

@app.route("/admin/addons")
@admin_required
def admin_addons():
    conn = get_db()
    addon_keys = conn.execute("SELECT * FROM addon_licenses ORDER BY created_at DESC LIMIT 500").fetchall()
    stats = {}
    for addon in ["crosshair","fps_counter","vibrance","ram_cleaner","overclock","antilag",
                  "process_boost","gpu_tuner","network_mon","temp_mon","input_lag","boot_speed"]:
        stats[addon] = {
            "active": conn.execute("SELECT COUNT(*) FROM addon_licenses WHERE addon_key=? AND status='active'", (addon,)).fetchone()[0],
            "used":   conn.execute("SELECT COUNT(*) FROM addon_licenses WHERE addon_key=? AND status='used'",   (addon,)).fetchone()[0],
        }
    conn.close()
    return _page_addons(addon_keys, stats, session["admin_user"], session["admin_role"])

@app.route("/admin/addons/revoke", methods=["POST"])
@admin_required
def admin_revoke_addon():
    key = request.form.get("key","")
    conn = get_db()
    conn.execute("UPDATE addon_licenses SET status='revoked' WHERE key=?", (key,))
    conn.commit(); conn.close()
    add_log("WARN","ADDON",f"Clé addon révoquée: {key[:11]}…", session["admin_user"])
    return redirect(request.referrer or "/admin/addons")

@app.route("/admin/addons/generate", methods=["POST"])
@admin_required
def admin_addons_generate():
    addon = request.form.get("addon_key","crosshair")
    qty = min(int(request.form.get("qty",1)), 500)
    note = request.form.get("note","")
    conn = get_db(); generated = []
    for _ in range(qty):
        key = generate_addon_key(addon)
        conn.execute("INSERT OR IGNORE INTO addon_licenses (key,addon_key,plan,status,created_at,note) VALUES (?,?,?,?,?,?)",
                     (key, addon, "PRO", "active", int(time.time()), note))
        generated.append(key)
    conn.commit(); conn.close()
    add_log("OK","ADDON_KEYS",f"{qty} clé(s) addon {addon}", session["admin_user"])
    return _page_keys_result(generated, addon, "addon", session["admin_user"], session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — KEYS / ADDON KEYS
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/keys")
@admin_required
def admin_keys():
    conn = get_db()
    keys = conn.execute("SELECT l.*,u.username FROM licenses l LEFT JOIN users u ON l.key=u.license_key ORDER BY l.created_at DESC LIMIT 200").fetchall()
    addon_keys = conn.execute("SELECT * FROM addon_licenses ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return _page_keys(keys, addon_keys, session["admin_user"], session["admin_role"])

@app.route("/admin/keys/generate", methods=["POST"])
@admin_required
def admin_gen_keys():
    plan = request.form.get("plan","NORMAL"); qty = min(int(request.form.get("qty",1)),500)
    note = request.form.get("note",""); conn = get_db(); generated = []
    for _ in range(qty):
        key = generate_key(plan)
        conn.execute("INSERT OR IGNORE INTO licenses (key,plan,status,created_at,note) VALUES (?,?,?,?,?)",
                     (key, plan, "active", int(time.time()), note))
        generated.append(key)
    conn.commit(); conn.close()
    add_log("OK","KEYS",f"{qty} clé(s) {plan}", session["admin_user"])
    return _page_keys_result(generated, plan, "license", session["admin_user"], session["admin_role"])

@app.route("/admin/keys/generate_addon", methods=["POST"])
@admin_required
def admin_gen_addon_keys():
    addon = request.form.get("addon_key","crosshair")
    qty = min(int(request.form.get("qty",1)),100)
    note = request.form.get("note",""); conn = get_db(); generated = []
    for _ in range(qty):
        key = generate_addon_key(addon)
        conn.execute("INSERT OR IGNORE INTO addon_licenses (key,addon_key,status,created_at,note) VALUES (?,?,?,?,?)",
                     (key, addon, "active", int(time.time()), note))
        generated.append(key)
    conn.commit(); conn.close()
    add_log("OK","ADDON_KEYS",f"{qty} clé(s) addon {addon}", session["admin_user"])
    return _page_keys_result(generated, addon, "addon", session["admin_user"], session["admin_role"])

@app.route("/admin/keys/revoke", methods=["POST"])
@admin_required
def admin_revoke_key():
    key = request.form.get("key",""); conn = get_db()
    conn.execute("UPDATE licenses SET status='revoked' WHERE key=?", (key,))
    conn.commit(); conn.close()
    add_log("WARN","KEYS",f"Révoquée: {key[:11]}…", session["admin_user"])
    return redirect("/admin/keys")

@app.route("/admin/keys/bulk_revoke", methods=["POST"])
@admin_required
def admin_bulk_revoke():
    keys = [k.strip() for k in request.form.get("keys","").split("\n") if k.strip()]
    conn = get_db()
    for k in keys: conn.execute("UPDATE licenses SET status='revoked' WHERE key=?", (k,))
    conn.commit(); conn.close()
    add_log("WARN","KEYS",f"{len(keys)} clé(s) révoquées en masse", session["admin_user"])
    return redirect("/admin/keys")

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — MAINTENANCE / IPs / RESETS / TICKETS / LOGS / BROADCAST / OWNERS
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/maintenance", methods=["GET","POST"])
@admin_required
def admin_maintenance():
    if request.method == "POST":
        set_setting("maintenance", request.form.get("state","0"))
        if request.form.get("msg_text",""): set_setting("maintenance_msg", request.form.get("msg_text"))
        if request.form.get("announce",""): set_setting("announce", request.form.get("announce",""))
        if request.form.get("announce_color",""): set_setting("announce_color", request.form.get("announce_color","blue"))
        add_log("OK","ADMIN",f"Maintenance: {'ON' if request.form.get('state')=='1' else 'OFF'}", session["admin_user"])
        return redirect("/admin/maintenance")
    return _page_maintenance(get_setting("maintenance")=="1", get_setting("maintenance_msg"),
                             get_setting("announce"), get_setting("announce_color"),
                             session["admin_user"], session["admin_role"])

@app.route("/admin/ips")
@admin_required
def admin_ips():
    conn = get_db(); rules = conn.execute("SELECT * FROM ip_rules ORDER BY added_at DESC").fetchall(); conn.close()
    return _page_ips(rules, get_setting("vpn_block")=="1", request.args.get("prefill",""),
                     session["admin_user"], session["admin_role"])

@app.route("/admin/ips/add", methods=["POST"])
@admin_required
def admin_add_ip():
    ip = request.form.get("ip","").strip(); rule = request.form.get("rule","blacklist"); note = request.form.get("note","")
    if ip:
        conn = get_db(); conn.execute("INSERT OR REPLACE INTO ip_rules VALUES (?,?,?,?)", (ip,rule,note,int(time.time()))); conn.commit(); conn.close()
        add_log("OK","IP",f"IP {rule}: {ip}", session["admin_user"])
    return redirect("/admin/ips")

@app.route("/admin/ips/delete", methods=["POST"])
@admin_required
def admin_del_ip():
    ip = request.form.get("ip",""); conn = get_db()
    conn.execute("DELETE FROM ip_rules WHERE ip=?", (ip,)); conn.commit(); conn.close()
    return redirect("/admin/ips")

@app.route("/admin/ips/vpn", methods=["POST"])
@admin_required
def admin_toggle_vpn():
    set_setting("vpn_block", "0" if get_setting("vpn_block")=="1" else "1")
    return redirect("/admin/ips")

@app.route("/admin/resets")
@admin_required
def admin_resets():
    conn = get_db(); rows = conn.execute("SELECT * FROM reset_requests ORDER BY requested_at DESC LIMIT 100").fetchall(); conn.close()
    return _page_resets(rows, session["admin_user"], session["admin_role"])

@app.route("/admin/resets/<int:rid>/approve", methods=["POST"])
@admin_required
def admin_approve_reset(rid):
    conn = get_db(); req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (rid,)).fetchone()
    if not req or req["status"] != "pending": conn.close(); return redirect("/admin/resets")
    if req["type"] == "password":
        temp = _gen_temp_password()
        conn.execute("UPDATE users SET password_hash=?,must_change_pass=1,temp_password=? WHERE username=?",
                     (_hash_password(temp), temp, req["username"]))
        conn.execute("UPDATE reset_requests SET status='approved',temp_pass=?,resolved_at=? WHERE id=?", (temp,int(time.time()),rid))
        if req["discord_id"]: _notify_discord(req["discord_id"], f"✅ MDP temp: `{temp}` — Change-le à la connexion!")
    elif req["type"] == "username":
        if req["discord_id"]: _notify_discord(req["discord_id"], f"✅ Ton username: `{req['username']}`")
        conn.execute("UPDATE reset_requests SET status='approved',resolved_at=? WHERE id=?", (int(time.time()),rid))
    conn.commit(); conn.close()
    return redirect("/admin/resets")

@app.route("/admin/resets/<int:rid>/deny", methods=["POST"])
@admin_required
def admin_deny_reset(rid):
    conn = get_db(); req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (rid,)).fetchone()
    if req and req["discord_id"]: _notify_discord(req["discord_id"], "❌ Ta demande de reset a été refusée.")
    conn.execute("UPDATE reset_requests SET status='denied',resolved_at=? WHERE id=?", (int(time.time()),rid))
    conn.commit(); conn.close(); return redirect("/admin/resets")

@app.route("/admin/tickets")
@admin_required
def admin_tickets():
    prio_f = request.args.get("priority","")
    conn = get_db()
    sql = "SELECT * FROM tickets WHERE 1=1"
    params = []
    if prio_f: sql += " AND priority=?"; params.append(prio_f)
    sql += " ORDER BY created_at DESC LIMIT 100"
    rows = conn.execute(sql, params).fetchall(); conn.close()
    return _page_tickets(rows, session["admin_user"], session["admin_role"])

@app.route("/admin/tickets/<int:tid>/reply", methods=["POST"])
@admin_required
def admin_ticket_reply(tid):
    response = request.form.get("response",""); close = request.form.get("close","0")
    conn = get_db(); ticket = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    conn.execute("UPDATE tickets SET response=?,status=?,updated_at=? WHERE id=?",
                 (response, "closed" if close=="1" else "answered", int(time.time()), tid))
    conn.commit()
    if ticket and ticket["discord_id"]: _notify_discord(ticket["discord_id"], f"📩 Réponse ticket #{tid}:\n{response}")
    conn.close(); return redirect("/admin/tickets")

@app.route("/admin/logs")
@admin_required
def admin_logs():
    ft = request.args.get("type",""); conn = get_db()
    rows = conn.execute("SELECT * FROM logs WHERE type=? ORDER BY ts DESC LIMIT 500" if ft else "SELECT * FROM logs ORDER BY ts DESC LIMIT 500",
                        (ft,) if ft else ()).fetchall()
    conn.close()
    return _page_logs(rows, ft, session["admin_user"], session["admin_role"])

@app.route("/admin/broadcast", methods=["GET","POST"])
@admin_required
def admin_broadcast():
    msg_sent = ""
    if request.method == "POST":
        message = request.form.get("message","").strip(); target = request.form.get("target","all")
        conn = get_db()
        q = {"all":"SELECT discord_id FROM users WHERE status='active' AND discord_id IS NOT NULL AND discord_id!=''",
             "pro":"SELECT discord_id FROM users WHERE plan='PRO' AND discord_id IS NOT NULL AND discord_id!=''",
             "normal":"SELECT discord_id FROM users WHERE plan='NORMAL' AND status='active' AND discord_id IS NOT NULL AND discord_id!=''"}.get(target,"")
        users_list = conn.execute(q).fetchall() if q else []; conn.close()
        for u in users_list: _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer**\n{message}")
        msg_sent = f"✅ Envoyé à {len(users_list)} utilisateur(s)."
        add_log("OK","BROADCAST",f"{target}: {message[:60]}", session["admin_user"])
    return _page_broadcast(msg_sent, session["admin_user"], session["admin_role"])

@app.route("/admin/owners")
@admin_required
def admin_owners():
    if session.get("admin_role") != "owner": return redirect("/admin")
    conn = get_db(); rows = conn.execute("SELECT * FROM admins ORDER BY created_at").fetchall(); conn.close()
    return _page_owners(rows, session["admin_user"], session["admin_role"])

@app.route("/admin/owners/create", methods=["POST"])
@admin_required
def admin_create_admin():
    if session.get("admin_role") != "owner": return redirect("/admin")
    u = request.form.get("username","").strip(); p = request.form.get("password","").strip(); r = request.form.get("role","staff")
    if u and p:
        conn = get_db()
        try:
            conn.execute("INSERT INTO admins (username,password_hash,role,created_at,created_by) VALUES (?,?,?,?,?)",
                         (u, _hash_password(p), r, int(time.time()), session["admin_user"]))
            conn.commit()
        except: pass
        conn.close()
    return redirect("/admin/owners")

@app.route("/admin/owners/delete", methods=["POST"])
@admin_required
def admin_delete_admin():
    if session.get("admin_role") != "owner": return redirect("/admin")
    u = request.form.get("username","")
    if u != "xywez":
        conn = get_db(); conn.execute("DELETE FROM admins WHERE username=?", (u,)); conn.commit(); conn.close()
    return redirect("/admin/owners")

@app.route("/admin/profile", methods=["GET","POST"])
@admin_required
def admin_profile():
    msg = ""
    if request.method == "POST":
        old = request.form.get("old_password",""); new = request.form.get("new_password","")
        conn = get_db(); row = conn.execute("SELECT * FROM admins WHERE username=?", (session["admin_user"],)).fetchone()
        if row and _hash_password(old) == row["password_hash"]:
            conn.execute("UPDATE admins SET password_hash=? WHERE username=?", (_hash_password(new), session["admin_user"]))
            conn.commit(); msg = "✅ MDP changé"
        else: msg = "❌ Ancien MDP incorrect"
        conn.close()
    return _page_profile(msg, session["admin_user"], session["admin_role"])

@app.route("/admin/anti-leak")
@admin_required
def admin_anti_leak():
    conn = get_db()
    alerts = conn.execute("SELECT * FROM hwid_alerts ORDER BY ts DESC LIMIT 100").fetchall()
    conn.close()
    return _page_anti_leak(alerts, session["admin_user"], session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — API JSON
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/api/user_addons")
@admin_required
def admin_api_user_addons():
    username = request.args.get("username","").lower()
    if not username:
        return jsonify({"addons":[]})
    conn = get_db()
    rows = conn.execute("SELECT addon_key, source FROM user_addons WHERE username=?", (username,)).fetchall()
    user = conn.execute("SELECT plan FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    addons = [{"key": r["addon_key"], "source": r["source"]} for r in rows]
    if user and user["plan"] == "PRO":
        PRO_FREE = ["fps_counter","vibrance","ram_cleaner","overclock","antilag","process_boost"]
        have = {a["key"] for a in addons}
        for a in PRO_FREE:
            if a not in have:
                addons.append({"key": a, "source": "pro_free_auto"})
    return jsonify({"addons": addons, "plan": user["plan"] if user else "NORMAL"})

@app.route("/admin/api/stats")
@admin_required
def admin_api_stats():
    conn = get_db()
    today = int(time.time()) - 86400
    hourly = []
    for i in range(24):
        ts = int(time.time())-(i+1)*3600; te = int(time.time())-i*3600
        hourly.append(conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (ts,te)).fetchone()[0])
    hourly.reverse()
    d = {
        "total":          conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":         conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":         conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":            conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "today_logins":   conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "total_keys":     conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "pending_resets": conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets":   conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "hwid_alerts":    conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "remote_active":  len([s for s in _remote_sessions.values() if s.get("status")=="active"]),
        "remote_pending": len([s for s in _remote_sessions.values() if s.get("status")=="pending"]),
        "hourly":         hourly,
        "maintenance":    get_setting("maintenance") == "1",
        "ts":             int(time.time()),
    }
    conn.close(); return jsonify(d)

@app.route("/admin/api/recent_users")
@admin_required
def admin_api_recent():
    conn = get_db()
    rows = conn.execute("SELECT username,plan,status,last_login,ip,connections,os_info,cpu_info,gpu_info FROM users ORDER BY last_login DESC LIMIT 10").fetchall()
    conn.close(); return jsonify([dict(r) for r in rows])

@app.route("/admin/api/geoip")
@admin_required
def admin_api_geoip():
    ip = request.args.get("ip","")
    if not ip: return jsonify({"error": "IP manquante"})
    return jsonify(get_geoip(ip))

@app.route("/admin/api/remote_sessions")
@admin_required
def admin_api_remote_sessions():
    sessions = []
    with _remote_lock:
        for sid, s in _remote_sessions.items():
            if s.get("status") in ("pending","active"):
                sessions.append({"id":sid,"username":s["username"],"ip":s.get("ip","?"),
                                 "status":s["status"],"started_at":s["started_at"],
                                 "has_frame":len(s.get("frames",[]))>0})
    return jsonify(sessions)

# ════════════════════════════════════════════════════════════════════════════════
#  API INTERNES BOT
# ════════════════════════════════════════════════════════════════════════════════

def _check_bot_token(data=None, args=None):
    token = (data or {}).get("bot_token") or (args or {}).get("bot_token","")
    return token == os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN")

@app.route("/api/internal/gen_key", methods=["POST"])
def internal_gen_key():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    plan = data.get("plan","NORMAL"); qty = min(int(data.get("qty",1)),10)
    conn = get_db(); keys = []
    for _ in range(qty):
        key = generate_key(plan)
        conn.execute("INSERT OR IGNORE INTO licenses (key,plan,status,created_at,note) VALUES (?,?,?,?,?)",
                     (key,plan,"active",int(time.time()),"Généré via bot"))
        keys.append(key)
    conn.commit(); conn.close()
    return jsonify({"keys": keys})

@app.route("/api/internal/approve_reset", methods=["POST"])
def internal_approve_reset():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    req_id = data.get("req_id"); conn = get_db()
    req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (req_id,)).fetchone()
    if not req: conn.close(); return jsonify({"error":"Not found"}), 404
    if req["type"] == "password":
        temp = _gen_temp_password()
        conn.execute("UPDATE users SET password_hash=?,must_change_pass=1,temp_password=? WHERE username=?",
                     (_hash_password(temp), temp, req["username"]))
        conn.execute("UPDATE reset_requests SET status='approved',temp_pass=?,resolved_at=? WHERE id=?",
                     (temp,int(time.time()),req_id))
        conn.commit(); conn.close()
        return jsonify({"success":True,"temp_pass":temp,"username":req["username"],"discord_id":req["discord_id"]})
    conn.close(); return jsonify({"success":False})

@app.route("/api/internal/pending_resets")
def internal_pending_resets():
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    conn = get_db(); rows = conn.execute("SELECT * FROM reset_requests WHERE status='pending' ORDER BY requested_at").fetchall(); conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/internal/stats")
def internal_stats():
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    conn = get_db(); today = int(time.time()) - 86400
    d = {
        "total":         conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":        conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":        conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":           conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "normal":        conn.execute("SELECT COUNT(*) FROM users WHERE plan='NORMAL'").fetchone()[0],
        "today":         conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "total_keys":    conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "addon_active":  conn.execute("SELECT COUNT(*) FROM addon_licenses WHERE status='active'").fetchone()[0],
        "pending_resets":conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets":  conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "hwid_alerts":   conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "maintenance":   get_setting("maintenance")=="1",
    }
    conn.close(); return jsonify(d)

@app.route("/api/internal/user_info")
def internal_user_info():
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    username = request.args.get("username","")
    conn = get_db(); row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone(); conn.close()
    if not row: return jsonify({"error":"Introuvable"}), 404
    return jsonify({k: row[k] for k in row.keys() if k != "password_hash"})

@app.route("/api/internal/user_action", methods=["POST"])
def internal_user_action():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    username = data.get("username","").lower(); action = data.get("action","")
    conn = get_db()
    actions_map = {"ban":"banned","reactivate":"active","suspend":"suspended"}
    if action in actions_map:
        conn.execute("UPDATE users SET status=? WHERE username=?", (actions_map[action], username))
        add_log("WARN" if action!="reactivate" else "OK","BOT",f"{action}: {username}")
    elif action == "reset_hwid":
        conn.execute("UPDATE users SET hwid='' WHERE username=?", (username,))
    else:
        conn.close(); return jsonify({"error":"Action inconnue"}), 400
    conn.commit(); conn.close()
    return jsonify({"success": True})

@app.route("/api/internal/revoke_key", methods=["POST"])
def internal_revoke_key():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    key = data.get("key","").upper()
    conn = get_db(); conn.execute("UPDATE licenses SET status='revoked' WHERE key=?", (key,)); conn.commit(); conn.close()
    return jsonify({"success": True})

@app.route("/api/internal/broadcast", methods=["POST"])
def internal_broadcast():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    message = data.get("message",""); target = data.get("target","all")
    conn = get_db()
    q = {
        "all":    "SELECT discord_id FROM users WHERE status='active' AND discord_id IS NOT NULL AND discord_id!=''",
        "pro":    "SELECT discord_id FROM users WHERE plan='PRO' AND status='active' AND discord_id IS NOT NULL AND discord_id!=''",
        "normal": "SELECT discord_id FROM users WHERE plan='NORMAL' AND status='active' AND discord_id IS NOT NULL AND discord_id!=''"
    }.get(target,"")
    users_list = conn.execute(q).fetchall() if q else []; conn.close()
    for u in users_list: _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer**\n{message}")
    return jsonify({"success": True, "count": len(users_list)})

@app.route("/api/internal/set_maintenance", methods=["POST"])
def internal_set_maintenance():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    state = data.get("state","0"); set_setting("maintenance", state)
    return jsonify({"success": True, "maintenance": state=="1"})

@app.route("/api/internal/gen_addon_key", methods=["POST"])
def internal_gen_addon_key():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    addon = data.get("addon_key","").strip()
    qty = min(int(data.get("qty",1)), 10)
    if not addon: return jsonify({"error":"addon_key manquant"}), 400
    conn = get_db(); keys = []
    for _ in range(qty):
        key = generate_addon_key(addon)
        conn.execute("INSERT OR IGNORE INTO addon_licenses (key,addon_key,plan,status,created_at,note) VALUES (?,?,?,?,?,?)",
                     (key, addon, "PRO", "active", int(time.time()), "Généré via bot Discord"))
        keys.append(key)
    conn.commit(); conn.close()
    add_log("OK","ADDON_KEYS",f"{qty} clé(s) addon '{addon}' générées via bot")
    return jsonify({"keys": keys})

@app.route("/api/internal/addon_info")
def internal_addon_info():
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    key = request.args.get("key","").upper().strip()
    if not key: return jsonify({"error":"Clé manquante"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM addon_licenses WHERE key=?", (key,)).fetchone()
    conn.close()
    if not row: return jsonify({"error":"Introuvable"}), 404
    return jsonify(dict(row))

@app.route("/api/internal/lookup_discord")
def internal_lookup_discord():
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    discord_id = request.args.get("discord_id","").strip()
    if not discord_id: return jsonify({"error":"discord_id manquant"}), 400
    conn = get_db()
    rows = conn.execute(
        "SELECT username,plan,status,connections,last_login,ip,discord_id FROM users WHERE discord_id=?",
        (discord_id,)
    ).fetchall()
    conn.close()
    if not rows: return jsonify({"error":"Introuvable"}), 404
    return jsonify([dict(r) for r in rows])

@app.route("/api/internal/upgrade_plan", methods=["POST"])
def internal_upgrade_plan():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    username = data.get("username","").lower()
    plan = data.get("plan","NORMAL").upper()
    if plan not in ("NORMAL","PRO"):
        return jsonify({"error":"Plan invalide — utilise NORMAL ou PRO"}), 400
    conn = get_db()
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        conn.close(); return jsonify({"error":"Utilisateur introuvable"}), 404
    conn.execute("UPDATE users SET plan=? WHERE username=?", (plan, username))
    conn.commit(); conn.close()
    add_log("OK","BOT",f"Plan mis à jour: {username} → {plan}")
    return jsonify({"success": True, "plan": plan})

@app.route("/api/internal/add_note", methods=["POST"])
def internal_add_note():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    username = data.get("username","").lower()
    note     = data.get("note","").strip()[:500]
    color    = data.get("color","gray")
    author   = data.get("author","Bot Discord")
    if not username or not note: return jsonify({"error":"Paramètres manquants"}), 400
    conn = get_db()
    if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        conn.close(); return jsonify({"error":"Utilisateur introuvable"}), 404
    conn.execute("INSERT INTO admin_notes (username,note,author,ts,color) VALUES (?,?,?,?,?)",
                 (username, note, author, int(time.time()), color))
    conn.commit(); conn.close()
    add_log("OK","BOT",f"Note ajoutée à {username} par {author}")
    return jsonify({"success": True})

# ─── HELPER DISCORD DM ───────────────────────────────────────────────────────
def _notify_discord(discord_id: str, message: str):
    try:
        payload = json.dumps({"user_id": discord_id, "message": message,
                              "bot_token": os.environ.get("BOT_TOKEN","BOT_INTERNAL_TOKEN")}).encode()
        req = urllib.request.Request(f"{DISCORD_BOT_URL}/dm", data=payload,
                                     headers={"Content-Type":"application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except: pass

def fmt_ts(ts):
    if not ts: return "—"
    try: return datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M")
    except: return "—"

def fmt_ts_rel(ts):
    if not ts: return "—"
    try:
        diff = int(time.time()) - int(ts)
        if diff < 60: return f"il y a {diff}s"
        if diff < 3600: return f"il y a {diff//60}m"
        if diff < 86400: return f"il y a {diff//3600}h"
        return f"il y a {diff//86400}j"
    except: return "—"

app.jinja_env.globals["fmt_ts"] = fmt_ts
app.jinja_env.globals["fmt_ts_rel"] = fmt_ts_rel

# ════════════════════════════════════════════════════════════════════════════════
#  DESIGN SYSTEM — CSS + JS
# ════════════════════════════════════════════════════════════════════════════════

_BASE_CSS = """
:root{--bg:#07070d;--card:#0f0f1a;--card2:#161625;--card3:#1c1c2e;--border:#252538;
  --green:#00ff88;--green2:#00cc6a;--blue:#4f8ef7;--red:#ff4466;--yellow:#ffcc00;
  --purple:#a855f7;--cyan:#06b6d4;--orange:#f97316;
  --text:#e8e8f4;--text2:#9898b8;--muted:#55556a;--sidebar:220px;
  --glow:0 0 20px rgba(0,255,136,.15);}
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:14px}
a{color:var(--green);text-decoration:none}a:hover{opacity:.8}
/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:10px}
/* Badge */
.badge{display:inline-flex;align-items:center;gap:4px;padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700;white-space:nowrap}
.b-green{background:rgba(0,255,136,.12);color:var(--green);border:1px solid rgba(0,255,136,.2)}
.b-red{background:rgba(255,68,102,.12);color:var(--red);border:1px solid rgba(255,68,102,.2)}
.b-yellow{background:rgba(255,204,0,.12);color:var(--yellow);border:1px solid rgba(255,204,0,.2)}
.b-blue{background:rgba(79,142,247,.12);color:var(--blue);border:1px solid rgba(79,142,247,.2)}
.b-purple{background:rgba(168,85,247,.12);color:var(--purple);border:1px solid rgba(168,85,247,.2)}
.b-gray{background:rgba(100,100,136,.12);color:var(--text2);border:1px solid var(--border)}
.b-cyan{background:rgba(6,182,212,.12);color:var(--cyan);border:1px solid rgba(6,182,212,.2)}
.b-orange{background:rgba(249,115,22,.12);color:var(--orange);border:1px solid rgba(249,115,22,.2)}
/* Layout */
.layout{display:flex;min-height:100vh}
/* Sidebar */
.sidebar{width:var(--sidebar);background:rgba(10,10,20,.98);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:100;transition:transform .25s cubic-bezier(.4,0,.2,1);backdrop-filter:blur(20px)}
.sidebar-logo{padding:18px 16px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.logo-icon{width:34px;height:34px;background:linear-gradient(135deg,var(--green),var(--cyan));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:17px;color:#000;box-shadow:var(--glow);flex-shrink:0}
.logo-txt span{font-weight:800;font-size:14px;color:var(--text);display:block}
.logo-txt small{font-size:10px;color:var(--muted);font-weight:500}
.sidebar nav{flex:1;overflow-y:auto;padding:8px 0}
.nav-sec{padding:12px 14px 3px;font-size:10px;text-transform:uppercase;color:var(--muted);letter-spacing:1.2px;font-weight:700}
.nav-item{display:flex;align-items:center;gap:9px;padding:9px 14px;color:var(--text2);font-size:13px;font-weight:500;transition:.12s;cursor:pointer;border-left:3px solid transparent;margin:1px 6px;border-radius:8px;position:relative}
.nav-item:hover{color:var(--text);background:rgba(255,255,255,.05);text-decoration:none}
.nav-item.active{color:var(--green);background:rgba(0,255,136,.07);border-left:3px solid var(--green)}
.nav-item .ico{width:18px;text-align:center;font-size:15px;flex-shrink:0}
.nav-item .cnt{margin-left:auto;background:var(--red);color:#fff;font-size:10px;padding:1px 6px;border-radius:10px;font-weight:700;min-width:18px;text-align:center}
.nav-item .cnt.yellow{background:var(--yellow);color:#000}
.nav-item .cnt.green{background:var(--green);color:#000}
.sidebar-footer{padding:10px 14px;border-top:1px solid var(--border);font-size:11px;color:var(--muted)}
.sidebar-footer b{color:var(--text2)}
/* Main */
.main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}
.topbar{background:rgba(10,10,20,.95);border-bottom:1px solid var(--border);padding:12px 22px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;backdrop-filter:blur(12px)}
.topbar h1{font-size:16px;font-weight:700;flex:1;display:flex;align-items:center;gap:8px}
.topbar .tbar-actions{display:flex;gap:8px;align-items:center}
.menu-toggle{display:none;background:none;border:none;color:var(--text);font-size:22px;cursor:pointer;padding:4px}
.content{padding:20px 22px;flex:1}
/* Notification bell */
.notif-bell{position:relative;cursor:pointer;color:var(--text2);font-size:18px;padding:4px;border-radius:6px;transition:.15s}
.notif-bell:hover{color:var(--text);background:var(--card2)}
.notif-dot{position:absolute;top:2px;right:2px;width:8px;height:8px;background:var(--red);border-radius:50%;border:2px solid var(--bg)}
.notif-panel{display:none;position:absolute;right:0;top:calc(100%+8px);width:320px;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:0 20px 60px rgba(0,0,0,.5);z-index:200;max-height:400px;overflow-y:auto}
.notif-panel.open{display:block}
.notif-item{padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;display:flex;gap:8px;align-items:start}
.notif-item:last-child{border-bottom:none}
.notif-item .ico{font-size:16px;flex-shrink:0;margin-top:1px}
/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:18px;margin-bottom:14px}
.card-sm{background:var(--card2);border:1px solid var(--border);border-radius:10px;padding:14px}
.card-title{font-weight:700;font-size:12px;color:var(--text2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:14px;display:flex;align-items:center;gap:6px}
.card-glow{border-color:rgba(0,255,136,.25);box-shadow:0 0 30px rgba(0,255,136,.06)}
/* Stats grid */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:10px;margin-bottom:18px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px;transition:.2s;cursor:default}
.stat-card:hover{border-color:rgba(0,255,136,.3);transform:translateY(-1px);box-shadow:var(--glow)}
.stat-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.stat-icon{font-size:20px;line-height:1}
.stat-delta{font-size:10px;font-weight:700;padding:2px 6px;border-radius:6px}
.stat-num{font-size:28px;font-weight:800;line-height:1.1}
.stat-label{font-size:11px;color:var(--text2);margin-top:4px;font-weight:600}
/* Table */
.tbl-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th{background:var(--card2);padding:10px 14px;font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;font-weight:700;text-align:left;white-space:nowrap}
td{padding:10px 14px;border-top:1px solid var(--border);font-size:13px;vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.015)}
/* Forms */
.form-group{margin-bottom:12px}
label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:5px}
input,select,textarea{width:100%;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:9px 12px;color:var(--text);font-size:13px;outline:none;transition:.15s;font-family:inherit}
input:focus,select:focus,textarea:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(0,255,136,.08)}
textarea{resize:vertical;min-height:80px}
.input-row{display:grid;gap:10px}
/* Buttons */
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:.15s;white-space:nowrap;font-family:inherit}
.btn-green{background:linear-gradient(135deg,var(--green),var(--cyan));color:#000}
.btn-green:hover{opacity:.9;transform:translateY(-1px)}
.btn-red{background:var(--red);color:#fff}.btn-red:hover{background:#cc3355}
.btn-blue{background:var(--blue);color:#fff}.btn-blue:hover{background:#3a7ae0}
.btn-purple{background:var(--purple);color:#fff}.btn-purple:hover{opacity:.9}
.btn-gray{background:var(--card2);color:var(--text);border:1px solid var(--border)}.btn-gray:hover{border-color:var(--green)}
.btn-ghost{background:transparent;color:var(--text2);border:1px solid var(--border)}.btn-ghost:hover{color:var(--text);border-color:var(--green)}
.btn-sm{padding:5px 11px;font-size:11px;border-radius:6px}
.btn-xs{padding:3px 8px;font-size:10px;border-radius:5px}
.btn-icon{padding:6px;width:32px;height:32px;justify-content:center;border-radius:7px}
/* Alert */
.alert{padding:11px 14px;border-radius:10px;margin-bottom:14px;font-size:13px;font-weight:600}
.alert-green{background:rgba(0,255,136,.08);border:1px solid rgba(0,255,136,.25);color:var(--green)}
.alert-red{background:rgba(255,68,102,.08);border:1px solid rgba(255,68,102,.25);color:var(--red)}
.alert-yellow{background:rgba(255,204,0,.08);border:1px solid rgba(255,204,0,.25);color:var(--yellow)}
.alert-blue{background:rgba(79,142,247,.08);border:1px solid rgba(79,142,247,.25);color:var(--blue)}
/* Mini chart */
.chart-bars{display:flex;align-items:flex-end;height:56px;gap:2px}
.chart-bars .bar{flex:1;background:linear-gradient(to top,var(--green),var(--cyan));border-radius:2px 2px 0 0;opacity:.6;min-height:2px;transition:.3s;cursor:pointer}
.chart-bars .bar:hover{opacity:1}
/* Toggle */
.toggle{position:relative;display:inline-block;width:46px;height:25px}
.toggle input{opacity:0;width:0;height:0}
.toggle-s{position:absolute;top:0;left:0;right:0;bottom:0;background:var(--border);border-radius:25px;transition:.3s;cursor:pointer}
.toggle-s:before{content:'';position:absolute;width:18px;height:18px;left:3.5px;bottom:3.5px;background:#fff;border-radius:50%;transition:.3s}
input:checked+.toggle-s{background:var(--green)}
input:checked+.toggle-s:before{transform:translateX(21px)}
/* Search bar */
.search-wrap{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
.search-wrap input,.search-wrap select{flex:1;min-width:140px;max-width:260px}
/* Hardware grid */
.hw-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px}
.hw-item{background:var(--card2);border:1px solid var(--border);border-radius:9px;padding:10px 12px}
.hw-label{font-size:10px;color:var(--muted);text-transform:uppercase;font-weight:700;margin-bottom:3px;display:flex;align-items:center;gap:4px}
.hw-val{font-size:12px;color:var(--text);font-weight:600;word-break:break-word}
/* Remote viewer */
.remote-screen{width:100%;background:#000;border-radius:10px;border:2px solid var(--border);position:relative;overflow:hidden;cursor:crosshair;aspect-ratio:16/9;display:flex;align-items:center;justify-content:center}
.remote-screen img{width:100%;height:100%;object-fit:contain;display:block}
.remote-overlay{position:absolute;top:0;left:0;right:0;bottom:0}
.remote-toolbar{display:flex;gap:8px;padding:10px;background:var(--card2);border-radius:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.remote-status-bar{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--card2);border-radius:8px;font-size:12px;margin-bottom:10px}
/* Session cards */
.session-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px;display:flex;gap:12px;align-items:center;transition:.2s}
.session-card:hover{border-color:var(--green);box-shadow:var(--glow)}
.session-avatar{width:40px;height:40px;background:linear-gradient(135deg,var(--green),var(--cyan));border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;color:#000;font-size:16px;flex-shrink:0}
/* Notes */
.note-card{padding:10px 12px;border-radius:8px;border-left:3px solid;margin-bottom:6px}
.note-gray{background:var(--card2);border-left-color:var(--muted)}
.note-red{background:rgba(255,68,102,.07);border-left-color:var(--red)}
.note-yellow{background:rgba(255,204,0,.07);border-left-color:var(--yellow)}
.note-green{background:rgba(0,255,136,.07);border-left-color:var(--green)}
.note-blue{background:rgba(79,142,247,.07);border-left-color:var(--blue)}
/* Login history */
.login-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;margin-top:4px}
/* Country map bars */
.country-bar{display:flex;align-items:center;gap:8px;padding:5px 0}
.country-prog{flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden}
.country-fill{height:100%;background:linear-gradient(90deg,var(--green),var(--cyan));border-radius:3px}
/* Announce banner */
.announce-bar{padding:8px 16px;font-size:13px;font-weight:600;text-align:center;border-bottom:1px solid var(--border)}
/* Tags */
.tag{display:inline-block;padding:1px 8px;border-radius:12px;font-size:10px;font-weight:700;background:var(--card3);color:var(--text2);border:1px solid var(--border);margin:1px;cursor:pointer}
.tag:hover{border-color:var(--green);color:var(--green)}
/* Responsive */
@media(max-width:768px){
  :root{--sidebar:0px}
  .sidebar{transform:translateX(-220px);width:220px}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .menu-toggle{display:block}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .content{padding:12px}
  .topbar{padding:10px 12px}
  td,th{padding:7px 9px;font-size:12px}
  .hw-grid{grid-template-columns:1fr 1fr}
  .input-row{grid-template-columns:1fr!important}
}
.sidebar-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:90}
.sidebar-overlay.show{display:block}
/* Pulse animation */
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.pulse{animation:pulse 2s infinite}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.fade-in{animation:fadeIn .3s ease}
"""

_BASE_JS = """
// Sidebar toggle
function toggleSidebar(){
  document.querySelector('.sidebar').classList.toggle('open');
  document.querySelector('.sidebar-overlay').classList.toggle('show');
}
document.addEventListener('DOMContentLoaded',function(){
  var ov=document.querySelector('.sidebar-overlay');
  if(ov) ov.addEventListener('click',function(){
    document.querySelector('.sidebar').classList.remove('open');
    ov.classList.remove('show');
  });
  // SSE connection
  if(window.EventSource && document.body.dataset.admin){
    var src = new EventSource('/admin/events');
    src.onmessage = function(e){
      try{
        var d = JSON.parse(e.data);
        handleSSE(d);
      }catch(err){}
    };
  }
  // Stats auto-refresh
  if(document.getElementById('stat-total')){
    setInterval(refreshStats, 20000);
  }
  // Remote session auto-check
  if(document.getElementById('remote-sessions-list')){
    setInterval(refreshRemoteSessions, 5000);
  }
});

var _notifications = [];
function handleSSE(d){
  if(!d.type || d.type==='connected') return;
  var dot = document.getElementById('notif-dot');
  if(dot) dot.style.display='block';
  var msg = '';
  var ico = '📋';
  if(d.type==='login'){ico='🟢';msg=`Connexion: <b>${d.username}</b> (${d.plan}) — ${d.ip||''}`;}
  else if(d.type==='new_user'){ico='✨';msg=`Nouveau compte: <b>${d.username}</b> (${d.plan})`;}
  else if(d.type==='new_ticket'){ico='📩';msg=`Nouveau ticket: <b>${d.user}</b> — ${d.subject}`;}
  else if(d.type==='reset_request'){ico='🔄';msg=`Reset demandé: <b>${d.username}</b>`;}
  else if(d.type==='support_request'){ico='🖥️';msg=`Support demandé: <b>${d.username}</b> — <a href="/admin/remote/${d.session_id}" class="btn btn-sm btn-green" style="padding:2px 8px">Rejoindre</a>`;}
  else if(d.type==='alert'){ico='⚠️';msg=d.msg||'';}
  else if(d.type==='remote_connected'){ico='🔗';msg=`Remote actif: session ${d.session_id.slice(0,8)}`;}
  else return;
  if(!msg) return;
  _notifications.unshift({ico,msg,ts:new Date().toLocaleTimeString()});
  renderNotifications();
}

function renderNotifications(){
  var panel = document.getElementById('notif-list');
  if(!panel) return;
  panel.innerHTML = _notifications.slice(0,15).map(n=>
    `<div class="notif-item fade-in"><span class="ico">${n.ico}</span><div><div style="font-size:11px;color:var(--text2)">${n.ts}</div><div>${n.msg}</div></div></div>`
  ).join('') || '<div style="padding:16px;text-align:center;color:var(--muted);font-size:12px">Aucune notification</div>';
}

function toggleNotifPanel(){
  var p = document.getElementById('notif-panel');
  p.classList.toggle('open');
  if(p.classList.contains('open')){
    var dot=document.getElementById('notif-dot');if(dot)dot.style.display='none';
  }
}

function refreshStats(){
  fetch('/admin/api/stats').then(r=>r.json()).then(d=>{
    var map = {
      'stat-total':d.total,'stat-active':d.active,'stat-banned':d.banned,
      'stat-pro':d.pro,'stat-today':d.today_logins,'stat-pending':d.pending_resets,
      'stat-tickets':d.open_tickets,'stat-hwid':d.hwid_alerts,
      'stat-remote':d.remote_active,'stat-remote-p':d.remote_pending
    };
    Object.entries(map).forEach(([id,val])=>{var e=document.getElementById(id);if(e)e.textContent=val;});
    var bars=document.querySelectorAll('#hourly-chart .bar');
    if(bars.length&&d.hourly){
      var mx=Math.max(...d.hourly,1);
      bars.forEach((b,i)=>{b.style.height=Math.max(3,(d.hourly[i]/mx)*52)+'px';b.title=d.hourly[i]+' conn';});
    }
  }).catch(()=>{});
}

function refreshRemoteSessions(){
  fetch('/admin/api/remote_sessions').then(r=>r.json()).then(sessions=>{
    var list = document.getElementById('remote-sessions-list');
    if(!list) return;
    if(!sessions.length){list.innerHTML='<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">Aucune session en attente</div>';return;}
    list.innerHTML = sessions.map(s=>`
      <div class="session-card fade-in">
        <div class="session-avatar">${s.username[0].toUpperCase()}</div>
        <div style="flex:1">
          <div style="font-weight:700;font-size:14px">${s.username}</div>
          <div style="color:var(--muted);font-size:11px">${s.ip} — ${s.has_frame?'Frame disponible':'En attente...'}</div>
        </div>
        <span class="badge ${s.status==='active'?'b-green':'b-yellow'}">${s.status==='active'?'🟢 Actif':'🟡 En attente'}</span>
        <a href="/admin/remote/${s.id}" class="btn btn-green btn-sm">🖥 Voir</a>
      </div>
    `).join('');
  }).catch(()=>{});
}

// Clipboard
function copyText(txt){navigator.clipboard.writeText(txt).then(()=>{showToast('Copié !')}).catch(()=>{});}
function showToast(msg,type='green'){
  var t=document.createElement('div');
  t.style.cssText=`position:fixed;bottom:20px;right:20px;background:var(--card);border:1px solid var(--${type});color:var(--${type});padding:10px 16px;border-radius:10px;font-size:13px;font-weight:600;z-index:9999;box-shadow:0 8px 24px rgba(0,0,0,.4);animation:fadeIn .3s ease`;
  t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),2500);
}

// Remote viewer
var _remoteInterval = null;
function startRemoteViewer(sessionId){
  var img = document.getElementById('remote-img');
  var status = document.getElementById('remote-frame-status');
  if(!img) return;
  _remoteInterval = setInterval(function(){
    fetch('/admin/remote/'+sessionId+'/frame')
      .then(r=>r.json())
      .then(d=>{
        if(d.frame){
          img.src='data:image/jpeg;base64,'+d.frame;
          img.style.display='block';
          var ph=document.getElementById('remote-placeholder');if(ph)ph.style.display='none';
          if(status)status.textContent='Live';
        }
        if(d.status==='ended'){
          clearInterval(_remoteInterval);
          if(status)status.textContent='Session terminée';
          showToast('Session terminée','yellow');
        }
      }).catch(()=>{});
  }, 150);
}
function stopRemoteViewer(){if(_remoteInterval)clearInterval(_remoteInterval);}

function sendRemoteCmd(sessionId, cmd){
  fetch('/admin/remote/'+sessionId+'/command',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:cmd})});
}

function setupRemoteInput(sessionId){
  var overlay = document.getElementById('remote-overlay');
  var img = document.getElementById('remote-img');
  if(!overlay||!img) return;
  // Mouse move
  overlay.addEventListener('mousemove',function(e){
    var r=overlay.getBoundingClientRect();
    var x=Math.round((e.clientX-r.left)/r.width*100);
    var y=Math.round((e.clientY-r.top)/r.height*100);
    sendRemoteCmd(sessionId,'MOVE:'+x+':'+y);
  });
  // Click
  overlay.addEventListener('click',function(e){
    var r=overlay.getBoundingClientRect();
    var x=Math.round((e.clientX-r.left)/r.width*100);
    var y=Math.round((e.clientY-r.top)/r.height*100);
    sendRemoteCmd(sessionId,'CLICK:'+x+':'+y);
  });
  // Right click
  overlay.addEventListener('contextmenu',function(e){
    e.preventDefault();
    var r=overlay.getBoundingClientRect();
    var x=Math.round((e.clientX-r.left)/r.width*100);
    var y=Math.round((e.clientY-r.top)/r.height*100);
    sendRemoteCmd(sessionId,'RCLICK:'+x+':'+y);
  });
  // Keyboard
  document.addEventListener('keydown',function(e){
    if(document.activeElement.tagName!=='INPUT'&&document.activeElement.tagName!=='TEXTAREA'){
      sendRemoteCmd(sessionId,'KEY:'+e.key);
    }
  });
}
"""

# ─── NAV BUILDER ─────────────────────────────────────────────────────────────
def _get_counts():
    try:
        conn = get_db()
        pr = int(conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0])
        ot = int(conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0])
        ha = int(conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (int(time.time())-86400,)).fetchone()[0])
        conn.close()
    except: pr=ot=ha=0
    rem_pending = len([s for s in _remote_sessions.values() if s.get("status")=="pending"])
    return pr, ot, ha, rem_pending

def _nav(active):
    pr, ot, ha, rp = _get_counts()
    items = [
        ("sec1",None,"PRINCIPAL",None),
        ("/admin","📊","Dashboard",""),
        ("/admin/users","👤","Utilisateurs",""),
        ("/admin/remote","🖥️","Remote Control", str(rp) if rp else ""),
        ("sec2",None,"GESTION",None),
        ("/admin/keys","🔑","Licences",""),
        ("/admin/addons","🎮","Addons",""),
        ("/admin/resets","🔄","Resets", str(pr) if pr else ""),
        ("/admin/tickets","📩","Tickets", str(ot) if ot else ""),
        ("/admin/anti-leak","🛡","Anti-Crack/Leak", str(ha) if ha else ""),
        ("sec3",None,"SYSTÈME",None),
        ("/admin/update","🔄","Mise à jour",""),
        ("/admin/logs","📋","Logs",""),
        ("/admin/ips","🌐","IPs / Whitelist",""),
        ("/admin/maintenance","⚙️","Maintenance",""),
        ("/admin/broadcast","📢","Broadcast",""),
        ("sec4",None,"ADMIN",None),
        ("/admin/owners","👑","Équipe",""),
        ("/admin/profile","🔐","Mon compte",""),
    ]
    html = ""
    for item in items:
        if item[1] is None:
            html += f'<div class="nav-sec">{item[2]}</div>'
            continue
        href, ico, label, cnt = item
        cls = "active" if active == href else ""
        badge = f'<span class="cnt {"yellow" if cnt and int(cnt)>0 and href not in ["/admin/remote"] else "green" if href=="/admin/remote" else ""}">{cnt}</span>' if cnt else ""
        html += f'<a href="{href}" class="nav-item {cls}"><span class="ico">{ico}</span>{label}{badge}</a>'
    return html

def _layout(title, active, content, admin_user="", admin_role=""):
    maint = get_setting("maintenance") == "1"
    announce = get_setting("announce")
    announce_color = get_setting("announce_color", "blue")
    color_map = {"green":"var(--green)","blue":"var(--blue)","red":"var(--red)","yellow":"var(--yellow)","purple":"var(--purple)"}
    ann_col = color_map.get(announce_color,"var(--blue)")
    announce_html = f'<div class="announce-bar" style="background:{ann_col}22;color:{ann_col}">{announce}</div>' if announce else ""
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — WinOptimizer v{APP_VERSION}</title>
<style>{_BASE_CSS}</style></head>
<body data-admin="{admin_user}">
<div class="sidebar-overlay"></div>
<div class="layout">
<aside class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">⚡</div>
    <div class="logo-txt"><span>WinOptimizer</span><small>Admin Panel v{APP_VERSION}</small></div>
  </div>
  <nav>{_nav(active)}</nav>
  <div class="sidebar-footer">
    <b>{admin_user}</b> — {admin_role}<br>
    <a href="/admin/logout" style="color:var(--red);font-size:11px">🚪 Déconnexion</a>
  </div>
</aside>
<div class="main">
  {announce_html}
  <div class="topbar">
    <button class="menu-toggle" onclick="toggleSidebar()">☰</button>
    <h1>{title}</h1>
    <div class="tbar-actions">
      <span class="badge {'b-red pulse' if maint else 'b-green'}">{'🔴 MAINTENANCE' if maint else '🟢 EN LIGNE'}</span>
      <div style="position:relative">
        <div class="notif-bell" onclick="toggleNotifPanel()">🔔<span id="notif-dot" class="notif-dot" style="display:none"></span></div>
        <div id="notif-panel" class="notif-panel">
          <div style="padding:10px 14px;border-bottom:1px solid var(--border);font-size:12px;font-weight:700;color:var(--text2)">NOTIFICATIONS</div>
          <div id="notif-list"><div style="padding:16px;text-align:center;color:var(--muted);font-size:12px">Aucune notification</div></div>
        </div>
      </div>
    </div>
  </div>
  <div class="content">{content}</div>
</div>
</div>
<script>{_BASE_JS}</script>
</body></html>"""

# ════════════════════════════════════════════════════════════════════════════════
#  PAGE BUILDERS
# ════════════════════════════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — WinOptimizer</title>
<style>
:root{--bg:#07070d;--card:#0f0f1a;--card2:#161625;--border:#252538;--green:#00ff88;--cyan:#06b6d4;--text:#e8e8f4;--text2:#9898b8;--muted:#55556a;--red:#ff4466;}
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at 30% 20%,#0a1020,var(--bg) 60%)}
.box{width:100%;max-width:400px;padding:16px}
.card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:36px 30px}
.logo{text-align:center;margin-bottom:28px}
.logo-icon{width:58px;height:58px;background:linear-gradient(135deg,#00ff88,#06b6d4);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;color:#000;margin-bottom:12px;box-shadow:0 0 30px rgba(0,255,136,.2)}
.logo h2{font-size:22px;font-weight:800}.logo p{color:var(--muted);font-size:13px;margin-top:4px}
.alert{padding:11px;border-radius:8px;background:rgba(255,68,102,.1);border:1px solid rgba(255,68,102,.3);color:#ff4466;font-size:13px;margin-bottom:14px}
.form-group{margin-bottom:12px}label{display:block;font-size:12px;font-weight:600;color:var(--text2);margin-bottom:5px}
input{width:100%;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:var(--text);font-size:14px;outline:none;transition:.15s}
input:focus{border-color:var(--green);box-shadow:0 0 0 3px rgba(0,255,136,.08)}
.btn{width:100%;padding:12px;border-radius:9px;background:linear-gradient(135deg,var(--green),var(--cyan));color:#000;font-size:14px;font-weight:700;border:none;cursor:pointer;margin-top:6px;font-family:inherit;transition:.15s}
.btn:hover{opacity:.9;transform:translateY(-1px)}
</style></head><body>
<div class="box"><div class="card">
  <div class="logo"><div class="logo-icon">⚡</div><h2>WinOptimizer</h2><p>Panel d'administration v"""+APP_VERSION+"""</p></div>
  {% if error %}<div class="alert">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="form-group"><label>Identifiant</label><input name="username" placeholder="admin" autofocus></div>
    <div class="form-group"><label>Mot de passe</label><input name="password" type="password" placeholder="••••••••"></div>
    <button type="submit" class="btn">Se connecter →</button>
  </form>
</div></div></body></html>"""


def _page_dashboard(stats, recent_users, recent_logs, top_ips, admin_user, admin_role):
    max_h = max(stats["hourly"] + [1])
    bars = "".join(f'<div class="bar" style="height:{max(3,int(v/max_h*52))}px" title="{v} conn"></div>' for v in stats["hourly"])

    rec_rows = ""
    for u in recent_users:
        if u["plan"]=="PRO": pb='<span class="badge b-blue">⭐ PRO</span>'
        else: pb='<span class="badge b-gray">🔷 NORMAL</span>'
        if u["status"]=="active": sb='<span class="badge b-green">actif</span>'
        elif u["status"]=="banned": sb='<span class="badge b-red">banni</span>'
        else: sb=f'<span class="badge b-yellow">{u["status"]}</span>'
        rec_rows += f"<tr><td><a href='/admin/user/{u['username']}'><b>{u['username']}</b></a></td><td>{pb}</td><td>{sb}</td><td style='font-size:11px;color:var(--text2)'>{u['gpu_info'] or '—'}</td><td style='color:var(--text2)'>{u['connections'] or 0}</td><td style='font-size:11px;color:var(--text2)'>{fmt_ts_rel(u['last_login'])}</td></tr>"

    log_rows = ""
    for l in recent_logs:
        lc = "b-green" if l["level"]=="OK" else "b-red" if l["level"]=="ERROR" else "b-yellow"
        log_rows += f'<tr><td><span class="badge {lc}">{l["level"]}</span></td><td style="font-size:11px;color:var(--text2)">{l["type"]}</td><td style="font-size:12px">{l["msg"][:60]}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts_rel(l["ts"])}</td></tr>'

    remote_stat_col = "b-green" if stats["remote_active"] > 0 else "b-gray"

    content = f"""
<div class="stats-grid">
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">👥</div></div><div class="stat-num" id="stat-total" style="color:var(--text)">{stats['total']}</div><div class="stat-label">Utilisateurs total</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">✅</div></div><div class="stat-num" id="stat-active" style="color:var(--green)">{stats['active']}</div><div class="stat-label">Actifs</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">⭐</div></div><div class="stat-num" id="stat-pro" style="color:var(--blue)">{stats['pro']}</div><div class="stat-label">Plan PRO</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">🔷</div></div><div class="stat-num" id="stat-normal" style="color:var(--cyan)">{stats['normal']}</div><div class="stat-label">Plan NORMAL</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">📅</div></div><div class="stat-num" id="stat-today" style="color:var(--cyan)">{stats['today_logins']}</div><div class="stat-label">Logins aujourd'hui</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">🔑</div></div><div class="stat-num" id="stat-keys" style="color:var(--text)">{stats['total_lic']}</div><div class="stat-label">Licences total</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">🔄</div></div><div class="stat-num" id="stat-pending" style="color:var(--yellow)">{stats['pending_reset']}</div><div class="stat-label">Resets en attente</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">📩</div></div><div class="stat-num" id="stat-tickets" style="color:var(--orange)">{stats['open_tickets']}</div><div class="stat-label">Tickets ouverts</div></div>
  <div class="stat-card"><div class="stat-top"><div class="stat-icon">🛡</div></div><div class="stat-num" id="stat-hwid" style="color:var(--red)">{stats['hwid_alerts']}</div><div class="stat-label">Alertes anti-leak</div></div>
  <div class="stat-card card-glow"><div class="stat-top"><div class="stat-icon">🖥️</div><span class="badge {remote_stat_col}" id="stat-remote-badge">{stats['remote_active']} actif</span></div><div class="stat-num" id="stat-remote" style="color:var(--purple)">{stats['remote_active']}</div><div class="stat-label">Remote sessions <span id="stat-remote-p" style="color:var(--yellow);font-size:11px">{f"· {stats['remote_pending']} en attente" if stats['remote_pending'] else ""}</span></div></div>
</div>

<div style="display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:14px">
<div class="card">
  <div class="card-title">📈 Activité 24h (par heure)</div>
  <div id="hourly-chart" class="chart-bars" style="margin-bottom:4px">{bars}</div>
  <div style="display:flex;justify-content:space-between;color:var(--muted);font-size:10px"><span>-24h</span><span>maintenant</span></div>
</div>
<div class="card">
  <div class="card-title">🌍 Top IPs</div>
  {''.join(f'<div class="country-bar"><span style="font-size:11px;color:var(--text2);width:110px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{ip["ip"]}</span><div class="country-prog"><div class="country-fill" style="width:{min(100,ip["cnt"]*10)}%"></div></div><span style="font-size:11px;color:var(--text2);width:24px;text-align:right">{ip["cnt"]}</span></div>' for ip in top_ips) or '<div style="color:var(--muted);font-size:12px;text-align:center;padding:16px">Pas encore de données</div>'}
</div>
</div>

<div style="display:grid;grid-template-columns:3fr 2fr;gap:14px">
<div class="card">
  <div class="card-title" style="display:flex;justify-content:space-between">
    <span>👤 Connexions récentes</span>
    <a href="/admin/users" style="font-size:11px;color:var(--green)">Voir tout →</a>
  </div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Username</th><th>Plan</th><th>Statut</th><th>GPU</th><th>Conn.</th><th>Quand</th></tr></thead>
    <tbody>{rec_rows or '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:20px">Aucune donnée</td></tr>'}</tbody>
  </table></div>
</div>
<div class="card">
  <div class="card-title" style="display:flex;justify-content:space-between">
    <span>📋 Logs récents</span>
    <a href="/admin/logs" style="font-size:11px;color:var(--green)">Voir tout →</a>
  </div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Niv.</th><th>Type</th><th>Message</th><th>Quand</th></tr></thead>
    <tbody>{log_rows or '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:16px">Aucun log</td></tr>'}</tbody>
  </table></div>
</div>
</div>
"""
    return _layout("Dashboard", "/admin", content, admin_user, admin_role)


def _page_users(users, q, plan_f, status_f, admin_user, admin_role):
    rows = ""
    for u in users:
        if u["plan"]=="PRO": pb='<span class="badge b-blue">⭐ PRO</span>'
        else: pb='<span class="badge b-gray">🔷 NORMAL</span>'
        if u["status"]=="active": sb='<span class="badge b-green">actif</span>'
        elif u["status"]=="banned": sb='<span class="badge b-red">banni</span>'
        else: sb=f'<span class="badge b-yellow">{u["status"]}</span>'
        geo = get_geoip(u["ip"]) if u["ip"] else {}
        flag = geo.get("flag","")
        tags_html = " ".join(f'<span class="tag">{t.strip()}</span>' for t in (u["tags"] or "").split(",") if t.strip()) if u["tags"] else ""
        rows += f"""<tr>
          <td><a href="/admin/user/{u['username']}"><b>{u['username']}</b></a> {tags_html}</td>
          <td>{pb}</td><td>{sb}</td>
          <td style="font-size:11px;color:var(--text2)">{flag} {u['ip'] or '—'}</td>
          <td style="font-size:11px;color:var(--text2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{u['gpu_info'] or '—'}</td>
          <td style="font-size:11px;color:var(--text2);max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{u['cpu_info'] or '—'}</td>
          <td style="color:var(--text2)">{u['connections'] or 0}</td>
          <td style="font-size:11px;color:var(--text2)">{fmt_ts_rel(u['last_login'])}</td>
          <td><a href="/admin/user/{u['username']}" class="btn btn-ghost btn-sm">→</a></td>
        </tr>"""

    content = f"""
<div class="search-wrap">
  <form method="GET" style="display:contents">
    <input name="q" value="{q}" placeholder="🔍 Nom, IP, Discord, GPU, clé...">
    <select name="plan" style="max-width:140px"><option value="">Tous plans</option><option {'selected' if plan_f=='PRO' else ''} value="PRO">⭐ PRO</option><option {'selected' if plan_f=='NORMAL' else ''} value="NORMAL">NORMAL</option></select>
    <select name="status" style="max-width:140px"><option value="">Tous statuts</option><option {'selected' if status_f=='active' else ''} value="active">Actif</option><option {'selected' if status_f=='banned' else ''} value="banned">Banni</option><option {'selected' if status_f=='suspended' else ''} value="suspended">Suspendu</option></select>
    <button type="submit" class="btn btn-green btn-sm">Filtrer</button>
    <a href="/admin/users" class="btn btn-gray btn-sm">Reset</a>
  </form>
  <div style="margin-left:auto;color:var(--text2);font-size:12px">{len(users)} résultat(s)</div>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Username</th><th>Plan</th><th>Statut</th><th>IP</th><th>GPU</th><th>CPU</th><th>Conn.</th><th>Dernier login</th><th></th></tr></thead>
  <tbody>{rows or '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px">Aucun résultat</td></tr>'}</tbody>
</table></div>
"""
    return _layout("Utilisateurs", "/admin/users", content, admin_user, admin_role)


def _page_user_detail(user, logs, alerts, login_hist, notes, remote_hist, geo, msg, admin_user, admin_role):
    hw_items = [
        ("💻 OS", user["os_info"] or "—"),
        ("🖥 CPU", user["cpu_info"] or "—"),
        ("🎮 GPU", user["gpu_info"] or "—"),
        ("💾 RAM", user["ram_info"] or "—"),
        ("🔌 Carte mère", user["motherboard_info"] or "—"),
        ("💿 Stockage", user["disk_info"] or "—"),
    ]
    hw_html = "".join(f'<div class="hw-item"><div class="hw-label">{l}</div><div class="hw-val">{v}</div></div>' for l,v in hw_items)

    if user["status"]=="active": sb='<span class="badge b-green">actif</span>'
    elif user["status"]=="banned": sb='<span class="badge b-red">banni</span>'
    else: sb=f'<span class="badge b-yellow">{user["status"]}</span>'
    if user["plan"]=="PRO": pb='<span class="badge b-blue">⭐ PRO</span>'
    else: pb='<span class="badge b-gray">🔷 NORMAL</span>'

    flag = geo.get("flag","🌐"); country = geo.get("country","?"); city = geo.get("city","?"); isp = geo.get("isp","?")
    proxy_warn = '<span class="badge b-yellow">🕵 VPN/Proxy</span>' if geo.get("proxy") else ""

    # Login history
    hist_html = ""
    for h in login_hist:
        dot_color = "var(--green)" if h["success"] else "var(--red)"
        hist_html += f"""<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border)">
          <div class="login-dot" style="background:{dot_color}"></div>
          <span style="font-size:12px">{h['flag'] or '🌐'} {h['ip']}</span>
          <span style="font-size:11px;color:var(--text2)">{h['city']}, {h['country']}</span>
          <span style="margin-left:auto;font-size:11px;color:var(--muted)">{fmt_ts_rel(h['ts'])}</span>
          {'<span class="badge b-red">'+h['reason']+'</span>' if not h['success'] and h['reason'] else ''}
        </div>"""

    # Notes
    notes_html = ""
    for n in notes:
        notes_html += f"""<div class="note-card note-{n['color']}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
            <span style="font-size:11px;color:var(--text2);font-weight:700">{n['author']} — {fmt_ts_rel(n['ts'])}</span>
            <form method="POST" action="/admin/user/{user['username']}/note/{n['id']}/delete" style="display:inline">
              <button class="btn btn-xs" style="background:transparent;color:var(--muted);border:none;cursor:pointer">✕</button>
            </form>
          </div>
          <div style="font-size:13px">{n['note']}</div>
        </div>"""

    # Remote history
    rem_html = ""
    for r in remote_hist:
        rem_html += f'<tr><td style="font-size:11px;color:var(--text2)">{fmt_ts(r["started_at"])}</td><td style="font-size:11px">{r["admin_user"] or "—"}</td><td><span class="badge {"b-green" if r["status"]=="ended" else "b-yellow"}">{r["status"]}</span></td><td style="font-size:11px;color:var(--text2)">{fmt_ts(r["ended_at"])}</td></tr>'

    # Tags
    tags = [t.strip() for t in (user["tags"] or "").split(",") if t.strip()]
    tags_html = " ".join(f'<span class="tag">{t}</span>' for t in tags) if tags else '<span style="color:var(--muted);font-size:12px">Aucun tag</span>'

    log_rows = "".join(f'<tr><td style="color:var(--muted);font-size:11px;white-space:nowrap">{fmt_ts(l["ts"])}</td><td><span class="badge {"b-green" if l["level"]=="OK" else "b-red"}">{l["level"]}</span></td><td style="font-size:11px;color:var(--text2)">{l["type"]}</td><td style="font-size:12px">{l["msg"]}</td></tr>' for l in logs)
    alert_rows = "".join(f'<tr><td style="font-size:11px;color:var(--muted)">{fmt_ts(a["ts"])}</td><td style="font-size:11px;font-family:monospace">{(a["hwid"] or "")[:20]}…</td><td style="color:var(--red);font-size:12px">{a["note"]}</td></tr>' for a in alerts)

    content = f"""
{f'<div class="alert alert-green">{msg}</div>' if msg else ''}
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">

<div class="card">
  <div class="card-title">👤 Profil</div>
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:16px">
    <div style="width:52px;height:52px;background:linear-gradient(135deg,var(--green),var(--cyan));border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#000;flex-shrink:0">{user['username'][0].upper()}</div>
    <div>
      <div style="font-size:18px;font-weight:800">{user['username']}</div>
      <div style="display:flex;gap:6px;margin-top:4px">{pb} {sb}</div>
    </div>
  </div>
  <div style="display:grid;gap:4px">
    {''.join(f'<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border)"><span style="color:var(--text2);font-size:12px">{k}</span><span style="font-size:12px;font-weight:600">{v}</span></div>' for k,v in [
      ("Discord ID", user["discord_id"] or "—"),
      ("Licence", user["license_key"] or "—"),
      ("Connexions", str(user["connections"] or 0)),
      ("Créé le", fmt_ts(user["created_at"])),
      ("Dernier login", fmt_ts(user["last_login"])),
    ])}
  </div>
  <div style="margin-top:10px">
    <div style="font-size:11px;color:var(--text2);margin-bottom:4px">TAGS</div>
    {tags_html}
  </div>
</div>

<div class="card">
  <div class="card-title">🌍 Géolocalisation & Actions</div>
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
    <div style="font-size:36px">{flag}</div>
    <div>
      <div style="font-size:16px;font-weight:700">{user["ip"] or "—"} {proxy_warn}</div>
      <div style="color:var(--text2);font-size:13px">{city}, {country}</div>
      <div style="color:var(--muted);font-size:11px">ISP: {isp}</div>
    </div>
  </div>
  <div style="font-size:11px;color:var(--muted);font-family:monospace;margin-bottom:14px">HWID: {(user["hwid"] or "")[:36] or "—"}</div>
  <div style="display:flex;flex-wrap:wrap;gap:6px">
    <form method="POST" action="/admin/user/{user['username']}/action" style="display:contents">
      <button name="action" value="reactivate" class="btn btn-green btn-sm">✅ Activer</button>
      <button name="action" value="suspend" class="btn btn-ghost btn-sm">⏸ Suspendre</button>
      <button name="action" value="ban" class="btn btn-red btn-sm">🚫 Bannir</button>
      <button name="action" value="reset_hwid" class="btn btn-ghost btn-sm">🔄 HWID</button>
      <button name="action" value="reset_password" class="btn btn-ghost btn-sm">🔑 Reset MDP</button>
      <button name="action" value="upgrade_pro" class="btn btn-sm btn-blue">⭐ PRO</button>
      
      <button name="action" value="downgrade_normal" class="btn btn-sm btn-gray">⬇ NORMAL</button>
    </form>
    <form method="POST" action="/admin/ips/add" style="display:contents">
      <input type="hidden" name="ip" value="{user['ip'] or ''}">
      <input type="hidden" name="rule" value="blacklist">
      <button type="submit" class="btn btn-red btn-sm">🚫 Ban IP</button>
    </form>
    <form method="POST" action="/admin/ips/add" style="display:contents">
      <input type="hidden" name="ip" value="{user['ip'] or ''}">
      <input type="hidden" name="rule" value="whitelist">
      <button type="submit" class="btn btn-green btn-sm">✅ Whitelist IP</button>
    </form>
  </div>
</div>
</div>

<div class="card">
  <div class="card-title">✏️ Modifier le profil</div>
  <form method="POST" action="/admin/user/{user['username']}/edit">
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px;align-items:end">
      <div class="form-group" style="margin:0"><label>Plan</label>
        <select name="plan">
          <option {'selected' if user['plan']=='NORMAL' else ''} value="NORMAL">NORMAL</option>
          <option {'selected' if user['plan']=='PRO' else ''} value="PRO">PRO</option>

        </select>
      </div>
      <div class="form-group" style="margin:0"><label>Discord ID</label><input name="discord_id" value="{user['discord_id'] or ''}"></div>
      <div class="form-group" style="margin:0"><label>Tags (virgule)</label><input name="tags" value="{user['tags'] or ''}" placeholder="vip, suspect, pro..."></div>
      <div class="form-group" style="margin:0"><label>Note interne</label><input name="note" value="{user['note'] or ''}"></div>
      <button type="submit" class="btn btn-green btn-sm">💾 Sauvegarder</button>
    </div>
  </form>
</div>

<div class="card">
  <div class="card-title">🖥 Hardware</div>
  <div class="hw-grid">{hw_html}</div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
<div class="card">
  <div class="card-title">🕐 Historique connexions ({len(login_hist)})</div>
  <div style="max-height:260px;overflow-y:auto">
    {hist_html or '<div style="color:var(--muted);font-size:12px;text-align:center;padding:16px">Aucun historique</div>'}
  </div>
</div>
<div class="card" id="notes">
  <div class="card-title">📝 Notes admin</div>
  <form method="POST" action="/admin/user/{user['username']}/note" style="margin-bottom:12px">
    <div style="display:flex;gap:8px;align-items:center">
      <input name="note" placeholder="Ajouter une note..." style="flex:1">
      <select name="color" style="width:90px">
        <option value="gray">Gris</option>
        <option value="red">Rouge</option>
        <option value="yellow">Jaune</option>
        <option value="green">Vert</option>
        <option value="blue">Bleu</option>
      </select>
      <button type="submit" class="btn btn-green btn-sm">+</button>
    </div>
  </form>
  <div style="max-height:200px;overflow-y:auto">
    {notes_html or '<div style="color:var(--muted);font-size:12px;text-align:center;padding:12px">Aucune note</div>'}
  </div>
</div>
</div>

{f'''<div class="card">
  <div class="card-title">🖥️ Historique Remote Control</div>
  <div class="tbl-wrap"><table><thead><tr><th>Début</th><th>Admin</th><th>Statut</th><th>Fin</th></tr></thead>
  <tbody>{rem_html or '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:16px">Aucune session</td></tr>'}</tbody></table></div>
</div>''' if True else ''}

{f'<div class="card"><div class="card-title">🛡 Alertes HWID</div><div class="tbl-wrap"><table><thead><tr><th>Date</th><th>HWID</th><th>Alerte</th></tr></thead><tbody>{alert_rows}</tbody></table></div></div>' if alerts else ''}

<div class="card">
  <div class="card-title">📋 Logs récents</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Date</th><th>Niveau</th><th>Type</th><th>Message</th></tr></thead>
    <tbody>{log_rows or '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">Aucun log</td></tr>'}</tbody>
  </table></div>
</div>

<div class="card" id="user-addons-section">
  <div class="card-title">🎮 Addons activés</div>
  <div id="user-addons-list" style="min-height:40px">
    <script>
    (function(){{
      fetch('/admin/api/user_addons?username={user["username"]}')
        .then(r=>r.json())
        .then(d=>{{
          const el = document.getElementById('user-addons-list');
          if(!d.addons||d.addons.length===0){{el.innerHTML='<span style="color:var(--muted);font-size:12px">Aucun addon activé</span>';return;}}
          const labels={{"fps_counter":"📊 FPS Counter","vibrance":"🎨 Vibrance","ram_cleaner":"🧹 RAM Cleaner","overclock":"⚡ Overclock","antilag":"🌐 Anti-Lag","process_boost":"🚀 Process Boost","crosshair":"🎯 Crosshair","gpu_tuner":"🖥 GPU Tuner","network_mon":"📡 Network Monitor","temp_mon":"🌡 Temp Monitor","input_lag":"⌨ Input Lag Reducer","boot_speed":"⚡ Boot Speed"}};
          el.innerHTML = d.addons.map(a=>{{
            const lbl = labels[a.key]||a.key;
            const src = a.source==='pro_free'||a.source==='pro_free_auto' ? '<span class="badge b-blue">PRO gratuit</span>' : '<span class="badge b-green">Clé activée</span>';
            return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border)"><span style="font-size:13px">${{lbl}}</span>${{src}}</div>`;
          }}).join('');
        }}).catch(()=>{{document.getElementById('user-addons-list').innerHTML='<span style="color:var(--red);font-size:12px">Erreur chargement</span>';}});
    }})();
    </script>
  </div>
</div>

<a href="/admin/users" class="btn btn-ghost btn-sm">← Retour</a>
"""
    return _layout(f"Utilisateur — {user['username']}", "/admin/users", content, admin_user, admin_role)


def _page_remote(active_sessions, sessions_db, admin_user, admin_role):
    db_rows = ""
    for s in sessions_db:
        if s["status"]=="active": sc='<span class="badge b-green">actif</span>'
        elif s["status"]=="ended": sc='<span class="badge b-gray">terminé</span>'
        else: sc='<span class="badge b-yellow">en attente</span>'
        db_rows += f'<tr><td style="font-size:11px;font-family:monospace">{s["id"][:16]}…</td><td><b>{s["username"]}</b></td><td>{s["admin_user"] or "—"}</td><td>{sc}</td><td style="font-size:11px;color:var(--text2)">{fmt_ts(s["started_at"])}</td><td style="font-size:11px;color:var(--text2)">{fmt_ts(s["ended_at"])}</td></tr>'

    content = f"""
<div style="display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:14px">

<div class="card card-glow">
  <div class="card-title">🖥️ Sessions actives & en attente</div>
  <div id="remote-sessions-list">
    {'<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">Aucune session en attente</div>' if not active_sessions else ''.join(f'''<div class="session-card">
      <div class="session-avatar">{s['username'][0].upper()}</div>
      <div style="flex:1">
        <div style="font-weight:700;font-size:14px">{s['username']}</div>
        <div style="color:var(--muted);font-size:11px;margin-top:2px">IP: {s.get('ip','?')} — {'Frame dispo' if s.get('frames') else 'En attente de connexion...'}</div>
        <div style="font-size:11px;color:var(--text2);margin-top:1px">Débuté {fmt_ts_rel(s.get('started_at',0))}</div>
      </div>
      <span class="badge {'b-green' if s['status']=='active' else 'b-yellow'}">{s['status']}</span>
      <a href="/admin/remote/{sid}" class="btn btn-purple btn-sm">🖥 Prendre le contrôle</a>
    </div>''' for sid, s in active_sessions.items())}
  </div>
</div>

<div class="card">
  <div class="card-title">ℹ️ Comment ça marche</div>
  <ul style="color:var(--text2);font-size:13px;line-height:2;padding-left:14px">
    <li>L'utilisateur clique <b>Demander support</b> dans son logiciel</li>
    <li>Une notification apparaît ici et dans les alertes</li>
    <li>Tu cliques <b>Prendre le contrôle</b> pour voir son écran</li>
    <li>Tu peux déplacer la souris, cliquer, taper du texte</li>
    <li>L'utilisateur peut arrêter la session à tout moment</li>
    <li>Chaque session est loggée avec admin + timestamps</li>
  </ul>
  <div style="margin-top:14px;padding:12px;background:var(--card2);border-radius:8px;border:1px solid rgba(0,255,136,.15)">
    <div style="font-size:12px;color:var(--green);font-weight:700;margin-bottom:4px">⚡ Latence estimée</div>
    <div style="font-size:11px;color:var(--text2)">~150ms via HTTP polling · JPEG 40% quality · 6-7 FPS</div>
  </div>
</div>
</div>

<div class="card">
  <div class="card-title">📋 Historique sessions</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>ID</th><th>Utilisateur</th><th>Admin</th><th>Statut</th><th>Début</th><th>Fin</th></tr></thead>
    <tbody>{db_rows or '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">Aucune session enregistrée</td></tr>'}</tbody>
  </table></div>
</div>
"""
    return _layout("Remote Control", "/admin/remote", content, admin_user, admin_role)


def _page_remote_viewer(session_id, sess, admin_user, admin_role):
    username = sess.get("username","?")
    ip = sess.get("ip","?")
    status = sess.get("status","unknown")
    content = f"""
<div class="remote-toolbar">
  <span class="badge b-purple">🖥 {username}</span>
  <span class="badge b-gray">IP: {ip}</span>
  <span class="badge {'b-green' if status=='active' else 'b-yellow'}" id="conn-badge">{status}</span>
  <button class="btn btn-green btn-sm" id="btn-connect" onclick="connectSession()">🔗 Connexion</button>
  <button class="btn btn-red btn-sm" onclick="disconnectSession()">⏹ Déconnecter</button>
  <div style="margin-left:auto;display:flex;gap:6px">
    <button class="btn btn-gray btn-sm" onclick="sendKey('ctrl+alt+del')">Ctrl+Alt+Del</button>
    <button class="btn btn-gray btn-sm" onclick="sendKey('Escape')">Esc</button>
    <button class="btn btn-gray btn-sm" onclick="sendKey('Return')">Entrée</button>
    <button class="btn btn-gray btn-sm" onclick="takeScreenshot()">📸 Screenshot</button>
  </div>
</div>

<div class="remote-status-bar">
  <span>🕐 <span id="remote-frame-status">En attente du flux...</span></span>
  <span style="margin-left:auto;color:var(--muted);font-size:11px" id="fps-counter">FPS: —</span>
</div>

<div class="remote-screen" id="remote-screen">
  <div id="remote-placeholder" style="text-align:center;color:var(--muted)">
    <div style="font-size:48px;margin-bottom:12px">🖥️</div>
    <div style="font-size:16px;font-weight:700">En attente du stream</div>
    <div style="font-size:12px;margin-top:8px">Clique sur <b>Connexion</b> pour démarrer</div>
  </div>
  <img id="remote-img" style="display:none;width:100%;height:100%;object-fit:contain">
  <div id="remote-overlay" class="remote-overlay"></div>
</div>

<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">
  <div style="flex:1">
    <input id="type-input" placeholder="Texte à taper sur le PC distant..." style="width:100%">
  </div>
  <button class="btn btn-green btn-sm" onclick="typeText()">⌨ Envoyer</button>
</div>

<div class="card" style="margin-top:14px">
  <div class="card-title">📋 Actions rapides</div>
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn btn-gray btn-sm" onclick="sendCmd('SHORTCUT:ctrl+c')">📋 Copier</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('SHORTCUT:ctrl+v')">📄 Coller</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('SHORTCUT:ctrl+z')">↩ Annuler</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('SHORTCUT:win+d')">🖥 Bureau</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('SHORTCUT:win+l')">🔒 Verrouiller</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('CMD:taskmgr')">⚙ Task Mgr</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('CMD:cmd')">💻 CMD</button>
    <button class="btn btn-gray btn-sm" onclick="sendCmd('CMD:explorer')">📁 Explorer</button>
  </div>
</div>

<script>
var SESSION_ID = '{session_id}';
var _viewerInterval = null;
var _inputReady = false;
var _frameCount = 0;
var _lastFpsTime = Date.now();

// ── FPS counter ──────────────────────────────────────────────────────────────
setInterval(function(){{
  var now = Date.now();
  var dt = (now - _lastFpsTime) / 1000;
  var el = document.getElementById('fps-counter');
  if(el && dt > 0) el.textContent = 'FPS: ~' + Math.round(_frameCount / dt);
  _frameCount = 0;
  _lastFpsTime = now;
}}, 2000);

// ── Frame polling ────────────────────────────────────────────────────────────
function startViewer(){{
  if(_viewerInterval) return;  // already running
  var img = document.getElementById('remote-img');
  var status = document.getElementById('remote-frame-status');
  _viewerInterval = setInterval(function(){{
    fetch('/admin/remote/' + SESSION_ID + '/frame')
      .then(function(r){{ return r.json(); }})
      .then(function(d){{
        if(d.frame){{
          img.src = 'data:image/jpeg;base64,' + d.frame;
          img.style.display = 'block';
          var ph = document.getElementById('remote-placeholder');
          if(ph) ph.style.display = 'none';
          if(status) status.textContent = '🟢 Live';
          _frameCount++;
        }}
        if(d.status === 'ended'){{
          clearInterval(_viewerInterval); _viewerInterval = null;
          if(status) status.textContent = '🔴 Session terminée';
          showToast('Session terminée', 'yellow');
        }}
      }}).catch(function(){{}});
  }}, 150);
}}

function stopViewer(){{
  if(_viewerInterval){{ clearInterval(_viewerInterval); _viewerInterval = null; }}
}}

// ── Admin actions ────────────────────────────────────────────────────────────
function connectSession(){{
  fetch('/admin/remote/' + SESSION_ID + '/connect', {{method:'POST'}})
    .then(function(r){{ return r.json(); }})
    .then(function(d){{
      if(d.success){{
        var badge = document.getElementById('conn-badge');
        if(badge){{ badge.textContent = '🟢 Connecté'; badge.className = 'badge b-green'; }}
        document.getElementById('btn-connect').style.display = 'none';
        startViewer();
        if(!_inputReady){{ setupRemoteInput(SESSION_ID); _inputReady = true; }}
        showToast('Session démarrée !', 'green');
      }} else {{
        showToast('Erreur connexion', 'yellow');
      }}
    }});
}}

function disconnectSession(){{
  stopViewer();
  fetch('/admin/remote/' + SESSION_ID + '/disconnect', {{method:'POST'}})
    .then(function(){{ window.location = '/admin/remote'; }});
}}

function sendKey(k){{ sendRemoteCmd(SESSION_ID, 'KEY:' + k); }}
function sendCmd(c){{ sendRemoteCmd(SESSION_ID, c); }}
function typeText(){{
  var inp = document.getElementById('type-input');
  var txt = inp ? inp.value.trim() : '';
  if(txt){{
    sendRemoteCmd(SESSION_ID, 'TYPE:' + txt);
    inp.value = '';
    showToast('Texte envoyé');
  }}
}}
function takeScreenshot(){{
  var img = document.getElementById('remote-img');
  if(!img || !img.src || img.style.display === 'none'){{
    showToast('Aucun frame disponible', 'yellow'); return;
  }}
  var a = document.createElement('a');
  a.href = img.src;
  a.download = 'screenshot_' + Date.now() + '.jpg';
  a.click();
  showToast('Screenshot sauvegardé');
}}
</script>
"""
    return _layout(f"Remote — {username}", "/admin/remote", content, admin_user, admin_role)


def _page_addons(addon_keys, stats, admin_user, admin_role):
    ADDON_META = {
        "crosshair":     ("🎯", "Crosshair Overlay",       "4.99€"),
        "fps_counter":   ("📊", "FPS Counter",             "2.99€"),
        "vibrance":      ("🎨", "Filtre Couleur / Vibrance","2.99€"),
        "ram_cleaner":   ("🧹", "RAM Cleaner Auto",        "1.99€"),
        "overclock":     ("⚡", "Overclock CPU/GPU",        "7.99€"),
        "antilag":       ("🌐", "Anti-Lag Réseau Pro",      "4.99€"),
        "process_boost": ("🚀", "Process Priority Booster", "3.99€"),
        "gpu_tuner":     ("🖥", "GPU Auto-Tuner",           "5.99€"),
        "network_mon":   ("📡", "Network Monitor",          "2.99€"),
        "temp_mon":      ("🌡", "Temperature Monitor",      "1.99€"),
        "input_lag":     ("⌨", "Input Lag Reducer",        "3.99€"),
        "boot_speed":    ("⚡", "Boot Speed Pro",           "2.99€"),
    }
    stat_cards = ""
    for key, (ico, name, price) in ADDON_META.items():
        a = stats.get(key, {"active":0,"used":0})
        stat_cards += f'''<div class="stat-card">
          <div class="stat-top"><div class="stat-icon">{ico}</div><span class="badge b-cyan">{price} · ♾️ Lifetime</span></div>
          <div style="font-weight:700;font-size:14px;margin:6px 0 2px">{name}</div>
          <div style="display:flex;gap:8px;margin-top:6px">
            <span class="badge b-green">{a["active"]} active(s)</span>
            <span class="badge b-gray">{a["used"]} utilisée(s)</span>
          </div>
          <form method="POST" action="/admin/addons/generate" style="margin-top:10px;display:flex;gap:6px">
            <input type="hidden" name="addon_key" value="{key}">
            <input name="qty" type="number" value="1" min="1" max="100" style="width:60px">
            <input name="note" placeholder="Note" style="flex:1">
            <button type="submit" class="btn btn-purple btn-sm">✨ Générer</button>
          </form>
        </div>'''

    ADDON_NAMES = {k: f"{v[0]} {v[1]}" for k, v in ADDON_META.items()}
    rows = ""
    filter_addon = ""
    for a in addon_keys:
        if a["status"]=="active": sc='<span class="badge b-green">active</span>'
        elif a["status"]=="used": sc='<span class="badge b-gray">utilisée</span>'
        else: sc=f'<span class="badge b-red">{a["status"]}</span>'
        label = ADDON_NAMES.get(a["addon_key"], a["addon_key"])
        revoke = f'<form method="POST" action="/admin/addons/revoke"><input type="hidden" name="key" value="{a["key"]}"><button class="btn btn-red btn-sm">Révoquer</button></form>' if a["status"]=="active" else "—"
        rows += f'<tr><td style="font-family:monospace;font-size:11px;cursor:pointer" onclick="copyText(\'{a["key"]}\')" title="Copier">{a["key"]}</td><td><span class="badge b-purple">{label}</span></td><td>{sc}</td><td><span class="badge b-cyan">♾️ Lifetime</span></td><td style="font-size:11px;color:var(--text2)">{fmt_ts(a["created_at"])}</td><td style="font-size:11px;color:var(--text2)">{a["note"] or "—"}</td><td>{revoke}</td></tr>'

    content = f"""
<div class="stats-grid" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr))">{stat_cards}</div>
<div class="card" style="margin-top:14px">
  <div class="card-title">🎮 Toutes les clés addon ({len(addon_keys)}) — Durée : ♾️ Lifetime (toutes)</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Clé</th><th>Addon</th><th>Statut</th><th>Durée</th><th>Créée</th><th>Note</th><th></th></tr></thead>
    <tbody>{rows or '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--muted)">Aucune clé addon</td></tr>'}</tbody>
  </table></div>
</div>"""
    return _layout("Addons", "/admin/addons", content, admin_user, admin_role)


def _page_keys(keys, addon_keys, admin_user, admin_role):
    rows = ""
    for k in keys:
        if k["status"]=="active": sb='<span class="badge b-green">active</span>'
        elif k["status"]=="revoked": sb='<span class="badge b-red">révoquée</span>'
        else: sb=f'<span class="badge b-gray">{k["status"]}</span>'
        if k["plan"]=="PRO": pb='<span class="badge b-blue">⭐ PRO</span>'
        else: pb='<span class="badge b-gray">NORMAL</span>'
        used = f'<a href="/admin/user/{k["username"]}"><b>{k["username"]}</b></a>' if k["username"] else '<span style="color:var(--muted)">—</span>'
        rows += f'<tr><td style="font-family:monospace;font-size:11px" onclick="copyText(\'{k["key"]}\')" title="Cliquer pour copier" style="cursor:pointer">{k["key"]}</td><td>{pb}</td><td>{sb}</td><td>{used}</td><td style="font-size:11px;color:var(--text2)">{fmt_ts(k["created_at"])}</td><td style="font-size:11px;color:var(--text2)">{k["note"] or "—"}</td><td><form method="POST" action="/admin/keys/revoke"><input type="hidden" name="key" value="{k["key"]}"><button class="btn btn-red btn-sm">Révoquer</button></form></td></tr>'

    addon_rows = ""
    ADDON_NAMES = {"crosshair":"🎯 Crosshair","fps_counter":"📊 FPS Counter","vibrance":"🎨 Vibrance",
                   "ram_cleaner":"🧹 RAM Cleaner","overclock":"⚡ Overclock","antilag":"🌐 Anti-Lag",
                   "process_boost":"🚀 Process Boost","gpu_tuner":"🖥 GPU Tuner","network_mon":"📡 Network Mon",
                   "temp_mon":"🌡 Temp Monitor","input_lag":"⌨ Input Lag","boot_speed":"⚡ Boot Speed"}
    for a in addon_keys:
        sc = '<span class="badge b-green">active</span>' if a["status"]=="active" else '<span class="badge b-gray">utilisée</span>' if a["status"]=="used" else f'<span class="badge b-red">{a["status"]}</span>'
        addon_label = ADDON_NAMES.get(a["addon_key"], a["addon_key"])
        revoke_btn = f'<form method="POST" action="/admin/addons/revoke"><input type="hidden" name="key" value="{a["key"]}"><button class="btn btn-red btn-sm">Révoquer</button></form>' if a["status"]=="active" else "—"
        addon_rows += f'<tr><td style="font-family:monospace;font-size:11px;cursor:pointer" onclick="copyText(\'{a["key"]}\')" title="Cliquer pour copier">{a["key"]}</td><td><span class="badge b-purple">{addon_label}</span></td><td>{sc}</td><td><span class="badge b-cyan">♾️ Lifetime</span></td><td style="font-size:11px;color:var(--text2)">{fmt_ts(a["created_at"])}</td><td style="font-size:11px;color:var(--text2)">{a["note"] or "—"}</td><td>{revoke_btn}</td></tr>'

    addon_options = "\n".join(f'<option value="{k}">{v}</option>' for k, v in [
        ("crosshair","🎯 Crosshair Overlay"),("fps_counter","📊 FPS Counter"),
        ("vibrance","🎨 Filtre Couleur / Vibrance"),("ram_cleaner","🧹 RAM Cleaner Auto"),
        ("overclock","⚡ Overclock CPU/GPU"),("antilag","🌐 Anti-Lag Réseau Pro"),
        ("process_boost","🚀 Process Priority Booster"),("gpu_tuner","🖥 GPU Auto-Tuner"),
        ("network_mon","📡 Network Monitor"),("temp_mon","🌡 Temperature Monitor"),
        ("input_lag","⌨ Input Lag Reducer"),("boot_speed","⚡ Boot Speed Pro"),
    ])

    content = f"""
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
<div class="card">
  <div class="card-title">🔑 Générer des licences</div>
  <form method="POST" action="/admin/keys/generate">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div class="form-group" style="margin:0"><label>Plan</label><select name="plan"><option value="NORMAL">NORMAL</option><option value="PRO">⭐ PRO</option></select></div>
      <div class="form-group" style="margin:0"><label>Quantité (max 500)</label><input name="qty" type="number" value="1" min="1" max="500"></div>
    </div>
    <div class="form-group" style="margin:6px 0 0"><label>Note</label><input name="note" placeholder="Batch Discord, resell..."></div>
    <button type="submit" class="btn btn-green" style="margin-top:8px;width:100%">✨ Générer licences</button>
  </form>
</div>
<div class="card">
  <div class="card-title">🧪 Générer des clés Addon</div>
  <form method="POST" action="/admin/keys/generate_addon">
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
      <div class="form-group" style="margin:0"><label>Addon</label><select name="addon_key">{addon_options}</select></div>
      <div class="form-group" style="margin:0"><label>Quantité (max 100)</label><input name="qty" type="number" value="1" min="1" max="100"></div>
    </div>
    <div class="form-group" style="margin:6px 0 0"><label>Note</label><input name="note" placeholder="Pour qui..."></div>
    <button type="submit" class="btn btn-purple" style="margin-top:8px;width:100%">✨ Générer clés addon</button>
  </form>
</div>
</div>

<div class="card">
  <div class="card-title">🗑 Révoquer en masse</div>
  <form method="POST" action="/admin/keys/bulk_revoke" style="display:flex;gap:8px;align-items:flex-end">
    <div style="flex:1"><label style="font-size:12px;font-weight:600;color:var(--text2)">Clés (une par ligne)</label>
    <textarea name="keys" rows="3" placeholder="XXXXX-XXXXX-XXXXX-XXXXX"></textarea></div>
    <button type="submit" class="btn btn-red" style="height:42px">🗑 Révoquer</button>
  </form>
</div>

<div class="card">
  <div class="card-title">🔑 Licences ({len(keys)})</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Clé</th><th>Plan</th><th>Statut</th><th>Utilisateur</th><th>Créée</th><th>Note</th><th></th></tr></thead>
    <tbody>{rows or '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--muted)">Aucune clé</td></tr>'}</tbody>
  </table></div>
</div>

<div class="card">
  <div class="card-title">🎮 Clés Addon ({len(addon_keys)})</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Clé</th><th>Addon</th><th>Statut</th><th>Durée</th><th>Créée</th><th>Note</th><th></th></tr></thead>
    <tbody>{addon_rows or '<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--muted)">Aucune clé addon</td></tr>'}</tbody>
  </table></div>
</div>"""
    return _layout("Licences", "/admin/keys", content, admin_user, admin_role)


def _page_keys_result(keys, plan, key_type, admin_user, admin_role):
    keys_disp = "<br>".join(f'<span style="font-family:monospace;font-size:13px;color:var(--green)">{k}</span>' for k in keys)
    textarea_val = "\n".join(keys)
    content = f"""
<div class="alert alert-green">✅ {len(keys)} clé(s) {plan} ({key_type}) générée(s) !</div>
<div class="card"><div class="card-title">Clés générées</div>
  <div style="margin-bottom:12px;line-height:1.8">{keys_disp}</div>
  <textarea style="font-family:monospace;font-size:12px;height:100px">{textarea_val}</textarea>
  <div style="margin-top:10px;display:flex;gap:8px">
    <a href="/admin/keys" class="btn btn-green">→ Voir toutes les clés</a>
    <button onclick="copyText(`{textarea_val.replace(chr(96),'').replace(chr(10),chr(92)+'n')}`);showToast('Copié !')" class="btn btn-gray">📋 Copier tout</button>
  </div>
</div>"""
    return _layout("Clés générées", "/admin/keys", content, admin_user, admin_role)


def _page_maintenance(maintenance, maint_msg, announce, announce_color, admin_user, admin_role):
    color = "var(--red)" if maintenance else "var(--green)"
    content = f"""
<div class="card card-glow">
  <div style="text-align:center;padding:24px 0">
    <div style="font-size:56px;margin-bottom:12px">{'🔧' if maintenance else '✅'}</div>
    <div style="font-size:24px;font-weight:800;color:{color};margin-bottom:8px">{'🔴 MAINTENANCE ACTIVE' if maintenance else '🟢 SERVEUR EN LIGNE'}</div>
    <div style="color:var(--text2);font-size:13px;margin-bottom:24px">Le logiciel vérifie /api/status au démarrage et affiche l'écran de maintenance si actif</div>
    <form method="POST">
      <input type="hidden" name="state" value="{'0' if maintenance else '1'}">
      <button type="submit" class="btn {'btn-green' if maintenance else 'btn-red'}" style="padding:14px 36px;font-size:16px">
        {'✅ Désactiver la maintenance' if maintenance else '🔴 Activer la maintenance'}
      </button>
    </form>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<div class="card">
  <div class="card-title">📝 Message de maintenance</div>
  <form method="POST">
    <input type="hidden" name="state" value="{'1' if maintenance else '0'}">
    <div class="form-group"><textarea name="msg_text" rows="3">{maint_msg}</textarea></div>
    <button type="submit" class="btn btn-blue btn-sm">💾 Sauvegarder</button>
  </form>
</div>
<div class="card">
  <div class="card-title">📢 Annonce en bandeau</div>
  <form method="POST">
    <input type="hidden" name="state" value="{'1' if maintenance else '0'}">
    <div class="form-group"><label>Texte (vide = masqué)</label><input name="announce" value="{announce}" placeholder="Nouvelle version v8.0 disponible !"></div>
    <div class="form-group"><label>Couleur</label>
      <select name="announce_color">
        <option {'selected' if announce_color=='blue' else ''} value="blue">Bleu</option>
        <option {'selected' if announce_color=='green' else ''} value="green">Vert</option>
        <option {'selected' if announce_color=='red' else ''} value="red">Rouge</option>
        <option {'selected' if announce_color=='yellow' else ''} value="yellow">Jaune</option>
        <option {'selected' if announce_color=='purple' else ''} value="purple">Violet</option>
      </select>
    </div>
    <button type="submit" class="btn btn-blue btn-sm">💾 Sauvegarder</button>
  </form>
</div>
</div>"""
    return _layout("Maintenance", "/admin/maintenance", content, admin_user, admin_role)


def _page_ips(rules, vpn_block, prefill, admin_user, admin_role):
    rows = ""
    for r in rules:
        color = "var(--green)" if r["rule"]=="whitelist" else "var(--red)"
        badge = f'<span class="badge {"b-green" if r["rule"]=="whitelist" else "b-red"}">{r["rule"]}</span>'
        rows += f'<tr><td style="font-family:monospace;font-weight:700;color:{color}">{r["ip"]}</td><td>{badge}</td><td style="font-size:12px;color:var(--text2)">{r["note"] or "—"}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts(r["added_at"])}</td><td><form method="POST" action="/admin/ips/delete"><input type="hidden" name="ip" value="{r["ip"]}"><button class="btn btn-red btn-sm">✕</button></form></td></tr>'

    content = f"""
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">
<div class="card">
  <div class="card-title">➕ Ajouter une règle IP</div>
  <form method="POST" action="/admin/ips/add">
    <div class="form-group"><label>Adresse IPv4</label><input name="ip" value="{prefill}" placeholder="123.45.67.89" required></div>
    <div class="form-group"><label>Règle</label><select name="rule"><option value="blacklist">🚫 Blacklist</option><option value="whitelist">✅ Whitelist</option></select></div>
    <div class="form-group"><label>Note</label><input name="note" placeholder="raison..."></div>
    <button type="submit" class="btn btn-green">Ajouter</button>
  </form>
</div>
<div class="card">
  <div class="card-title">🔒 Blocage VPN/Proxy</div>
  <div style="display:flex;align-items:center;gap:12px;padding:14px;background:var(--card2);border-radius:10px;border:1px solid var(--border)">
    <form method="POST" action="/admin/ips/vpn" id="vpnform"></form>
    <label class="toggle"><input type="checkbox" {'checked' if vpn_block else ''} onchange="document.getElementById('vpnform').submit()"><span class="toggle-s"></span></label>
    <div>
      <div style="font-weight:700">Bloquer VPN & Proxies</div>
      <div style="color:var(--text2);font-size:12px">Détection via ip-api.com</div>
    </div>
    <span class="badge {'b-green' if vpn_block else 'b-gray'}">{'ACTIF' if vpn_block else 'INACTIF'}</span>
  </div>
  <div style="margin-top:14px;color:var(--text2);font-size:12px;line-height:1.8">
    <b style="color:var(--text)">Whitelist</b>: Si ≥1 IP en whitelist, <u>seules</u> ces IPs passent.<br>
    <b style="color:var(--text)">Blacklist</b>: Ces IPs sont bloquées immédiatement.
  </div>
</div>
</div>
<div class="card">
  <div class="card-title">📋 Règles IP ({len(rules)})</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>IP</th><th>Règle</th><th>Note</th><th>Ajoutée</th><th></th></tr></thead>
    <tbody>{rows or '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">Aucune règle</td></tr>'}</tbody>
  </table></div>
</div>"""
    return _layout("IPs / Whitelist", "/admin/ips", content, admin_user, admin_role)


def _page_resets(resets, admin_user, admin_role):
    rows = ""
    for r in resets:
        sb = f'<span class="badge {"b-yellow" if r["status"]=="pending" else "b-green" if r["status"]=="approved" else "b-red"}">{r["status"]}</span>'
        actions = ""
        if r["status"] == "pending":
            actions = f'''<form method="POST" action="/admin/resets/{r["id"]}/approve" style="display:inline"><button class="btn btn-green btn-sm">✅</button></form>
                         <form method="POST" action="/admin/resets/{r["id"]}/deny" style="display:inline"><button class="btn btn-red btn-sm">❌</button></form>'''
        rows += f'<tr><td>#{r["id"]}</td><td><a href="/admin/user/{r["username"]}"><b>{r["username"] or "—"}</b></a></td><td style="font-size:12px;color:var(--text2)">{r["discord_id"] or "—"}</td><td><span class="badge b-gray">{r["type"]}</span></td><td>{sb}</td><td style="font-family:monospace;font-size:12px;color:var(--green)">{r["temp_pass"] or "—"}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts_rel(r["requested_at"])}</td><td>{actions}</td></tr>'
    content = f"""<div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Username</th><th>Discord ID</th><th>Type</th><th>Statut</th><th>MDP temp</th><th>Quand</th><th>Actions</th></tr></thead>
    <tbody>{rows or '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--muted)">Aucune demande</td></tr>'}</tbody>
  </table></div>"""
    return _layout("Demandes de reset", "/admin/resets", content, admin_user, admin_role)


def _page_tickets(tickets, admin_user, admin_role):
    rows = ""
    for t in tickets:
        if t["status"]=="open": sc='<span class="badge b-yellow">open</span>'
        elif t["status"]=="answered": sc='<span class="badge b-blue">répondu</span>'
        else: sc='<span class="badge b-gray">fermé</span>'
        if t["priority"]=="urgent": pc='<span class="badge b-red">🔥 urgent</span>'
        elif t["priority"]=="high": pc='<span class="badge b-orange">⬆ élevé</span>'
        else: pc='<span class="badge b-gray">normal</span>'
        safe_msg = t["message"][:200].replace("`","").replace("'","").replace('"','').replace('<','').replace('>','')
        safe_resp = (t["response"] or "").replace("`","").replace("'","").replace('"','').replace('<','').replace('>','')
        rows += f"""<tr>
          <td>#{t["id"]}</td>
          <td><a href="/admin/user/{t['user'] or ''}"><b>{t['user'] or 'Anonyme'}</b></a></td>
          <td style="font-size:12px">{t['subject'][:40]}</td>
          <td>{sc}</td><td>{pc}</td>
          <td style="font-size:11px;color:var(--muted)">{fmt_ts_rel(t['created_at'])}</td>
          <td><button onclick="openTicket({t['id']},`{safe_msg}`,`{safe_resp}`)" class="btn btn-ghost btn-sm">Répondre</button></td>
        </tr>"""
    content = f"""
<div style="margin-bottom:10px;display:flex;gap:6px">
  <a href="/admin/tickets" class="btn btn-sm {'btn-green' if True else 'btn-gray'}">Tous</a>
  <a href="/admin/tickets?priority=urgent" class="btn btn-sm btn-red">🔥 Urgents</a>
  <a href="/admin/tickets?priority=high" class="btn btn-sm btn-ghost">⬆ Élevés</a>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>#</th><th>Utilisateur</th><th>Sujet</th><th>Statut</th><th>Priorité</th><th>Date</th><th></th></tr></thead>
  <tbody>{rows or '<tr><td colspan="7" style="text-align:center;padding:24px;color:var(--muted)">Aucun ticket</td></tr>'}</tbody>
</table></div>

<div id="ticket-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.8);z-index:999;align-items:center;justify-content:center;padding:16px">
  <div style="background:var(--card);border:1px solid var(--border);border-radius:16px;padding:24px;width:100%;max-width:520px;max-height:90vh;overflow-y:auto">
    <h3 style="margin-bottom:12px;font-size:16px">💬 Répondre au ticket</h3>
    <div id="ticket-msg-display" style="background:var(--card2);border-radius:8px;padding:12px;color:var(--text2);font-size:13px;margin-bottom:12px;max-height:120px;overflow-y:auto;white-space:pre-wrap"></div>
    <form id="ticket-form" method="POST">
      <div class="form-group"><label>Réponse</label><textarea name="response" id="ticket-response" rows="4" placeholder="Votre réponse..."></textarea></div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button type="submit" name="close" value="0" class="btn btn-blue">📩 Répondre</button>
        <button type="submit" name="close" value="1" class="btn btn-green">✅ Répondre & Fermer</button>
        <button type="button" onclick="closeTicket()" class="btn btn-ghost">Annuler</button>
      </div>
    </form>
  </div>
</div>
<script>
function openTicket(id,msg,resp){{
  document.getElementById('ticket-msg-display').textContent=msg;
  document.getElementById('ticket-response').value=resp||'';
  document.getElementById('ticket-form').action='/admin/tickets/'+id+'/reply';
  document.getElementById('ticket-modal').style.display='flex';
}}
function closeTicket(){{document.getElementById('ticket-modal').style.display='none'}}
</script>"""
    return _layout("Tickets Support", "/admin/tickets", content, admin_user, admin_role)


def _page_logs(logs, filter_type, admin_user, admin_role):
    rows = ""
    for l in logs:
        lc = "b-green" if l["level"]=="OK" else "b-red" if l["level"]=="ERROR" else "b-yellow"
        rows += f'<tr><td style="color:var(--muted);font-size:11px;white-space:nowrap">{fmt_ts(l["ts"])}</td><td><span class="badge {lc}">{l["level"]}</span></td><td style="font-size:11px;color:var(--text2)">{l["type"]}</td><td style="font-size:12px">{l["msg"][:100]}</td><td style="font-size:12px;color:var(--blue)">{l["user"] or "—"}</td></tr>'
    types = ["LOGIN","REGISTER","ANTI-CRACK","ANTI-LEAK","KEYS","ADDON","ADMIN","RESET","BROADCAST","IP","REMOTE"]
    filter_btns = " ".join(f'<a href="/admin/logs?type={t}" class="btn btn-sm {"btn-green" if filter_type==t else "btn-ghost"}">{t}</a>' for t in types)
    content = f"""
<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px">
  <a href="/admin/logs" class="btn btn-sm {"btn-green" if not filter_type else "btn-ghost"}">Tous</a>
  {filter_btns}
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Date</th><th>Niveau</th><th>Type</th><th>Message</th><th>User</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">Aucun log</td></tr>'}</tbody>
</table></div>"""
    return _layout("Logs système", "/admin/logs", content, admin_user, admin_role)


def _page_broadcast(msg_sent, admin_user, admin_role):
    content = f"""
{f'<div class="alert alert-green">{msg_sent}</div>' if msg_sent else ''}
<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
<div class="card">
  <div class="card-title">📢 Message Discord</div>
  <form method="POST">
    <div class="form-group"><label>Cible</label>
      <select name="target"><option value="all">Tous les actifs (avec Discord)</option><option value="pro">PRO uniquement</option><option value="normal">NORMAL uniquement</option></select>
    </div>
    <div class="form-group"><label>Message</label><textarea name="message" rows="5" placeholder="Votre annonce..."></textarea></div>
    <button type="submit" class="btn btn-green">📤 Envoyer</button>
  </form>
</div>
<div class="card">
  <div class="card-title">📋 Templates</div>
  <div style="display:flex;flex-direction:column;gap:8px">
    {''.join(f'<div class="card-sm" style="cursor:pointer" onclick="document.querySelector(\'textarea[name=message]\').value=`{t[1].replace(chr(96),chr(39))}`"><div style="font-weight:700;font-size:12px;margin-bottom:4px">{t[0]}</div><div style="font-size:11px;color:var(--text2)">{t[1][:80]}...</div></div>' for t in [
      ("🔔 Nouvelle mise à jour", "⚡ WinOptimizer Pro a été mis à jour !\n\nNouvelles fonctionnalités disponibles. Relancez l'application pour profiter des améliorations."),
      ("⚠ Maintenance planifiée", "🔧 Une maintenance est planifiée ce soir à 23h.\n\nDurée estimée : 30 minutes. L'accès sera temporairement indisponible."),
      ("🎉 Promo PRO", "⭐ Offre spéciale PRO disponible !\n\nMontez en PRO avec 20% de réduction. Contactez le support pour en profiter."),
    ])}
  </div>
</div>
</div>"""
    return _layout("Broadcast", "/admin/broadcast", content, admin_user, admin_role)


def _page_owners(admins, admin_user, admin_role):
    rows = ""
    for a in admins:
        rb = f'<span class="badge {"b-yellow" if a["role"]=="owner" else "b-blue" if a["role"]=="admin" else "b-gray"}">{a["role"]}</span>'
        del_btn = "" if a["username"]=="xywez" else f'<form method="POST" action="/admin/owners/delete" style="display:inline"><input type="hidden" name="username" value="{a["username"]}"><button class="btn btn-red btn-sm">🗑</button></form>'
        rows += f'<tr><td><b>{a["username"]}</b></td><td>{rb}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts(a["created_at"])}</td><td style="font-size:12px;color:var(--text2)">{a["created_by"] or "système"}</td><td>{del_btn}</td></tr>'
    content = f"""
<div class="card">
  <div class="card-title">➕ Ajouter un admin</div>
  <form method="POST" action="/admin/owners/create">
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;align-items:end">
      <div class="form-group" style="margin:0"><label>Username</label><input name="username" placeholder="username"></div>
      <div class="form-group" style="margin:0"><label>Mot de passe</label><input name="password" type="password"></div>
      <div class="form-group" style="margin:0"><label>Rôle</label><select name="role"><option value="staff">Staff</option><option value="admin">Admin</option><option value="owner">Owner</option></select></div>
      <button type="submit" class="btn btn-green">➕ Créer</button>
    </div>
  </form>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Username</th><th>Rôle</th><th>Créé le</th><th>Créé par</th><th></th></tr></thead>
  <tbody>{rows}</tbody>
</table></div>"""
    return _layout("Équipe / Admins", "/admin/owners", content, admin_user, admin_role)


def _page_profile(msg, admin_user, admin_role):
    content = f"""
{f'<div class="alert {"alert-green" if "✅" in msg else "alert-red"}">{msg}</div>' if msg else ''}
<div style="max-width:420px">
<div class="card">
  <div class="card-title">🔐 Changer mon mot de passe</div>
  <form method="POST">
    <div class="form-group"><label>Ancien MDP</label><input name="old_password" type="password"></div>
    <div class="form-group"><label>Nouveau MDP (6 min)</label><input name="new_password" type="password" minlength="6"></div>
    <button type="submit" class="btn btn-green">🔐 Changer</button>
  </form>
</div>
</div>"""
    return _layout("Mon compte", "/admin/profile", content, admin_user, admin_role)


def _page_anti_leak(alerts, admin_user, admin_role):
    rows = ""
    for a in alerts:
        rows += f'<tr><td style="font-size:11px;color:var(--muted)">{fmt_ts_rel(a["ts"])}</td><td><a href="/admin/user/{a["username"]}"><b style="color:var(--blue)">{a["username"]}</b></a></td><td style="font-family:monospace;font-size:11px">{(a["hwid"] or "")[:24]}…</td><td style="font-size:12px;color:var(--text2)">{a["ip"] or "—"}</td><td style="color:var(--red);font-size:12px">{a["note"]}</td><td><a href="/admin/ips?prefill={a['ip'] or ''}" class="btn btn-red btn-xs">Ban IP</a></td></tr>'
    content = f"""
<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px">
  <div class="stat-card"><div class="stat-icon">🛡</div><div class="stat-num" style="color:var(--red)">{len(alerts)}</div><div class="stat-label">Alertes (24h)</div></div>
  <div class="stat-card"><div class="stat-icon">🔍</div><div class="stat-num" style="color:var(--yellow)">{len(set(a['username'] for a in alerts))}</div><div class="stat-label">Users concernés</div></div>
  <div class="stat-card"><div class="stat-icon">🌐</div><div class="stat-num" style="color:var(--orange)">{len(set(a['ip'] for a in alerts if a['ip']))}</div><div class="stat-label">IPs uniques</div></div>
</div>
<div class="card">
  <div class="card-title">ℹ️ Détections</div>
  <ul style="color:var(--text2);font-size:13px;line-height:2;padding-left:14px">
    <li><b style="color:var(--text)">HWID partagé</b> : même machine sur plusieurs comptes → partage de compte</li>
    <li><b style="color:var(--text)">IP farm</b> : même IP sur +3 comptes → création en masse</li>
    <li><b style="color:var(--text)">HWID mismatch</b> : login refusé si machine différente du HWID enregistré</li>
  </ul>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Quand</th><th>Username</th><th>HWID</th><th>IP</th><th>Alerte</th><th>Action</th></tr></thead>
  <tbody>{rows or '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">Aucune alerte 🎉</td></tr>'}</tbody>
</table></div>"""
    return _layout("Anti-Crack / Anti-Leak", "/admin/anti-leak", content, admin_user, admin_role)


# ════════════════════════════════════════════════════════════════════════════════
#  SYSTÈME DE MISE À JOUR LOGICIEL
# ════════════════════════════════════════════════════════════════════════════════

UPDATE_DIR = "updates"
UPDATE_META_FILE = os.path.join(UPDATE_DIR, "meta.json")

def _ensure_update_dir():
    os.makedirs(UPDATE_DIR, exist_ok=True)

def _get_update_meta():
    try:
        with open(UPDATE_META_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"version": None, "filename": None, "uploaded_at": None, "uploaded_by": None, "changelog": ""}

def _save_update_meta(meta):
    _ensure_update_dir()
    with open(UPDATE_META_FILE, "w") as f:
        json.dump(meta, f)

# ── API publique : le client vérifie s'il y a une update ──────────────────────
@app.route("/api/update/check", methods=["POST"])
def api_update_check():
    """Le .exe appelle ça au démarrage pour savoir si une update est dispo."""
    data = request.get_json(silent=True) or {}
    client_version = data.get("version", "0")
    meta = _get_update_meta()
    server_version = meta.get("version")
    if not server_version or not meta.get("filename"):
        return jsonify({"update_available": False})
    # Compare versions (ex: "7.0" vs "7.1")
    try:
        cv = [int(x) for x in str(client_version).split(".")]
        sv = [int(x) for x in str(server_version).split(".")]
        has_update = sv > cv
    except Exception:
        has_update = server_version != client_version
    return jsonify({
        "update_available": has_update,
        "new_version": server_version,
        "changelog": meta.get("changelog", ""),
        "download_url": f"/api/update/download" if has_update else None,
    })

# ── API publique : téléchargement du fichier ──────────────────────────────────
@app.route("/api/update/download")
def api_update_download():
    """Sert le fichier optimizer.py (ou .exe) au client qui veut se mettre à jour."""
    meta = _get_update_meta()
    filename = meta.get("filename")
    if not filename:
        return jsonify({"error": "Aucune update disponible"}), 404
    filepath = os.path.join(UPDATE_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Fichier introuvable sur le serveur"}), 404
    from flask import send_file
    return send_file(filepath, as_attachment=True, download_name=filename)

# ── Panel admin : page mise à jour ───────────────────────────────────────────
@app.route("/admin/update", methods=["GET", "POST"])
@admin_required
def admin_update():
    msg = ""
    if request.method == "POST":
        action = request.form.get("action", "upload")
        if action == "upload":
            f = request.files.get("update_file")
            version = request.form.get("version", "").strip()
            changelog = request.form.get("changelog", "").strip()
            if not f or not f.filename:
                msg = "❌ Aucun fichier sélectionné"
            elif not version:
                msg = "❌ Version requise (ex: 7.1)"
            else:
                _ensure_update_dir()
                # Garde le nom original du fichier
                safe_name = f.filename.replace(" ", "_")
                save_path = os.path.join(UPDATE_DIR, safe_name)
                f.save(save_path)
                meta = {
                    "version": version,
                    "filename": safe_name,
                    "uploaded_at": int(time.time()),
                    "uploaded_by": session["admin_user"],
                    "changelog": changelog,
                    "size": os.path.getsize(save_path),
                }
                _save_update_meta(meta)
                add_log("OK", "UPDATE", f"Update v{version} uploadée par {session['admin_user']} ({safe_name})", session["admin_user"])
                _push_sse({"type": "update_pushed", "version": version, "admin": session["admin_user"]})
                msg = f"✅ Update v{version} ({safe_name}) publiée avec succès !"
        elif action == "delete":
            meta = _get_update_meta()
            if meta.get("filename"):
                try:
                    os.remove(os.path.join(UPDATE_DIR, meta["filename"]))
                except Exception:
                    pass
            _save_update_meta({"version": None, "filename": None, "uploaded_at": None, "uploaded_by": None, "changelog": ""})
            add_log("WARN", "UPDATE", f"Update supprimée par {session['admin_user']}", session["admin_user"])
            msg = "🗑️ Update supprimée."
    meta = _get_update_meta()
    return _page_update(meta, msg, session["admin_user"], session["admin_role"])


def _page_update(meta, msg, admin_user, admin_role):
    has_update = bool(meta.get("filename") and meta.get("version"))
    size_kb = f"{meta['size'] // 1024} KB" if has_update and meta.get("size") else "—"
    uploaded_at = fmt_ts(meta.get("uploaded_at")) if has_update else "—"
    current_block = f"""
<div class="card card-glow" style="border-color:rgba(0,255,136,.3)">
  <div class="card-title">✅ Update actuellement publiée</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:16px">
    <div class="card-sm"><div style="font-size:11px;color:var(--muted);margin-bottom:4px">VERSION</div><div style="font-size:22px;font-weight:800;color:var(--green)">v{meta['version']}</div></div>
    <div class="card-sm"><div style="font-size:11px;color:var(--muted);margin-bottom:4px">FICHIER</div><div style="font-size:13px;color:var(--text)">{meta['filename']}</div></div>
    <div class="card-sm"><div style="font-size:11px;color:var(--muted);margin-bottom:4px">TAILLE</div><div style="font-size:13px;color:var(--text)">{size_kb}</div></div>
    <div class="card-sm"><div style="font-size:11px;color:var(--muted);margin-bottom:4px">UPLOADÉ LE</div><div style="font-size:13px;color:var(--text)">{uploaded_at}</div></div>
    <div class="card-sm"><div style="font-size:11px;color:var(--muted);margin-bottom:4px">PAR</div><div style="font-size:13px;color:var(--text)">{meta.get('uploaded_by','—')}</div></div>
  </div>
  {"<div class='card-sm' style='margin-bottom:16px'><div style='font-size:11px;color:var(--muted);margin-bottom:4px'>CHANGELOG</div><div style='font-size:13px;color:var(--text2);white-space:pre-wrap'>" + meta.get('changelog','—') + "</div></div>" if meta.get('changelog') else ''}
  <div style="display:flex;gap:8px;flex-wrap:wrap">
    <a href="/api/update/download" class="btn btn-sm btn-blue" download>⬇ Télécharger</a>
    <form method="POST" style="display:inline" onsubmit="return confirm('Supprimer cette update ?')">
      <input type="hidden" name="action" value="delete">
      <button type="submit" class="btn btn-sm btn-red">🗑 Supprimer</button>
    </form>
  </div>
</div>
""" if has_update else """
<div class="card" style="border-color:rgba(255,68,102,.2)">
  <div style="text-align:center;padding:24px;color:var(--muted)">
    <div style="font-size:40px;margin-bottom:10px">📭</div>
    <div style="font-size:14px">Aucune update publiée actuellement</div>
    <div style="font-size:12px;margin-top:4px">Les utilisateurs resteront sur leur version actuelle</div>
  </div>
</div>
"""
    content = f"""
{f'<div class="alert {"alert-green" if "✅" in msg else "alert-red"}">{msg}</div>' if msg else ''}
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;align-items:start">
<div>
  <div class="card">
    <div class="card-title">📤 Publier une nouvelle update</div>
    <p style="font-size:12px;color:var(--text2);margin-bottom:16px;line-height:1.6">
      Glisse et dépose ton <b>optimizer.py</b> (ou .exe) ici.<br>
      Les utilisateurs téléchargeront automatiquement cette version au prochain lancement.
    </p>
    <form method="POST" enctype="multipart/form-data" id="upload-form">
      <input type="hidden" name="action" value="upload">
      <div class="form-group">
        <label>Version (ex: 7.1, 8.0)</label>
        <input name="version" placeholder="7.1" required style="margin-top:4px">
      </div>
      <div class="form-group" style="margin-top:10px">
        <label>Changelog (optionnel)</label>
        <textarea name="changelog" rows="3" placeholder="- Fix bug X&#10;- Ajout feature Y" style="width:100%;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:10px;color:var(--text);font-size:13px;resize:vertical;outline:none;margin-top:4px"></textarea>
      </div>
      <div id="drop-zone" style="border:2px dashed var(--border);border-radius:12px;padding:30px;text-align:center;cursor:pointer;transition:.2s;margin-top:10px;background:var(--card2)" ondragover="event.preventDefault();this.style.borderColor='var(--green)'" ondragleave="this.style.borderColor='var(--border)'" ondrop="handleDrop(event)">
        <div id="drop-text" style="color:var(--muted);font-size:13px">
          <div style="font-size:32px;margin-bottom:8px">📁</div>
          <div>Glisse ton fichier ici</div>
          <div style="font-size:11px;margin-top:4px">optimizer.py ou WinOptimizer.exe</div>
        </div>
        <input type="file" name="update_file" id="file-input" accept=".py,.exe,.zip" style="display:none" onchange="showFileSelected(this)">
      </div>
      <button type="button" class="btn btn-ghost" style="width:100%;margin-top:8px;font-size:12px" onclick="document.getElementById('file-input').click()">Ou cliquer pour choisir un fichier</button>
      <button type="submit" class="btn btn-green" style="margin-top:10px" id="submit-btn" disabled>⬆️ Publier l'update</button>
    </form>
  </div>

  <div class="card">
    <div class="card-title">ℹ️ Comment ça marche ?</div>
    <div style="font-size:12px;color:var(--text2);line-height:2">
      <div>1️⃣ Tu uploades ton <b style="color:var(--text)">optimizer.py</b> ou <b style="color:var(--text)">.exe</b> ici</div>
      <div>2️⃣ Au lancement, chaque <b style="color:var(--text)">.exe</b> appelle <code style="color:var(--green)">/api/update/check</code></div>
      <div>3️⃣ Si la version serveur est plus récente → <b style="color:var(--text)">téléchargement automatique</b></div>
      <div>4️⃣ Le .exe se remplace lui-même et redémarre</div>
      <div style="margin-top:8px;color:var(--muted)">Le client actuel est en version <b style="color:var(--cyan)">v{meta.get("version","—") if has_update else "?"}</b> côté serveur</div>
    </div>
  </div>
</div>

<div>
  {current_block}
  <div class="card">
    <div class="card-title">🔗 Endpoints API</div>
    <div style="font-size:12px;color:var(--text2);line-height:2.2">
      <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">
        <code style="color:var(--green)">POST /api/update/check</code>
        <span>Vérifier si update dispo</span>
      </div>
      <div style="display:flex;justify-content:space-between;padding:6px 0">
        <code style="color:var(--blue)">GET /api/update/download</code>
        <span>Télécharger le fichier</span>
      </div>
    </div>
    <div style="margin-top:12px;background:var(--card2);border-radius:8px;padding:10px;font-size:11px;color:var(--text2)">
      <b style="color:var(--text)">Payload check :</b><br>
      <code style="color:var(--green)">{"{"}"version": "7.0"{"}"}</code>
    </div>
  </div>
</div>
</div>

<script>
function handleDrop(e){{
  e.preventDefault();
  var files=e.dataTransfer.files;
  if(files.length){{
    document.getElementById('file-input').files=files;
    showFileSelected(document.getElementById('file-input'),files[0]);
    document.getElementById('drop-zone').style.borderColor='var(--green)';
  }}
}}
function showFileSelected(input, file){{
  var f = file || input.files[0];
  if(!f) return;
  var kb = Math.round(f.size/1024);
  document.getElementById('drop-text').innerHTML=`<div style="font-size:24px;margin-bottom:6px">✅</div><div style="color:var(--green);font-weight:700">${{f.name}}</div><div style="font-size:11px;color:var(--muted)">${{kb}} KB</div>`;
  document.getElementById('submit-btn').disabled=false;
  document.getElementById('submit-btn').textContent='⬆️ Publier ' + f.name;
}}
</script>
"""
    return _layout("🔄 Mise à jour logiciel", "/admin/update", content, admin_user, admin_role)


# ─── DÉMARRAGE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*54)
    print(f"  ⚡ WINOPTIMIZER LICENSE SERVER v{APP_VERSION}")
    print("="*54)
    print(f"  Port     : {port}")
    print(f"  Admin    : {DEFAULT_ADMIN['username']} / {DEFAULT_ADMIN['password']}")
    print(f"  Panel    : http://localhost:{port}/admin")
    print(f"  Remote   : http://localhost:{port}/admin/remote")
    print(f"  DB       : {DB_PATH}")
    print("="*54)
    app.run(host="0.0.0.0", port=port, debug=False)
