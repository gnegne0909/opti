"""
server.py — WinOptimizer Pro v3.0
Panel admin : /admin  |  API : /api/...

NOUVEAU v3.0 :
  - UI panel admin redesign complet, 100% mobile-first responsive
  - Écran maintenance retourné au logiciel via API /api/status
  - IP v4 forcée + whitelist IP
  - Infos hardware complètes en BDD (GPU, RAM, CPU, disque, carte mère)
  - Anti-crack / anti-leak : détection multi-HWID, token unique par session
  - Logs hardware détaillés dans la fiche utilisateur
  - Keep-alive /ping pour Render free tier
"""

from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import hmac, hashlib, json, time, os, sqlite3, secrets, string, random
import re, urllib.request
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ─── CONFIG ───────────────────────────────────────────────────────────────────
MASTER_SECRET   = os.environ.get("MASTER_SECRET", "WinOpt_k7#Xm2@pQ9_zR4wN8_2025!").encode()
DB_PATH         = "licenses.db"
DISCORD_BOT_URL = "http://localhost:8080"
DEFAULT_ADMIN   = {"username": "xywez", "password": "Admin2025!", "role": "owner"}
APP_VERSION     = "3.0"

# ─── IP HELPER ────────────────────────────────────────────────────────────────
_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def _is_ipv4(ip: str) -> bool:
    return bool(_IPV4_RE.match(ip or ""))

def get_real_ip() -> str:
    """Retourne toujours une IPv4 publique réelle."""
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
    # Fallback : retourner quand même ce qu'on a
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
                "proxy": data.get("proxy", False), "hosting": data.get("hosting", False),
                "ts": now,
            }
        else:
            result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "proxy": False, "hosting": False, "ts": now}
    except Exception:
        result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "proxy": False, "hosting": False, "ts": now}
    _geoip_cache[ip] = result
    return result

# ─── DB ───────────────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
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
        session_token TEXT,
        FOREIGN KEY (license_key) REFERENCES licenses(key)
    )""")
    # Migrations colonnes
    for col, typ in [
        ("os_info","TEXT"),("cpu_info","TEXT"),("gpu_info","TEXT"),
        ("ram_info","TEXT"),("motherboard_info","TEXT"),("disk_info","TEXT"),
        ("session_token","TEXT"),
    ]:
        try: c.execute(f"ALTER TABLE users ADD COLUMN {col} {typ}")
        except: pass
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
        response TEXT, created_at INTEGER, updated_at INTEGER
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
    conn.commit()
    if not conn.execute("SELECT 1 FROM admins WHERE username=?", (DEFAULT_ADMIN["username"],)).fetchone():
        conn.execute("INSERT INTO admins (username,password_hash,role,created_at) VALUES (?,?,?,?)",
                     (DEFAULT_ADMIN["username"], _hash_password(DEFAULT_ADMIN["password"]), DEFAULT_ADMIN["role"], int(time.time())))
    for k, v in [("maintenance","0"),("vpn_block","0"),("maintenance_msg","Maintenance en cours. Revenez dans quelques minutes."),("offline_mode","0")]:
        conn.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k,v))
    conn.commit(); conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn

def add_log(level, type_, msg, user=""):
    conn = get_db()
    conn.execute("INSERT INTO logs (ts,level,type,msg,user) VALUES (?,?,?,?,?)",
                 (int(time.time()), level, type_, msg, user))
    conn.commit(); conn.close()

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

# ─── AUTH ─────────────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged"): return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated

# ─── ANTI-CRACK / ANTI-LEAK ───────────────────────────────────────────────────
def check_anti_leak(username: str, hwid: str, ip: str) -> dict:
    """
    Détecte :
    - Même HWID sur plusieurs comptes (leak de compte)
    - Même IP sur trop de comptes différents (farm)
    """
    conn = get_db()
    # HWID sur plusieurs comptes
    hwid_users = conn.execute(
        "SELECT username FROM users WHERE hwid=? AND username!=? AND status='active'",
        (hwid, username)).fetchall() if hwid else []
    # IP sur plusieurs comptes (>3 = suspect)
    ip_users = conn.execute(
        "SELECT COUNT(DISTINCT username) as cnt FROM users WHERE ip=? AND username!=?",
        (ip, username)).fetchone() if ip else None
    conn.close()
    warnings = []
    if hwid_users:
        others = [r["username"] for r in hwid_users]
        warnings.append(f"HWID partagé avec: {', '.join(others)}")
        add_log("WARN", "ANTI-LEAK", f"HWID {hwid[:16]}… partagé entre {username} et {', '.join(others)}", username)
        # Enregistrer l'alerte
        conn2 = get_db()
        conn2.execute("INSERT INTO hwid_alerts (username,hwid,ip,ts,note) VALUES (?,?,?,?,?)",
                      (username, hwid, ip, int(time.time()), f"Partagé avec {', '.join(others)}"))
        conn2.commit(); conn2.close()
    if ip_users and ip_users["cnt"] > 3:
        warnings.append(f"IP {ip} utilisée par {ip_users['cnt']+1} comptes")
        add_log("WARN", "ANTI-LEAK", f"IP {ip} sur {ip_users['cnt']+1} comptes (suspect)", username)
    return {"warnings": warnings, "flagged": len(warnings) > 0}

# ════════════════════════════════════════════════════════════════════════════════
#  API PUBLIQUES
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/ping")
def ping():
    """Keep-alive Render + status global pour le logiciel."""
    maintenance = get_setting("maintenance") == "1"
    msg = get_setting("maintenance_msg")
    return jsonify({
        "status": "maintenance" if maintenance else "ok",
        "message": msg if maintenance else "Serveur opérationnel",
        "version": APP_VERSION,
        "ts": int(time.time())
    }), 200

@app.route("/api/status")
def api_status():
    """
    Appelé par le logiciel AU DÉMARRAGE pour savoir si :
    - Le serveur est en ligne
    - La maintenance est active
    Retourne les infos nécessaires pour afficher l'écran maintenance.
    """
    maintenance = get_setting("maintenance") == "1"
    return jsonify({
        "online": True,
        "maintenance": maintenance,
        "maintenance_msg": get_setting("maintenance_msg") if maintenance else "",
        "version": APP_VERSION,
        "ts": int(time.time())
    }), 200

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
    # Vérif whitelist/blacklist IP
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
        conn.close(); return jsonify({"success": False, "reason": "Accès refusé depuis cette IP"})
    # Whitelist : si whitelist existe, seules ces IPs passent
    whitelist_count = conn.execute("SELECT COUNT(*) FROM ip_rules WHERE rule='whitelist'").fetchone()[0]
    if whitelist_count > 0:
        is_whitelisted = conn.execute("SELECT 1 FROM ip_rules WHERE ip=? AND rule='whitelist'", (ip,)).fetchone()
        if not is_whitelisted:
            conn.close(); return jsonify({"success": False, "reason": "IP non autorisée"})

    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
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
        conn.close()
        add_log("WARN","LOGIN",f"Mauvais MDP: {username} IP={ip}")
        return jsonify({"success": False, "reason": "Identifiants incorrects"})

    # Anti-crack HWID
    if row["hwid"] and machine_id and row["hwid"] != machine_id:
        add_log("WARN","ANTI-CRACK",f"HWID mismatch: {username} attendu={row['hwid'][:16]} reçu={machine_id[:16]}")
        conn.close()
        return jsonify({"success": False, "reason": "Machine non autorisée. Contactez le support."})
    if not row["hwid"] and machine_id:
        conn.execute("UPDATE users SET hwid=? WHERE username=?", (machine_id, username))

    # Anti-leak check
    check_anti_leak(username, machine_id, ip)

    # Générer token de session
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
    add_log("OK","LOGIN",f"Connexion: {username} plan={row['plan']} IP={ip}", username)

    return jsonify({
        "success": True, "username": username, "plan": row["plan"],
        "discord_id": row["discord_id"] or "", "first_login": first_login,
        "must_change_pass": must_change, "license_key": row["license_key"],
        "session_token": session_token,
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
    conn.execute("UPDATE users SET last_login=?,ip=?,connections=connections+1 WHERE username=?",
                 (int(time.time()), ip, username))
    conn.commit(); conn.close()
    return jsonify({"valid": True, "plan": row["plan"], "username": username})

@app.route("/api/ticket", methods=["POST"])
def api_create_ticket():
    data = request.get_json(silent=True) or {}
    subject = data.get("subject", "").strip(); message = data.get("message", "").strip()
    if not subject or not message: return jsonify({"success": False, "reason": "Champs manquants"})
    conn = get_db()
    conn.execute("INSERT INTO tickets (user,discord_id,subject,message,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                 (data.get("username",""), data.get("discord_id",""), subject[:100], message[:1000], "open", int(time.time()), int(time.time())))
    conn.commit(); conn.close()
    return jsonify({"success": True})

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — AUTH
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
    today = int(time.time()) - 86400; week = int(time.time()) - 604800
    stats = {
        "total":        conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":       conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":       conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":          conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "total_lic":    conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "active_lic":   conn.execute("SELECT COUNT(*) FROM licenses WHERE status='active'").fetchone()[0],
        "pending_reset":conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets": conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "today_logins": conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "week_logins":  conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (week,)).fetchone()[0],
        "new_today":    conn.execute("SELECT COUNT(*) FROM users WHERE created_at>?", (today,)).fetchone()[0],
        "hwid_alerts":  conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "maintenance":  get_setting("maintenance") == "1",
    }
    hourly = []
    for i in range(24):
        ts = int(time.time()) - (i+1)*3600; te = int(time.time()) - i*3600
        hourly.append(conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (ts,te)).fetchone()[0])
    hourly.reverse()
    stats["hourly"] = hourly
    recent = conn.execute("SELECT username,plan,status,last_login,ip,connections,os_info,cpu_info,gpu_info FROM users ORDER BY last_login DESC LIMIT 8").fetchall()
    conn.close()
    return render_template_string(DASHBOARD_HTML, stats=stats, recent=recent,
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — USERS
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/users")
@admin_required
def admin_users():
    q = request.args.get("q",""); plan_f = request.args.get("plan",""); status_f = request.args.get("status","")
    conn = get_db()
    sql = "SELECT * FROM users WHERE 1=1"
    params = []
    if q: sql += " AND (username LIKE ? OR discord_id LIKE ? OR ip LIKE ? OR license_key LIKE ?)"; params += [f"%{q}%"]*4
    if plan_f: sql += " AND plan=?"; params.append(plan_f)
    if status_f: sql += " AND status=?"; params.append(status_f)
    sql += " ORDER BY last_login DESC LIMIT 150"
    rows = conn.execute(sql, params).fetchall(); conn.close()
    return render_template_string(USERS_HTML, users=rows, q=q, plan_f=plan_f, status_f=status_f,
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

@app.route("/admin/user/<username>")
@admin_required
def admin_user_detail(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user: conn.close(); return "Introuvable", 404
    logs = conn.execute("SELECT * FROM logs WHERE user=? ORDER BY ts DESC LIMIT 50", (username,)).fetchall()
    alerts = conn.execute("SELECT * FROM hwid_alerts WHERE username=? ORDER BY ts DESC LIMIT 10", (username,)).fetchall()
    conn.close()
    geo = get_geoip(user["ip"]) if user["ip"] else {}
    msg = request.args.get("msg","")
    return render_template_string(USER_DETAIL_HTML, user=user, logs=logs, alerts=alerts, geo=geo, msg=msg,
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

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
    conn.commit(); conn.close()
    return redirect(f"/admin/user/{username}")

@app.route("/admin/user/<username>/edit", methods=["POST"])
@admin_required
def admin_user_edit(username):
    conn = get_db()
    conn.execute("UPDATE users SET plan=?,note=?,discord_id=? WHERE username=?",
                 (request.form.get("plan","NORMAL"), request.form.get("note",""), request.form.get("discord_id",""), username))
    conn.commit(); conn.close()
    add_log("OK","ADMIN",f"User {username} modifié", session["admin_user"])
    return redirect(f"/admin/user/{username}?msg=Sauvegardé")

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — KEYS
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/keys")
@admin_required
def admin_keys():
    conn = get_db()
    keys = conn.execute("SELECT l.*,u.username FROM licenses l LEFT JOIN users u ON l.key=u.license_key ORDER BY l.created_at DESC LIMIT 200").fetchall()
    conn.close()
    return render_template_string(KEYS_HTML, keys=keys, admin_user=session["admin_user"], admin_role=session["admin_role"])

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
    return render_template_string(KEYS_RESULT_HTML, keys=generated, plan=plan,
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

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
#  ADMIN — MAINTENANCE
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/maintenance", methods=["GET","POST"])
@admin_required
def admin_maintenance():
    if request.method == "POST":
        set_setting("maintenance", request.form.get("state","0"))
        if request.form.get("msg_text",""):
            set_setting("maintenance_msg", request.form.get("msg_text"))
        add_log("OK","ADMIN",f"Maintenance: {'ON' if request.form.get('state')=='1' else 'OFF'}", session["admin_user"])
        return redirect("/admin/maintenance")
    return render_template_string(MAINTENANCE_HTML,
                                  maintenance=get_setting("maintenance")=="1",
                                  maint_msg=get_setting("maintenance_msg"),
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — IPs
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/ips")
@admin_required
def admin_ips():
    conn = get_db(); rules = conn.execute("SELECT * FROM ip_rules ORDER BY added_at DESC").fetchall(); conn.close()
    prefill = request.args.get("prefill","")
    return render_template_string(IPS_HTML, rules=rules, vpn_block=get_setting("vpn_block")=="1", prefill=prefill,
                                  admin_user=session["admin_user"], admin_role=session["admin_role"])

@app.route("/admin/ips/add", methods=["POST"])
@admin_required
def admin_add_ip():
    ip = request.form.get("ip","").strip(); rule = request.form.get("rule","blacklist"); note = request.form.get("note","")
    if not _is_ipv4(ip) and ip:
        return redirect("/admin/ips?error=IPv4+uniquement")
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

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — RESETS / TICKETS / LOGS / BROADCAST / OWNERS / PROFILE
# ════════════════════════════════════════════════════════════════════════════════

@app.route("/admin/resets")
@admin_required
def admin_resets():
    conn = get_db(); rows = conn.execute("SELECT * FROM reset_requests ORDER BY requested_at DESC LIMIT 100").fetchall(); conn.close()
    return render_template_string(RESETS_HTML, resets=rows, admin_user=session["admin_user"], admin_role=session["admin_role"])

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
    conn = get_db(); rows = conn.execute("SELECT * FROM tickets ORDER BY created_at DESC LIMIT 100").fetchall(); conn.close()
    return render_template_string(TICKETS_HTML, tickets=rows, admin_user=session["admin_user"], admin_role=session["admin_role"])

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
    return render_template_string(LOGS_HTML, logs=rows, filter_type=ft, admin_user=session["admin_user"], admin_role=session["admin_role"])

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
        users = conn.execute(q).fetchall() if q else []; conn.close()
        for u in users: _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer**\n{message}")
        msg_sent = f"✅ Envoyé à {len(users)} utilisateur(s)."
        add_log("OK","BROADCAST",f"{target}: {message[:60]}", session["admin_user"])
    return render_template_string(BROADCAST_HTML, msg=msg_sent, admin_user=session["admin_user"], admin_role=session["admin_role"])

@app.route("/admin/owners")
@admin_required
def admin_owners():
    if session.get("admin_role") != "owner": return redirect("/admin")
    conn = get_db(); rows = conn.execute("SELECT * FROM admins ORDER BY created_at").fetchall(); conn.close()
    return render_template_string(OWNERS_HTML, admins=rows, admin_user=session["admin_user"], admin_role=session["admin_role"])

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
    return render_template_string(PROFILE_HTML, msg=msg, admin_user=session["admin_user"], admin_role=session["admin_role"])

@app.route("/admin/anti-leak")
@admin_required
def admin_anti_leak():
    conn = get_db()
    alerts = conn.execute("SELECT * FROM hwid_alerts ORDER BY ts DESC LIMIT 100").fetchall()
    conn.close()
    return render_template_string(ANTI_LEAK_HTML, alerts=alerts, admin_user=session["admin_user"], admin_role=session["admin_role"])

# ════════════════════════════════════════════════════════════════════════════════
#  ADMIN — API JSON (dashboard live)
# ════════════════════════════════════════════════════════════════════════════════

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
        "total":         conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":        conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":        conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":           conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "today_logins":  conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "total_keys":    conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "pending_resets":conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets":  conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "hwid_alerts":   conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "hourly":        hourly,
        "maintenance":   get_setting("maintenance") == "1",
        "ts":            int(time.time()),
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
    conn = get_db()
    today = int(time.time()) - 86400
    d = {
        "total":       conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":      conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "today":       conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "maintenance": get_setting("maintenance") == "1",
    }
    conn.close(); return jsonify(d)

@app.route("/api/internal/user_info")
def internal_user_info():
    """Infos complètes d'un user pour le bot."""
    if not _check_bot_token(args=request.args): return jsonify({"error":"Non autorisé"}), 403
    username = request.args.get("username","")
    conn = get_db(); row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone(); conn.close()
    if not row: return jsonify({"error":"Introuvable"}), 404
    return jsonify({k: row[k] for k in row.keys() if k != "password_hash"})

# ════════════════════════════════════════════════════════════════════════════════
#  HELPER DISCORD DM
# ════════════════════════════════════════════════════════════════════════════════

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

app.jinja_env.globals["fmt_ts"] = fmt_ts


# ════════════════════════════════════════════════════════════════════════════════
#  TEMPLATES HTML — UI v3 MOBILE FIRST
# ════════════════════════════════════════════════════════════════════════════════

_BASE_CSS = """
:root{--bg:#0a0a0f;--card:#13131a;--card2:#1a1a24;--border:#2a2a3a;--green:#00ff88;--green2:#00cc6a;--blue:#4f8ef7;--red:#ff4466;--yellow:#ffcc00;--text:#e8e8f0;--muted:#666688;--sidebar:220px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;font-size:15px}
a{color:var(--green);text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:700}
.badge-green{background:rgba(0,255,136,.15);color:var(--green)}
.badge-red{background:rgba(255,68,102,.15);color:var(--red)}
.badge-yellow{background:rgba(255,204,0,.15);color:var(--yellow)}
.badge-blue{background:rgba(79,142,247,.15);color:var(--blue)}
.badge-gray{background:rgba(100,100,136,.15);color:var(--muted)}
/* Layout */
.layout{display:flex;min-height:100vh}
/* Sidebar */
.sidebar{width:var(--sidebar);background:var(--card);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:100;transition:transform .3s}
.sidebar-logo{padding:20px 16px 12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sidebar-logo .icon{width:36px;height:36px;background:var(--green);border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;color:#000}
.sidebar-logo span{font-weight:800;font-size:15px;color:var(--text)}
.sidebar-logo small{display:block;font-size:11px;color:var(--muted);font-weight:400}
.sidebar nav{flex:1;overflow-y:auto;padding:10px 0}
.nav-section{padding:14px 16px 4px;font-size:11px;text-transform:uppercase;color:var(--muted);letter-spacing:1px;font-weight:700}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 16px;color:var(--muted);font-size:14px;font-weight:500;transition:.15s;cursor:pointer;border-left:3px solid transparent}
.nav-item:hover{color:var(--text);background:rgba(255,255,255,.04);text-decoration:none}
.nav-item.active{color:var(--green);background:rgba(0,255,136,.06);border-left-color:var(--green)}
.nav-item .ico{width:20px;text-align:center;font-size:16px}
.nav-item .cnt{margin-left:auto;background:var(--red);color:#fff;font-size:11px;padding:1px 6px;border-radius:10px;font-weight:700}
.sidebar-footer{padding:12px 16px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
/* Main */
.main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}
.topbar{background:var(--card);border-bottom:1px solid var(--border);padding:14px 24px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50}
.topbar h1{font-size:18px;font-weight:700;flex:1}
.topbar .topbar-actions{display:flex;gap:8px;align-items:center}
.menu-toggle{display:none;background:none;border:none;color:var(--text);font-size:22px;cursor:pointer;padding:4px}
.content{padding:24px;flex:1}
/* Cards */
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:20px;margin-bottom:16px}
.card-title{font-weight:700;font-size:14px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;margin-bottom:16px}
/* Stats grid */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:16px;text-align:center;transition:.2s}
.stat-card:hover{border-color:var(--green);transform:translateY(-2px)}
.stat-num{font-size:32px;font-weight:800;color:var(--green)}
.stat-label{font-size:12px;color:var(--muted);margin-top:4px;font-weight:600}
.stat-icon{font-size:22px;margin-bottom:8px}
/* Table */
.tbl-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse}
th{background:var(--card2);padding:12px 16px;font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:700;text-align:left;white-space:nowrap}
td{padding:11px 16px;border-top:1px solid var(--border);font-size:13px;vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.02)}
/* Forms */
.form-group{margin-bottom:14px}
label{display:block;font-size:13px;font-weight:600;color:var(--muted);margin-bottom:6px}
input,select,textarea{width:100%;background:var(--card2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;color:var(--text);font-size:14px;outline:none;transition:.15s}
input:focus,select:focus,textarea:focus{border-color:var(--green)}
textarea{resize:vertical;min-height:80px}
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border-radius:8px;font-size:13px;font-weight:700;border:none;cursor:pointer;transition:.15s;white-space:nowrap}
.btn-green{background:var(--green);color:#000}.btn-green:hover{background:var(--green2)}
.btn-red{background:var(--red);color:#fff}.btn-red:hover{background:#cc3355}
.btn-blue{background:var(--blue);color:#fff}.btn-blue:hover{background:#3a7ae0}
.btn-gray{background:var(--card2);color:var(--text);border:1px solid var(--border)}.btn-gray:hover{border-color:var(--green)}
.btn-sm{padding:5px 12px;font-size:12px}
/* Alert */
.alert{padding:12px 16px;border-radius:10px;margin-bottom:16px;font-size:14px;font-weight:600}
.alert-green{background:rgba(0,255,136,.1);border:1px solid rgba(0,255,136,.3);color:var(--green)}
.alert-red{background:rgba(255,68,102,.1);border:1px solid rgba(255,68,102,.3);color:var(--red)}
.alert-yellow{background:rgba(255,204,0,.1);border:1px solid rgba(255,204,0,.3);color:var(--yellow)}
/* Search */
.search-bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.search-bar input,.search-bar select{flex:1;min-width:140px;max-width:280px}
/* Hardware info */
.hw-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px}
.hw-item{background:var(--card2);border:1px solid var(--border);border-radius:10px;padding:12px}
.hw-item .hw-label{font-size:11px;color:var(--muted);text-transform:uppercase;font-weight:700;margin-bottom:4px}
.hw-item .hw-val{font-size:13px;color:var(--text);font-weight:600}
/* Toggle switch */
.toggle-wrap{display:flex;align-items:center;gap:12px;padding:16px;background:var(--card2);border-radius:12px;border:1px solid var(--border)}
.toggle{position:relative;display:inline-block;width:52px;height:28px}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;top:0;left:0;right:0;bottom:0;background:var(--border);border-radius:28px;transition:.3s;cursor:pointer}
.toggle-slider:before{content:'';position:absolute;width:20px;height:20px;left:4px;bottom:4px;background:#fff;border-radius:50%;transition:.3s}
input:checked+.toggle-slider{background:var(--green)}
input:checked+.toggle-slider:before{transform:translateX(24px)}
/* Responsive MOBILE */
@media(max-width:768px){
  :root{--sidebar:0px}
  .sidebar{transform:translateX(-220px);width:220px}
  .sidebar.open{transform:translateX(0)}
  .main{margin-left:0}
  .menu-toggle{display:block}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .content{padding:14px}
  .topbar{padding:12px 14px}
  .topbar h1{font-size:15px}
  td,th{padding:8px 10px;font-size:12px}
  .btn{padding:7px 12px;font-size:12px}
  .hw-grid{grid-template-columns:repeat(2,1fr)}
  .search-bar input,.search-bar select{min-width:100%;max-width:100%}
}
@media(max-width:400px){
  .stats-grid{grid-template-columns:1fr 1fr}
  .stat-num{font-size:24px}
}
/* Sidebar overlay */
.sidebar-overlay{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.6);z-index:90}
.sidebar-overlay.show{display:block}
/* Mini chart */
.chart-bar{display:flex;align-items:flex-end;height:60px;gap:2px;padding-top:8px}
.chart-bar .bar{flex:1;background:var(--green);border-radius:3px 3px 0 0;opacity:.7;min-height:2px;transition:.3s}
.chart-bar .bar:hover{opacity:1}
"""

_BASE_JS = """
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
  // Auto-refresh stats every 30s on dashboard
  if(document.getElementById('dash-stats')){
    setInterval(refreshStats,30000);
  }
});
function refreshStats(){
  fetch('/admin/api/stats').then(r=>r.json()).then(d=>{
    ['total','active','banned','pro','today_logins','total_keys','pending_resets','open_tickets','hwid_alerts'].forEach(k=>{
      var el=document.getElementById('s-'+k);
      if(el) el.textContent=d[k];
    });
    var maint=document.getElementById('maint-badge');
    if(maint) maint.textContent=d.maintenance?'🔴 MAINTENANCE':'🟢 EN LIGNE';
    // mini chart
    if(d.hourly&&document.getElementById('hourly-chart')){
      var mx=Math.max(...d.hourly,1);
      var bars=document.querySelectorAll('#hourly-chart .bar');
      bars.forEach((b,i)=>{ b.style.height=Math.max(4,(d.hourly[i]/mx)*56)+'px'; b.title=d.hourly[i]+' conn'; });
    }
  }).catch(()=>{});
}
"""

def _nav(active, pending_resets=0, open_tickets=0, hwid_alerts=0):
    items = [
        ("/admin","📊","Dashboard",""),
        ("/admin/users","👤","Utilisateurs",""),
        ("/admin/keys","🔑","Licences",""),
        ("/admin/resets","🔄","Resets", str(pending_resets) if pending_resets else ""),
        ("/admin/tickets","📩","Tickets", str(open_tickets) if open_tickets else ""),
        ("/admin/anti-leak","🛡","Anti-Crack", str(hwid_alerts) if hwid_alerts else ""),
        ("/admin/logs","📋","Logs",""),
        ("/admin/ips","🌐","IPs / Whitelist",""),
        ("/admin/maintenance","⚙️","Maintenance",""),
        ("/admin/broadcast","📢","Broadcast",""),
        ("/admin/owners","👑","Équipe",""),
        ("/admin/profile","🔐","Mon compte",""),
    ]
    html = ""
    for href,ico,label,cnt in items:
        cls = "active" if active==href else ""
        badge = f'<span class="cnt">{cnt}</span>' if cnt else ""
        html += f'<a href="{href}" class="nav-item {cls}"><span class="ico">{ico}</span>{label}{badge}</a>'
    return html

def _conn():
    conn = get_db(); row = conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()
    t = conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()
    h = conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (int(time.time())-86400,)).fetchone()
    conn.close(); return int(row[0]), int(t[0]), int(h[0])

def _layout(title, active, content, admin_user="", admin_role=""):
    pr,ot,ha = _conn()
    return f"""<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — WinOptimizer Admin</title>
<style>{_BASE_CSS}</style></head>
<body>
<div class="sidebar-overlay"></div>
<div class="layout">
<aside class="sidebar">
  <div class="sidebar-logo"><div class="icon">⚡</div><div><span>WinOptimizer</span><small>Panel Admin v3.0</small></div></div>
  <nav>{_nav(active,pr,ot,ha)}</nav>
  <div class="sidebar-footer">👤 <b>{admin_user}</b> &nbsp;·&nbsp; {admin_role}<br><a href="/admin/logout">Se déconnecter →</a></div>
</aside>
<div class="main">
  <div class="topbar">
    <button class="menu-toggle" onclick="toggleSidebar()">☰</button>
    <h1>{title}</h1>
    <div class="topbar-actions">
      <span id="maint-badge" class="badge {'badge-red' if get_setting('maintenance')=='1' else 'badge-green'}">
        {'🔴 MAINTENANCE' if get_setting('maintenance')=='1' else '🟢 EN LIGNE'}
      </span>
    </div>
  </div>
  <div class="content">{content}</div>
</div>
</div>
<script>{_BASE_JS}</script>
</body></html>"""


# ─── LOGIN PAGE ───────────────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — WinOptimizer</title>
<style>
""" + _BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;min-height:100vh;background:radial-gradient(ellipse at top,#0f1420,var(--bg))}
.login-box{width:100%;max-width:380px;padding:16px}
.login-card{background:var(--card);border:1px solid var(--border);border-radius:18px;padding:36px 32px}
.login-logo{text-align:center;margin-bottom:28px}
.login-logo .icon{width:56px;height:56px;background:var(--green);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;font-size:28px;color:#000;margin-bottom:12px}
.login-logo h2{font-size:22px;font-weight:800}.login-logo p{color:var(--muted);font-size:14px;margin-top:4px}
</style></head><body>
<div class="login-box">
  <div class="login-card">
    <div class="login-logo"><div class="icon">⚡</div><h2>WinOptimizer</h2><p>Panel d'administration v3.0</p></div>
    {% if error %}<div class="alert alert-red">{{ error }}</div>{% endif %}
    <form method="POST">
      <div class="form-group"><label>Identifiant</label><input name="username" placeholder="admin" autofocus></div>
      <div class="form-group"><label>Mot de passe</label><input name="password" type="password" placeholder="••••••••"></div>
      <button type="submit" class="btn btn-green" style="width:100%;justify-content:center;padding:12px">Se connecter →</button>
    </form>
  </div>
</div>
</body></html>"""


# ─── DASHBOARD ────────────────────────────────────────────────────────────────
def _render_dashboard(stats, recent):
    max_h = max(stats["hourly"] + [1])
    bars = "".join(f'<div class="bar" style="height:{max(4,int(v/max_h*56))}px" title="{v} connexions"></div>' for v in stats["hourly"])
    rec_rows = ""
    for u in recent:
        plan_badge = f'<span class="badge badge-blue">PRO</span>' if u["plan"]=="PRO" else f'<span class="badge badge-gray">NORMAL</span>'
        rec_rows += f"<tr><td><a href='/admin/user/{u['username']}'><b>{u['username']}</b></a></td><td>{plan_badge}</td><td>{u['connections'] or 0}</td><td style='color:var(--muted);font-size:11px'>{u['os_info'] or '—'}</td><td style='color:var(--muted);font-size:11px'>{u['gpu_info'] or '—'}</td></tr>"
    return f"""
<div id="dash-stats">
<div class="stats-grid">
  <div class="stat-card"><div class="stat-icon">👥</div><div class="stat-num" id="s-total">{stats['total']}</div><div class="stat-label">Utilisateurs</div></div>
  <div class="stat-card"><div class="stat-icon">✅</div><div class="stat-num" id="s-active">{stats['active']}</div><div class="stat-label">Actifs</div></div>
  <div class="stat-card"><div class="stat-icon">🚫</div><div class="stat-num" id="s-banned" style="color:var(--red)">{stats['banned']}</div><div class="stat-label">Bannis</div></div>
  <div class="stat-card"><div class="stat-icon">⭐</div><div class="stat-num" id="s-pro" style="color:var(--blue)">{stats['pro']}</div><div class="stat-label">Plan PRO</div></div>
  <div class="stat-card"><div class="stat-icon">🔑</div><div class="stat-num" id="s-total_keys">{stats['total_lic']}</div><div class="stat-label">Licences</div></div>
  <div class="stat-card"><div class="stat-icon">📅</div><div class="stat-num" id="s-today_logins">{stats['today_logins']}</div><div class="stat-label">Logins aujourd'hui</div></div>
  <div class="stat-card"><div class="stat-icon">🔄</div><div class="stat-num" id="s-pending_resets" style="color:var(--yellow)">{stats['pending_reset']}</div><div class="stat-label">Resets en attente</div></div>
  <div class="stat-card"><div class="stat-icon">🛡</div><div class="stat-num" id="s-hwid_alerts" style="color:var(--red)">{stats['hwid_alerts']}</div><div class="stat-label">Alertes anti-leak</div></div>
</div>
</div>
<div class="card">
  <div class="card-title">Connexions 24h (par heure)</div>
  <div id="hourly-chart" class="chart-bar">{bars}</div>
  <div style="display:flex;justify-content:space-between;color:var(--muted);font-size:11px;margin-top:4px"><span>-24h</span><span>maintenant</span></div>
</div>
<div class="card">
  <div class="card-title">Connexions récentes</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Utilisateur</th><th>Plan</th><th>Connexions</th><th>OS</th><th>GPU</th></tr></thead>
    <tbody>{rec_rows}</tbody>
  </table></div>
</div>
"""

def DASHBOARD_HTML_render(stats, recent, admin_user, admin_role):
    return _layout("Dashboard", "/admin", _render_dashboard(stats, recent), admin_user, admin_role)

DASHBOARD_HTML = property(lambda self: None)  # placeholder replaced below


# ─── PAGES HTML DYNAMIQUES (render functions) ─────────────────────────────────

def _users_content(users, q, plan_f, status_f):
    rows = ""
    for u in users:
        if u["plan"]=="PRO": pb=f'<span class="badge badge-blue">PRO</span>'
        else: pb=f'<span class="badge badge-gray">NORMAL</span>'
        if u["status"]=="active": sb=f'<span class="badge badge-green">actif</span>'
        elif u["status"]=="banned": sb=f'<span class="badge badge-red">banni</span>'
        else: sb=f'<span class="badge badge-yellow">{u["status"]}</span>'
        geo = get_geoip(u["ip"]) if u["ip"] else {}
        flag = geo.get("flag","")
        rows += f"""<tr>
          <td><a href="/admin/user/{u['username']}"><b>{u['username']}</b></a></td>
          <td>{pb}</td><td>{sb}</td>
          <td style="font-size:11px;color:var(--muted)">{flag} {u['ip'] or '—'}</td>
          <td style="font-size:11px;color:var(--muted)">{u['os_info'] or '—'}</td>
          <td style="font-size:11px;color:var(--muted)">{u['gpu_info'] or '—'}</td>
          <td style="color:var(--muted)">{u['connections'] or 0}</td>
          <td style="color:var(--muted);font-size:11px">{fmt_ts(u['last_login'])}</td>
          <td><a href="/admin/user/{u['username']}" class="btn btn-gray btn-sm">Détail</a></td>
        </tr>"""
    return f"""
<div class="search-bar">
  <form method="GET" style="display:contents">
    <input name="q" value="{q}" placeholder="🔍 Nom, IP, Discord, Clé...">
    <select name="plan"><option value="">Tous plans</option><option {'selected' if plan_f=='PRO' else ''} value="PRO">PRO</option><option {'selected' if plan_f=='NORMAL' else ''} value="NORMAL">NORMAL</option></select>
    <select name="status"><option value="">Tous statuts</option><option {'selected' if status_f=='active' else ''} value="active">Actif</option><option {'selected' if status_f=='banned' else ''} value="banned">Banni</option></select>
    <button type="submit" class="btn btn-green">Filtrer</button>
    <a href="/admin/users" class="btn btn-gray">Reset</a>
  </form>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Username</th><th>Plan</th><th>Statut</th><th>IP</th><th>OS</th><th>GPU</th><th>Conn.</th><th>Dernier login</th><th></th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="9" style="text-align:center;color:var(--muted);padding:30px">Aucun résultat</td></tr>'}</tbody>
</table></div>"""

def _user_detail_content(user, logs, alerts, geo, msg):
    # Hardware grid
    hw_items = [
        ("💻 OS", user["os_info"] or "—"),
        ("🖥 CPU", user["cpu_info"] or "—"),
        ("🎮 GPU", user["gpu_info"] or "—"),
        ("💾 RAM", user["ram_info"] or "—"),
        ("🔌 Carte mère", user["motherboard_info"] or "—"),
        ("💿 Stockage", user["disk_info"] or "—"),
    ]
    hw_html = "".join(f'<div class="hw-item"><div class="hw-label">{l}</div><div class="hw-val">{v}</div></div>' for l,v in hw_items)

    if user["status"]=="active": sb=f'<span class="badge badge-green">actif</span>'
    elif user["status"]=="banned": sb=f'<span class="badge badge-red">banni</span>'
    else: sb=f'<span class="badge badge-yellow">{user["status"]}</span>'
    if user["plan"]=="PRO": pb=f'<span class="badge badge-blue">PRO</span>'
    else: pb=f'<span class="badge badge-gray">NORMAL</span>'

    flag = geo.get("flag","🌐"); country = geo.get("country","?"); city = geo.get("city","?"); isp = geo.get("isp","?")
    proxy_warn = '<span class="badge badge-yellow">🕵 VPN/Proxy détecté</span>' if geo.get("proxy") else ""

    alert_rows = "".join(f'<tr><td>{fmt_ts(a["ts"])}</td><td style="font-size:11px">{a["hwid"][:20] if a["hwid"] else "—"}…</td><td style="color:var(--red);font-size:12px">{a["note"]}</td></tr>' for a in alerts)
    log_rows = "".join(f'<tr><td style="color:var(--muted);font-size:11px;white-space:nowrap">{fmt_ts(l["ts"])}</td><td><span class="badge {"badge-green" if l["level"]=="OK" else "badge-red"}">{l["level"]}</span></td><td style="font-size:12px;color:var(--muted)">{l["type"]}</td><td style="font-size:12px">{l["msg"]}</td></tr>' for l in logs)

    return f"""
{f'<div class="alert alert-green">{msg}</div>' if msg else ''}
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
<div class="card" style="margin:0">
  <div class="card-title">Informations</div>
  <table style="width:100%">
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Username</td><td><b>{user["username"]}</b></td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Plan</td><td>{pb}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Statut</td><td>{sb}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Discord ID</td><td style="font-size:12px">{user["discord_id"] or "—"}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Licence</td><td style="font-size:12px;font-family:monospace">{user["license_key"] or "—"}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Connexions</td><td><b>{user["connections"] or 0}</b></td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Créé</td><td style="font-size:12px">{fmt_ts(user["created_at"])}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Dernier login</td><td style="font-size:12px">{fmt_ts(user["last_login"])}</td></tr>
    <tr><td style="color:var(--muted);font-size:13px;padding:6px 0">Note</td><td style="font-size:12px;color:var(--muted)">{user["note"] or "—"}</td></tr>
  </table>
</div>
<div class="card" style="margin:0">
  <div class="card-title">Géolocalisation IP</div>
  <div style="font-size:28px;margin-bottom:8px">{flag}</div>
  <div><b style="font-size:16px">{user["ip"] or "—"}</b> {proxy_warn}</div>
  <div style="color:var(--muted);margin-top:6px;font-size:13px">{city}, {country}</div>
  <div style="color:var(--muted);font-size:12px;margin-top:4px">ISP: {isp}</div>
  <div style="margin-top:12px;font-size:12px;color:var(--muted);font-family:monospace">HWID: {(user["hwid"] or "")[:32] or "—"}</div>
  <div style="margin-top:16px;display:flex;flex-wrap:wrap;gap:6px">
    <form method="POST" action="/admin/user/{user["username"]}/action" style="display:contents">
      <button name="action" value="reactivate" class="btn btn-green btn-sm">✅ Activer</button>
      <button name="action" value="suspend" class="btn btn-gray btn-sm">⏸ Suspendre</button>
      <button name="action" value="ban" class="btn btn-red btn-sm">🚫 Bannir</button>
      <button name="action" value="reset_hwid" class="btn btn-blue btn-sm">🔄 Reset HWID</button>
      <button name="action" value="reset_password" class="btn btn-gray btn-sm">🔑 Reset MDP</button>
    </form>
    <form method="POST" action="/admin/ips/add" style="display:contents">
      <input type="hidden" name="ip" value="{user["ip"] or ''}">
      <input type="hidden" name="rule" value="blacklist">
      <button type="submit" class="btn btn-red btn-sm">🚫 Ban IP</button>
    </form>
    <form method="POST" action="/admin/ips/add" style="display:contents">
      <input type="hidden" name="ip" value="{user["ip"] or ''}">
      <input type="hidden" name="rule" value="whitelist">
      <button type="submit" class="btn btn-green btn-sm">✅ Whitelist IP</button>
    </form>
  </div>
</div>
</div>
<div class="card">
  <div class="card-title">🖥 Informations système</div>
  <div class="hw-grid">{hw_html}</div>
</div>
<div class="card">
  <div class="card-title">✏️ Modifier</div>
  <form method="POST" action="/admin/user/{user["username"]}/edit" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
    <div class="form-group" style="margin:0"><label>Plan</label>
      <select name="plan">
        <option {'selected' if user["plan"]=="NORMAL" else ''} value="NORMAL">NORMAL</option>
        <option {'selected' if user["plan"]=="PRO" else ''} value="PRO">PRO</option>
        <option {'selected' if user["plan"]=="LIFETIME" else ''} value="LIFETIME">LIFETIME</option>
      </select></div>
    <div class="form-group" style="margin:0"><label>Discord ID</label><input name="discord_id" value="{user["discord_id"] or ''}"></div>
    <div class="form-group" style="margin:0"><label>Note</label><input name="note" value="{user["note"] or ''}"></div>
    <button type="submit" class="btn btn-green">💾 Sauvegarder</button>
  </form>
</div>
{f'<div class="card"><div class="card-title">🛡 Alertes Anti-Leak</div><div class="tbl-wrap"><table><thead><tr><th>Date</th><th>HWID</th><th>Alerte</th></tr></thead><tbody>{alert_rows}</tbody></table></div></div>' if alerts else ''}
<div class="card">
  <div class="card-title">📋 Logs récents</div>
  <div class="tbl-wrap"><table>
    <thead><tr><th>Date</th><th>Niveau</th><th>Type</th><th>Message</th></tr></thead>
    <tbody>{log_rows if log_rows else '<tr><td colspan="4" style="color:var(--muted);text-align:center;padding:20px">Aucun log</td></tr>'}</tbody>
  </table></div>
</div>
<div style="margin-top:8px"><a href="/admin/users" class="btn btn-gray">← Retour</a></div>
"""


# ─── TEMPLATE VARIABLES (render_template_string compat) ───────────────────────
# On remplace les render_template_string par des fonctions Python directes

def _render_tmpl(template_str, **ctx):
    """Mini render: remplace {{ var }} et {% if/for/endif/endfor %} basiques."""
    from flask import render_template_string as rts
    return rts(template_str, **ctx)

# Toutes les pages utilisent _layout() + contenu généré dynamiquement

# Override des routes pour utiliser _layout pur
# (pas de render_template_string pour les pages complexes)

USERS_HTML = None      # handled by route
KEYS_HTML = None       # handled below
KEYS_RESULT_HTML = None
MAINTENANCE_HTML = None
IPS_HTML = None
RESETS_HTML = None
TICKETS_HTML = None
LOGS_HTML = None
BROADCAST_HTML = None
OWNERS_HTML = None
PROFILE_HTML = None
ANTI_LEAK_HTML = None
USER_DETAIL_HTML = None
DASHBOARD_HTML = None


# ─── PAGES RENDER (remplace render_template_string) ───────────────────────────

def _page_users(users, q, plan_f, status_f, admin_user, admin_role):
    return _layout("Utilisateurs", "/admin/users", _users_content(users,q,plan_f,status_f), admin_user, admin_role)

def _page_user_detail(user, logs, alerts, geo, msg, admin_user, admin_role):
    return _layout(f"Utilisateur — {user['username']}", "/admin/users",
                   _user_detail_content(user,logs,alerts,geo,msg), admin_user, admin_role)

def _keys_content(keys):
    rows = ""
    for k in keys:
        if k["status"]=="active": sb='<span class="badge badge-green">active</span>'
        elif k["status"]=="revoked": sb='<span class="badge badge-red">révoquée</span>'
        else: sb=f'<span class="badge badge-gray">{k["status"]}</span>'
        if k["plan"]=="PRO": pb='<span class="badge badge-blue">PRO</span>'
        else: pb='<span class="badge badge-gray">NORMAL</span>'
        used = f'<a href="/admin/user/{k["username"]}"><b>{k["username"]}</b></a>' if k["username"] else '<span style="color:var(--muted)">Disponible</span>'
        key_fmt = f'<span style="font-family:monospace;font-size:12px">{k["key"]}</span>'
        rows += f'<tr><td>{key_fmt}</td><td>{pb}</td><td>{sb}</td><td>{used}</td><td style="color:var(--muted);font-size:11px">{fmt_ts(k["created_at"])}</td><td><form method="POST" action="/admin/keys/revoke"><input type="hidden" name="key" value="{k["key"]}"><button class="btn btn-red btn-sm" type="submit">Révoquer</button></form></td></tr>'
    return f"""
<div class="card">
  <div class="card-title">Générer des clés</div>
  <form method="POST" action="/admin/keys/generate" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
    <div class="form-group" style="margin:0"><label>Plan</label><select name="plan"><option value="NORMAL">NORMAL</option><option value="PRO">PRO</option><option value="LIFETIME">LIFETIME</option></select></div>
    <div class="form-group" style="margin:0"><label>Quantité</label><input name="qty" type="number" value="1" min="1" max="500"></div>
    <div class="form-group" style="margin:0"><label>Note</label><input name="note" placeholder="Discord, batch…"></div>
    <button type="submit" class="btn btn-green">✨ Générer</button>
  </form>
</div>
<div class="card">
  <div class="card-title">Révoquer en masse</div>
  <form method="POST" action="/admin/keys/bulk_revoke" style="display:flex;gap:8px;align-items:flex-end">
    <div style="flex:1"><label style="font-size:13px;font-weight:600;color:var(--muted)">Clés (une par ligne)</label>
    <textarea name="keys" rows="3" placeholder="XXXXX-XXXXX-XXXXX-XXXXX"></textarea></div>
    <button type="submit" class="btn btn-red" style="height:42px">🗑 Révoquer tout</button>
  </form>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Clé</th><th>Plan</th><th>Statut</th><th>Utilisateur</th><th>Créée</th><th></th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--muted)">Aucune clé</td></tr>'}</tbody>
</table></div>"""

def _page_keys(keys, admin_user, admin_role):
    return _layout("Licences", "/admin/keys", _keys_content(keys), admin_user, admin_role)

def _page_keys_result(keys, plan, admin_user, admin_role):
    keys_list = "<br>".join(f'<span style="font-family:monospace;font-size:14px;color:var(--green)">{k}</span>' for k in keys)
    textarea_val = "\n".join(keys)
    content = f"""
<div class="alert alert-green">✅ {len(keys)} clé(s) {plan} générée(s) avec succès !</div>
<div class="card"><div class="card-title">Clés générées</div>
  <div style="margin-bottom:12px">{keys_list}</div>
  <textarea style="font-family:monospace;font-size:13px;background:var(--card2);height:120px">{textarea_val}</textarea>
  <div style="margin-top:12px;display:flex;gap:8px">
    <a href="/admin/keys" class="btn btn-green">→ Voir toutes les clés</a>
    <button onclick="navigator.clipboard.writeText(`{textarea_val.replace('`','')}`)" class="btn btn-gray">📋 Copier</button>
  </div>
</div>"""
    return _layout("Clés générées", "/admin/keys", content, admin_user, admin_role)

def _page_maintenance(maintenance, maint_msg, admin_user, admin_role):
    color = "var(--red)" if maintenance else "var(--green)"
    status_text = "🔴 MAINTENANCE ACTIVE" if maintenance else "🟢 SERVEUR EN LIGNE"
    content = f"""
<div class="card">
  <div style="text-align:center;padding:20px 0">
    <div style="font-size:48px;margin-bottom:12px">{'🔧' if maintenance else '✅'}</div>
    <div style="font-size:22px;font-weight:800;color:{color};margin-bottom:8px">{status_text}</div>
    <div style="color:var(--muted);font-size:14px;margin-bottom:24px">Le logiciel affiche un écran de maintenance quand ce mode est actif</div>
  </div>
  <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:24px">
    <form method="POST" style="display:contents">
      <input type="hidden" name="state" value="{'0' if maintenance else '1'}">
      <button type="submit" class="btn {'btn-green' if maintenance else 'btn-red'}" style="padding:14px 32px;font-size:16px">
        {'✅ Désactiver la maintenance' if maintenance else '🔴 Activer la maintenance'}
      </button>
    </form>
  </div>
</div>
<div class="card">
  <div class="card-title">Message de maintenance</div>
  <form method="POST" style="display:flex;gap:10px;align-items:flex-end">
    <input type="hidden" name="state" value="{'1' if maintenance else '0'}">
    <div style="flex:1"><textarea name="msg_text" rows="2">{maint_msg}</textarea></div>
    <button type="submit" class="btn btn-blue">💾 Sauvegarder</button>
  </form>
  <div style="color:var(--muted);font-size:12px;margin-top:8px">Ce message est affiché dans le logiciel lors de la maintenance</div>
</div>
<div class="card">
  <div class="card-title">ℹ️ Comment ça fonctionne</div>
  <ul style="color:var(--muted);font-size:13px;line-height:1.8;padding-left:16px">
    <li>Le logiciel appelle <code style="color:var(--green)">/api/status</code> au démarrage</li>
    <li>Si maintenance active → écran de maintenance avec le message ci-dessus</li>
    <li>Si serveur hors ligne → écran "Serveur inaccessible" automatique</li>
    <li>Les admins connectés ne voient pas la maintenance dans le panel</li>
  </ul>
</div>"""
    return _layout("Maintenance", "/admin/maintenance", content, admin_user, admin_role)

def _page_ips(rules, vpn_block, prefill, admin_user, admin_role):
    rows = ""
    for r in rules:
        color = "var(--green)" if r["rule"]=="whitelist" else "var(--red)"
        badge = f'<span class="badge {"badge-green" if r["rule"]=="whitelist" else "badge-red"}">{r["rule"]}</span>'
        rows += f'<tr><td style="font-family:monospace;font-weight:700;color:{color}">{r["ip"]}</td><td>{badge}</td><td style="color:var(--muted);font-size:12px">{r["note"] or "—"}</td><td style="color:var(--muted);font-size:11px">{fmt_ts(r["added_at"])}</td><td><form method="POST" action="/admin/ips/delete"><input type="hidden" name="ip" value="{r["ip"]}"><button class="btn btn-red btn-sm" type="submit">Supprimer</button></form></td></tr>'
    content = f"""
<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px">
<div class="card" style="margin:0">
  <div class="card-title">Ajouter une règle IP</div>
  <form method="POST" action="/admin/ips/add">
    <div class="form-group"><label>Adresse IPv4</label><input name="ip" value="{prefill}" placeholder="123.45.67.89" required></div>
    <div class="form-group"><label>Règle</label><select name="rule"><option value="blacklist">🚫 Blacklist</option><option value="whitelist">✅ Whitelist</option></select></div>
    <div class="form-group"><label>Note</label><input name="note" placeholder="ex: farm, suspect..."></div>
    <button type="submit" class="btn btn-green">Ajouter</button>
  </form>
</div>
<div class="card" style="margin:0">
  <div class="card-title">Blocage VPN/Proxy</div>
  <div class="toggle-wrap">
    <label class="toggle"><input type="checkbox" {'checked' if vpn_block else ''} onchange="this.form.submit()">
    <form method="POST" action="/admin/ips/vpn" id="vpnform" style="display:none"></form>
    <span class="toggle-slider"></span></label>
    <div>
      <div style="font-weight:700">Bloquer les VPN & Proxies</div>
      <div style="color:var(--muted);font-size:12px">Détection automatique via ip-api.com</div>
    </div>
  </div>
  <div style="margin-top:16px;color:var(--muted);font-size:13px">
    <b style="color:var(--text)">Whitelist</b> : si au moins 1 IP est en whitelist, seules ces IPs peuvent se connecter.<br>
    <b style="color:var(--text)">Blacklist</b> : ces IPs sont bloquées directement.
  </div>
</div>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>IP</th><th>Règle</th><th>Note</th><th>Ajoutée</th><th></th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">Aucune règle</td></tr>'}</tbody>
</table></div>
<script>document.querySelector('input[type=checkbox]')?.addEventListener('change',()=>document.getElementById('vpnform').submit())</script>"""
    return _layout("IPs / Whitelist", "/admin/ips", content, admin_user, admin_role)

def _page_resets(resets, admin_user, admin_role):
    rows = ""
    for r in resets:
        sb = f'<span class="badge {"badge-yellow" if r["status"]=="pending" else "badge-green" if r["status"]=="approved" else "badge-red"}">{r["status"]}</span>'
        actions = ""
        if r["status"] == "pending":
            actions = f'<form method="POST" action="/admin/resets/{r["id"]}/approve" style="display:inline"><button class="btn btn-green btn-sm" type="submit">✅</button></form> <form method="POST" action="/admin/resets/{r["id"]}/deny" style="display:inline"><button class="btn btn-red btn-sm" type="submit">❌</button></form>'
        rows += f'<tr><td>{r["id"]}</td><td style="font-weight:700">{r["username"] or "—"}</td><td style="font-size:12px;color:var(--muted)">{r["discord_id"] or "—"}</td><td><span class="badge badge-gray">{r["type"]}</span></td><td>{sb}</td><td style="font-family:monospace;font-size:12px;color:var(--green)">{r["temp_pass"] or "—"}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts(r["requested_at"])}</td><td>{actions}</td></tr>'
    content = f"""<div class="tbl-wrap"><table>
    <thead><tr><th>#</th><th>Username</th><th>Discord ID</th><th>Type</th><th>Statut</th><th>MDP temp</th><th>Date</th><th>Actions</th></tr></thead>
    <tbody>{rows if rows else '<tr><td colspan="8" style="text-align:center;padding:24px;color:var(--muted)">Aucune demande</td></tr>'}</tbody>
  </table></div>"""
    return _layout("Demandes de reset", "/admin/resets", content, admin_user, admin_role)

def _page_tickets(tickets, admin_user, admin_role):
    rows = ""
    for t in tickets:
        sb = f'<span class="badge {"badge-yellow" if t["status"]=="open" else "badge-blue" if t["status"]=="answered" else "badge-gray"}">{t["status"]}</span>'
        rows += f"""<tr>
          <td>#{t["id"]}</td><td style="font-weight:700">{t["user"] or "Anonyme"}</td>
          <td style="font-size:13px">{t["subject"][:40]}</td><td>{sb}</td>
          <td style="font-size:11px;color:var(--muted)">{fmt_ts(t["created_at"])}</td>
          <td><button onclick="openTicket({t["id"]},`{t["message"][:200].replace(chr(96),'').replace(chr(39),'').replace(chr(34),'')}`,`{t["response"] or ''}`)" class="btn btn-gray btn-sm">Répondre</button></td>
        </tr>"""
    content = f"""
<div class="tbl-wrap"><table>
  <thead><tr><th>#</th><th>Utilisateur</th><th>Sujet</th><th>Statut</th><th>Date</th><th></th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="6" style="text-align:center;padding:24px;color:var(--muted)">Aucun ticket</td></tr>'}</tbody>
</table></div>
<div id="ticket-modal" style="display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.8);z-index:999;align-items:center;justify-content:center">
  <div style="background:var(--card);border:1px solid var(--border);border-radius:16px;padding:28px;width:90%;max-width:500px">
    <h3 style="margin-bottom:12px">💬 Répondre au ticket</h3>
    <div id="ticket-msg" style="background:var(--card2);border-radius:8px;padding:12px;color:var(--muted);font-size:13px;margin-bottom:14px;max-height:120px;overflow-y:auto"></div>
    <form id="ticket-form" method="POST">
      <textarea name="response" id="ticket-response" rows="3" placeholder="Votre réponse…"></textarea>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
        <button type="submit" name="close" value="0" class="btn btn-blue">📩 Répondre</button>
        <button type="submit" name="close" value="1" class="btn btn-green">✅ Répondre & Fermer</button>
        <button type="button" onclick="closeTicket()" class="btn btn-gray">Annuler</button>
      </div>
    </form>
  </div>
</div>
<script>
function openTicket(id,msg,resp){{
  document.getElementById('ticket-msg').textContent=msg;
  document.getElementById('ticket-response').value=resp||'';
  document.getElementById('ticket-form').action='/admin/tickets/'+id+'/reply';
  var m=document.getElementById('ticket-modal');m.style.display='flex';
}}
function closeTicket(){{document.getElementById('ticket-modal').style.display='none'}}
</script>"""
    return _layout("Tickets Support", "/admin/tickets", content, admin_user, admin_role)

def _page_logs(logs, filter_type, admin_user, admin_role):
    rows = ""
    for l in logs:
        lc = "badge-green" if l["level"]=="OK" else "badge-red" if l["level"]=="ERROR" else "badge-yellow"
        rows += f'<tr><td style="color:var(--muted);font-size:11px;white-space:nowrap">{fmt_ts(l["ts"])}</td><td><span class="badge {lc}">{l["level"]}</span></td><td style="color:var(--muted);font-size:12px">{l["type"]}</td><td style="font-size:12px">{l["msg"]}</td><td style="font-size:12px;color:var(--blue)">{l["user"] or ""}</td></tr>'
    types = ["LOGIN","REGISTER","ANTI-CRACK","ANTI-LEAK","KEYS","ADMIN","RESET","BROADCAST","IP"]
    filter_btns = " ".join(f'<a href="/admin/logs?type={t}" class="btn {"btn-green" if filter_type==t else "btn-gray"} btn-sm">{t}</a>' for t in types)
    content = f"""
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
  <a href="/admin/logs" class="btn {"btn-green" if not filter_type else "btn-gray"} btn-sm">Tous</a>
  {filter_btns}
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Date</th><th>Niveau</th><th>Type</th><th>Message</th><th>User</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">Aucun log</td></tr>'}</tbody>
</table></div>"""
    return _layout("Logs système", "/admin/logs", content, admin_user, admin_role)

def _page_broadcast(msg, admin_user, admin_role):
    content = f"""
{f'<div class="alert alert-green">{msg}</div>' if msg else ''}
<div class="card"><div class="card-title">📢 Envoyer une annonce Discord</div>
<form method="POST">
  <div class="form-group"><label>Cible</label>
    <select name="target"><option value="all">Tous les utilisateurs actifs</option><option value="pro">Plan PRO uniquement</option><option value="normal">Plan NORMAL uniquement</option></select></div>
  <div class="form-group"><label>Message</label><textarea name="message" rows="4" placeholder="Votre message..."></textarea></div>
  <button type="submit" class="btn btn-green">📤 Envoyer</button>
</form></div>"""
    return _layout("Broadcast", "/admin/broadcast", content, admin_user, admin_role)

def _page_owners(admins, admin_user, admin_role):
    rows = ""
    for a in admins:
        rb = f'<span class="badge {"badge-yellow" if a["role"]=="owner" else "badge-blue"}">{a["role"]}</span>'
        del_btn = "" if a["username"]=="xywez" else f'<form method="POST" action="/admin/owners/delete" style="display:inline"><input type="hidden" name="username" value="{a["username"]}"><button class="btn btn-red btn-sm">🗑</button></form>'
        rows += f'<tr><td><b>{a["username"]}</b></td><td>{rb}</td><td style="font-size:11px;color:var(--muted)">{fmt_ts(a["created_at"])}</td><td style="font-size:12px;color:var(--muted)">{a["created_by"] or "système"}</td><td>{del_btn}</td></tr>'
    content = f"""
<div class="card"><div class="card-title">Ajouter un admin</div>
<form method="POST" action="/admin/owners/create" style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:10px;align-items:end">
  <div class="form-group" style="margin:0"><label>Username</label><input name="username" placeholder="username"></div>
  <div class="form-group" style="margin:0"><label>Mot de passe</label><input name="password" type="password"></div>
  <div class="form-group" style="margin:0"><label>Rôle</label><select name="role"><option value="staff">Staff</option><option value="admin">Admin</option><option value="owner">Owner</option></select></div>
  <button type="submit" class="btn btn-green">➕ Créer</button>
</form></div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Username</th><th>Rôle</th><th>Créé le</th><th>Créé par</th><th></th></tr></thead>
  <tbody>{rows}</tbody>
</table></div>"""
    return _layout("Équipe / Admins", "/admin/owners", content, admin_user, admin_role)

def _page_profile(msg, admin_user, admin_role):
    content = f"""
{f'<div class="alert {"alert-green" if "✅" in msg else "alert-red"}">{msg}</div>' if msg else ''}
<div class="card" style="max-width:400px"><div class="card-title">Changer mon mot de passe</div>
<form method="POST">
  <div class="form-group"><label>Ancien MDP</label><input name="old_password" type="password"></div>
  <div class="form-group"><label>Nouveau MDP</label><input name="new_password" type="password" minlength="6"></div>
  <button type="submit" class="btn btn-green">🔐 Changer</button>
</form></div>"""
    return _layout("Mon compte", "/admin/profile", content, admin_user, admin_role)

def _page_anti_leak(alerts, admin_user, admin_role):
    rows = ""
    for a in alerts:
        rows += f'<tr><td style="font-size:11px;color:var(--muted)">{fmt_ts(a["ts"])}</td><td style="font-weight:700;color:var(--blue)"><a href="/admin/user/{a["username"]}">{a["username"]}</a></td><td style="font-family:monospace;font-size:11px">{(a["hwid"] or "")[:24]}…</td><td style="font-size:12px;color:var(--muted)">{a["ip"] or "—"}</td><td style="color:var(--red);font-size:13px">{a["note"]}</td></tr>'
    content = f"""
<div class="card">
  <div class="card-title">Comment ça marche</div>
  <ul style="color:var(--muted);font-size:13px;line-height:2;padding-left:16px">
    <li>Détection HWID partagé entre plusieurs comptes (partage de compte)</li>
    <li>Détection même IP sur +3 comptes différents (farm de comptes)</li>
    <li>HWID mismatch au login → connexion refusée</li>
    <li>Toutes les alertes sont loggées ici en temps réel</li>
  </ul>
</div>
<div class="tbl-wrap"><table>
  <thead><tr><th>Date</th><th>Username</th><th>HWID</th><th>IP</th><th>Alerte</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--muted)">Aucune alerte 🎉</td></tr>'}</tbody>
</table></div>"""
    return _layout("🛡 Anti-Crack / Anti-Leak", "/admin/anti-leak", content, admin_user, admin_role)


# ─── PATCH ROUTES → utiliser les fonctions _page_* ───────────────────────────
# On remplace render_template_string(USERS_HTML,...) etc. par _page_*(...)

# Monkey-patch des fonctions de route déjà définies
import types

_orig_admin_dashboard = admin_dashboard.__wrapped__ if hasattr(admin_dashboard,'__wrapped__') else None

# On réécrit les fonctions de route directement
@app.route("/admin", endpoint="admin_dashboard_v3")
@admin_required
def admin_dashboard_v3():
    conn = get_db()
    today = int(time.time()) - 86400; week = int(time.time()) - 604800
    stats = {
        "total":        conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":       conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0],
        "banned":       conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0],
        "pro":          conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0],
        "total_lic":    conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "active_lic":   conn.execute("SELECT COUNT(*) FROM licenses WHERE status='active'").fetchone()[0],
        "pending_reset":conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0],
        "open_tickets": conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0],
        "today_logins": conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0],
        "week_logins":  conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (week,)).fetchone()[0],
        "new_today":    conn.execute("SELECT COUNT(*) FROM users WHERE created_at>?", (today,)).fetchone()[0],
        "hwid_alerts":  conn.execute("SELECT COUNT(*) FROM hwid_alerts WHERE ts>?", (today,)).fetchone()[0],
        "maintenance":  get_setting("maintenance") == "1",
    }
    hourly = []
    for i in range(24):
        ts = int(time.time()) - (i+1)*3600; te = int(time.time()) - i*3600
        hourly.append(conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (ts,te)).fetchone()[0])
    hourly.reverse()
    stats["hourly"] = hourly
    recent = conn.execute("SELECT username,plan,status,last_login,ip,connections,os_info,cpu_info,gpu_info FROM users ORDER BY last_login DESC LIMIT 8").fetchall()
    conn.close()
    return DASHBOARD_HTML_render(stats, recent, session["admin_user"], session["admin_role"])

# Supprimer les anciennes routes et les remplacer
# Flask n'aime pas les doublons, on utilise des endpoints différents dans les routes déjà enregistrées
# Donc on utilise app.view_functions pour remplacer

app.view_functions["admin_dashboard"] = admin_dashboard_v3
app.view_functions["admin_users"] = lambda: (lambda q=request.args.get("q",""), plan_f=request.args.get("plan",""), status_f=request.args.get("status",""): (lambda: (lambda conn=get_db(): (lambda rows=conn.execute("SELECT * FROM users WHERE 1=1" + (" AND (username LIKE ? OR discord_id LIKE ? OR ip LIKE ? OR license_key LIKE ?)" if q else "") + (" AND plan=?" if plan_f else "") + (" AND status=?" if status_f else "") + " ORDER BY last_login DESC LIMIT 150", [f"%{q}%"]*4+([plan_f] if plan_f else [])+([status_f] if status_f else [])).fetchall(): (conn.close(), _page_users(rows, q, plan_f, status_f, session["admin_user"], session["admin_role"]))[1])())())())()

# Plus simple : on réécrit proprement
def _vu():
    q = request.args.get("q",""); plan_f = request.args.get("plan",""); status_f = request.args.get("status","")
    conn = get_db()
    sql = "SELECT * FROM users WHERE 1=1"; params = []
    if q: sql += " AND (username LIKE ? OR discord_id LIKE ? OR ip LIKE ? OR license_key LIKE ?)"; params += [f"%{q}%"]*4
    if plan_f: sql += " AND plan=?"; params.append(plan_f)
    if status_f: sql += " AND status=?"; params.append(status_f)
    sql += " ORDER BY last_login DESC LIMIT 150"
    rows = conn.execute(sql, params).fetchall(); conn.close()
    return _page_users(rows, q, plan_f, status_f, session["admin_user"], session["admin_role"])

app.view_functions["admin_users"] = admin_required(_vu)

def _vud(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user: conn.close(); return "Introuvable", 404
    logs = conn.execute("SELECT * FROM logs WHERE user=? ORDER BY ts DESC LIMIT 50", (username,)).fetchall()
    alerts = conn.execute("SELECT * FROM hwid_alerts WHERE username=? ORDER BY ts DESC LIMIT 10", (username,)).fetchall()
    conn.close()
    geo = get_geoip(user["ip"]) if user["ip"] else {}
    msg = request.args.get("msg","")
    return _page_user_detail(user, logs, alerts, geo, msg, session["admin_user"], session["admin_role"])

app.view_functions["admin_user_detail"] = admin_required(_vud)

def _vk():
    conn = get_db()
    keys = conn.execute("SELECT l.*,u.username FROM licenses l LEFT JOIN users u ON l.key=u.license_key ORDER BY l.created_at DESC LIMIT 200").fetchall()
    conn.close(); return _page_keys(keys, session["admin_user"], session["admin_role"])

app.view_functions["admin_keys"] = admin_required(_vk)

def _vkgen():
    plan = request.form.get("plan","NORMAL"); qty = min(int(request.form.get("qty",1)),500)
    note = request.form.get("note",""); conn = get_db(); generated = []
    for _ in range(qty):
        key = generate_key(plan)
        conn.execute("INSERT OR IGNORE INTO licenses (key,plan,status,created_at,note) VALUES (?,?,?,?,?)", (key,plan,"active",int(time.time()),note))
        generated.append(key)
    conn.commit(); conn.close()
    add_log("OK","KEYS",f"{qty} clé(s) {plan}", session["admin_user"])
    return _page_keys_result(generated, plan, session["admin_user"], session["admin_role"])

app.view_functions["admin_gen_keys"] = admin_required(_vkgen)

def _vmaint():
    if request.method == "POST":
        set_setting("maintenance", request.form.get("state","0"))
        if request.form.get("msg_text",""):
            set_setting("maintenance_msg", request.form.get("msg_text"))
        add_log("OK","ADMIN",f"Maintenance: {'ON' if request.form.get('state')=='1' else 'OFF'}", session["admin_user"])
        return redirect("/admin/maintenance")
    return _page_maintenance(get_setting("maintenance")=="1", get_setting("maintenance_msg"), session["admin_user"], session["admin_role"])

app.view_functions["admin_maintenance"] = admin_required(_vmaint)

def _vips():
    conn = get_db(); rules = conn.execute("SELECT * FROM ip_rules ORDER BY added_at DESC").fetchall(); conn.close()
    return _page_ips(rules, get_setting("vpn_block")=="1", request.args.get("prefill",""), session["admin_user"], session["admin_role"])

app.view_functions["admin_ips"] = admin_required(_vips)

def _vresets():
    conn = get_db(); rows = conn.execute("SELECT * FROM reset_requests ORDER BY requested_at DESC LIMIT 100").fetchall(); conn.close()
    return _page_resets(rows, session["admin_user"], session["admin_role"])

app.view_functions["admin_resets"] = admin_required(_vresets)

def _vtickets():
    conn = get_db(); rows = conn.execute("SELECT * FROM tickets ORDER BY created_at DESC LIMIT 100").fetchall(); conn.close()
    return _page_tickets(rows, session["admin_user"], session["admin_role"])

app.view_functions["admin_tickets"] = admin_required(_vtickets)

def _vlogs():
    ft = request.args.get("type",""); conn = get_db()
    rows = conn.execute("SELECT * FROM logs WHERE type=? ORDER BY ts DESC LIMIT 500" if ft else "SELECT * FROM logs ORDER BY ts DESC LIMIT 500", (ft,) if ft else ()).fetchall()
    conn.close(); return _page_logs(rows, ft, session["admin_user"], session["admin_role"])

app.view_functions["admin_logs"] = admin_required(_vlogs)

def _vbroadcast():
    msg_sent = ""
    if request.method == "POST":
        message = request.form.get("message","").strip(); target = request.form.get("target","all")
        conn = get_db()
        q = {"all":"SELECT discord_id FROM users WHERE status='active' AND discord_id IS NOT NULL AND discord_id!=''","pro":"SELECT discord_id FROM users WHERE plan='PRO' AND discord_id IS NOT NULL AND discord_id!=''","normal":"SELECT discord_id FROM users WHERE plan='NORMAL' AND status='active' AND discord_id IS NOT NULL AND discord_id!=''"}.get(target,"")
        users = conn.execute(q).fetchall() if q else []; conn.close()
        for u in users: _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer**\n{message}")
        msg_sent = f"✅ Envoyé à {len(users)} utilisateur(s)."; add_log("OK","BROADCAST",f"{target}: {message[:60]}", session["admin_user"])
    return _page_broadcast(msg_sent, session["admin_user"], session["admin_role"])

app.view_functions["admin_broadcast"] = admin_required(_vbroadcast)

def _vowners():
    if session.get("admin_role") != "owner": return redirect("/admin")
    conn = get_db(); rows = conn.execute("SELECT * FROM admins ORDER BY created_at").fetchall(); conn.close()
    return _page_owners(rows, session["admin_user"], session["admin_role"])

app.view_functions["admin_owners"] = admin_required(_vowners)

def _vprofile():
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

app.view_functions["admin_profile"] = admin_required(_vprofile)

def _vantileak():
    conn = get_db(); alerts = conn.execute("SELECT * FROM hwid_alerts ORDER BY ts DESC LIMIT 100").fetchall(); conn.close()
    return _page_anti_leak(alerts, session["admin_user"], session["admin_role"])

app.view_functions["admin_anti_leak"] = admin_required(_vantileak)

# ─── ROUTES INTERNES SUPPLÉMENTAIRES (bot v3) ────────────────────────────────

@app.route("/api/internal/user_action", methods=["POST"])
def internal_user_action():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    username = data.get("username","").lower(); action = data.get("action","")
    conn = get_db()
    if action == "ban":
        conn.execute("UPDATE users SET status='banned' WHERE username=?", (username,))
        add_log("WARN","BOT",f"Ban: {username}")
    elif action == "reactivate":
        conn.execute("UPDATE users SET status='active' WHERE username=?", (username,))
        add_log("OK","BOT",f"Réactivé: {username}")
    elif action == "suspend":
        conn.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
        add_log("WARN","BOT",f"Suspendu: {username}")
    elif action == "reset_hwid":
        conn.execute("UPDATE users SET hwid='' WHERE username=?", (username,))
        add_log("OK","BOT",f"HWID reset: {username}")
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
    add_log("WARN","BOT",f"Clé révoquée: {key[:11]}…")
    return jsonify({"success": True})

@app.route("/api/internal/add_ip_rule", methods=["POST"])
def internal_add_ip_rule():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    ip = data.get("ip","").strip(); rule = data.get("rule","blacklist"); note = data.get("note","")
    if not _is_ipv4(ip): return jsonify({"error":"IPv4 invalide"}), 400
    conn = get_db(); conn.execute("INSERT OR REPLACE INTO ip_rules VALUES (?,?,?,?)", (ip,rule,note,int(time.time()))); conn.commit(); conn.close()
    add_log("OK","BOT",f"IP {rule}: {ip}")
    return jsonify({"success": True})

@app.route("/api/internal/broadcast", methods=["POST"])
def internal_broadcast():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    message = data.get("message",""); target = data.get("target","all")
    conn = get_db()
    q = {"all":"SELECT discord_id FROM users WHERE status='active' AND discord_id IS NOT NULL AND discord_id!=''",
         "pro":"SELECT discord_id FROM users WHERE plan='PRO' AND discord_id IS NOT NULL AND discord_id!=''",
         "normal":"SELECT discord_id FROM users WHERE plan='NORMAL' AND status='active' AND discord_id IS NOT NULL AND discord_id!=''"}.get(target,"")
    users = conn.execute(q).fetchall() if q else []; conn.close()
    count = 0
    for u in users:
        _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer**\n{message}"); count += 1
    add_log("OK","BROADCAST",f"Bot broadcast {target}: {message[:40]}")
    return jsonify({"success": True, "count": count})

@app.route("/api/internal/set_maintenance", methods=["POST"])
def internal_set_maintenance():
    data = request.get_json(silent=True) or {}
    if not _check_bot_token(data): return jsonify({"error":"Non autorisé"}), 403
    state = data.get("state","0")
    set_setting("maintenance", state)
    add_log("OK","BOT",f"Maintenance: {'ON' if state=='1' else 'OFF'}")
    return jsonify({"success": True, "maintenance": state=="1"})


# ─── DÉMARRAGE ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*54)
    print("  ⚡ WINOPTIMIZER LICENSE SERVER v3.0")
    print("="*54)
    print(f"  Port     : {port}")
    print(f"  Admin    : {DEFAULT_ADMIN['username']} / {DEFAULT_ADMIN['password']}")
    print(f"  Panel    : http://localhost:{port}/admin")
    print(f"  DB       : {DB_PATH}")
    print("="*54)
    app.run(host="0.0.0.0", port=port, debug=False)

