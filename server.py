"""
server.py — WinOptimizer Pro — Serveur de licences & comptes
Lancer : python server.py
Panel admin : http://localhost:5000/admin
API         : http://localhost:5000/api/...

CORRECTIONS v2.1 :
  - Vraie IP via X-Forwarded-For / X-Real-IP (proxy/Nginx)
  - GeoIP via ip-api.com (gratuit, sans clé)
  - Maintenance bypass pour les admins connectés
  - Page maintenance propre côté client
"""

from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import hmac, hashlib, json, time, os, sqlite3, secrets, string, random
import re, urllib.request
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
MASTER_SECRET    = b"WinOptPro_S3cr3t_K3y_2025_!#@$_CHANGE_ME"
DB_PATH          = "licenses.db"
OWNER_ID         = "969065205067825222"
DISCORD_BOT_URL  = "http://localhost:8080"

DEFAULT_ADMIN = {"username": "xywez", "password": "Admin2025!", "role": "owner"}

# ─── HELPER : VRAIE IP ────────────────────────────────────────────────────────
def get_real_ip():
    """
    Récupère la vraie IP du client même derrière un proxy/Nginx.
    Ordre de priorité : X-Real-IP > X-Forwarded-For > remote_addr
    """
    # X-Real-IP (Nginx)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    # X-Forwarded-For (proxies/CDN) — on prend la 1ère IP (l'originale)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr

# ─── HELPER : GEOIP ───────────────────────────────────────────────────────────
_geoip_cache = {}   # {ip: {"country":…, "city":…, "ts": timestamp}}
GEOIP_TTL = 3600    # 1h de cache

def get_geoip(ip: str) -> dict:
    """
    Retourne {"country": "FR", "city": "Paris", "flag": "🇫🇷", "isp": "…"}
    Utilise ip-api.com (gratuit, 1000 req/min, sans clé).
    Résultats mis en cache 1h.
    """
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return {"country": "Local", "city": "Localhost", "flag": "🖥", "isp": "Local"}

    now = time.time()
    if ip in _geoip_cache and now - _geoip_cache[ip]["ts"] < GEOIP_TTL:
        return _geoip_cache[ip]

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp"
        with urllib.request.urlopen(url, timeout=3) as r:
            data = json.loads(r.read().decode())
        if data.get("status") == "success":
            # Générer le drapeau emoji depuis le code pays
            cc = data.get("countryCode", "")
            flag = "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper()) if len(cc) == 2 else "🌐"
            result = {
                "country": data.get("country", "?"),
                "city":    data.get("city", "?"),
                "flag":    flag,
                "isp":     data.get("isp", "?"),
                "ts":      now,
            }
        else:
            result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "ts": now}
    except Exception:
        result = {"country": "?", "city": "?", "flag": "🌐", "isp": "?", "ts": now}

    _geoip_cache[ip] = result
    return result


# ═══ BASE DE DONNÉES ══════════════════════════════════════════════════════════
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses (
        key         TEXT PRIMARY KEY,
        plan        TEXT DEFAULT 'NORMAL',
        status      TEXT DEFAULT 'active',
        created_at  INTEGER,
        note        TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT UNIQUE NOT NULL,
        password_hash   TEXT NOT NULL,
        license_key     TEXT,
        plan            TEXT DEFAULT 'NORMAL',
        discord_id      TEXT,
        discord_tag     TEXT,
        hwid            TEXT,
        ip              TEXT,
        status          TEXT DEFAULT 'active',
        created_at      INTEGER,
        last_login      INTEGER,
        connections     INTEGER DEFAULT 0,
        first_login_done INTEGER DEFAULT 0,
        must_change_pass INTEGER DEFAULT 0,
        temp_password   TEXT,
        note            TEXT,
        FOREIGN KEY (license_key) REFERENCES licenses(key)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS admins (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role        TEXT DEFAULT 'staff',
        created_at  INTEGER,
        created_by  TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id      INTEGER PRIMARY KEY AUTOINCREMENT,
        ts      INTEGER,
        level   TEXT,
        type    TEXT,
        msg     TEXT,
        user    TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS ip_rules (
        ip      TEXT PRIMARY KEY,
        rule    TEXT,
        note    TEXT,
        added_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS tickets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user        TEXT,
        discord_id  TEXT,
        subject     TEXT,
        message     TEXT,
        status      TEXT DEFAULT 'open',
        response    TEXT,
        created_at  INTEGER,
        updated_at  INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS reset_requests (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT,
        discord_id  TEXT,
        type        TEXT,
        status      TEXT DEFAULT 'pending',
        temp_pass   TEXT,
        requested_at INTEGER,
        resolved_at  INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS settings (
        key     TEXT PRIMARY KEY,
        value   TEXT
    )""")
    conn.commit()
    admin_exists = conn.execute("SELECT 1 FROM admins WHERE username=?", (DEFAULT_ADMIN["username"],)).fetchone()
    if not admin_exists:
        ph = _hash_password(DEFAULT_ADMIN["password"])
        conn.execute("INSERT INTO admins (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                     (DEFAULT_ADMIN["username"], ph, DEFAULT_ADMIN["role"], int(time.time())))
        conn.commit()
    conn.execute("INSERT OR IGNORE INTO settings VALUES ('maintenance','0')")
    conn.execute("INSERT OR IGNORE INTO settings VALUES ('vpn_block','0')")
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def add_log(level, type_, msg, user=""):
    conn = get_db()
    conn.execute("INSERT INTO logs (ts,level,type,msg,user) VALUES (?,?,?,?,?)",
                 (int(time.time()), level, type_, msg, user))
    conn.commit()
    conn.close()


def _hash_password(pwd: str) -> str:
    return hashlib.sha256((pwd + "WinOpt_SALT_2025").encode()).hexdigest()


def _gen_temp_password(length=10) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))


def get_setting(key, default="0"):
    conn = get_db()
    row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    conn.close()
    return row["value"] if row else default


def set_setting(key, value):
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (key, value))
    conn.commit()
    conn.close()


# ═══ GÉNÉRATION DE CLÉ ════════════════════════════════════════════════════════
def generate_key(plan="NORMAL"):
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    license_id = "".join(random.choices(chars, k=12))
    sig = hmac.new(MASTER_SECRET, license_id.encode(), hashlib.sha256).hexdigest()[:8].upper()
    combined = (license_id + sig)[:20]
    return "-".join([combined[i:i+5] for i in range(0, 20, 5)])


# ═══ AUTH ADMIN ═══════════════════════════════════════════════════════════════
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged"):
            return redirect("/admin/login")
        return f(*args, **kwargs)
    return decorated


def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged"):
            return redirect("/admin/login")
        if session.get("admin_role") != "owner":
            return jsonify({"error": "Owner requis"}), 403
        return f(*args, **kwargs)
    return decorated


# ═══ PAGE MAINTENANCE (affichée aux clients, PAS aux admins) ══════════════════
MAINTENANCE_PAGE = """<!DOCTYPE html>
<html><head><title>WinOptimizer — Maintenance</title>
<meta charset="utf-8">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#040810;color:#c8e0ff;font-family:'Courier New',monospace;
     display:flex;align-items:center;justify-content:center;height:100vh}
.box{text-align:center;padding:40px;background:#080f1e;border:1px solid #0d2040;
     border-radius:8px;max-width:500px}
.icon{font-size:64px;margin-bottom:20px}
h1{color:#ffb800;font-size:22px;margin-bottom:10px}
p{color:#4a7aaa;font-size:13px;line-height:1.6;margin-bottom:6px}
.badge{display:inline-block;padding:4px 12px;background:#2a1a00;border:1px solid #ffb80033;
       color:#ffb800;border-radius:4px;font-size:11px;margin-top:16px}
</style>
</head><body>
<div class="box">
  <div class="icon">⚙️</div>
  <h1>Maintenance en cours</h1>
  <p>Le serveur WinOptimizer Pro est actuellement en maintenance.</p>
  <p>Tes données sont en sécurité. Reviens dans quelques minutes.</p>
  <div class="badge">⏳ Retour imminent</div>
</div>
</body></html>
"""


# ═══ API — INSCRIPTION ════════════════════════════════════════════════════════
@app.route("/api/register", methods=["POST"])
def api_register():
    if get_setting("maintenance") == "1":
        return jsonify({"success": False, "reason": "Serveur en maintenance. Revenez plus tard."})

    data = request.get_json(silent=True) or {}
    username    = data.get("username", "").strip().lower()
    password    = data.get("password", "").strip()
    license_key = data.get("license_key", "").strip().upper()
    discord_id  = data.get("discord_id", "").strip()
    ip          = get_real_ip()   # ← CORRIGÉ

    if not username or not password or not license_key:
        return jsonify({"success": False, "reason": "Champs manquants"})
    if len(username) < 3 or len(username) > 20:
        return jsonify({"success": False, "reason": "Username: 3 à 20 caractères"})
    if not re.match(r'^[a-z0-9_]+$', username):
        return jsonify({"success": False, "reason": "Username: lettres, chiffres, underscore uniquement"})
    if len(password) < 6:
        return jsonify({"success": False, "reason": "Mot de passe: 6 caractères minimum"})

    conn = get_db()
    ip_rule = conn.execute("SELECT rule FROM ip_rules WHERE ip=?", (ip,)).fetchone()
    if ip_rule and ip_rule["rule"] == "blacklist":
        conn.close()
        return jsonify({"success": False, "reason": "Accès refusé"})

    existing = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"success": False, "reason": "Ce nom d'utilisateur est déjà pris"})

    if not re.match(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$', license_key):
        conn.close()
        return jsonify({"success": False, "reason": "Format de clé invalide"})

    raw = license_key.replace("-", "")
    lic_id = raw[:12]
    sig_given = raw[12:20]
    sig_expected = hmac.new(MASTER_SECRET, lic_id.encode(), hashlib.sha256).hexdigest()[:8].upper()
    if not hmac.compare_digest(sig_given, sig_expected):
        conn.close()
        return jsonify({"success": False, "reason": "Clé de licence invalide ou falsifiée"})

    lic_row = conn.execute("SELECT * FROM licenses WHERE key=?", (license_key,)).fetchone()
    if not lic_row:
        conn.close()
        return jsonify({"success": False, "reason": "Clé non trouvée. Contactez le support."})
    if lic_row["status"] != "active":
        conn.close()
        return jsonify({"success": False, "reason": f"Clé {lic_row['status']}. Contactez le support."})

    already_used = conn.execute("SELECT username FROM users WHERE license_key=?", (license_key,)).fetchone()
    if already_used:
        conn.close()
        return jsonify({"success": False, "reason": "Cette clé est déjà associée à un compte"})

    ph = _hash_password(password)
    plan = lic_row["plan"]
    conn.execute("""INSERT INTO users
        (username, password_hash, license_key, plan, discord_id, ip, status, created_at, first_login_done)
        VALUES (?,?,?,?,?,?,?,?,?)""",
        (username, ph, license_key, plan, discord_id, ip, "active", int(time.time()), 0))
    conn.commit()
    conn.close()

    add_log("OK", "REGISTER", f"Nouveau compte: {username} plan={plan} IP={ip}", username)
    return jsonify({"success": True, "plan": plan, "username": username})


# ═══ API — CONNEXION ══════════════════════════════════════════════════════════
@app.route("/api/login", methods=["POST"])
def api_login():
    if get_setting("maintenance") == "1":
        return jsonify({"success": False, "reason": "Serveur en maintenance."})

    data = request.get_json(silent=True) or {}
    username    = data.get("username", "").strip().lower()
    password    = data.get("password", "").strip()
    machine_id  = data.get("machine_id", "").strip()
    ip          = get_real_ip()   # ← CORRIGÉ

    if not username or not password:
        return jsonify({"success": False, "reason": "Champs manquants"})

    conn = get_db()
    ip_rule = conn.execute("SELECT rule FROM ip_rules WHERE ip=?", (ip,)).fetchone()
    if ip_rule and ip_rule["rule"] == "blacklist":
        conn.close()
        return jsonify({"success": False, "reason": "Accès refusé depuis cette adresse IP"})

    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        add_log("WARN", "LOGIN", f"Tentative compte inconnu: {username} IP={ip}")
        return jsonify({"success": False, "reason": "Identifiants incorrects"})

    if row["status"] == "banned":
        conn.close()
        return jsonify({"success": False, "reason": "Votre compte a été suspendu. Contactez le support."})
    if row["status"] == "suspended":
        conn.close()
        return jsonify({"success": False, "reason": "Votre compte est suspendu temporairement."})

    ph = _hash_password(password)
    must_change = False

    if ph == row["password_hash"]:
        pass
    elif row["must_change_pass"] and row["temp_password"] and password == row["temp_password"]:
        must_change = True
    else:
        conn.close()
        add_log("WARN", "LOGIN", f"Mauvais MDP: {username} IP={ip}")
        return jsonify({"success": False, "reason": "Identifiants incorrects"})

    if row["hwid"] and machine_id and row["hwid"] != machine_id:
        conn.close()
        add_log("WARN", "LOGIN", f"HWID mismatch: {username}")
        return jsonify({"success": False, "reason": "Ce compte est lié à une autre machine. Contactez le support."})

    if not row["hwid"] and machine_id:
        conn.execute("UPDATE users SET hwid=? WHERE username=?", (machine_id, username))

    first_login = row["first_login_done"] == 0

    conn.execute("""UPDATE users SET
        connections=connections+1,
        last_login=?,
        ip=?,
        first_login_done=1
        WHERE username=?""", (int(time.time()), ip, username))
    conn.commit()
    conn.close()

    add_log("OK", "LOGIN", f"Connexion: {username} plan={row['plan']} IP={ip}", username)

    return jsonify({
        "success": True,
        "username": username,
        "plan": row["plan"],
        "discord_id": row["discord_id"] or "",
        "first_login": first_login,
        "must_change_pass": must_change,
        "license_key": row["license_key"]
    })


# ═══ API — CHANGEMENT MDP ═════════════════════════════════════════════════════
@app.route("/api/change_password", methods=["POST"])
def api_change_password():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip().lower()
    old_pass = data.get("old_password", "").strip()
    new_pass = data.get("new_password", "").strip()

    if len(new_pass) < 6:
        return jsonify({"success": False, "reason": "Nouveau mot de passe trop court (6 min)"})

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"success": False, "reason": "Utilisateur inconnu"})

    ph_old = _hash_password(old_pass)
    valid = (ph_old == row["password_hash"]) or (row["temp_password"] and old_pass == row["temp_password"])
    if not valid:
        conn.close()
        return jsonify({"success": False, "reason": "Ancien mot de passe incorrect"})

    ph_new = _hash_password(new_pass)
    conn.execute("UPDATE users SET password_hash=?, must_change_pass=0, temp_password=NULL WHERE username=?",
                 (ph_new, username))
    conn.commit()
    conn.close()
    add_log("OK", "ACCOUNT", f"MDP changé: {username}", username)
    return jsonify({"success": True})


# ═══ API — DEMANDE RESET MDP ══════════════════════════════════════════════════
@app.route("/api/request_reset", methods=["POST"])
def api_request_reset():
    data = request.get_json(silent=True) or {}
    req_type   = data.get("type", "password")
    username   = data.get("username", "").strip().lower()
    discord_id = data.get("discord_id", "").strip()

    if not discord_id:
        return jsonify({"success": False, "reason": "Discord ID requis pour le reset"})

    conn = get_db()
    if req_type == "password":
        if not username:
            conn.close()
            return jsonify({"success": False, "reason": "Username requis"})
        row = conn.execute("SELECT 1 FROM users WHERE username=? AND discord_id=?",
                           (username, discord_id)).fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "reason": "Compte introuvable ou Discord non correspondant"})
    elif req_type == "username":
        row = conn.execute("SELECT username FROM users WHERE discord_id=?", (discord_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"success": False, "reason": "Aucun compte lié à ce Discord"})
        username = row["username"]

    pending = conn.execute(
        "SELECT 1 FROM reset_requests WHERE username=? AND status='pending' AND type=?",
        (username, req_type)).fetchone()
    if pending:
        conn.close()
        return jsonify({"success": False, "reason": "Une demande est déjà en attente d'approbation"})

    conn.execute("""INSERT INTO reset_requests
        (username, discord_id, type, status, requested_at)
        VALUES (?,?,?,?,?)""",
        (username, discord_id, req_type, "pending", int(time.time())))
    conn.commit()
    conn.close()

    add_log("OK", "RESET", f"Demande reset {req_type}: {username} Discord={discord_id}")
    return jsonify({"success": True, "message": "Demande envoyée. Un admin va l'examiner."})


# ═══ API — VÉRIFICATION ══════════════════════════════════════════════════════
@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip().lower()
    machine_id = data.get("machine_id", "")
    ip         = get_real_ip()   # ← CORRIGÉ

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not row or row["status"] != "active":
        conn.close()
        return jsonify({"valid": False})

    if row["hwid"] and machine_id and row["hwid"] != machine_id:
        conn.close()
        return jsonify({"valid": False, "reason": "HWID mismatch"})

    conn.execute("UPDATE users SET last_login=?, ip=?, connections=connections+1 WHERE username=?",
                 (int(time.time()), ip, username))
    conn.commit()
    conn.close()
    return jsonify({"valid": True, "plan": row["plan"], "username": username})


# ═══════════════════════════════════════════════════════════════════════════════
#  PANEL ADMIN — ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        ph = _hash_password(p)
        conn = get_db()
        row = conn.execute("SELECT * FROM admins WHERE username=?", (u,)).fetchone()
        conn.close()
        if row and row["password_hash"] == ph:
            session["admin_logged"] = True
            session["admin_user"]   = row["username"]
            session["admin_role"]   = row["role"]
            add_log("OK", "ADMIN", f"Connexion admin: {u}")
            return redirect("/admin")
        else:
            error = "Identifiants incorrects"
    return render_template_string(ADMIN_LOGIN_HTML, error=error)


@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect("/admin/login")


# ── MAINTENANCE : bypass si admin connecté ─────────────────────────────────
def check_maintenance():
    """
    Retourne True si la maintenance est active ET que l'utilisateur n'est pas admin.
    Les admins connectés voient toujours le panel normalement.
    """
    return get_setting("maintenance") == "1" and not session.get("admin_logged")


@app.route("/admin")
@admin_required
def admin_dashboard():
    # Maintenance n'affecte pas le panel admin
    conn = get_db()
    total_users   = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users  = conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    banned_users  = conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0]
    pro_users     = conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0]
    total_lic     = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    active_keys   = conn.execute("SELECT COUNT(*) FROM licenses WHERE status='active'").fetchone()[0]
    pending_resets = conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0]
    open_tickets  = conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
    today         = int(time.time()) - 86400
    week          = int(time.time()) - 604800
    today_logins  = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0]
    week_logins   = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (week,)).fetchone()[0]
    new_today     = conn.execute("SELECT COUNT(*) FROM users WHERE created_at>?", (today,)).fetchone()[0]
    maintenance   = get_setting("maintenance") == "1"
    hourly = []
    for i in range(24):
        t_start = int(time.time()) - (i+1)*3600
        t_end   = int(time.time()) - i*3600
        c = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (t_start, t_end)).fetchone()[0]
        hourly.append(c)
    hourly.reverse()
    conn.close()
    stats = {
        "total_users": total_users, "active_users": active_users,
        "banned_users": banned_users, "pro_users": pro_users,
        "total_lic": total_lic, "active_keys": active_keys,
        "pending_resets": pending_resets, "open_tickets": open_tickets,
        "today_logins": today_logins, "week_logins": week_logins,
        "new_today": new_today, "maintenance": maintenance,
        "hourly_logins": hourly,
    }
    return render_template_string(ADMIN_DASHBOARD_HTML, stats=stats,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/users")
@admin_required
def admin_users():
    search = request.args.get("q", "")
    conn = get_db()
    if search:
        rows = conn.execute(
            "SELECT * FROM users WHERE username LIKE ? OR discord_id LIKE ? OR ip LIKE ? ORDER BY created_at DESC LIMIT 100",
            (f"%{search}%", f"%{search}%", f"%{search}%")
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return render_template_string(ADMIN_USERS_HTML, users=rows, search=search,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/user/<username>")
@admin_required
def admin_user_detail(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        conn.close()
        return "Utilisateur introuvable", 404
    logs = conn.execute("SELECT * FROM logs WHERE user=? ORDER BY ts DESC LIMIT 50", (username,)).fetchall()
    conn.close()

    # GeoIP de l'utilisateur
    geo = get_geoip(user["ip"]) if user["ip"] else {}

    return render_template_string(ADMIN_USER_DETAIL_HTML, user=user, logs=logs, geo=geo,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/user/<username>/action", methods=["POST"])
@admin_required
def admin_user_action(username):
    action = request.form.get("action")
    conn = get_db()
    if action == "suspend":
        conn.execute("UPDATE users SET status='suspended' WHERE username=?", (username,))
        add_log("WARN", "ADMIN", f"Compte suspendu: {username}", session["admin_user"])
    elif action == "ban":
        conn.execute("UPDATE users SET status='banned' WHERE username=?", (username,))
        add_log("WARN", "ADMIN", f"Compte banni: {username}", session["admin_user"])
    elif action == "reactivate":
        conn.execute("UPDATE users SET status='active' WHERE username=?", (username,))
        add_log("OK", "ADMIN", f"Compte réactivé: {username}", session["admin_user"])
    elif action == "reset_hwid":
        conn.execute("UPDATE users SET hwid='' WHERE username=?", (username,))
        add_log("OK", "ADMIN", f"HWID reset: {username}", session["admin_user"])
    elif action == "reset_password":
        temp = _gen_temp_password()
        ph = _hash_password(temp)
        conn.execute("UPDATE users SET password_hash=?, must_change_pass=1, temp_password=? WHERE username=?",
                     (ph, temp, username))
        conn.commit()
        conn.close()
        add_log("OK", "ADMIN", f"MDP reset: {username}", session["admin_user"])
        user_row = get_db().execute("SELECT discord_id FROM users WHERE username=?", (username,)).fetchone()
        if user_row and user_row["discord_id"]:
            _notify_discord(user_row["discord_id"],
                f"🔑 **Mot de passe réinitialisé**\nTon nouveau mot de passe temporaire est: `{temp}`\nChange-le à ta prochaine connexion!")
        return redirect(f"/admin/user/{username}?msg=MDP+temporaire+envoyé:+{temp}")
    conn.commit()
    conn.close()
    return redirect(f"/admin/user/{username}")


@app.route("/admin/keys")
@admin_required
def admin_keys():
    conn = get_db()
    keys = conn.execute("SELECT l.*, u.username FROM licenses l LEFT JOIN users u ON l.key=u.license_key ORDER BY l.created_at DESC LIMIT 200").fetchall()
    conn.close()
    return render_template_string(ADMIN_KEYS_HTML, keys=keys,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/keys/generate", methods=["POST"])
@admin_required
def admin_gen_keys():
    plan = request.form.get("plan", "NORMAL")
    qty  = min(int(request.form.get("qty", 1)), 500)
    note = request.form.get("note", "")
    conn = get_db()
    generated = []
    for _ in range(qty):
        key = generate_key(plan)
        conn.execute("INSERT OR IGNORE INTO licenses (key, plan, status, created_at, note) VALUES (?,?,?,?,?)",
                     (key, plan, "active", int(time.time()), note))
        generated.append(key)
    conn.commit()
    conn.close()
    add_log("OK", "KEYS", f"{qty} clé(s) {plan} générée(s)", session["admin_user"])
    return render_template_string(ADMIN_KEYS_GEN_RESULT_HTML, keys=generated, plan=plan,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/keys/revoke", methods=["POST"])
@admin_required
def admin_revoke_key():
    key = request.form.get("key", "")
    conn = get_db()
    conn.execute("UPDATE licenses SET status='revoked' WHERE key=?", (key,))
    conn.commit()
    conn.close()
    add_log("WARN", "KEYS", f"Clé révoquée: {key[:11]}…", session["admin_user"])
    return redirect("/admin/keys")


@app.route("/admin/resets")
@admin_required
def admin_resets():
    conn = get_db()
    rows = conn.execute("SELECT * FROM reset_requests ORDER BY requested_at DESC LIMIT 100").fetchall()
    conn.close()
    return render_template_string(ADMIN_RESETS_HTML, resets=rows,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/resets/<int:req_id>/approve", methods=["POST"])
@admin_required
def admin_approve_reset(req_id):
    conn = get_db()
    req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (req_id,)).fetchone()
    if not req or req["status"] != "pending":
        conn.close()
        return redirect("/admin/resets")
    if req["type"] == "password":
        temp = _gen_temp_password()
        ph = _hash_password(temp)
        conn.execute("UPDATE users SET password_hash=?, must_change_pass=1, temp_password=? WHERE username=?",
                     (ph, temp, req["username"]))
        conn.execute("UPDATE reset_requests SET status='approved', temp_pass=?, resolved_at=? WHERE id=?",
                     (temp, int(time.time()), req_id))
        if req["discord_id"]:
            _notify_discord(req["discord_id"],
                f"✅ **Demande de reset approuvée**\n"
                f"Ton mot de passe temporaire: `{temp}`\n"
                f"Connecte-toi avec ce MDP et change-le immédiatement!")
        msg = f"MDP reset approuvé pour {req['username']} — temp: {temp}"
    elif req["type"] == "username":
        username = req["username"]
        if req["discord_id"]:
            _notify_discord(req["discord_id"],
                f"✅ **Ton identifiant WinOptimizer**\nTon username est: `{username}`")
        conn.execute("UPDATE reset_requests SET status='approved', resolved_at=? WHERE id=?",
                     (int(time.time()), req_id))
        msg = f"Username envoyé à {req['discord_id']}"
    conn.commit()
    conn.close()
    add_log("OK", "ADMIN", msg, session["admin_user"])
    return redirect("/admin/resets")


@app.route("/admin/resets/<int:req_id>/deny", methods=["POST"])
@admin_required
def admin_deny_reset(req_id):
    conn = get_db()
    req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (req_id,)).fetchone()
    if req and req["discord_id"]:
        _notify_discord(req["discord_id"],
            "❌ **Demande refusée**\nTa demande de reset a été refusée. Contacte un admin.")
    conn.execute("UPDATE reset_requests SET status='denied', resolved_at=? WHERE id=?",
                 (int(time.time()), req_id))
    conn.commit()
    conn.close()
    return redirect("/admin/resets")


@app.route("/admin/tickets")
@admin_required
def admin_tickets():
    conn = get_db()
    rows = conn.execute("SELECT * FROM tickets ORDER BY created_at DESC LIMIT 100").fetchall()
    conn.close()
    return render_template_string(ADMIN_TICKETS_HTML, tickets=rows,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/tickets/<int:tid>/reply", methods=["POST"])
@admin_required
def admin_ticket_reply(tid):
    response = request.form.get("response", "")
    close = request.form.get("close", "0")
    conn = get_db()
    ticket = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    status = "closed" if close == "1" else "answered"
    conn.execute("UPDATE tickets SET response=?, status=?, updated_at=? WHERE id=?",
                 (response, status, int(time.time()), tid))
    conn.commit()
    if ticket and ticket["discord_id"]:
        _notify_discord(ticket["discord_id"], f"📩 **Réponse à ton ticket #{tid}**\n{response}")
    conn.close()
    return redirect("/admin/tickets")


@app.route("/admin/ips")
@admin_required
def admin_ips():
    conn = get_db()
    rows = conn.execute("SELECT * FROM ip_rules ORDER BY added_at DESC").fetchall()
    vpn_block = get_setting("vpn_block") == "1"
    conn.close()
    return render_template_string(ADMIN_IPS_HTML, rules=rows, vpn_block=vpn_block,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/ips/add", methods=["POST"])
@admin_required
def admin_add_ip():
    ip   = request.form.get("ip", "").strip()
    rule = request.form.get("rule", "blacklist")
    note = request.form.get("note", "")
    if ip:
        conn = get_db()
        conn.execute("INSERT OR REPLACE INTO ip_rules VALUES (?,?,?,?)",
                     (ip, rule, note, int(time.time())))
        conn.commit()
        conn.close()
        add_log("OK", "IP", f"IP {rule}: {ip}", session["admin_user"])
    return redirect("/admin/ips")


@app.route("/admin/ips/delete", methods=["POST"])
@admin_required
def admin_del_ip():
    ip = request.form.get("ip", "")
    conn = get_db()
    conn.execute("DELETE FROM ip_rules WHERE ip=?", (ip,))
    conn.commit()
    conn.close()
    return redirect("/admin/ips")


@app.route("/admin/ips/vpn", methods=["POST"])
@admin_required
def admin_toggle_vpn():
    current = get_setting("vpn_block")
    new_val = "0" if current == "1" else "1"
    set_setting("vpn_block", new_val)
    add_log("OK", "IP", f"VPN block: {'activé' if new_val=='1' else 'désactivé'}", session["admin_user"])
    return redirect("/admin/ips")


@app.route("/admin/maintenance", methods=["GET", "POST"])
@admin_required
def admin_maintenance():
    if request.method == "POST":
        state = request.form.get("state", "0")
        set_setting("maintenance", state)
        add_log("OK", "ADMIN", f"Maintenance: {'ON' if state=='1' else 'OFF'}", session["admin_user"])
        return redirect("/admin/maintenance")
    maintenance = get_setting("maintenance") == "1"
    return render_template_string(ADMIN_MAINTENANCE_HTML, maintenance=maintenance,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/owners")
@admin_required
def admin_owners():
    if session.get("admin_role") != "owner":
        return redirect("/admin")
    conn = get_db()
    rows = conn.execute("SELECT * FROM admins ORDER BY created_at").fetchall()
    conn.close()
    return render_template_string(ADMIN_OWNERS_HTML, admins=rows,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/owners/create", methods=["POST"])
@admin_required
def admin_create_admin():
    if session.get("admin_role") != "owner":
        return redirect("/admin")
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role     = request.form.get("role", "staff")
    if username and password:
        ph = _hash_password(password)
        conn = get_db()
        try:
            conn.execute("INSERT INTO admins (username, password_hash, role, created_at, created_by) VALUES (?,?,?,?,?)",
                         (username, ph, role, int(time.time()), session["admin_user"]))
            conn.commit()
            add_log("OK", "ADMIN", f"Nouvel admin créé: {username} role={role}", session["admin_user"])
        except Exception:
            pass
        conn.close()
    return redirect("/admin/owners")


@app.route("/admin/owners/delete", methods=["POST"])
@admin_required
def admin_delete_admin():
    if session.get("admin_role") != "owner":
        return redirect("/admin")
    username = request.form.get("username", "")
    if username != "xywez":
        conn = get_db()
        conn.execute("DELETE FROM admins WHERE username=?", (username,))
        conn.commit()
        conn.close()
    return redirect("/admin/owners")


@app.route("/admin/profile", methods=["GET", "POST"])
@admin_required
def admin_profile():
    msg = ""
    if request.method == "POST":
        old_p = request.form.get("old_password", "")
        new_p = request.form.get("new_password", "")
        if len(new_p) < 6:
            msg = "❌ Nouveau MDP trop court"
        else:
            conn = get_db()
            row = conn.execute("SELECT * FROM admins WHERE username=?", (session["admin_user"],)).fetchone()
            if row and _hash_password(old_p) == row["password_hash"]:
                conn.execute("UPDATE admins SET password_hash=? WHERE username=?",
                             (_hash_password(new_p), session["admin_user"]))
                conn.commit()
                msg = "✅ Mot de passe changé"
                add_log("OK", "ADMIN", f"MDP admin changé: {session['admin_user']}")
            else:
                msg = "❌ Ancien MDP incorrect"
            conn.close()
    return render_template_string(ADMIN_PROFILE_HTML, msg=msg,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/logs")
@admin_required
def admin_logs():
    filter_type = request.args.get("type", "")
    conn = get_db()
    if filter_type:
        rows = conn.execute("SELECT * FROM logs WHERE type=? ORDER BY ts DESC LIMIT 500", (filter_type,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM logs ORDER BY ts DESC LIMIT 500").fetchall()
    conn.close()
    return render_template_string(ADMIN_LOGS_HTML, logs=rows, filter_type=filter_type,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/broadcast", methods=["GET", "POST"])
@admin_required
def admin_broadcast():
    msg_sent = ""
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        target  = request.form.get("target", "all")
        conn = get_db()
        if target == "all":
            users = conn.execute("SELECT discord_id FROM users WHERE status='active' AND discord_id IS NOT NULL AND discord_id != ''").fetchall()
        elif target == "pro":
            users = conn.execute("SELECT discord_id FROM users WHERE plan='PRO' AND discord_id IS NOT NULL AND discord_id != ''").fetchall()
        else:
            users = conn.execute("SELECT discord_id FROM users WHERE plan='NORMAL' AND status='active' AND discord_id IS NOT NULL AND discord_id != ''").fetchall()
        conn.close()
        sent = 0
        for u in users:
            _notify_discord(u["discord_id"], f"📢 **Annonce WinOptimizer Pro**\n{message}")
            sent += 1
        msg_sent = f"✅ Message envoyé à {sent} utilisateur(s) sur Discord."
        add_log("OK", "BROADCAST", f"Broadcast {target}: {message[:60]}", session["admin_user"])
    return render_template_string(ADMIN_BROADCAST_HTML, msg=msg_sent,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/user/<username>/edit", methods=["POST"])
@admin_required
def admin_user_edit(username):
    plan       = request.form.get("plan", "NORMAL")
    note       = request.form.get("note", "")
    discord_id = request.form.get("discord_id", "")
    conn = get_db()
    conn.execute("UPDATE users SET plan=?, note=?, discord_id=? WHERE username=?",
                 (plan, note, discord_id, username))
    conn.commit()
    conn.close()
    add_log("OK", "ADMIN", f"User {username} édité: plan={plan}", session["admin_user"])
    return redirect(f"/admin/user/{username}?msg=Utilisateur+modifié")


@app.route("/admin/api/stats")
@admin_required
def admin_api_stats():
    conn = get_db()
    total   = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active  = conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    banned  = conn.execute("SELECT COUNT(*) FROM users WHERE status='banned'").fetchone()[0]
    pro     = conn.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'").fetchone()[0]
    today   = int(time.time()) - 86400
    week    = int(time.time()) - 604800
    today_l = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0]
    week_l  = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (week,)).fetchone()[0]
    new_today = conn.execute("SELECT COUNT(*) FROM users WHERE created_at>?", (today,)).fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM reset_requests WHERE status='pending'").fetchone()[0]
    tickets = conn.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
    total_keys = conn.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    active_keys = conn.execute("SELECT COUNT(*) FROM licenses WHERE status='active'").fetchone()[0]
    hourly = []
    for i in range(24):
        t_start = int(time.time()) - (i+1)*3600
        t_end   = int(time.time()) - i*3600
        c = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>? AND last_login<?", (t_start, t_end)).fetchone()[0]
        hourly.append(c)
    hourly.reverse()
    conn.close()
    return jsonify({
        "total": total, "active": active, "banned": banned, "pro": pro,
        "today_logins": today_l, "week_logins": week_l, "new_today": new_today,
        "pending_resets": pending, "open_tickets": tickets,
        "total_keys": total_keys, "active_keys": active_keys,
        "hourly_logins": hourly,
        "timestamp": int(time.time()),
    })


@app.route("/admin/api/recent_users")
@admin_required
def admin_api_recent():
    conn = get_db()
    rows = conn.execute("SELECT username, plan, status, last_login, ip, connections FROM users ORDER BY last_login DESC LIMIT 10").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/admin/api/geoip")
@admin_required
def admin_api_geoip():
    """Endpoint AJAX pour récupérer le GeoIP d'une IP."""
    ip = request.args.get("ip", "")
    if not ip:
        return jsonify({"error": "IP manquante"})
    geo = get_geoip(ip)
    return jsonify(geo)


@app.route("/admin/search")
@admin_required
def admin_search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        conn = get_db()
        results = conn.execute(
            "SELECT username, plan, status, discord_id, ip, last_login, connections FROM users WHERE username LIKE ? OR discord_id LIKE ? OR ip LIKE ? OR license_key LIKE ? ORDER BY last_login DESC LIMIT 50",
            (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%")
        ).fetchall()
        conn.close()
    return render_template_string(ADMIN_SEARCH_HTML, results=results, q=q,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


@app.route("/admin/keys/bulk_revoke", methods=["POST"])
@admin_required
def admin_bulk_revoke():
    keys_raw = request.form.get("keys", "")
    keys = [k.strip() for k in keys_raw.split("\n") if k.strip()]
    conn = get_db()
    for k in keys:
        conn.execute("UPDATE licenses SET status='revoked' WHERE key=?", (k,))
    conn.commit()
    conn.close()
    add_log("WARN", "KEYS", f"{len(keys)} clé(s) révoquée(s) en masse", session["admin_user"])
    return redirect("/admin/keys?msg=Clés+révoquées")


@app.route("/admin/bot")
@admin_required
def admin_bot():
    try:
        import urllib.request as ur
        r = ur.urlopen(f"{DISCORD_BOT_URL}/status", timeout=2)
        bot_status = "online" if r.status == 200 else "offline"
    except Exception:
        bot_status = "offline"
    return render_template_string(ADMIN_BOT_HTML, bot_status=bot_status,
                                  admin_user=session["admin_user"],
                                  admin_role=session["admin_role"])


# ─── API internes bot ──────────────────────────────────────────────────────────
@app.route("/api/internal/approve_reset", methods=["POST"])
def internal_approve_reset():
    data = request.get_json(silent=True) or {}
    if data.get("bot_token") != os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN"):
        return jsonify({"error": "Non autorisé"}), 403
    req_id = data.get("req_id")
    conn = get_db()
    req = conn.execute("SELECT * FROM reset_requests WHERE id=?", (req_id,)).fetchone()
    if not req:
        conn.close()
        return jsonify({"error": "Not found"}), 404
    if req["type"] == "password":
        temp = _gen_temp_password()
        ph = _hash_password(temp)
        conn.execute("UPDATE users SET password_hash=?, must_change_pass=1, temp_password=? WHERE username=?",
                     (ph, temp, req["username"]))
        conn.execute("UPDATE reset_requests SET status='approved', temp_pass=?, resolved_at=? WHERE id=?",
                     (temp, int(time.time()), req_id))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "temp_pass": temp, "username": req["username"], "discord_id": req["discord_id"]})
    conn.close()
    return jsonify({"success": False})


@app.route("/api/internal/gen_key", methods=["POST"])
def internal_gen_key():
    data = request.get_json(silent=True) or {}
    if data.get("bot_token") != os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN"):
        return jsonify({"error": "Non autorisé"}), 403
    plan = data.get("plan", "NORMAL")
    qty  = min(int(data.get("qty", 1)), 10)
    conn = get_db()
    keys = []
    for _ in range(qty):
        key = generate_key(plan)
        conn.execute("INSERT OR IGNORE INTO licenses (key, plan, status, created_at, note) VALUES (?,?,?,?,?)",
                     (key, plan, "active", int(time.time()), "Généré via bot Discord"))
        keys.append(key)
    conn.commit()
    conn.close()
    return jsonify({"keys": keys})


@app.route("/api/internal/pending_resets", methods=["GET"])
def internal_pending_resets():
    if request.args.get("bot_token") != os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN"):
        return jsonify({"error": "Non autorisé"}), 403
    conn = get_db()
    rows = conn.execute("SELECT * FROM reset_requests WHERE status='pending' ORDER BY requested_at").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/internal/stats", methods=["GET"])
def internal_stats():
    if request.args.get("bot_token") != os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN"):
        return jsonify({"error": "Non autorisé"}), 403
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active = conn.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    today = int(time.time()) - 86400
    today_l = conn.execute("SELECT COUNT(*) FROM users WHERE last_login>?", (today,)).fetchone()[0]
    maintenance = get_setting("maintenance") == "1"
    conn.close()
    return jsonify({"total": total, "active": active, "today": today_l, "maintenance": maintenance})


@app.route("/api/ticket", methods=["POST"])
def api_create_ticket():
    data = request.get_json(silent=True) or {}
    username   = data.get("username", "").strip()
    discord_id = data.get("discord_id", "").strip()
    subject    = data.get("subject", "").strip()
    message    = data.get("message", "").strip()
    if not subject or not message:
        return jsonify({"success": False, "reason": "Champs manquants"})
    conn = get_db()
    conn.execute("INSERT INTO tickets (user, discord_id, subject, message, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                 (username, discord_id, subject[:100], message[:1000], "open", int(time.time()), int(time.time())))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ═══ HELPER DISCORD ════════════════════════════════════════════════════════════
def _notify_discord(discord_id: str, message: str):
    try:
        import urllib.request as ur, urllib.parse
        payload = json.dumps({
            "user_id": discord_id, "message": message,
            "bot_token": os.environ.get("BOT_TOKEN", "BOT_INTERNAL_TOKEN")
        }).encode()
        req = ur.Request(f"{DISCORD_BOT_URL}/dm", data=payload,
                         headers={"Content-Type": "application/json"}, method="POST")
        ur.urlopen(req, timeout=3)
    except Exception:
        pass


def fmt_ts(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(int(ts)).strftime("%d/%m/%Y %H:%M")
    except Exception:
        return "—"

app.jinja_env.globals["fmt_ts"] = fmt_ts


# ═══════════════════════════════════════════════════════════════════════════════
#  TEMPLATES HTML ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

ADMIN_BASE_STYLE = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #040810; color: #c8e0ff; font-family: 'Courier New', monospace; }
::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #040810; }
::-webkit-scrollbar-thumb { background: #0d2040; border-radius: 3px; }
a { color: #00d4ff; text-decoration: none; }
a:hover { color: #fff; }

.sidebar {
  position: fixed; top: 0; left: 0; width: 220px; height: 100vh;
  background: #080f1e; border-right: 1px solid #0d2040;
  display: flex; flex-direction: column; z-index: 100;
  padding: 20px 0;
}
.sidebar-logo { padding: 10px 20px 20px; border-bottom: 1px solid #0d2040; margin-bottom: 12px; }
.sidebar-logo .title { color: #00d4ff; font-size: 14px; font-weight: bold; }
.sidebar-logo .sub { color: #2a4a6a; font-size: 10px; margin-top: 2px; }
.sidebar a {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 20px; color: #4a7aaa; font-size: 11px;
  transition: all 0.15s;
}
.sidebar a:hover, .sidebar a.active { color: #00d4ff; background: #0d2040; border-left: 2px solid #00d4ff; padding-left: 18px; }
.sidebar .section-title { padding: 10px 20px 4px; color: #1a3a5a; font-size: 9px; text-transform: uppercase; }
.sidebar .bottom { margin-top: auto; padding: 14px 20px; border-top: 1px solid #0d2040; font-size: 10px; color: #2a4a6a; }
.sidebar .logout-btn {
  display: block; margin: 8px 20px 0; padding: 8px 14px;
  background: #2a0010; border: 1px solid #ff2d5533; color: #ff2d55;
  font-size: 10px; cursor: pointer; border-radius: 4px; text-align: center;
  text-decoration: none; transition: all 0.15s;
}
.sidebar .logout-btn:hover { background: #3a0015; color: #ff5577; }

.main { margin-left: 220px; padding: 24px; min-height: 100vh; }
.page-header { margin-bottom: 24px; }
.page-header h1 { font-size: 18px; color: #00d4ff; }
.page-header p { font-size: 11px; color: #2a4a6a; margin-top: 4px; }

.card { background: #080f1e; border: 1px solid #0d2040; border-radius: 4px; padding: 18px; margin-bottom: 16px; }
.card-header { font-size: 11px; color: #4a7aaa; text-transform: uppercase; margin-bottom: 12px; }

.stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 20px; }
.stat-card { background: #080f1e; border: 1px solid #0d2040; border-radius: 4px; padding: 16px; text-align: center; }
.stat-card .num { font-size: 28px; font-weight: bold; color: #00d4ff; }
.stat-card .label { font-size: 10px; color: #2a4a6a; margin-top: 4px; }
.stat-card.warn .num { color: #ffb800; }
.stat-card.danger .num { color: #ff2d55; }
.stat-card.success .num { color: #00ff9d; }

table { width: 100%; border-collapse: collapse; font-size: 11px; }
th { background: #040810; padding: 10px 12px; text-align: left; color: #2a4a6a; border-bottom: 1px solid #0d2040; }
td { padding: 9px 12px; border-bottom: 1px solid #050d1a; }
tr:hover td { background: #050d1a; }

.badge { padding: 2px 8px; border-radius: 3px; font-size: 9px; font-weight: bold; display: inline-block; }
.badge.active  { background: #002a1a; color: #00ff9d; border: 1px solid #00ff9d33; }
.badge.banned  { background: #2a0010; color: #ff2d55; border: 1px solid #ff2d5533; }
.badge.suspended { background: #2a1a00; color: #ffb800; border: 1px solid #ffb80033; }
.badge.pending { background: #1a1a00; color: #ffb800; border: 1px solid #ffb80033; }
.badge.approved { background: #002a1a; color: #00ff9d; border: 1px solid #00ff9d33; }
.badge.denied  { background: #2a0010; color: #ff2d55; border: 1px solid #ff2d5533; }
.badge.open    { background: #001a2a; color: #00d4ff; border: 1px solid #00d4ff33; }
.badge.answered { background: #1a1a2a; color: #8866ff; border: 1px solid #8866ff33; }
.badge.closed  { background: #0d0d0d; color: #4a7aaa; border: 1px solid #4a7aaa33; }
.badge.NORMAL  { background: #001a2a; color: #00d4ff; border: 1px solid #00d4ff33; }
.badge.PRO     { background: #1a0040; color: #aa66ff; border: 1px solid #aa66ff33; }
.badge.revoked { background: #2a0010; color: #ff2d55; border: 1px solid #ff2d5533; }
.badge.online  { background: #002a1a; color: #00ff9d; }
.badge.offline { background: #2a0010; color: #ff2d55; }

.btn { padding: 7px 14px; border: 1px solid #0d2040; background: transparent; color: #4a7aaa; cursor: pointer; font-family: 'Courier New'; font-size: 11px; border-radius: 3px; transition: all 0.15s; }
.btn:hover { border-color: #00d4ff; color: #00d4ff; }
.btn.primary { border-color: #00d4ff; color: #00d4ff; }
.btn.primary:hover { background: #001a2a; }
.btn.danger  { border-color: #ff2d55; color: #ff2d55; }
.btn.danger:hover { background: #2a0010; }
.btn.success { border-color: #00ff9d; color: #00ff9d; }
.btn.success:hover { background: #002a1a; }
.btn.warn    { border-color: #ffb800; color: #ffb800; }
.btn.warn:hover { background: #2a1a00; }

input, select, textarea {
  background: #020610; border: 1px solid #0d2040; color: #c8e0ff;
  padding: 8px 12px; font-family: 'Courier New'; font-size: 11px;
  border-radius: 3px; outline: none; width: 100%;
}
input:focus, select:focus, textarea:focus { border-color: #00d4ff; }
label { font-size: 10px; color: #4a7aaa; display: block; margin-bottom: 4px; }
.form-row { margin-bottom: 12px; }
.form-inline { display: flex; gap: 10px; align-items: flex-end; }
.form-inline input, .form-inline select { width: auto; }
.form-inline .btn { white-space: nowrap; }

.alert { padding: 10px 14px; border-radius: 3px; font-size: 11px; margin-bottom: 14px; }
.alert.success { background: #002a1a; border: 1px solid #00ff9d33; color: #00ff9d; }
.alert.error   { background: #2a0010; border: 1px solid #ff2d5533; color: #ff2d55; }
.alert.warn    { background: #2a1a00; border: 1px solid #ffb80033; color: #ffb800; }
.alert.info    { background: #001a2a; border: 1px solid #00d4ff33; color: #00d4ff; }

.search-bar { display: flex; gap: 8px; margin-bottom: 14px; }
.search-bar input { flex: 1; }

.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.detail-item { background: #020610; border: 1px solid #0d2040; padding: 10px 14px; border-radius: 3px; }
.detail-item .k { font-size: 9px; color: #2a4a6a; text-transform: uppercase; margin-bottom: 3px; }
.detail-item .v { font-size: 12px; color: #00d4ff; }

.maintenance-indicator {
  position: fixed; top: 0; right: 0; left: 220px; height: 3px;
  background: linear-gradient(90deg, #ff2d55, #ffb800);
  z-index: 200;
}

/* GeoIP badge */
.geo-badge { display:inline-flex; align-items:center; gap:5px; padding:3px 8px;
             background:#020610; border:1px solid #0d2040; border-radius:4px; font-size:10px; }
</style>
"""

def sidebar_html(active_page=""):
    return f"""
<div class="sidebar">
  <div class="sidebar-logo">
    <div class="title">⚡ WINOPTIMIZER</div>
    <div class="sub">Panel d'administration v2.1</div>
  </div>
  <div class="section-title">Principal</div>
  <a href="/admin" class="{'active' if active_page=='dashboard' else ''}">📊 Dashboard</a>
  <a href="/admin/users" class="{'active' if active_page=='users' else ''}">👥 Utilisateurs</a>
  <a href="/admin/search" class="{'active' if active_page=='search' else ''}">🔎 Recherche avancée</a>
  <a href="/admin/keys" class="{'active' if active_page=='keys' else ''}">🔑 Gen Key</a>
  <div class="section-title">Communication</div>
  <a href="/admin/broadcast" class="{'active' if active_page=='broadcast' else ''}">📢 Broadcast</a>
  <a href="/admin/resets" class="{'active' if active_page=='resets' else ''}">🔓 Resets MDP</a>
  <a href="/admin/tickets" class="{'active' if active_page=='tickets' else ''}">🎫 Tickets</a>
  <div class="section-title">Système</div>
  <a href="/admin/bot" class="{'active' if active_page=='bot' else ''}">🤖 Bot Discord</a>
  <a href="/admin/maintenance" class="{'active' if active_page=='maintenance' else ''}">⚙️ Maintenance</a>
  <a href="/admin/ips" class="{'active' if active_page=='ips' else ''}">🌐 Gestion IP</a>
  <a href="/admin/logs" class="{'active' if active_page=='logs' else ''}">📜 Logs</a>
  <a href="/admin/owners" class="{'active' if active_page=='owners' else ''}">👑 Équipe</a>
  <a href="/admin/profile" class="{'active' if active_page=='profile' else ''}">🔐 Mon Profil</a>
  <div class="bottom">
    <span style="color:#4a7aaa">{{{{ session.admin_user }}}}</span>
    <a href="/admin/logout" class="logout-btn">🚪 Se déconnecter</a>
  </div>
</div>
"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html><head><title>Admin Login — WinOptimizer</title>
""" + ADMIN_BASE_STYLE + """
<style>
.login-box { width: 380px; margin: 100px auto; background: #080f1e; border: 1px solid #0d2040; padding: 36px; border-radius: 4px; }
.login-logo { text-align: center; margin-bottom: 28px; }
.login-logo h1 { color: #00d4ff; font-size: 18px; }
.login-logo p { color: #2a4a6a; font-size: 10px; margin-top: 4px; }
</style>
</head><body>
<div class="login-box">
  <div class="login-logo">
    <h1>⚡ WINOPTIMIZER</h1>
    <p>Panel d'administration — Connexion sécurisée</p>
  </div>
  {% if error %}<div class="alert error">{{ error }}</div>{% endif %}
  <form method="POST">
    <div class="form-row"><label>Identifiant</label><input type="text" name="username" placeholder="admin" autofocus></div>
    <div class="form-row"><label>Mot de passe</label><input type="password" name="password" placeholder="••••••••"></div>
    <button type="submit" class="btn primary" style="width:100%;margin-top:8px;padding:10px">CONNEXION</button>
  </form>
</div>
</body></html>
"""

ADMIN_DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><title>Dashboard — WinOptimizer Admin</title>""" + ADMIN_BASE_STYLE + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
.chart-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 12px; margin-bottom: 20px; }
.live-dot { display:inline-block; width:7px; height:7px; border-radius:50%; background:#00ff9d; margin-right:6px; animation: pulse 1.5s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
.user-row-mini { display:flex; align-items:center; gap:10px; padding:8px 0; border-bottom:1px solid #0a1a2a; }
.user-row-mini:last-child { border-bottom:none; }
.actions-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:8px; }
</style>
</head><body>
{% if stats.maintenance %}<div class="maintenance-indicator"></div>{% endif %}
""" + sidebar_html("dashboard") + """
<div class="main">
  <div class="page-header">
    <h1>📊 Dashboard <span class="live-dot"></span><span style="font-size:11px;color:#2a4a6a">LIVE</span></h1>
    <p>Vue d'ensemble — admin connecté en tant que <strong style="color:#00d4ff">{{ admin_user }}</strong> ({{ admin_role }})</p>
  </div>

  {% if stats.maintenance %}
  <div class="alert warn">
    ⚠️ <strong>Mode maintenance ACTIF</strong> — Les clients ne peuvent pas se connecter.
    Le panel admin fonctionne normalement.
    <a href="/admin/maintenance" style="margin-left:10px">Désactiver →</a>
  </div>
  {% endif %}
  {% if stats.pending_resets > 0 %}<div class="alert warn">🔔 {{ stats.pending_resets }} demande(s) de reset — <a href="/admin/resets">Traiter →</a></div>{% endif %}
  {% if stats.open_tickets > 0 %}<div class="alert info">🎫 {{ stats.open_tickets }} ticket(s) ouvert(s) — <a href="/admin/tickets">Voir →</a></div>{% endif %}

  <div class="stats-grid" id="stats-grid">
    <div class="stat-card success"><div class="num" id="s-active">{{ stats.active_users }}</div><div class="label">Comptes actifs</div></div>
    <div class="stat-card"><div class="num" id="s-total">{{ stats.total_users }}</div><div class="label">Total utilisateurs</div></div>
    <div class="stat-card"><div class="num" id="s-pro" style="color:#aa66ff">{{ stats.pro_users }}</div><div class="label">Comptes PRO</div></div>
    <div class="stat-card danger"><div class="num" id="s-banned">{{ stats.banned_users }}</div><div class="label">Comptes bannis</div></div>
    <div class="stat-card warn"><div class="num" id="s-today">{{ stats.today_logins }}</div><div class="label">Connexions aujourd'hui</div></div>
    <div class="stat-card"><div class="num" id="s-week">{{ stats.week_logins }}</div><div class="label">Cette semaine</div></div>
    <div class="stat-card"><div class="num" id="s-keys">{{ stats.total_lic }}</div><div class="label">Licences générées</div></div>
    <div class="stat-card {% if stats.maintenance %}danger{% else %}success{% endif %}">
      <div class="num">{% if stats.maintenance %}⚠{% else %}✓{% endif %}</div>
      <div class="label">Maintenance</div>
    </div>
  </div>

  <div class="chart-grid">
    <div class="card">
      <div class="card-header">📈 Connexions — 24 dernières heures</div>
      <canvas id="chart-logins" height="80"></canvas>
    </div>
    <div class="card">
      <div class="card-header">📊 Répartition des plans</div>
      <canvas id="chart-plans" height="160"></canvas>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:20px">
    <div class="card">
      <div class="card-header">🕐 Dernières connexions</div>
      <div id="recent-users">Chargement…</div>
    </div>
    <div class="card">
      <div class="card-header">⚡ Actions rapides</div>
      <div class="actions-grid">
        <a href="/admin/users" class="btn primary" style="text-align:center">👥 Utilisateurs</a>
        <a href="/admin/keys" class="btn primary" style="text-align:center">🔑 Générer clés</a>
        <a href="/admin/search" class="btn primary" style="text-align:center">🔎 Recherche</a>
        <a href="/admin/broadcast" class="btn warn" style="text-align:center">📢 Broadcast</a>
        <a href="/admin/resets" class="btn warn" style="text-align:center">🔓 Resets</a>
        <a href="/admin/tickets" class="btn" style="text-align:center">🎫 Tickets</a>
        <a href="/admin/maintenance" class="btn {% if stats.maintenance %}danger{% else %}success{% endif %}" style="text-align:center">
          {% if stats.maintenance %}⚙️ Désactiver maint.{% else %}⚙️ Maintenance{% endif %}
        </a>
        <a href="/admin/logs" class="btn" style="text-align:center">📜 Logs</a>
        <a href="/admin/ips" class="btn" style="text-align:center">🌐 IP Rules</a>
      </div>
    </div>
  </div>
</div>

<script>
const hourlyData = {{ stats.hourly_logins | tojson }};
const labels = Array.from({length:24}, (_,i) => {
  const h = (new Date().getHours() - 23 + i + 24) % 24;
  return h + 'h';
});
new Chart(document.getElementById('chart-logins'), {
  type: 'line',
  data: { labels, datasets: [{ label: 'Connexions', data: hourlyData, borderColor: '#00d4ff', backgroundColor: 'rgba(0,212,255,0.08)', tension: 0.4, fill: true, pointRadius: 3, pointBackgroundColor: '#00d4ff' }] },
  options: { responsive: true, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#2a4a6a', font: { size: 9 } }, grid: { color: '#0a1a2a' } }, y: { ticks: { color: '#2a4a6a', font: { size: 9 } }, grid: { color: '#0a1a2a' }, beginAtZero: true, precision: 0 } } }
});
new Chart(document.getElementById('chart-plans'), {
  type: 'doughnut',
  data: { labels: ['NORMAL', 'PRO', 'Bannis'], datasets: [{ data: [{{ stats.active_users - stats.pro_users }}, {{ stats.pro_users }}, {{ stats.banned_users }}], backgroundColor: ['#00d4ff33','#aa66ff33','#ff2d5533'], borderColor: ['#00d4ff','#aa66ff','#ff2d55'], borderWidth: 1 }] },
  options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#4a7aaa', font: { size: 9 }, boxWidth: 12 } } } }
});

function refreshStats() {
  fetch('/admin/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('s-active').textContent = d.active;
    document.getElementById('s-total').textContent  = d.total;
    document.getElementById('s-banned').textContent = d.banned;
    document.getElementById('s-pro').textContent    = d.pro;
    document.getElementById('s-today').textContent  = d.today_logins;
    document.getElementById('s-week').textContent   = d.week_logins;
    if(document.getElementById('s-keys')) document.getElementById('s-keys').textContent = d.total_keys;
  }).catch(()=>{});

  fetch('/admin/api/recent_users').then(r=>r.json()).then(users=>{
    const el = document.getElementById('recent-users');
    if(!users.length){ el.innerHTML='<span style="color:#2a4a6a;font-size:11px">Aucune connexion récente</span>'; return; }
    el.innerHTML = users.map(u=>`
      <div class="user-row-mini">
        <span class="badge ${u.status}">${u.status}</span>
        <a href="/admin/user/${u.username}" style="color:#00d4ff;font-size:11px;flex:1">${u.username}</a>
        <span class="badge ${u.plan}" style="font-size:8px">${u.plan}</span>
        <span style="color:#2a4a6a;font-size:9px" id="geo-${u.username}">${u.ip||'?'}</span>
      </div>
    `).join('');
    // Charger le GeoIP pour chaque user
    users.forEach(u => {
      if(!u.ip) return;
      fetch('/admin/api/geoip?ip='+encodeURIComponent(u.ip)).then(r=>r.json()).then(g=>{
        const el2 = document.getElementById('geo-'+u.username);
        if(el2) el2.textContent = (g.flag||'') + ' ' + (g.city||u.ip) + ', ' + (g.country||'');
      }).catch(()=>{});
    });
  }).catch(()=>{});
}
refreshStats();
setInterval(refreshStats, 15000);
</script>
</body></html>
"""

ADMIN_USERS_HTML = """<!DOCTYPE html>
<html><head><title>Utilisateurs — WinOptimizer Admin</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("users") + """
<div class="main">
  <div class="page-header"><h1>👥 Gestion des utilisateurs</h1></div>
  <form class="search-bar" method="GET">
    <input type="text" name="q" value="{{ search }}" placeholder="Rechercher par username, Discord ID, IP…">
    <button type="submit" class="btn primary">🔍 Chercher</button>
    <a href="/admin/users" class="btn">Réinitialiser</a>
  </form>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>Username</th><th>Plan</th><th>Statut</th><th>IP + Localisation</th><th>Discord</th><th>Dernière connexion</th><th>Connexions</th><th>Actions</th></tr></thead>
    <tbody>{% for u in users %}<tr>
      <td><a href="/admin/user/{{ u.username }}">{{ u.username }}</a></td>
      <td><span class="badge {{ u.plan }}">{{ u.plan }}</span></td>
      <td><span class="badge {{ u.status }}">{{ u.status }}</span></td>
      <td>
        <span style="color:#4a7aaa;font-size:10px">{{ u.ip or '—' }}</span>
        {% if u.ip %}
        <span class="geo-badge" id="geo-list-{{ loop.index }}" style="margin-left:4px">…</span>
        <script>
        fetch('/admin/api/geoip?ip={{ u.ip }}').then(r=>r.json()).then(g=>{
          const el = document.getElementById('geo-list-{{ loop.index }}');
          if(el) el.innerHTML = (g.flag||'🌐') + ' ' + (g.city||'?') + ', ' + (g.country||'?');
        }).catch(()=>{const el=document.getElementById('geo-list-{{ loop.index }}');if(el)el.style.display='none';});
        </script>
        {% endif %}
      </td>
      <td style="color:#4a7aaa">{{ u.discord_id or '—' }}</td>
      <td style="color:#4a7aaa">{{ fmt_ts(u.last_login) }}</td>
      <td style="color:#00d4ff">{{ u.connections }}</td>
      <td><a href="/admin/user/{{ u.username }}" class="btn" style="padding:4px 8px;font-size:10px">Détails</a></td>
    </tr>{% endfor %}</tbody>
  </table></div>
</div></body></html>
"""

ADMIN_USER_DETAIL_HTML = """<!DOCTYPE html>
<html><head><title>{{ user.username }} — WinOptimizer Admin</title>""" + ADMIN_BASE_STYLE + """
<style>
.detail-3col { display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px; margin-bottom:16px; }
.detail-2col { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:16px; }
.actions-bar { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:16px; }
</style>
</head><body>
""" + sidebar_html("users") + """
<div class="main">
  <div class="page-header">
    <h1>👤 {{ user.username }}
      <span class="badge {{ user.plan }}" style="font-size:12px;vertical-align:middle">{{ user.plan }}</span>
      <span class="badge {{ user.status }}" style="font-size:12px;vertical-align:middle">{{ user.status }}</span>
    </h1>
    <p><a href="/admin/users">← Liste des utilisateurs</a></p>
  </div>

  {% set msg = request.args.get('msg','') %}
  {% if msg %}<div class="alert success">{{ msg }}</div>{% endif %}

  <!-- GeoIP banner -->
  {% if user.ip and geo %}
  <div class="card" style="padding:12px 16px;margin-bottom:12px;background:#020a14;border-color:#00d4ff22">
    <span style="font-size:24px">{{ geo.flag }}</span>
    <span style="color:#00d4ff;font-weight:bold;margin-left:10px">{{ geo.city }}, {{ geo.country }}</span>
    <span style="color:#4a7aaa;margin-left:12px;font-size:11px">{{ user.ip }}</span>
    <span style="color:#2a4a6a;margin-left:12px;font-size:10px">ISP: {{ geo.isp }}</span>
  </div>
  {% endif %}

  <div class="detail-3col">
    <div class="stat-card"><div class="num" style="font-size:20px">{{ user.connections or 0 }}</div><div class="label">Connexions totales</div></div>
    <div class="stat-card {% if user.status=='active' %}success{% elif user.status=='banned' %}danger{% else %}warn{% endif %}">
      <div class="num" style="font-size:14px">{{ user.status.upper() }}</div><div class="label">Statut actuel</div>
    </div>
    <div class="stat-card">
      <div class="num" style="font-size:14px;{% if user.plan=='PRO' %}color:#aa66ff{% endif %}">{{ user.plan }}</div>
      <div class="label">Plan actif</div>
    </div>
  </div>

  <div class="detail-2col">
    <div class="card">
      <div class="card-header">📋 Informations du compte</div>
      <div class="detail-grid">
        <div class="detail-item"><div class="k">Username</div><div class="v">{{ user.username }}</div></div>
        <div class="detail-item"><div class="k">Plan</div><div class="v"><span class="badge {{ user.plan }}">{{ user.plan }}</span></div></div>
        <div class="detail-item"><div class="k">Créé le</div><div class="v">{{ fmt_ts(user.created_at) }}</div></div>
        <div class="detail-item"><div class="k">Dernière co.</div><div class="v">{{ fmt_ts(user.last_login) }}</div></div>
        <div class="detail-item"><div class="k">Licence</div><div class="v" style="font-size:9px;word-break:break-all;color:#4a7aaa">{{ user.license_key or '—' }}</div></div>
        <div class="detail-item"><div class="k">Connexions</div><div class="v">{{ user.connections or 0 }}</div></div>
        <div class="detail-item"><div class="k">IP</div><div class="v">
          <a href="/admin/search?q={{ user.ip }}" style="color:#00d4ff">{{ user.ip or '—' }}</a>
          {% if geo %}<span style="font-size:10px;color:#4a7aaa;display:block">{{ geo.flag }} {{ geo.city }}, {{ geo.country }}</span>{% endif %}
        </div></div>
        <div class="detail-item"><div class="k">Discord ID</div><div class="v">{{ user.discord_id or '—' }}</div></div>
        <div class="detail-item"><div class="k">HWID</div><div class="v" style="font-size:8px;word-break:break-all;color:#2a4a6a">{{ user.hwid or '—' }}</div></div>
        <div class="detail-item"><div class="k">Changer MDP</div><div class="v">{% if user.must_change_pass %}<span class="badge warn">Requis</span>{% else %}Non{% endif %}</div></div>
        {% if user.temp_password %}<div class="detail-item" style="grid-column:span 2;background:#1a1000;border-color:#ffb80044">
          <div class="k">MDP TEMPORAIRE</div>
          <div class="v" style="color:#ffb800;font-family:monospace;font-size:14px">{{ user.temp_password }}</div>
        </div>{% endif %}
      </div>
      {% if user.note %}<div style="margin-top:12px;padding:10px;background:#040810;border-left:3px solid #ffb800;font-size:11px;color:#ffb800">📝 Note: {{ user.note }}</div>{% endif %}
    </div>

    <div class="card">
      <div class="card-header">✏️ Modifier le compte</div>
      <form method="POST" action="/admin/user/{{ user.username }}/edit">
        <div class="form-row"><label>Plan</label>
          <select name="plan">
            <option value="NORMAL" {% if user.plan=='NORMAL' %}selected{% endif %}>NORMAL</option>
            <option value="PRO" {% if user.plan=='PRO' %}selected{% endif %}>PRO</option>
          </select>
        </div>
        <div class="form-row"><label>Discord ID</label>
          <input type="text" name="discord_id" value="{{ user.discord_id or '' }}" placeholder="ex: 123456789012345678">
        </div>
        <div class="form-row"><label>Note admin</label>
          <textarea name="note" rows="3">{{ user.note or '' }}</textarea>
        </div>
        <button type="submit" class="btn primary">💾 Sauvegarder</button>
      </form>
    </div>
  </div>

  <div class="card">
    <div class="card-header">🛡️ Actions de modération</div>
    <div class="actions-bar">
      {% if user.status == 'active' %}
      <form method="POST" action="/admin/user/{{ user.username }}/action">
        <input type="hidden" name="action" value="suspend">
        <button type="submit" class="btn warn">⚠️ Suspendre</button>
      </form>
      <form method="POST" action="/admin/user/{{ user.username }}/action">
        <input type="hidden" name="action" value="ban">
        <button type="submit" class="btn danger" onclick="return confirm('Bannir {{ user.username }} ?')">🚫 Bannir</button>
      </form>
      {% else %}
      <form method="POST" action="/admin/user/{{ user.username }}/action">
        <input type="hidden" name="action" value="reactivate">
        <button type="submit" class="btn success">✅ Réactiver</button>
      </form>
      {% endif %}
      <form method="POST" action="/admin/user/{{ user.username }}/action">
        <input type="hidden" name="action" value="reset_hwid">
        <button type="submit" class="btn">🖥️ Reset HWID</button>
      </form>
      <form method="POST" action="/admin/user/{{ user.username }}/action">
        <input type="hidden" name="action" value="reset_password">
        <button type="submit" class="btn warn" onclick="return confirm('Réinitialiser le MDP ?')">🔑 Reset MDP</button>
      </form>
      {% if user.ip %}
      <a href="/admin/ips?prefill={{ user.ip }}" class="btn danger">🚫 Bannir IP {{ user.ip }}</a>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <div class="card-header">📜 Logs d'activité (50 derniers)</div>
    <table>
      <thead><tr><th>Date</th><th>Type</th><th>Niveau</th><th>Message</th></tr></thead>
      <tbody>
      {% for l in logs %}
      <tr>
        <td style="color:#4a7aaa;font-size:10px">{{ fmt_ts(l.ts) }}</td>
        <td><span class="badge open">{{ l.type }}</span></td>
        <td style="color:{% if l.level=='OK' %}#00ff9d{% elif l.level=='WARN' %}#ffb800{% else %}#ff2d55{% endif %}">{{ l.level }}</td>
        <td style="font-size:10px">{{ l.msg }}</td>
      </tr>
      {% endfor %}
      {% if not logs %}<tr><td colspan="4" style="text-align:center;color:#2a4a6a;padding:20px">Aucun log</td></tr>{% endif %}
      </tbody>
    </table>
  </div>
</div></body></html>
"""

ADMIN_KEYS_HTML = """<!DOCTYPE html>
<html><head><title>Licences — WinOptimizer Admin</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("keys") + """
<div class="main">
  <div class="page-header"><h1>🔑 Gestion des licences</h1></div>
  {% set msg = request.args.get('msg','') %}
  {% if msg %}<div class="alert success">{{ msg }}</div>{% endif %}

  <div style="display:grid;grid-template-columns:2fr 1fr;gap:12px;margin-bottom:16px">
    <div class="card"><div class="card-header">⚡ Générer des clés</div>
      <form method="POST" action="/admin/keys/generate">
        <div class="form-inline">
          <div><label>Type</label><select name="plan" style="width:130px"><option value="NORMAL">NORMAL</option><option value="PRO">PRO</option></select></div>
          <div><label>Quantité</label><input type="number" name="qty" value="1" min="1" max="500" style="width:80px"></div>
          <div style="flex:1"><label>Note</label><input type="text" name="note" placeholder="ex: giveaway discord…"></div>
          <button type="submit" class="btn success">⚡ Générer</button>
        </div>
      </form>
    </div>
    <div class="card"><div class="card-header">🗑 Révoquer en masse</div>
      <form method="POST" action="/admin/keys/bulk_revoke">
        <div class="form-row"><label>Clés (une par ligne)</label>
          <textarea name="keys" rows="3" placeholder="XXXX-XXXX-XXXX&#10;YYYY-YYYY-YYYY"></textarea>
        </div>
        <button type="submit" class="btn danger" onclick="return confirm('Révoquer ces clés ?')">🚫 Révoquer</button>
      </form>
    </div>
  </div>

  <div class="card" style="padding:0"><table>
    <thead><tr><th>Clé</th><th>Plan</th><th>Statut</th><th>Créée le</th><th>Utilisateur</th><th>Note</th><th>Action</th></tr></thead>
    <tbody>{% for k in keys %}<tr>
      <td style="font-family:monospace;font-size:10px;color:#00d4ff">
        {{ k.key }}
        <button onclick="navigator.clipboard.writeText('{{ k.key }}')" style="background:none;border:none;color:#2a4a6a;cursor:pointer;font-size:10px" title="Copier">📋</button>
      </td>
      <td><span class="badge {{ k.plan }}">{{ k.plan }}</span></td>
      <td><span class="badge {{ k.status }}">{{ k.status }}</span></td>
      <td style="color:#4a7aaa;font-size:10px">{{ fmt_ts(k.created_at) }}</td>
      <td>{% if k.username %}<a href="/admin/user/{{ k.username }}">{{ k.username }}</a>{% else %}<span style="color:#2a4a6a">Libre</span>{% endif %}</td>
      <td style="color:#4a7aaa;font-size:10px">{{ k.note or '—' }}</td>
      <td>{% if k.status == 'active' %}
        <form method="POST" action="/admin/keys/revoke" style="display:inline">
          <input type="hidden" name="key" value="{{ k.key }}">
          <button type="submit" class="btn danger" style="padding:3px 8px;font-size:9px">Révoquer</button>
        </form>{% endif %}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
</div></body></html>
"""

ADMIN_KEYS_GEN_RESULT_HTML = """<!DOCTYPE html>
<html><head><title>Clés générées</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("keys") + """
<div class="main">
  <div class="page-header"><h1>✅ {{ keys|length }} clé(s) {{ plan }} générée(s)</h1><p><a href="/admin/keys">← Retour</a></p></div>
  <div class="card">
    <textarea style="height:300px;font-family:monospace;font-size:12px;background:#020610;color:#00d4ff;border:1px solid #0d2040;padding:14px;width:100%" readonly>{% for k in keys %}{{ k }}
{% endfor %}</textarea>
    <div style="margin-top:10px">
      <button onclick="navigator.clipboard.writeText(document.querySelector('textarea').value)" class="btn primary">📋 Copier tout</button>
      <a href="/admin/keys" class="btn" style="margin-left:8px">Retour →</a>
    </div>
  </div>
</div></body></html>
"""

ADMIN_RESETS_HTML = """<!DOCTYPE html>
<html><head><title>Resets MDP</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("resets") + """
<div class="main">
  <div class="page-header"><h1>🔓 Demandes de reset</h1></div>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>Date</th><th>Username</th><th>Discord ID</th><th>Type</th><th>Statut</th><th>MDP temp.</th><th>Actions</th></tr></thead>
    <tbody>{% for r in resets %}<tr>
      <td style="color:#4a7aaa">{{ fmt_ts(r.requested_at) }}</td>
      <td><a href="/admin/user/{{ r.username }}">{{ r.username }}</a></td>
      <td style="color:#4a7aaa">{{ r.discord_id }}</td>
      <td><span class="badge open">{{ r.type }}</span></td>
      <td><span class="badge {{ r.status }}">{{ r.status }}</span></td>
      <td style="color:#ffb800;font-family:monospace">{{ r.temp_pass or '—' }}</td>
      <td>{% if r.status == 'pending' %}
        <form method="POST" action="/admin/resets/{{ r.id }}/approve" style="display:inline">
          <button type="submit" class="btn success" style="padding:3px 8px;font-size:10px">✅ Approuver</button>
        </form>
        <form method="POST" action="/admin/resets/{{ r.id }}/deny" style="display:inline">
          <button type="submit" class="btn danger" style="padding:3px 8px;font-size:10px">❌ Refuser</button>
        </form>{% endif %}</td>
    </tr>{% endfor %}
    {% if not resets %}<tr><td colspan="7" style="text-align:center;color:#2a4a6a;padding:30px">Aucune demande</td></tr>{% endif %}
    </tbody>
  </table></div>
</div></body></html>
"""

ADMIN_TICKETS_HTML = """<!DOCTYPE html>
<html><head><title>Tickets</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("tickets") + """
<div class="main">
  <div class="page-header"><h1>🎫 Support Tickets</h1></div>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>Date</th><th>User</th><th>Sujet</th><th>Statut</th><th>Action</th></tr></thead>
    <tbody>{% for t in tickets %}<tr>
      <td style="color:#4a7aaa">{{ fmt_ts(t.created_at) }}</td>
      <td>{{ t.user or '—' }}</td>
      <td>{{ t.subject }}</td>
      <td><span class="badge {{ t.status }}">{{ t.status }}</span></td>
      <td><details><summary class="btn" style="cursor:pointer;display:inline-block;padding:3px 8px;font-size:10px">Répondre</summary>
        <div style="padding:12px;background:#020610;border:1px solid #0d2040;margin-top:6px">
          <div style="color:#4a7aaa;font-size:10px;margin-bottom:8px">{{ t.message }}</div>
          {% if t.response %}<div style="color:#00ff9d;font-size:10px;margin-bottom:8px">{{ t.response }}</div>{% endif %}
          <form method="POST" action="/admin/tickets/{{ t.id }}/reply">
            <textarea name="response" rows="3" style="margin-bottom:8px"></textarea>
            <div style="display:flex;gap:8px">
              <button type="submit" class="btn primary" style="font-size:10px">Répondre</button>
              <button type="submit" name="close" value="1" class="btn" style="font-size:10px">Fermer</button>
            </div>
          </form>
        </div>
      </details></td>
    </tr>{% endfor %}
    {% if not tickets %}<tr><td colspan="5" style="text-align:center;color:#2a4a6a;padding:30px">Aucun ticket</td></tr>{% endif %}
    </tbody>
  </table></div>
</div></body></html>
"""

ADMIN_MAINTENANCE_HTML = """<!DOCTYPE html>
<html><head><title>Maintenance</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("maintenance") + """
<div class="main">
  <div class="page-header">
    <h1>⚙️ Mode Maintenance</h1>
    <p>Quand activé, les clients voient une page de maintenance. Le panel admin reste accessible normalement.</p>
  </div>
  <div class="card" style="max-width:560px">
    <div class="alert info" style="margin-bottom:16px">
      ℹ️ <strong>Les admins ne sont jamais bloqués par la maintenance.</strong>
      Seules les API <code>/api/login</code> et <code>/api/register</code> retournent une erreur aux clients.
    </div>
    {% if maintenance %}
    <div class="alert warn">⚠️ Maintenance <strong>ACTIVÉE</strong> — Les clients ne peuvent pas se connecter.</div>
    <form method="POST" style="margin-top:12px">
      <input type="hidden" name="state" value="0">
      <button type="submit" class="btn success" style="width:100%;padding:14px;font-size:13px">✅ DÉSACTIVER la maintenance</button>
    </form>
    {% else %}
    <div class="alert success">✅ Serveur opérationnel — Clients autorisés à se connecter.</div>
    <form method="POST" style="margin-top:12px">
      <input type="hidden" name="state" value="1">
      <button type="submit" class="btn danger" style="width:100%;padding:14px;font-size:13px" onclick="return confirm('Activer la maintenance ?')">⚙️ ACTIVER la maintenance</button>
    </form>
    {% endif %}
  </div>
</div></body></html>
"""

ADMIN_IPS_HTML = """<!DOCTYPE html>
<html><head><title>Gestion IP</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("ips") + """
<div class="main">
  <div class="page-header"><h1>🌐 Gestion des adresses IP</h1></div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
    <div class="card"><div class="card-header">Ajouter une règle IP</div>
      <form method="POST" action="/admin/ips/add">
        <div class="form-row"><label>Adresse IP</label><input type="text" name="ip" placeholder="192.168.1.1"></div>
        <div class="form-row"><label>Règle</label><select name="rule"><option value="blacklist">🚫 Blacklist</option><option value="whitelist">✅ Whitelist</option></select></div>
        <div class="form-row"><label>Note</label><input type="text" name="note"></div>
        <button type="submit" class="btn primary">Ajouter</button>
      </form>
    </div>
    <div class="card"><div class="card-header">Blocage VPN/Proxy</div>
      <form method="POST" action="/admin/ips/vpn">
        <button type="submit" class="btn {% if vpn_block %}danger{% else %}success{% endif %}" style="width:100%;padding:12px">
          {% if vpn_block %}🚫 VPN BLOQUÉ — Cliquer pour autoriser{% else %}✅ VPN autorisé — Cliquer pour bloquer{% endif %}
        </button>
      </form>
    </div>
  </div>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>IP</th><th>Règle</th><th>Note</th><th>Ajouté le</th><th>Action</th></tr></thead>
    <tbody>{% for r in rules %}<tr>
      <td style="font-family:monospace;color:#00d4ff">{{ r.ip }}</td>
      <td><span class="badge {% if r.rule=='blacklist' %}banned{% else %}active{% endif %}">{{ r.rule }}</span></td>
      <td style="color:#4a7aaa">{{ r.note or '—' }}</td>
      <td style="color:#4a7aaa">{{ fmt_ts(r.added_at) }}</td>
      <td><form method="POST" action="/admin/ips/delete" style="display:inline">
        <input type="hidden" name="ip" value="{{ r.ip }}">
        <button type="submit" class="btn danger" style="padding:3px 8px;font-size:9px">Supprimer</button>
      </form></td>
    </tr>{% endfor %}
    {% if not rules %}<tr><td colspan="5" style="text-align:center;color:#2a4a6a;padding:20px">Aucune règle IP</td></tr>{% endif %}
    </tbody>
  </table></div>
</div></body></html>
"""

ADMIN_OWNERS_HTML = """<!DOCTYPE html>
<html><head><title>Équipe</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("owners") + """
<div class="main">
  <div class="page-header"><h1>👑 Gestion des accès admin</h1></div>
  <div class="card" style="max-width:500px;margin-bottom:16px"><div class="card-header">Créer un accès admin</div>
    <form method="POST" action="/admin/owners/create">
      <div class="form-row"><label>Username</label><input type="text" name="username" required></div>
      <div class="form-row"><label>Mot de passe</label><input type="password" name="password" required></div>
      <div class="form-row"><label>Rôle</label><select name="role"><option value="staff">Staff</option><option value="admin">Admin</option><option value="owner">Owner</option></select></div>
      <button type="submit" class="btn primary">✅ Créer l'accès</button>
    </form>
  </div>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>Username</th><th>Rôle</th><th>Créé le</th><th>Par</th><th>Action</th></tr></thead>
    <tbody>{% for a in admins %}<tr>
      <td style="color:#00d4ff">{{ a.username }}</td>
      <td><span class="badge {% if a.role=='owner' %}PRO{% elif a.role=='admin' %}active{% else %}NORMAL{% endif %}">{{ a.role }}</span></td>
      <td style="color:#4a7aaa">{{ fmt_ts(a.created_at) }}</td>
      <td style="color:#4a7aaa">{{ a.created_by or '—' }}</td>
      <td>{% if a.username != 'xywez' %}
        <form method="POST" action="/admin/owners/delete" style="display:inline">
          <input type="hidden" name="username" value="{{ a.username }}">
          <button type="submit" class="btn danger" style="padding:3px 8px;font-size:9px">Supprimer</button>
        </form>{% else %}<span style="color:#2a4a6a;font-size:10px">Protégé</span>{% endif %}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
</div></body></html>
"""

ADMIN_PROFILE_HTML = """<!DOCTYPE html>
<html><head><title>Mon Profil</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("profile") + """
<div class="main">
  <div class="page-header"><h1>🔐 Mon Profil</h1></div>
  <div class="card" style="max-width:400px">
    {% if msg %}<div class="alert {% if '✅' in msg %}success{% else %}error{% endif %}">{{ msg }}</div>{% endif %}
    <form method="POST">
      <div class="form-row"><label>Ancien mot de passe</label><input type="password" name="old_password" required></div>
      <div class="form-row"><label>Nouveau mot de passe</label><input type="password" name="new_password" required minlength="6"></div>
      <button type="submit" class="btn primary" style="width:100%;padding:10px">Changer</button>
    </form>
  </div>
</div></body></html>
"""

ADMIN_LOGS_HTML = """<!DOCTYPE html>
<html><head><title>Logs</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("logs") + """
<div class="main">
  <div class="page-header"><h1>📜 Journal système</h1></div>
  <div style="margin-bottom:12px;display:flex;gap:8px">
    <a href="/admin/logs" class="btn {% if not filter_type %}primary{% endif %}">Tous</a>
    <a href="/admin/logs?type=LOGIN" class="btn {% if filter_type=='LOGIN' %}primary{% endif %}">LOGIN</a>
    <a href="/admin/logs?type=REGISTER" class="btn {% if filter_type=='REGISTER' %}primary{% endif %}">REGISTER</a>
    <a href="/admin/logs?type=ADMIN" class="btn {% if filter_type=='ADMIN' %}primary{% endif %}">ADMIN</a>
    <a href="/admin/logs?type=RESET" class="btn {% if filter_type=='RESET' %}primary{% endif %}">RESET</a>
  </div>
  <div class="card" style="padding:0"><table>
    <thead><tr><th>Date</th><th>Type</th><th>Niveau</th><th>Message</th><th>User</th></tr></thead>
    <tbody>{% for l in logs %}<tr>
      <td style="color:#4a7aaa;white-space:nowrap">{{ fmt_ts(l.ts) }}</td>
      <td><span style="font-size:10px;color:#00d4ff">{{ l.type }}</span></td>
      <td style="color:{% if l.level=='OK' %}#00ff9d{% elif l.level=='WARN' %}#ffb800{% else %}#ff2d55{% endif %};font-size:10px">{{ l.level }}</td>
      <td style="font-size:11px">{{ l.msg }}</td>
      <td style="color:#4a7aaa;font-size:10px">{{ l.user or '—' }}</td>
    </tr>{% endfor %}</tbody>
  </table></div>
</div></body></html>
"""

ADMIN_BOT_HTML = """<!DOCTYPE html>
<html><head><title>Bot Discord</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("bot") + """
<div class="main">
  <div class="page-header"><h1>🤖 Bot Discord</h1></div>
  <div class="card" style="max-width:500px"><div style="text-align:center;padding:20px">
    <div style="font-size:48px;margin-bottom:16px">🤖</div>
    <div>Statut : <span class="badge {{ bot_status }}">{{ bot_status.upper() }}</span></div>
    {% if bot_status == 'online' %}
    <div class="alert success" style="margin-top:16px">✅ Bot connecté</div>
    {% else %}
    <div class="alert error" style="margin-top:16px">❌ Bot hors ligne — Lance bot.py</div>
    {% endif %}
  </div></div>
</div></body></html>
"""

ADMIN_BROADCAST_HTML = """<!DOCTYPE html>
<html><head><title>Broadcast</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("broadcast") + """
<div class="main">
  <div class="page-header"><h1>📢 Broadcast Discord</h1></div>
  {% if msg %}<div class="alert success">{{ msg }}</div>{% endif %}
  <div class="card">
    <form method="POST">
      <div class="form-row"><label>Destinataires</label>
        <select name="target">
          <option value="all">Tous les utilisateurs actifs</option>
          <option value="pro">Comptes PRO seulement</option>
          <option value="normal">Comptes NORMAL seulement</option>
        </select>
      </div>
      <div class="form-row"><label>Message</label>
        <textarea name="message" rows="6" placeholder="Tape ton message ici…"></textarea>
      </div>
      <div class="alert warn" style="margin-bottom:12px">⚠️ Message envoyé en DM Discord aux utilisateurs avec Discord ID lié.</div>
      <button type="submit" class="btn danger" onclick="return confirm('Envoyer ce message en masse ?')">📢 ENVOYER</button>
    </form>
  </div>
</div></body></html>
"""

ADMIN_SEARCH_HTML = """<!DOCTYPE html>
<html><head><title>Recherche</title>""" + ADMIN_BASE_STYLE + """</head><body>
""" + sidebar_html("search") + """
<div class="main">
  <div class="page-header"><h1>🔎 Recherche avancée</h1></div>
  <div class="card">
    <form method="GET" action="/admin/search">
      <div class="form-inline">
        <input type="text" name="q" value="{{ q }}" placeholder="Username, Discord ID, IP, clé licence…" autofocus style="flex:1">
        <button type="submit" class="btn primary">🔎 Rechercher</button>
      </div>
    </form>
  </div>
  {% if q %}
  <div class="card" style="padding:0">
    <div style="padding:12px 16px;border-bottom:1px solid #0d2040;font-size:11px;color:#4a7aaa">
      {{ results|length }} résultat(s) pour "<span style="color:#00d4ff">{{ q }}</span>"
    </div>
    <table>
      <thead><tr><th>Username</th><th>Plan</th><th>Statut</th><th>IP</th><th>Discord</th><th>Connexions</th><th>Dernière co.</th><th>Actions</th></tr></thead>
      <tbody>
        {% for u in results %}
        <tr>
          <td><a href="/admin/user/{{ u.username }}">{{ u.username }}</a></td>
          <td><span class="badge {{ u.plan }}">{{ u.plan }}</span></td>
          <td><span class="badge {{ u.status }}">{{ u.status }}</span></td>
          <td style="color:#4a7aaa;font-size:10px">{{ u.ip or '—' }}</td>
          <td style="color:#4a7aaa;font-size:10px">{{ u.discord_id or '—' }}</td>
          <td>{{ u.connections or 0 }}</td>
          <td style="color:#4a7aaa;font-size:10px">{{ fmt_ts(u.last_login) }}</td>
          <td>
            <a href="/admin/user/{{ u.username }}" class="btn primary" style="padding:3px 8px;font-size:9px">Voir</a>
          </td>
        </tr>
        {% endfor %}
        {% if not results %}
        <tr><td colspan="8" style="text-align:center;color:#2a4a6a;padding:30px">Aucun résultat</td></tr>
        {% endif %}
      </tbody>
    </table>
  </div>
  {% endif %}
</div></body></html>
"""


# ═══ DÉMARRAGE ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "="*54)
    print("  ⚡ WINOPTIMIZER LICENSE SERVER v2.1")
    print("="*54)
    print(f"  Port             : {port}")
    print(f"  Login admin      : xywez / Admin2025!")
    print(f"  Base de données  : {DB_PATH}")
    print(f"  GeoIP            : ip-api.com (gratuit, sans clé)")
    print("="*54)
    app.run(host="0.0.0.0", port=port, debug=False)
