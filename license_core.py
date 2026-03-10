"""
license_core.py — Module de licence partagé
Vérification HMAC-SHA256 + cache local signé + ID machine
"""
import hmac, hashlib, base64, json, time, uuid, re, os, platform

# ── Clé secrète maître ── CHANGER AVANT DÉPLOIEMENT ──────────────────────────
MASTER_SECRET     = b"WinOpt_k7#Xm2@pQ9_zR4wN8_2025!"
LICENSE_SERVER    = "http://localhost:5000"          # ton domaine ici
LICENSE_CACHE_FILE = os.path.join(os.path.expanduser("~"), ".winopt_lic")

# ─────────────────────────────────────────────────────────────────────────────
def get_machine_id() -> str:
    """ID unique basé sur le hardware (Windows BIOS UUID → SHA-256)."""
    try:
        import subprocess
        raw = subprocess.check_output(
            "wmic csproduct get uuid", shell=True, timeout=5
        ).decode(errors="ignore").split("\n")
        uid = next((l.strip() for l in raw if l.strip() and l.strip() != "UUID"), "")
        if uid:
            return hashlib.sha256(uid.encode()).hexdigest()[:32]
    except Exception:
        pass
    # Fallback hostname + username
    import socket, getpass
    return hashlib.sha256(
        (socket.gethostname() + getpass.getuser()).encode()
    ).hexdigest()[:32]


# ─────────────────────────────────────────────────────────────────────────────
def _hmac_sign(data: str) -> str:
    return hmac.new(MASTER_SECRET, data.encode(), hashlib.sha256).hexdigest()


def _struct_ok(key: str) -> bool:
    return bool(re.match(r'^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$',
                         key.strip().upper()))


# ─────────────────────────────────────────────────────────────────────────────
def verify_license_offline(key: str, machine_id: str = "") -> dict:
    """
    Vérifie la structure HMAC sans réseau.
    Les 12 premiers chars = ID licence
    Les 8 suivants = signature (8 chars du HMAC)
    """
    key = key.strip().upper()
    if not _struct_ok(key):
        return {"valid": False, "reason": "Format invalide", "plan": None}

    raw       = key.replace("-", "")
    lic_id    = raw[:12]
    sig_given = raw[12:20]

    sig_expected = _hmac_sign(lic_id)[:8].upper()

    if not hmac.compare_digest(sig_given, sig_expected):
        return {"valid": False, "reason": "Signature invalide — clé non reconnue", "plan": None}

    return {"valid": True, "reason": "OK (hors-ligne)", "plan": "PRO",
            "machine_id": machine_id, "key": key}


def verify_license_online(key: str, machine_id: str = "") -> dict:
    """Vérifie via le serveur Flask. Fallback offline si injoignable."""
    key = key.strip().upper()
    if not _struct_ok(key):
        return {"valid": False, "reason": "Format invalide", "plan": None}

    try:
        import requests
        resp = requests.post(
            f"{LICENSE_SERVER}/api/verify",
            json={"key": key, "machine_id": machine_id},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()
        return {"valid": False, "reason": f"Serveur HTTP {resp.status_code}", "plan": None}

    except Exception:
        # Serveur injoignable → fallback offline
        result = verify_license_offline(key, machine_id)
        result["reason"] += " (serveur injoignable — mode hors-ligne)"
        return result


# ─────────────────────────────────────────────────────────────────────────────
def save_license_cache(key: str, data: dict):
    mid     = get_machine_id()
    payload = json.dumps({"key": key, "data": data, "mid": mid},
                         separators=(",", ":"))
    sig     = _hmac_sign(payload)
    try:
        with open(LICENSE_CACHE_FILE, "w") as f:
            json.dump({"p": payload, "s": sig}, f)
    except Exception:
        pass


def load_license_cache() -> dict | None:
    try:
        with open(LICENSE_CACHE_FILE) as f:
            obj = json.load(f)
        payload = obj["p"]
        sig     = obj["s"]

        # Vérif intégrité
        if not hmac.compare_digest(sig, _hmac_sign(payload)):
            return None          # fichier tamperé

        parsed = json.loads(payload)

        # Vérif machine
        if parsed.get("mid") != get_machine_id():
            return None          # autre machine = non valide

        return parsed
    except Exception:
        return None
