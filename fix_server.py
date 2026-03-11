"""
fix_server.py — Corrige automatiquement les erreurs dans server.py
Usage : python fix_server.py
Le fichier server.py doit être dans le même dossier.
"""

import re

with open("server.py", "r", encoding="utf-8") as f:
    content = f.read()

fixes = 0

# ── Fix 1 : def generate_key(="NORMAL"): → def generate_key(plan="NORMAL"):
old = 'def generate_key(="NORMAL"):'
new = 'def generate_key(plan="NORMAL"):'
if old in content:
    content = content.replace(old, new)
    fixes += 1
    print("✅ Fix 1 : generate_key(plan=...) corrigé")
else:
    print("⚠️  Fix 1 : déjà correct ou introuvable")

# ── Fix 2 : indentation de result = _send_email( (5 espaces → 4)
old2 = '     result = _send_email('
new2 = '    result = _send_email('
if old2 in content:
    content = content.replace(old2, new2)
    fixes += 1
    print("✅ Fix 2 : indentation result = _send_email( corrigée")
else:
    print("⚠️  Fix 2 : déjà correct ou introuvable")

# ── Fix 3 : indentation de add_log après _send_email (5 espaces → 4)
old3 = '     add_log("OK", "SHOP"'
new3 = '    add_log("OK", "SHOP"'
if old3 in content:
    content = content.replace(old3, new3)
    fixes += 1
    print("✅ Fix 3 : indentation add_log corrigée")
else:
    print("⚠️  Fix 3 : déjà correct ou introuvable")

# ── Fix 4 : indentation de print([EMAIL RESULT]) si 5 espaces
old4 = '     print(f"[EMAIL RESULT]'
new4 = '    print(f"[EMAIL RESULT]'
if old4 in content:
    content = content.replace(old4, new4)
    fixes += 1
    print("✅ Fix 4 : indentation print([EMAIL RESULT]) corrigée")
else:
    print("⚠️  Fix 4 : déjà correct ou introuvable")

# ── Vérification syntaxe finale
import py_compile, tempfile, os
tmp = tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w", encoding="utf-8")
tmp.write(content)
tmp.close()
try:
    py_compile.compile(tmp.name, doraise=True)
    print(f"\n✅ Syntaxe Python OK — {fixes} correction(s) appliquée(s)")
    ok = True
except py_compile.PyCompileError as e:
    print(f"\n❌ Erreur de syntaxe restante : {e}")
    ok = False
finally:
    os.unlink(tmp.name)

if ok:
    # Sauvegarde de l'original
    import shutil
    shutil.copy("server.py", "server.py.bak")
    with open("server.py", "w", encoding="utf-8") as f:
        f.write(content)
    print("💾 server.py corrigé sauvegardé (backup → server.py.bak)")
else:
    print("⚠️  server.py NON modifié à cause des erreurs restantes")
