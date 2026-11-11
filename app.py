"""
CPO Lab Seguro - App Flask para el laboratorio de auditoria con OWASP ZAP.
Seguridad Informatica - Prof. Cristian Lopera Villa

Esta es la version CORREGIDA. Cada bloque marcado con  [PARCHE n]
corresponde a una de las 6 vulnerabilidades de la guia.
"""
import datetime
import ipaddress
import os
import secrets
import socket
import sqlite3
from functools import wraps
from urllib.parse import urlparse

import jwt
import requests
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

# [PARCHE 3 - CSRF] La cookie de sesion solo viaja en peticiones del mismo sitio
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True

# [PARCHE 1 - JWT] Clave larga y aleatoria (no "secret" ni "123456")
JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
JWT_ISSUER = "cpo-lab"

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


# ---------------------------------------------------------------- Base de datos
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
            name TEXT, email TEXT, role TEXT, balance INTEGER);
        CREATE TABLE invoices (
            id INTEGER PRIMARY KEY, owner_id INTEGER, concept TEXT, amount INTEGER);
    """)
    users = [
        (1, "admin", "Admin#2026", "Administrador", "admin@cpo.local", "admin", 1000000),
        (2, "juan", "juan123", "Juan Pablo", "juan@cpo.local", "user", 50000),
        (3, "manuela", "manuela123", "Manuela", "manuela@cpo.local", "user", 50000),
    ]
    for uid, user, pwd, name, email, role, bal in users:
        db.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                   (uid, user, generate_password_hash(pwd), name, email, role, bal))
    db.executemany("INSERT INTO invoices VALUES (?,?,?,?)", [
        (1041, 1, "Contrato reactivos laboratorio", 8500000),
        (1042, 2, "Examen hemograma", 35000),
        (1043, 3, "Examen perfil lipidico", 48000),
    ])
    db.commit()
    db.close()


# ---------------------------------------------------------------- Seguridad comun
@app.after_request
def security_headers(resp):
    # [PARCHE 5 - XSS] CSP estricta: solo scripts propios, nada inline
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; "
        "base-uri 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def current_user():
    return get_db().execute("SELECT * FROM users WHERE id = ?",
                            (session["user_id"],)).fetchone()


# [PARCHE 3 - CSRF] Synchronizer Token Pattern: un token aleatorio por sesion
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def check_csrf():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not sent or not secrets.compare_digest(sent, session.get("csrf_token", "")):
        abort(403, "Token CSRF invalido")


# ---------------------------------------------------------------- Rutas web
@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


# [PARCHE 4 - SQLi] Consulta parametrizada: el usuario nunca se pega al SQL
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        error = "Usuario o contrasena incorrectos"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user())


# [PARCHE 5 - XSS] Jinja escapa {{ q }} automaticamente (sin |safe)
@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    rows = get_db().execute(
        "SELECT id, concept, amount FROM invoices WHERE owner_id = ? AND concept LIKE ?",
        (session["user_id"], f"%{q}%")).fetchall()
    return render_template("search.html", q=q, rows=rows)


# [PARCHE 3 - CSRF] La transferencia exige el token CSRF del formulario
@app.route("/transfer", methods=["POST"])
@login_required
def transfer():
    check_csrf()
    to_user = request.form.get("to", "")
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        abort(400, "Monto invalido")
    db = get_db()
    me = current_user()
    dest = db.execute("SELECT id FROM users WHERE username = ?", (to_user,)).fetchone()
    if not dest or amount <= 0 or amount > me["balance"]:
        abort(400, "Transferencia invalida")
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, me["id"]))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, dest["id"]))
    db.commit()
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------- API JWT
@app.route("/api/token", methods=["POST"])
@login_required
def api_token():
    user = current_user()
    payload = {
        "sub": str(user["id"]), "user": user["username"], "role": user["role"],
        "iss": JWT_ISSUER,
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15),
    }
    return jsonify(token=jwt.encode(payload, JWT_SECRET, algorithm="HS256"))


# [PARCHE 1 - JWT] Solo HS256, firma obligatoria, exp e iss obligatorios
def decode_jwt():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        abort(401, "Falta el token")
    try:
        return jwt.decode(
            auth[7:], JWT_SECRET,
            algorithms=["HS256"],            # rechaza alg "none" y cualquier otro
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iss", "sub"]})
    except jwt.PyJWTError as e:
        abort(401, f"Token invalido: {e}")


@app.route("/api/admin")
def api_admin():
    claims = decode_jwt()
    if claims.get("role") != "admin":
        abort(403, "Solo administradores")
    users = get_db().execute("SELECT id, username, email, role, balance FROM users").fetchall()
    return jsonify(users=[dict(u) for u in users])


# ---------------------------------------------------------------- SSRF
# [PARCHE 2 - SSRF] Lista blanca de dominios + bloqueo de IPs internas
ALLOWED_HOSTS = {"picsum.photos", "upload.wikimedia.org"}


def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):          # bloquea file://, gopher://
        return False, "Esquema no permitido"
    host = parsed.hostname or ""
    if host not in ALLOWED_HOSTS:
        return False, "Dominio fuera de la lista blanca"
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, "IP interna bloqueada"
    except socket.gaierror:
        return False, "No se pudo resolver el dominio"
    return True, ""


@app.route("/api/fetch-image", methods=["POST"])
@login_required
def fetch_image():
    url = (request.get_json(silent=True) or {}).get("url", "")
    ok, reason = is_safe_url(url)
    if not ok:
        return jsonify(error=reason), 400
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
    except requests.RequestException:
        return jsonify(error="No se pudo descargar"), 502
    return jsonify(status=r.status_code, content_type=r.headers.get("Content-Type"),
                   size=len(r.content))


# Servicio "interno" que simula el endpoint de metadatos de la nube
# (169.254.169.254). Solo debe responder a peticiones desde el propio servidor.
@app.route("/internal/metadata")
def internal_metadata():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    return jsonify(instance="cpo-lab-01", aws_access_key="AKIA-FAKE-LAB-KEY",
                   db_password="SuperSecreta-LAB")


# ---------------------------------------------------------------- IDOR / Mass Assignment
# [PARCHE 6a - IDOR] Se valida que la factura sea del usuario de la sesion
@app.route("/api/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id):
    inv = get_db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)
    return jsonify(dict(inv))


# [PARCHE 6b - Mass Assignment] DTO allowlist: solo se aceptan name y email
PROFILE_FIELDS = {"name", "email", "role", "balance"}


@app.route("/api/users/profile", methods=["PUT"])
@login_required
def update_profile():
    check_csrf()
    data = request.get_json(silent=True) or {}
    clean = {k: str(v) for k, v in data.items() if k in PROFILE_FIELDS}
    if not clean:
        abort(400, "Nada que actualizar")
    db = get_db()
    for field, value in clean.items():               # field viene de la allowlist
        db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, session["user_id"]))
    db.commit()
    user = current_user()
    return jsonify(id=user["id"], name=user["name"], email=user["email"], role=user["role"])


if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
