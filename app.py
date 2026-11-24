
import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect

APP_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("BTR_DATABASE", os.path.join(APP_DIR, "btr.sqlite3"))
SECRET_KEY = os.environ.get("BTR_SECRET_KEY")
ADMIN_EMAIL = os.environ.get("BTR_ADMIN_EMAIL")
ADMIN_PASSWORD = os.environ.get("BTR_ADMIN_PASSWORD")

if not SECRET_KEY or not ADMIN_EMAIL or not ADMIN_PASSWORD:
    raise RuntimeError(
        "Set BTR_SECRET_KEY, BTR_ADMIN_EMAIL and BTR_ADMIN_PASSWORD environment variables. "
        "Do not put production secrets in source code."
    )

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("BTR_HTTPS", "1") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1024 * 1024,
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1) if os.environ.get("BTR_TRUST_PROXY") == "1" else app.wsgi_app
CSRFProtect(app)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        existing = conn.execute("SELECT id FROM admin_users WHERE email = ?", (ADMIN_EMAIL,)).fetchone()
        if existing is None:
            conn.execute(
                "INSERT INTO admin_users (email, password_hash) VALUES (?, ?)",
                (ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD))
            )

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("dashboard") if session.get("admin_id") else url_for("login"))

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM admin_users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["admin_id"] = user["id"]
            session["admin_email"] = user["email"]
            session.permanent = True
            db().execute("INSERT INTO admin_events (event) VALUES (?)", ("Admin login",))
            db().commit()
            return redirect(url_for("dashboard"))
        flash("ইমেইল অথবা পাসওয়ার্ড সঠিক নয়।", "error")
    return render_template("login.html")

@app.route("/admin")
@admin_required
def dashboard():
    count = db().execute("SELECT COUNT(*) FROM admin_events").fetchone()[0]
    events = db().execute("SELECT event, created_at FROM admin_events ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("dashboard.html", email=session.get("admin_email"), count=count, events=events)

@app.route("/admin/logout", methods=["POST"])
@admin_required
def logout():
    db().execute("INSERT INTO admin_events (event) VALUES (?)", ("Admin logout",))
    db().commit()
    session.clear()
    flash("লগআউট সম্পন্ন হয়েছে।", "success")
    return redirect(url_for("login"))

@app.errorhandler(400)
def bad_request(_error):
    return "অনুরোধটি গ্রহণ করা যায়নি। পেজটি রিফ্রেশ করে আবার চেষ্টা করো।", 400

if __name__ == "__main__":
    init_db()
    # Local testing only. Production deployment must use a WSGI server and HTTPS.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
