import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from urllib.parse import urlparse

import psycopg
from flask import Flask, jsonify, make_response, redirect, request, send_from_directory
from psycopg.rows import dict_row
from werkzeug.middleware.proxy_fix import ProxyFix


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = os.path.join(BASE_DIR, "securenet.sqlite3")
LEGACY_USERS_FILE = os.path.join(BASE_DIR, "users.json")
SESSION_COOKIE = "securenet_session"
SESSION_SECONDS = 12 * 60 * 60
PASSWORD_ITERATIONS = 600_000
MAX_REQUEST_BYTES = 16 * 1024
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def database_url():
    value = os.environ.get("DATABASE_URL")
    if value:
        if value.startswith("postgres://"):
            return "postgresql://" + value[len("postgres://"):]
        return value
    if os.environ.get("RENDER"):
        raise RuntimeError("DATABASE_URL must be configured for the hosted service.")
    return "sqlite:///{}".format(DATABASE_FILE.replace("\\", "/"))


@contextmanager
def database_connection():
    url = database_url()
    if url.startswith("sqlite:///"):
        connection = sqlite3.connect(url[len("sqlite:///"):], timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        placeholder = "?"
    else:
        connection = psycopg.connect(url, row_factory=dict_row)
        placeholder = "%s"

    try:
        yield connection, placeholder
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password, stored_hash):
    try:
        algorithm, iterations, salt_hex, digest_hex = stored_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (AttributeError, ValueError):
        return False


def build_risk_payload(wifi_type):
    profiles = {
        "open": {
            "network": "Open Public WiFi",
            "risk": 85,
            "level": "HIGH RISK",
            "color": "#fb7185",
            "threats": [
                "Possible data interception",
                "Fake WiFi hotspot risks",
                "Man-in-the-Middle attack risks",
                "Packet sniffing risks",
            ],
            "advice": "Avoid sensitive activities on unknown open networks.",
        },
        "weak": {
            "network": "Weak Secured WiFi",
            "risk": 50,
            "level": "MEDIUM RISK",
            "color": "#fbbf24",
            "threats": [
                "Weak password risks",
                "Unauthorized access risks",
                "Suspicious login page risks",
            ],
            "advice": "Use a strong password and verify the network.",
        },
        "strong": {
            "network": "Strong Secured WiFi",
            "risk": 15,
            "level": "LOWER RISK",
            "color": "#4ade80",
            "threats": [
                "Misconfigured security risks",
                "Fake network name risks",
                "Risks from outdated devices",
            ],
            "advice": "Keep devices updated and continue safe browsing.",
        },
    }
    return profiles.get(wifi_type)


def initialize_database():
    statements = (
        """
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at BIGINT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            expires_at BIGINT NOT NULL
        )
        """,
    )
    with database_connection() as (connection, placeholder):
        for statement in statements:
            connection.execute(statement)

        if os.path.exists(LEGACY_USERS_FILE):
            import json

            with open(LEGACY_USERS_FILE, "r", encoding="utf-8") as legacy_file:
                legacy_users = json.load(legacy_file)
            if not isinstance(legacy_users, dict):
                raise ValueError("The legacy users file must contain a JSON object.")
            for email, record in legacy_users.items():
                if (
                    not isinstance(email, str)
                    or not isinstance(record, dict)
                    or not isinstance(record.get("password"), str)
                ):
                    raise ValueError("The legacy users file contains an invalid user record.")
                connection.execute(
                    """
                    INSERT INTO users (email, name, password_hash, created_at)
                    VALUES ({}, {}, {}, {})
                    ON CONFLICT (email) DO NOTHING
                    """.format(*([placeholder] * 4)),
                    (
                        email.strip().lower(),
                        str(record.get("name", "User")).strip() or "User",
                        hash_password(record["password"]),
                        int(time.time()),
                    ),
                )
    if os.path.exists(LEGACY_USERS_FILE):
        os.remove(LEGACY_USERS_FILE)


def create_app():
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_REQUEST_BYTES
    app.config["SECURE_COOKIES"] = os.environ.get("SECURE_COOKIES", "").lower() == "true"
    trusted_hosts = {
        host.strip()
        for host in os.environ.get("ALLOWED_HOSTS", "").split(",")
        if host.strip()
    }
    render_hostname = os.environ.get("RENDER_EXTERNAL_HOSTNAME")
    if render_hostname:
        trusted_hosts.add(render_hostname)
    if trusted_hosts:
        app.config["TRUSTED_HOSTS"] = sorted(trusted_hosts)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self' 'unsafe-inline'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.before_request
    def require_https_and_protect_api():
        if app.config["SECURE_COOKIES"] and not request.is_secure:
            secure_url = request.url.replace("http://", "https://", 1)
            return redirect(secure_url, code=308)
        if request.path.startswith("/api/") and request.method == "POST":
            origin = request.headers.get("Origin")
            if not origin:
                return jsonify(success=False, message="Request origin is required."), 403
            parsed = urlparse(origin)
            if parsed.scheme != request.scheme or parsed.netloc != request.host:
                return jsonify(success=False, message="Request origin is not allowed."), 403
            if request.mimetype != "application/json":
                return jsonify(success=False, message="Content-Type must be application/json."), 415

    def current_user():
        token = request.cookies.get(SESSION_COOKIE, "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,60}", token):
            return None
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        with database_connection() as (connection, placeholder):
            user = connection.execute(
                """
                SELECT users.email, users.name
                FROM sessions
                JOIN users ON users.email = sessions.email
                WHERE sessions.token_hash = {} AND sessions.expires_at > {}
                """.format(placeholder, placeholder),
                (token_hash, now),
            ).fetchone()
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= {}".format(placeholder),
                (now,),
            )
        return user

    def read_payload():
        if request.content_length is None or request.content_length <= 0:
            return None, (jsonify(success=False, message="Request body is missing."), 400)
        if request.content_length > MAX_REQUEST_BYTES:
            return None, (jsonify(success=False, message="Request body is too large."), 413)
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return None, (jsonify(success=False, message="Invalid JSON request."), 400)
        return payload, None

    def set_session_cookie(response, token, max_age):
        response.set_cookie(
            SESSION_COOKIE,
            token,
            max_age=max_age,
            httponly=True,
            secure=app.config["SECURE_COOKIES"],
            samesite="Lax",
            path="/",
        )
        return response

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/")
    @app.get("/index.html")
    def dashboard():
        if current_user() is None:
            return redirect("/login.html")
        return send_from_directory(BASE_DIR, "index.html")

    @app.get("/login.html")
    @app.get("/register.html")
    def account_page():
        if current_user() is not None:
            return redirect("/index.html")
        filename = "login.html" if request.path == "/login.html" else "register.html"
        return send_from_directory(BASE_DIR, filename)

    @app.get("/api/me")
    def me():
        user = current_user()
        if user is None:
            return jsonify(success=False, message="Please log in."), 401
        return jsonify(success=True, name=user["name"])

    @app.post("/api/register")
    def register():
        payload, error = read_payload()
        if error:
            return error
        name = payload.get("name")
        email = payload.get("email")
        password = payload.get("password")
        if not all(isinstance(value, str) for value in (name, email, password)):
            return jsonify(success=False, message="Enter a name, email, and password."), 400

        name = name.strip()
        email = email.strip().lower()
        if (
            not name
            or len(name) > 100
            or len(email) > 254
            or not EMAIL_PATTERN.fullmatch(email)
            or len(password) < 8
            or len(password) > 128
        ):
            return (
                jsonify(
                    success=False,
                    message="Enter a valid name and email, and use a password 8–128 characters long.",
                ),
                400,
            )

        try:
            with database_connection() as (connection, placeholder):
                connection.execute(
                    """
                    INSERT INTO users (email, name, password_hash, created_at)
                    VALUES ({}, {}, {}, {})
                    """.format(*([placeholder] * 4)),
                    (email, name, hash_password(password), int(time.time())),
                )
        except (sqlite3.IntegrityError, psycopg.errors.UniqueViolation):
            return jsonify(success=False, message="An account with this email already exists."), 409
        return jsonify(success=True, message="Account created. You can now log in."), 201

    @app.post("/api/login")
    def login():
        payload, error = read_payload()
        if error:
            return error
        email = payload.get("email")
        password = payload.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return jsonify(success=False, message="Email and password are required."), 400
        email = email.strip().lower()
        if len(email) > 254 or len(password) > 128:
            return jsonify(success=False, message="Invalid email or password."), 401

        with database_connection() as (connection, placeholder):
            user = connection.execute(
                "SELECT email, name, password_hash FROM users WHERE email = {}".format(placeholder),
                (email,),
            ).fetchone()
        if user is None or not verify_password(password, user["password_hash"]):
            return jsonify(success=False, message="Invalid email or password."), 401

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        now = int(time.time())
        with database_connection() as (connection, placeholder):
            connection.execute(
                "DELETE FROM sessions WHERE expires_at <= {}".format(placeholder),
                (now,),
            )
            connection.execute(
                """
                INSERT INTO sessions (token_hash, email, expires_at)
                VALUES ({}, {}, {})
                """.format(*([placeholder] * 3)),
                (token_hash, user["email"], now + SESSION_SECONDS),
            )

        response = make_response(
            jsonify(
                success=True,
                message="Login successful! Opening dashboard.",
                name=user["name"],
            )
        )
        return set_session_cookie(response, token, SESSION_SECONDS)

    @app.post("/api/logout")
    def logout():
        token = request.cookies.get(SESSION_COOKIE, "")
        if re.fullmatch(r"[A-Za-z0-9_-]{40,60}", token):
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            with database_connection() as (connection, placeholder):
                connection.execute(
                    "DELETE FROM sessions WHERE token_hash = {}".format(placeholder),
                    (token_hash,),
                )
        response = make_response(jsonify(success=True, message="Logged out."))
        return set_session_cookie(response, "", 0)

    @app.post("/api/risk")
    @app.post("/api/report")
    def risk_or_report():
        if current_user() is None:
            return jsonify(success=False, message="Please log in again."), 401
        payload, error = read_payload()
        if error:
            return error
        wifi_type = payload.get("wifiType")
        if not isinstance(wifi_type, str):
            return jsonify(success=False, message="Choose a valid network type."), 400
        risk = build_risk_payload(wifi_type.strip().lower())
        if risk is None:
            return jsonify(success=False, message="Choose a valid network type."), 400

        if request.path == "/api/risk":
            return jsonify(risk)
        report = (
            "PUBLIC WIFI RISK SCANNER REPORT\n\n"
            f"WiFi Type: {risk['network']}\n"
            f"Risk Level: {risk['level']}\n"
            f"Simulated Risk Score: {risk['risk']}%\n\n"
            "Safety Tips:\n"
            "1. Avoid banking on public WiFi.\n"
            "2. Use HTTPS websites.\n"
            "3. Disable automatic WiFi connection.\n"
            "4. Use a trusted VPN when appropriate.\n\n"
            "Educational simulation only. This is not a real network scan."
        )
        response = make_response(report)
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Content-Disposition"] = 'attachment; filename="WiFi_Risk_Report.txt"'
        return response

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify(success=False, message="Request body is too large."), 413

    return app


app = create_app()
initialize_database()
