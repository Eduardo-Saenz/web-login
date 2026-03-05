import hashlib
import hmac
import logging
import os
import sqlite3
from logging.handlers import RotatingFileHandler
from typing import Optional

import bcrypt
from flask import Flask, flash, redirect, render_template, request, session, url_for

DB_PATH = "users.db"
MAX_FAILED_ATTEMPTS = 5

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# Key used only to generate non-reversible password fingerprints in logs.
PW_FINGERPRINT_KEY = os.environ.get("PW_FINGERPRINT_KEY", app.config["SECRET_KEY"])



def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn



def setup_logging() -> None:
    log_handler = RotatingFileHandler("auth.log", maxBytes=1_000_000, backupCount=3)
    log_handler.setLevel(logging.INFO)
    log_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))

    app.logger.handlers = []
    app.logger.addHandler(log_handler)
    app.logger.setLevel(logging.INFO)



def password_fingerprint(raw_password: str) -> str:
    digest = hmac.new(
        PW_FINGERPRINT_KEY.encode("utf-8"),
        raw_password.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest



def log_auth_attempt(
    outcome: str,
    username: str,
    attempts: Optional[int] = None,
    raw_password: Optional[str] = None,
) -> None:
    ip = request.remote_addr or "unknown"
    user_agent = (request.headers.get("User-Agent") or "unknown")[:180]
    attempts_text = str(attempts) if attempts is not None else "N/A"

    log_parts = [
        f"ip={ip}",
        f"username={username}",
        f"outcome={outcome}",
        f"attempts={attempts_text}",
        f'user_agent="{user_agent}"',
    ]

    if raw_password is not None:
        log_parts.append(f"pw_fingerprint={password_fingerprint(raw_password)}")

    app.logger.info(" ".join(log_parts))



def init_db() -> None:
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER DEFAULT 0,
                is_locked BOOLEAN DEFAULT 0
            )
            """
        )
        conn.commit()



def seed_admin_user() -> None:
    admin_username = "admin"
    admin_password = "SecurePass123"

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?", (admin_username,)
        ).fetchone()
        if user:
            return

        hashed = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (admin_username, hashed),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            # Safe fallback if another process inserted at same time.
            conn.rollback()



@app.route("/", methods=["GET"])
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    with get_db_connection() as conn:
        user = conn.execute(
            "SELECT id, username, password_hash, failed_attempts, is_locked FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None:
            flash("Usuario o contraseña incorrectos.", "error")
            log_auth_attempt(
                outcome="FAIL_UNKNOWN_USER",
                username=username,
                attempts=None,
                raw_password=password,
            )
            return render_template("login.html"), 401

        if bool(user["is_locked"]):
            flash("Cuenta bloqueada.", "error")
            log_auth_attempt(
                outcome="FAIL_LOCKED",
                username=username,
                attempts=int(user["failed_attempts"]),
                raw_password=password,
            )
            return render_template("login.html"), 403

        password_ok = bcrypt.checkpw(
            password.encode("utf-8"), user["password_hash"].encode("utf-8")
        )

        if password_ok:
            conn.execute(
                "UPDATE users SET failed_attempts = 0 WHERE id = ?",
                (user["id"],),
            )
            conn.commit()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            log_auth_attempt(
                outcome="SUCCESS",
                username=username,
                attempts=0,
                raw_password=password,
            )
            return redirect(url_for("dashboard"))

        new_attempts = int(user["failed_attempts"]) + 1
        should_lock = new_attempts >= MAX_FAILED_ATTEMPTS

        # Lock is permanent unless changed manually in the DB.
        conn.execute(
            "UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?",
            (new_attempts, int(should_lock), user["id"]),
        )
        conn.commit()

        flash("Usuario o contraseña incorrectos.", "error")
        log_auth_attempt(
            outcome="FAIL_BAD_CREDENTIALS",
            username=username,
            attempts=new_attempts,
            raw_password=password,
        )
        return render_template("login.html"), 401


@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session.get("username", ""))


@app.route("/logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    setup_logging()
    init_db()
    seed_admin_user()
    app.run(debug=False)
