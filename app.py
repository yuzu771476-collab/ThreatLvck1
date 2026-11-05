import os
import sqlite3
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import check_password_hash, generate_password_hash
from analyzer import analyze_url

app = Flask(__name__)
app.secret_key = os.environ.get("THREATLVCK_SECRET", "change-this-development-secret")
DATABASE = os.path.join(os.path.dirname(__file__), "threatlvck.db")

# Local demo credentials. Set THREATLVCK_USERNAME and THREATLVCK_PASSWORD in
# your environment before using this outside a classroom/demo environment.
LOGIN_USERNAME = os.environ.get("THREATLVCK_USERNAME", "admin")
LOGIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("THREATLVCK_PASSWORD", "ThreatLvck@123")
)

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                findings_count INTEGER NOT NULL
            )
        """)

init_db()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("home"))
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == LOGIN_USERNAME and check_password_hash(LOGIN_PASSWORD_HASH, password):
            session.clear()
            session["authenticated"] = True
            session["username"] = username
            return redirect(url_for("home"))
        error = "The username or password is incorrect."
    return render_template("login.html", error=error)

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("index.html", username=session.get("username", "Analyst"))

@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html", username=session.get("username", "Analyst"))


@app.route("/scan", methods=["POST"])
@login_required
def scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "Please enter a URL."}), 400
    try:
        result = analyze_url(url)
        with get_db() as db:
            db.execute(
                """INSERT INTO scans (scanned_at, url, risk_score, status, findings_count)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    result.get("url", url.strip()),
                    int(result.get("risk_score", 0)),
                    str(result.get("status", "UNKNOWN")),
                    len(result.get("findings", []))
                )
            )
        app.logger.info("Scan completed: score=%s, status=%s",
                        result["risk_score"], result["status"])
        return jsonify(result)
    except Exception:
        app.logger.exception("URL scan failed")
        return jsonify({"error": "The scan failed. Check the VS Code terminal."}), 500

@app.route("/api/analytics")
@login_required
def analytics_data():
    with get_db() as db:
        rows = db.execute(
            "SELECT id, scanned_at, url, risk_score, status, findings_count "
            "FROM scans ORDER BY id DESC LIMIT 100"
        ).fetchall()
    scans = [dict(row) for row in rows]
    scores = [item["risk_score"] for item in scans]
    total = len(scans)
    high = sum(1 for item in scans if item["risk_score"] >= 40)
    suspicious = sum(1 for item in scans if 15 <= item["risk_score"] < 40)
    low = sum(1 for item in scans if item["risk_score"] < 15)
    return jsonify({
        "scans": scans,
        "total_scans": total,
        "average_score": round(sum(scores) / total, 1) if total else 0,
        "highest_score": max(scores) if scores else 0,
        "high_risk": high,
        "suspicious": suspicious,
        "lower_risk": low
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
