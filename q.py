from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import timedelta
import os, json, threading

app = Flask(__name__)

# SECURITY WARNING:
# Storing plaintext passwords is unsafe. Do not use this in real apps.
# This is for demonstration only.
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.permanent_session_lifetime = timedelta(hours=2)

USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
_lock = threading.Lock()

def load_users():
    """Load user store from JSON, return {username: plaintext_password}."""
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}

def save_users(users_dict):
    """Persist user store to JSON atomically."""
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users_dict, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_FILE)

@app.route("/", methods=["GET"])
def index():
    if "user" in session:
        return (
            f"<main style='font-family:system-ui, -apple-system, Segoe UI, Roboto, sans-serif;"
            f"background:#000;color:#fff;min-height:100vh;display:grid;place-items:center;'>"
            f"<div style='text-align:center'>"
            f"<h1 style='margin:0 0 1rem 0;font-weight:600;'>Welcome, {session['user']}</h1>"
            f"<a href='{url_for('logout')}' "
            f"style='color:#000;background:#fff;padding:.6rem 1rem;border-radius:.5rem;"
            f"text-decoration:none;display:inline-block'>Log out</a>"
            f"</div></main>"
        )
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()
        # Plaintext comparison
        if username in users and users[username] == password:
            session.permanent = True
            session["user"] = username
            return redirect(url_for("index"))
        # Show warning if wrong creds (user OR pass)
        flash("Warning: wrong username or password.")
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # minimal validation
    if not username or not password:
        flash("Username and password are required.")
        return redirect(url_for("login"))
    if len(username) < 3:
        flash("Username must be at least 3 characters.")
        return redirect(url_for("login"))
    if len(password) < 6:
        flash("Password must be at least 6 characters.")
        return redirect(url_for("login"))

    with _lock:
        users = load_users()
        if username in users:
            flash("Username is already taken.")
            return redirect(url_for("login"))
        # Store plaintext (⚠️ insecure)
        users[username] = password
        save_users(users)

    flash("Account created. Please sign in.")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    if not os.path.exists(USERS_FILE):
        save_users({})
    app.run(debug=True)
