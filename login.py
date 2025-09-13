from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_file, abort
)
from datetime import timedelta, datetime
from functools import wraps
from werkzeug.utils import secure_filename, safe_join
import os, json, threading, uuid, re

app = Flask(__name__)

# ---- basic config ----
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
app.permanent_session_lifetime = timedelta(hours=2)

BASE_DIR = os.environ.get("DATA_DIR", os.path.dirname(__file__))


USERS_FILE    = os.path.join(BASE_DIR, "users.json")
RECORDS_FILE  = os.path.join(BASE_DIR, "records.json")   # user records/invoices
RECEIPTS_FILE = os.path.join(BASE_DIR, "receipts.json")  # admin "money received"
UPLOAD_DIR    = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
_lock = threading.Lock()

# Choices
PAYMENT_METHODS = ["cash", "card", "check", "bank transfer", "petty cash"]
PAYMENT_STATUS  = ["paid", "unpaid", "partially paid"]
APPROVAL_STATUS = ["pending", "confirmed", "not confirmed"]

# ---- user store (PLAINTEXT for demo). Supports {user:"pass"} and {user:{password,role}} ----
def _normalize_users(data):
    out = {}
    if isinstance(data, dict):
        for u, v in data.items():
            if isinstance(v, dict):
                out[u] = {"password": v.get("password",""), "role": v.get("role","user")}
            else:
                out[u] = {"password": str(v), "role": "user"}
    return out

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return _normalize_users(json.load(f))
    except Exception:
        return {}

def save_users(users_dict):
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users_dict, f, indent=2, ensure_ascii=False)
    os.replace(tmp, USERS_FILE)

def is_admin_user(username):
    admins_env = os.environ.get("ADMIN_USERS", "")
    admin_set = {u.strip() for u in admins_env.split(",") if u.strip()}
    users = load_users()
    if username in users and users[username].get("role") == "admin":
        return True
    if username in admin_set:
        return True
    return False

# ---- JSON stores ----
def _load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, type(default)) else default
    except Exception:
        return default

def _save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)

def load_records():  return _load_json(RECORDS_FILE, [])
def save_records(v): _save_json(RECORDS_FILE, v)

def load_receipts():  return _load_json(RECEIPTS_FILE, [])
def save_receipts(v): _save_json(RECEIPTS_FILE, v)

# ---- helpers ----
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def safe_user_dir(username: str):
    """Return (absolute_path, slug) for a user's upload folder."""
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", username)
    path = os.path.join(UPLOAD_DIR, slug)
    os.makedirs(path, exist_ok=True)
    return path, slug

# ---- routes: auth ----
@app.route("/", methods=["GET"])
def index():
    if "user" in session:
        return redirect(url_for("records"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()
        if username in users and users[username]["password"] == password:
            session.permanent = True
            session["user"] = username
            role = users[username].get("role", "user")
            if is_admin_user(username):
                role = "admin"
            session["role"] = role
            return redirect(url_for("records"))
        flash("Warning: wrong username or password.")
    return render_template("login.html")

@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
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
        role = "admin" if username.lower() == "admin" else "user"
        users[username] = {"password": password, "role": role}
        save_users(users)
    flash("Account created. Please log in.")
    return redirect(url_for("login"))

@app.route("/logout")
def logout():
    session.pop("user", None)
    session.pop("role", None)
    flash("You have been logged out.")
    return redirect(url_for("login"))

# ---- records page (with correct totals: paid amounts only) ----
@app.route("/records")
@login_required
def records():
    all_records = sorted(load_records(), key=lambda r: r.get("created_at",""), reverse=True)
    all_receipts = load_receipts()
    current_user = session["user"]

    def paid_amount(r):
        status = (r.get("payment_status") or "").lower()
        total  = float(r.get("total_amount") or 0)
        paid   = float(r.get("amount_paid")  or 0)
        if status == "partially paid":
            return paid
        elif status == "paid":
            return paid if paid > 0 else total
        else:
            return 0.0

    # Spending = money actually paid on CONFIRMED records
    spending_confirmed = sum(
        paid_amount(r)
        for r in all_records
        if r.get("recorded_by") == current_user and r.get("approval_status") == "confirmed"
    )

    received_total = sum(
        float(rc.get("amount") or 0)
        for rc in all_receipts
        if rc.get("to_user") == current_user
    )

    balance = received_total - spending_confirmed

    my_receipts = [rc for rc in all_receipts if rc.get("to_user") == current_user]
    my_receipts.sort(key=lambda x: (x.get("date") or "", x.get("created_at") or ""), reverse=True)

    return render_template(
        "records.html",
        records=all_records,
        my_receipts=my_receipts,
        spending_confirmed=spending_confirmed,
        received_total=received_total,
        balance=balance
    )

@app.route("/record/new", methods=["GET", "POST"])
@login_required
def record_new():
    if request.method == "POST":
        data = {
            "id": str(uuid.uuid4()),
            "project_number": request.form.get("project_number","").strip(),
            "document_number": request.form.get("document_number","").strip(),
            "cost_center": request.form.get("cost_center","").strip(),
            "counterparty": request.form.get("counterparty","").strip(),
            "payment_method": request.form.get("payment_method","").strip(),
            "payment_due_date": request.form.get("payment_due_date","").strip(),
            "deductions": request.form.get("deductions","").strip(),
            "unit_of_measure": request.form.get("unit_of_measure","").strip(),
            "quantity": request.form.get("quantity","").strip(),
            "description": request.form.get("description","").strip(),
            "payment_status": request.form.get("payment_status","").strip(),
            "recorded_by": session.get("user"),
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "attachments": [],
            # Approval / audit
            "approval_status": "pending",
            "approval_action_by": "",
            "approval_action_at": ""
        }

        # Required base fields
        if not data["project_number"] or not data["document_number"]:
            flash("Project Number and Document/Invoice Number are required.")
            return redirect(url_for("record_new"))

        # ---- Amounts ----
        status = (data["payment_status"] or "").lower()
        amount_paid_raw = request.form.get("amount_paid", "").strip()
        total_amount_raw = request.form.get("total_amount", "").strip()  # required only for partially paid

        # Amount Paid is ALWAYS required
        if amount_paid_raw == "":
            flash("Amount Paid is required.")
            return redirect(url_for("record_new"))
        try:
            amount_paid_val = round(float(amount_paid_raw), 2)
        except ValueError:
            flash("Amount Paid must be a number.")
            return redirect(url_for("record_new"))
        if amount_paid_val < 0:
            flash("Amount Paid cannot be negative.")
            return redirect(url_for("record_new"))

        if status == "partially paid":
            # Total required only here
            if total_amount_raw == "":
                flash("Total Amount is required for partially paid status.")
                return redirect(url_for("record_new"))
            try:
                total_amount_val = round(float(total_amount_raw), 2)
            except ValueError:
                flash("Total Amount must be a number.")
                return redirect(url_for("record_new"))
            if total_amount_val <= 0:
                flash("Total Amount must be greater than 0 for partially paid.")
                return redirect(url_for("record_new"))
            if not (0 < amount_paid_val < total_amount_val):
                flash("For partially paid, Amount Paid must be > 0 and < Total Amount.")
                return redirect(url_for("record_new"))
            data["total_amount"] = f"{total_amount_val:.2f}"
            data["amount_paid"]  = f"{amount_paid_val:.2f}"

        elif status == "paid":
            if amount_paid_val == 0:
                flash("For paid status, Amount Paid must be > 0.")
                return redirect(url_for("record_new"))
            data["total_amount"] = ""  # not meaningful here
            data["amount_paid"]  = f"{amount_paid_val:.2f}"

        else:  # unpaid
            if amount_paid_val != 0:
                flash("For unpaid status, Amount Paid must be 0.")
                return redirect(url_for("record_new"))
            data["total_amount"] = ""
            data["amount_paid"]  = "0.00"

        # ---- Save attachments to per-user folder (multi-upload) ----
        files = request.files.getlist("attachments[]")
        user_dir_abs, user_dir_slug = safe_user_dir(session["user"])
        for f in files:
            if not f or not f.filename:
                continue
            safe_name = secure_filename(f.filename)
            unique_name = f"{data['id']}_{safe_name}"
            f.save(os.path.join(user_dir_abs, unique_name))
            data["attachments"].append(f"{user_dir_slug}/{unique_name}")  # relative path

        with _lock:
            recs = load_records()
            recs.append(data)
            save_records(recs)

        flash("Record saved.")
        return redirect(url_for("records"))

    return render_template(
        "record.html",
        payment_methods=PAYMENT_METHODS,
        payment_statuses=PAYMENT_STATUS
    )

@app.route("/record/<rid>/delete", methods=["POST"])
@login_required
def record_delete(rid):
    with _lock:
        recs = load_records()
        new_recs, deleted = [], False
        for r in recs:
            if r.get("id") == rid:
                is_owner = r.get("recorded_by") == session.get("user")
                is_admin = session.get("role") == "admin"
                if r.get("approval_status") == "pending" and (is_owner or is_admin):
                    deleted = True
                    continue
            new_recs.append(r)
        save_records(new_recs)
    flash("Record removed." if deleted else "You can only remove pending records that you created.")
    return redirect(url_for("records"))

# ---- Admin: confirm / reject ----
def _set_approval_status(rid, status, actor):
    assert status in {"confirmed", "not confirmed"}
    with _lock:
        recs = load_records()
        changed = False
        now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        for r in recs:
            if r.get("id") == rid:
                r["approval_status"]   = status
                r["approval_action_by"] = actor
                r["approval_action_at"] = now
                changed = True
                break
        if changed:
            save_records(recs)
    return changed

@app.route("/record/<rid>/approve", methods=["POST"])
@login_required
@admin_required
def record_approve(rid):
    flash("Record confirmed." if _set_approval_status(rid, "confirmed", session["user"]) else "Record not found.")
    return redirect(url_for("records"))

@app.route("/record/<rid>/reject", methods=["POST"])
@login_required
@admin_required
def record_reject(rid):
    flash("Record rejected." if _set_approval_status(rid, "not confirmed", session["user"]) else "Record not found.")
    return redirect(url_for("records"))

# ---- Admin: receipts (money received from users) ----
@app.route("/admin/receipts", methods=["GET", "POST"])
@login_required
@admin_required
def admin_receipts():
    users = sorted(load_users().keys())
    if request.method == "POST":
        to_user   = request.form.get("to_user","").strip()
        amount_s  = request.form.get("amount","").strip()
        date_s    = request.form.get("date","").strip()      # YYYY-MM-DD
        number    = request.form.get("number","").strip()    # receipt/chq number
        method    = request.form.get("method","").strip()
        if not to_user or to_user not in users:
            flash("Select a valid user.")
            return redirect(url_for("admin_receipts"))
        if not amount_s or not date_s or not method:
            flash("Amount, Date and Method are required.")
            return redirect(url_for("admin_receipts"))
        try:
            amount_v = round(float(amount_s), 2)
        except ValueError:
            flash("Amount must be a number.")
            return redirect(url_for("admin_receipts"))
        if amount_v <= 0:
            flash("Amount must be positive.")
            return redirect(url_for("admin_receipts"))

        # Store attachment in the *user's* folder
        attach_rel = ""
        file = request.files.get("attachment")
        if file and file.filename:
            user_dir_abs, user_dir_slug = safe_user_dir(to_user)
            safe_name = secure_filename(file.filename)
            rid = str(uuid.uuid4())
            unique_name = f"receipt_{rid}_{safe_name}"
            file.save(os.path.join(user_dir_abs, unique_name))
            attach_rel = f"{user_dir_slug}/{unique_name}"

        rec = {
            "id": str(uuid.uuid4()),
            "to_user": to_user,
            "amount": f"{amount_v:.2f}",
            "date": date_s,
            "number": number,
            "method": method,
            "attachment": attach_rel,
            "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "created_by": session["user"]
        }
        with _lock:
            lst = load_receipts()
            lst.append(rec)
            save_receipts(lst)
        flash("Receipt recorded.")
        return redirect(url_for("admin_receipts"))

    receipts = sorted(load_receipts(), key=lambda r: (r.get("date",""), r.get("created_at","")), reverse=True)
    return render_template("admin_receipts.html", users=users, receipts=receipts, payment_methods=PAYMENT_METHODS)

# ---- serve uploaded files (supports subfolders) ----
@app.route("/uploads/<path:filepath>")
@login_required
def uploaded_file(filepath):
    safe_path = safe_join(UPLOAD_DIR, filepath)
    if not safe_path or not os.path.isfile(safe_path):
        abort(404)
    return send_file(safe_path)

if __name__ == "__main__":
    if not os.path.exists(USERS_FILE):
        save_users({})
    if not os.path.exists(RECORDS_FILE):
        save_records([])
    if not os.path.exists(RECEIPTS_FILE):
        save_receipts([])
    app.run(debug=True)
