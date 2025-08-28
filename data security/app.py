from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import sqlite3, os, hmac, hashlib, json
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecret-change-this"  # for sessions/flash

DB_PATH = "employees.db"
KEY_PATH = "secret.key"
DTP_SECRET = app.secret_key  # HMAC signing key for DTP

# ---------- Encryption key ----------
def load_or_create_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    return key

key = load_or_create_key()
cipher = Fernet(key)

# ---------- DB Helpers ----------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _now_ts():
    return datetime.utcnow().isoformat() + "Z"

def _hmac_sign(payload: str) -> str:
    return hmac.new(DTP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

# ---------- DB init ----------
def init_db():
    conn = get_conn()
    cur = conn.cursor()
    # Existing tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS employee (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    # DTP tables
    cur.execute("""
        CREATE TABLE IF NOT EXISTS t1 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            t1_payload TEXT NOT NULL,
            signature TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS t2 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            t1_id INTEGER,
            received_payload TEXT NOT NULL,
            signature TEXT NOT NULL,
            received_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS t3 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            t1_id INTEGER,
            original_payload TEXT NOT NULL,
            received_payload TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL, -- ok or tampered
            note TEXT,
            ts TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# ---------- DTP Functions ----------
def insert_into_t1(payload_dict: dict) -> int:
    payload = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True)
    sig = _hmac_sign(payload)
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO t1 (t1_payload, signature, created_at) VALUES (?, ?, ?)",
                (payload, sig, _now_ts()))
    conn.commit()
    t1_id = cur.lastrowid
    conn.close()
    return t1_id

def transfer_row(t1_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM t1 WHERE id = ?", (t1_id,))
    src = cur.fetchone()
    if not src:
        conn.close()
        raise ValueError("t1 row not found")

    original_payload = src["t1_payload"]
    signature = src["signature"]

    # Transfer to t2
    cur.execute("INSERT INTO t2 (t1_id, received_payload, signature, received_at) VALUES (?, ?, ?, ?)",
                (t1_id, original_payload, signature, _now_ts()))
    t2_id = cur.lastrowid

    # Verify integrity
    recomputed = _hmac_sign(original_payload)
    is_valid = hmac.compare_digest(recomputed, signature)
    status = "ok" if is_valid else "tampered"
    note = "" if is_valid else "Signature mismatch!"

    # Log in t3
    cur.execute("""
        INSERT INTO t3 (t1_id, original_payload, received_payload, signature, status, note, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (t1_id, original_payload, original_payload, signature, status, note, _now_ts()))
    t3_id = cur.lastrowid

    conn.commit()
    conn.close()
    return {"t1_id": t1_id, "t2_id": t2_id, "t3_id": t3_id, "status": status}

def transfer_all():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM t1")
    ids = [r["id"] for r in cur.fetchall()]
    conn.close()
    results = []
    for t1_id in ids:
        results.append(transfer_row(t1_id))
    return results

# ---------- Routes ----------
@app.route("/")
def index():
    return render_template("index.html")

# --- Admin signup/login ---
@app.route("/admin_signup", methods=["GET","POST"])
def admin_signup():
    if request.method=="POST":
        username=request.form["username"].strip()
        email=request.form["email"].strip().lower()
        raw_pass=request.form["password"]
        enc_pass=cipher.encrypt(raw_pass.encode()).decode()
        try:
            conn=get_conn()
            cur=conn.cursor()
            cur.execute("INSERT INTO admin (username,email,password) VALUES (?,?,?)",
                        (username,email,enc_pass))
            conn.commit()
            flash("Admin registered successfully.","success")
            return redirect(url_for("admin_login"))
        except sqlite3.IntegrityError:
            flash("Admin email already exists.","danger")
        finally:
            conn.close()
    return render_template("admin_signup.html")

@app.route("/admin_login", methods=["GET","POST"])
def admin_login():
    if request.method=="POST":
        email=request.form["email"].strip().lower()
        password=request.form["password"]
        conn=get_conn()
        cur=conn.cursor()
        cur.execute("SELECT id,username,email,password FROM admin WHERE email=?",(email,))
        row=cur.fetchone()
        conn.close()
        if row:
            try:
                if cipher.decrypt(row[3].encode()).decode() == password:
                    session["admin_email"]=row[2]
                    session["admin_username"]=row[1]
                    return redirect(url_for("admin_dashboard"))
            except Exception:
                pass
        flash("Invalid admin credentials.","danger")
    return render_template("admin_login.html")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "admin_email" not in session:
        return redirect(url_for("admin_login"))
    conn=get_conn()
    cur=conn.cursor()
    cur.execute("SELECT id,name,email,password FROM employee ORDER BY id DESC")
    employees=cur.fetchall()
    # fetch t2 + latest t3 status
    cur.execute("""
        SELECT t2.id as t2_id, t2.t1_id, t2.received_payload, t2.signature, t2.received_at,
               t3.status as latest_status, t3.note as latest_note
        FROM t2
        LEFT JOIN (
            SELECT t1_id, status, note, MAX(ts) as mts
            FROM t3
            GROUP BY t1_id
        ) t3 ON t2.t1_id = t3.t1_id
        ORDER BY t2.id DESC
    """)
    t2_entries=cur.fetchall()
    conn.close()
    return render_template("admin_dashboard.html",
                           employees=employees,
                           t2_entries=t2_entries,
                           admin_name=session.get("admin_username","Admin"))

# --- Employee signup/login ---
@app.route("/employee_signup", methods=["GET","POST"])
def employee_signup():
    if request.method=="POST":
        name=request.form["name"].strip()
        email=request.form["email"].strip().lower()
        raw_pass=request.form["password"]
        enc_pass=cipher.encrypt(raw_pass.encode()).decode()
        try:
            conn=get_conn()
            cur=conn.cursor()
            cur.execute("INSERT INTO employee (name,email,password) VALUES (?,?,?)",
                        (name,email,enc_pass))
            conn.commit()
            # insert into t1 for DTP
            payload={"name":name,"email":email,"password_enc":enc_pass}
            insert_into_t1(payload)
            flash("Employee registered successfully. Please login.","success")
            return redirect(url_for("employee_login"))
        except sqlite3.IntegrityError:
            flash("Employee email already exists.","danger")
        finally:
            conn.close()
    return render_template("employee_signup.html")

@app.route("/employee_login", methods=["GET","POST"])
def employee_login():
    if request.method=="POST":
        email=request.form["email"].strip().lower()
        password=request.form["password"]
        conn=get_conn()
        cur=conn.cursor()
        cur.execute("SELECT id,name,email,password FROM employee WHERE email=?",(email,))
        row=cur.fetchone()
        conn.close()
        if row:
            try:
                if cipher.decrypt(row[3].encode()).decode() == password:
                    session["employee_email"]=row[2]
                    session["employee_name"]=row[1]
                    flash(f"Welcome {row[1]}!","success")
                    return redirect(url_for("index"))
            except Exception:
                pass
        flash("Invalid employee credentials.","danger")
    return render_template("employee_login.html")

# --- Permission popup (fix for earlier BuildError) ---
@app.route("/popup_permission", methods=["GET", "POST"])
def popup_permission():
    decrypted_value = None
    if request.method == "POST":
        enc_value = request.form["enc_value"].strip()
        try:
            decrypted_value = cipher.decrypt(enc_value.encode()).decode()
            flash("Permission verified (value decrypted successfully).", "success")
        except Exception:
            flash("Invalid encrypted value.", "danger")
    return render_template("popup_permission.html", decrypted_value=decrypted_value)

# --- Transfer routes ---
@app.route("/transfer/<int:t1_id>")
def transfer_one_route(t1_id):
    try:
        res = transfer_row(t1_id)
        flash(f"Transferred t1_id={t1_id}, status={res['status']}","info")
    except Exception as e:
        flash(str(e),"danger")
    return redirect(url_for("admin_dashboard"))

@app.route("/transfer_all")
def transfer_all_route():
    results = transfer_all()
    flash(f"Transferred {len(results)} rows.","info")
    return redirect(url_for("admin_dashboard"))

# --- Debug DTP ---
@app.route("/_debug/dtp_status")
def dtp_status():
    conn=get_conn()
    cur=conn.cursor()
    cur.execute("SELECT * FROM t1 ORDER BY id DESC")
    t1=[dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM t2 ORDER BY id DESC")
    t2=[dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM t3 ORDER BY id DESC")
    t3=[dict(r) for r in cur.fetchall()]
    conn.close()
    return jsonify({"t1":t1,"t2":t2,"t3":t3})

# --- Logouts ---
@app.route("/admin_logout")
def admin_logout():
    session.pop("admin_email",None)
    session.pop("admin_username",None)
    return redirect(url_for("index"))

@app.route("/employee_logout")
def employee_logout():
    session.pop("employee_email",None)
    session.pop("employee_name",None)
    return redirect(url_for("index"))

if __name__=="__main__":
    app.run(debug=True)
