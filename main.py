import os
import io
import re
import sqlite3
import datetime
import hashlib
import secrets
import jwt
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Security, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

SECRET_KEY = os.environ.get("SECRET_KEY", "VASTU_HFC_RECONCILIATION_SECRET_KEY_2026")
ALGORITHM = "HS256"
DB_PATH = os.environ.get("DB_PATH", "vastu_reconciliation.db")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

app = FastAPI(
    title="Vastu Housing Finance - Repayment Reconciliation System",
    description="Production-grade Full Stack Automated Multi-Channel Repayment Reconciliation Engine",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reconciliation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        run_by TEXT NOT NULL,
        total_records INTEGER,
        matched_records INTEGER,
        exception_records INTEGER,
        auto_match_rate REAL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        user TEXT NOT NULL,
        reference_id TEXT NOT NULL,
        action TEXT NOT NULL,
        notes TEXT
    )
    """)

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO users (username, password, full_name, role) VALUES ('admin', ?, 'Rajesh Sharma (Admin)', 'Finance Director')", (hash_password('admin123'),))
        cursor.execute("INSERT INTO users (username, password, full_name, role) VALUES ('ops', ?, 'Priya Verma (Ops)', 'Reconciliation Manager')", (hash_password('ops123'),))
        cursor.execute("INSERT INTO users (username, password, full_name, role) VALUES ('auditor', ?, 'Amit Kumar (Auditor)', 'Internal Auditor')", (hash_password('audit123'),))

    conn.commit()
    conn.close()

init_db()

class LoginRequest(BaseModel):
    username: str
    password: str

class ManualMatchRequest(BaseModel):
    reference_id: str
    account_id: str
    notes: str

class CSVDataInput(BaseModel):
    payment_csv: str
    ledger_csv: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=12)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def parse_csv_rows(text: str):
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return []
    headers = [h.strip().lower() for h in lines[0].split(',')]
    rows = []
    for line in lines[1:]:
        cells = [c.strip() for c in line.split(',')]
        row = {}
        for i, h in enumerate(headers):
            row[h] = cells[i] if i < len(cells) else ""
        rows.append(row)
    return rows

@app.post("/api/login")
def login(req: LoginRequest):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (req.username,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials. Try username: 'admin' and password: 'admin123'")

    stored_pw = user["password"]
    hashed_input = hash_password(req.password)
    if stored_pw != hashed_input and stored_pw != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials. Try username: 'admin' and password: 'admin123'")

    token = create_access_token({"sub": user["username"], "name": user["full_name"], "role": user["role"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"]
    }

@app.get("/api/me")
def get_me(user: dict = Depends(get_current_user)):
    return user

@app.post("/api/reconcile")
def run_reconciliation_api(data: CSVDataInput, user: dict = Depends(get_current_user)):
    payment_rows = parse_csv_rows(data.payment_csv)
    ledger_rows = parse_csv_rows(data.ledger_csv)

    if not payment_rows or not ledger_rows:
        raise HTTPException(status_code=400, detail="Payment and Ledger CSV content required.")

    ledger_map = {}
    for r in ledger_rows:
        ref = r.get("reference_id")
        if ref and ref not in ledger_map:
            ledger_map[ref] = r

    results = []
    payment_seen = set()

    for row in payment_rows:
        ref = row.get("reference_id")
        if not ref:
            continue

        if ref in payment_seen:
            results.append({
                "reference_id": ref, "account_id": row.get("account_id", ""),
                "pay_amount": row.get("amount", ""), "ledger_amount": "",
                "pay_date": row.get("payment_date", ""), "ledger_date": "",
                "status": "duplicate", "note": "Duplicate transaction reference in payment file"
            })
            continue

        payment_seen.add(ref)
        ledger = ledger_map.get(ref)

        if not ledger:
            results.append({
                "reference_id": ref, "account_id": row.get("account_id", ""),
                "pay_amount": row.get("amount", ""), "ledger_amount": "",
                "pay_date": row.get("payment_date", ""), "ledger_date": "",
                "status": "missing_in_ledger", "note": "Payment received, no matching ledger entry"
            })
            continue

        try:
            pay_amt = float(row.get("amount", 0))
            ledg_amt = float(ledger.get("amount", 0))
            amt_match = abs(pay_amt - ledg_amt) < 0.01
        except:
            amt_match = False

        date_match = row.get("payment_date") == ledger.get("due_date")

        if amt_match and date_match:
            status_code = "matched"
            note_str = "Exact match across Reference, Amount, and Date"
        elif not amt_match:
            status_code = "amount_mismatch"
            note_str = f"Ledger expected {ledger.get('amount')}, received {row.get('amount')}"
        else:
            status_code = "date_mismatch"
            note_str = f"Due date {ledger.get('due_date')}, paid on {row.get('payment_date')}"

        results.append({
            "reference_id": ref,
            "account_id": row.get("account_id") or ledger.get("account_id"),
            "pay_amount": row.get("amount"),
            "ledger_amount": ledger.get("amount"),
            "pay_date": row.get("payment_date"),
            "ledger_date": ledger.get("due_date"),
            "status": status_code,
            "note": note_str
        })

    for r in ledger_rows:
        ref = r.get("reference_id")
        if ref and ref not in payment_seen:
            results.append({
                "reference_id": ref, "account_id": r.get("account_id"),
                "pay_amount": "", "ledger_amount": r.get("amount"),
                "pay_date": "", "ledger_date": r.get("due_date"),
                "status": "missing_in_payment", "note": "Ledger expects this repayment, no bank credit received"
            })

    total = len(results)
    matched = sum(1 for r in results if r["status"] == "matched")
    exceptions = total - matched
    match_rate = round((matched / total * 100), 2) if total > 0 else 0

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO reconciliation_runs (run_by, total_records, matched_records, exception_records, auto_match_rate)
    VALUES (?, ?, ?, ?, ?)
    """, (user.get("name", "User"), total, matched, exceptions, match_rate))
    conn.commit()
    conn.close()

    return {
        "summary": {
            "total": total,
            "matched": matched,
            "exceptions": exceptions,
            "auto_match_rate": match_rate,
            "amount_mismatch": sum(1 for r in results if r["status"] == "amount_mismatch"),
            "date_mismatch": sum(1 for r in results if r["status"] == "date_mismatch"),
            "missing_in_ledger": sum(1 for r in results if r["status"] == "missing_in_ledger"),
            "missing_in_payment": sum(1 for r in results if r["status"] == "missing_in_payment"),
            "duplicate": sum(1 for r in results if r["status"] == "duplicate")
        },
        "results": results
    }

@app.post("/api/reconcile-upload")
async def reconcile_upload(
    payment_file: UploadFile = File(...),
    ledger_file: UploadFile = File(...),
    user: dict = Depends(get_current_user)
):
    try:
        payment_bytes = await payment_file.read()
        ledger_bytes = await ledger_file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"File read error: {str(e)}")

    if len(payment_bytes) > 10_000_000 or len(ledger_bytes) > 10_000_000:
        raise HTTPException(status_code=413, detail="File too large. Maximum 10 MB per file.")

    payment_csv = payment_bytes.decode("utf-8", errors="replace")
    ledger_csv = ledger_bytes.decode("utf-8", errors="replace")

    payment_rows = parse_csv_rows(payment_csv)
    ledger_rows = parse_csv_rows(ledger_csv)

    if not payment_rows:
        raise HTTPException(status_code=400, detail="Payment file is empty.")
    if not ledger_rows:
        raise HTTPException(status_code=400, detail="Ledger file is empty.")

    data = CSVDataInput(payment_csv=payment_csv, ledger_csv=ledger_csv)
    return run_reconciliation_api(data, user)

@app.post("/api/manual-match")
def manual_match(req: ManualMatchRequest, user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO audit_trail (user, reference_id, action, notes)
    VALUES (?, ?, ?, ?)
    """, (user.get("name", "User"), req.reference_id, "MANUAL_RECONCILE_LINK", f"Linked to Acc {req.account_id}: {req.notes}"))
    conn.commit()
    conn.close()
    return {"status": "success", "message": f"Reference {req.reference_id} linked to Account {req.account_id}"}

@app.get("/api/audit-trail")
def get_audit_trail(user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_trail ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/history")
def get_history(user: dict = Depends(get_current_user)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM reconciliation_runs ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/sample/payment")
def download_sample_payment():
    csv = """reference_id,account_id,amount,payment_date
TXN1001,ACC2001,18500,2026-09-05
TXN1002,ACC2002,9750,2026-09-05
TXN1003,ACC2003,15000,2026-09-06
TXN1004,ACC2004,22300,2026-09-08
TXN1005,ACC2005,11200,2026-09-06
TXN1006,ACC2099,7600,2026-09-07
TXN1008,ACC2008,13400,2026-09-07
TXN1008,ACC2008,13400,2026-09-07
TXN1009,ACC2009,16800,2026-09-09
TXN1010,ACC2010,20100,2026-09-09"""
    return StreamingResponse(
        io.BytesIO(csv.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_payment.csv"}
    )

@app.get("/api/sample/ledger")
def download_sample_ledger():
    csv = """reference_id,account_id,amount,due_date
TXN1001,ACC2001,18500,2026-09-05
TXN1002,ACC2002,9750,2026-09-05
TXN1003,ACC2003,15500,2026-09-06
TXN1004,ACC2004,22300,2026-09-07
TXN1005,ACC2005,11200,2026-09-06
TXN1007,ACC2007,9800,2026-09-07
TXN1008,ACC2008,13400,2026-09-07
TXN1009,ACC2009,16800,2026-09-09
TXN1010,ACC2010,20100,2026-09-09"""
    return StreamingResponse(
        io.BytesIO(csv.encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_ledger.csv"}
    )

@app.get("/health")
def health_check():
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        conn.close()
        db_ok = True
    except Exception:
        db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "version": "2.1.0",
        "db": "connected" if db_ok else "error",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def index_page():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()
