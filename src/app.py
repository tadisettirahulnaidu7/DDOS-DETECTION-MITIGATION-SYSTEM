import time
import sqlite3
from collections import defaultdict, deque
from datetime import datetime, timedelta

import pandas as pd
from fastapi import FastAPI, Request
from joblib import load

app = FastAPI(title="Local DDoS Detection Demo")

model = load("models/ddos_model.joblib")

DB = "data/traffic.db"

def init_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            path TEXT,
            timestamp TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            prediction TEXT,
            confidence REAL,
            action TEXT,
            requests_last_10s INTEGER,
            timestamp TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            blocked_until TEXT,
            reason TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

request_history = defaultdict(lambda: deque(maxlen=1000))

@app.get("/")
def home():
    return {"message": "Local DDoS detection demo is running"}

@app.get("/api/data")
def get_data(request: Request):
    ip = request.client.host
    path = request.url.path
    now = datetime.now()

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO requests (ip, path, timestamp) VALUES (?, ?, ?)",
        (ip, path, now.isoformat())
    )
    conn.commit()
    conn.close()

    request_history[ip].append(now)

    recent = [t for t in request_history[ip] if now - t <= timedelta(seconds=10)]
    requests_last_10s = len(recent)
    requests_per_second = requests_last_10s / 10

    features = pd.DataFrame([{
        "flow_duration": max(1000, int(100000 / max(requests_last_10s, 1))),
        "packets_per_second": requests_per_second * 10,
        "bytes_per_second": requests_per_second * 2000,
        "syn_flag_count": requests_last_10s,
        "udp_flag_count": 0
    }])

    prediction = model.predict(features)[0]
    confidence = float(model.predict_proba(features).max())

    if prediction == "BENIGN":
        action = "ALLOW"
    elif confidence >= 0.80:
        action = "RATE_LIMIT"
    else:
        action = "MONITOR"

    if action == "RATE_LIMIT":
        blocked_until = (now + timedelta(minutes=5)).isoformat()
        conn = sqlite3.connect(DB)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO blocked_ips (ip, blocked_until, reason)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                blocked_until=excluded.blocked_until,
                reason=excluded.reason
        """, (ip, blocked_until, "High request rate detected"))
        conn.commit()
        conn.close()

    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detections
        (ip, prediction, confidence, action, requests_last_10s, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (ip, prediction, confidence, action, requests_last_10s, now.isoformat()))
    conn.commit()
    conn.close()

    return {
        "ip": ip,
        "prediction": prediction,
        "confidence": round(confidence, 3),
        "action": action,
        "requests_last_10s": requests_last_10s,
        "requests_per_second": round(requests_per_second, 2),
        "message": "Request processed successfully"
    }

@app.get("/dashboard-data")
def dashboard_data():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM detections ORDER BY id DESC LIMIT 20")
    detections = cursor.fetchall()

    cursor.execute("SELECT * FROM blocked_ips")
    blocked = cursor.fetchall()

    conn.close()

    return {
        "recent_detections": [
            {
                "id": row[0], "ip": row[1], "prediction": row[2],
                "confidence": row[3], "action": row[4],
                "requests_last_10s": row[5], "timestamp": row[6]
            }
            for row in detections
        ],
        "blocked_ips": [
            {"ip": row[0], "blocked_until": row[1], "reason": row[2]}
            for row in blocked
        ]
    }