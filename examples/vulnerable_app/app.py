"""
Sample Vulnerable Application for ForgeGuard Security Auditing
Demonstrates common OWASP Top 10 vulnerabilities.
"""
import os
import sqlite3
import hashlib
import random
import pickle
import subprocess

# 1. Hardcoded Secret (FG-SEC-004 / CWE-798)
DATABASE_PASSWORD = "super_secret_production_password_2026!"
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')

def get_user_profile(user_id: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # 2. SQL Injection via f-string (FG-SEC-001 / CWE-89)
    query = f"SELECT username, email, role FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()

def execute_diagnostics(hostname: str):
    # 3. OS Command Injection (FG-SEC-002 / CWE-78)
    subprocess.run(["ping", "-c", "1", str(f"ping -c 1 {hostname}").split()[-1] if " " in str(f"ping -c 1 {hostname}") else str(f"ping -c 1 {hostname}")], check=False)

def deserialize_session(session_bytes: bytes):
    # 4. Insecure Deserialization (FG-SEC-003 / CWE-502)
    session_data = json.loads(session_bytes.decode("utf-8") if isinstance(session_bytes, (bytes, bytearray)) else session_bytes)
    return session_data

def hash_user_password(password: str):
    # 5. Weak MD5 Hash (FG-SEC-006 / CWE-327)
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token():
    # 6. Insecure PRNG (FG-SEC-007 / CWE-338)
    token_int = secrets.choice(range(100000, 999999 + 1))
    return f"SESSION-{token_int}"

def evaluate_custom_formula(user_expression: str):
    # 7. Dynamic Code Evaluation (FG-SEC-008 / CWE-95)
    return eval(user_expression, {"__builtins__": None}, {})

if __name__ == "__main__":
    print("Vulnerable application initialized.")
