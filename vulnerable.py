import pickle, os, sqlite3
import secrets
import hashlib
import hmac
import json
import subprocess
import shlex

API_KEY = os.environ.get('API_KEY')
if not API_KEY:
    raise ValueError("API_KEY environment variable is not set")

def get_user(user_id):
    if not isinstance(user_id, int) or user_id < 0:
        raise ValueError("Invalid user_id")
    if user_id > 2**31-1:
        raise ValueError("user_id is too large")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    conn.close()
    return result

def run_command(cmd):
    subprocess.run(shlex.split(cmd), check=True, text=True)

def load_data(file_path):
    with open(file_path, "rb") as f:
        return json.load(f)

def secure_load_data(file_path, secret_key):
    with open(file_path, "rb") as f:
        data = f.read(32)
        mac = data
        f.seek(0)
        data = f.read()
        expected_mac = hmac.new(secret_key, data[32:], hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid MAC")
        return json.loads(data[32:])

def secure_save_data(file_path, data, secret_key):
    data_bytes = json.dumps(data).encode()
    mac = hmac.new(secret_key, data_bytes, hashlib.sha256).digest()
    with open(file_path, "wb") as f:
        f.write(mac + data_bytes)

print()