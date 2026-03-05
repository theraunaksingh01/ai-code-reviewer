import pickle, os, sqlite3
import secrets
import hashlib
import hmac
import json

API_KEY = os.environ.get('API_KEY')

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def run_command(cmd):
    import subprocess
    subprocess.run(cmd, shell=True, check=True)

def load_data(file_path):
    with open(file_path, "rb") as f:
        return json.load(f)

def secure_load_data(file_path, secret_key):
    with open(file_path, "rb") as f:
        data = f.read()
        expected_mac = data[:32]
        data = data[32:]
        mac = hmac.new(secret_key, data, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("Invalid MAC")
        return json.loads(data)

def secure_save_data(file_path, data, secret_key):
    data_bytes = json.dumps(data).encode()
    mac = hmac.new(secret_key, data_bytes, hashlib.sha256).digest()
    with open(file_path, "wb") as f:
        f.write(mac + data_bytes)