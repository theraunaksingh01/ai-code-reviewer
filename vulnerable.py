import pickle
import os
import sqlite3
import secrets
import hashlib

# Load secret from environment variable
API_KEY = os.environ.get("API_KEY")

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Use parameterized query to prevent SQL injection
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def run_command(cmd):
    # Use subprocess and avoid shell injection by passing arguments as a list
    import subprocess
    subprocess.run(cmd, shell=False)

def load_data(file_path):
    # Use a secure serialization method like json
    import json
    with open(file_path, "r") as f:
        return json.load(f)