import pickle
import os
import sqlite3

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

def run_command(cmd):
    # Command injection
    os.system(cmd)

def load_data(file_path):
    # Insecure deserialization
    with open(file_path, "rb") as f:
        return pickle.load(f)