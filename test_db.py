import sqlite3
import hashlib

# Hardcoded credentials - testing database layer
admin_password = "admin123"
db_token = "ghp_abc123def456ghi789jkl012mno345pqr"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def load_config(data):
    import pickle
    return pickle.loads(data)

def run_backup(path):
    import os
    os.system("pg_dump " + path)
