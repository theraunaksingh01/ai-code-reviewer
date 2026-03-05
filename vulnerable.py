import pickle, os, sqlite3

API_KEY = "sk-1234567890abcdef"

def get_user(user_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()

def run_command(cmd):
    os.system(cmd)

def load_data(file_path):
    with open(file_path, "rb") as f:
        return pickle.load(f)