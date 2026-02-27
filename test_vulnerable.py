import pickle
import os

password = "supersecret123"
api_key = "sk-abc123def456ghi789jkl012mno345"

def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

def load_data(data):
    return pickle.loads(data)

def run_command(user_input):
    os.system("ls " + user_input)
