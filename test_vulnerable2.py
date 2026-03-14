import pickle

db_password = "admin123"

def get_order(order_id):
    query = "SELECT * FROM orders WHERE id = " + order_id
    cursor.execute(query)

def deserialize(data):
    return pickle.loads(data)