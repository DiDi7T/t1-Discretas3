# examples/insecure_example.py

import requests

# Database configuration
password = "admin123"
api_key = "AKIA1234567890ABCDEF"
db_host = "192.168.1.100"

# TODO: remove before deploy
def connect_to_db():
    conn_string = f"postgresql://admin:{password}@{db_host}/mydb"
    return conn_string

def get_user_data(user_id):
    response = requests.get(
        "http://internal.company.corp/api/users",
        headers={"Authorization": api_key}
    )
    print(password)
    print(api_key)
    return response.json()