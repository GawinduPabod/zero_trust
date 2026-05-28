import sqlite3

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    username TEXT UNIQUE NOT NULL,
    phone_number TEXT NOT NULL, 
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    known_ip TEXT,
    known_device TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    device TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT
)
''')

conn.commit()
conn.close()
print("Database updated successfully with phone number field.")