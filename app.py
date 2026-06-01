import os
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import random
import sqlite3
import smtplib
import requests # අලුතින් එක් කළ ස්ථාන හඳුනාගැනීමේ පුස්තකාලය
from email.mime.text import MIMEText

app = Flask(__name__)
application = app
app.secret_key = "Super_secret_zero_trust_key"

ALLOWED_START_TIME = 8
ALLOWED_END_TIME = 18

# --- Email Configuration ---
SENDER_EMAIL = os.environ.get('SENDER_EMAIL') or "your_email@gmail.com"
APP_PASSWORD = os.environ.get('APP_PASSWORD') or "your_app_password"

# --- IP එක හරහා Location එක සෙවීමේ ශ්‍රිතය ---
def get_location_from_ip(ip):
    try:
        # Localhost පරීක්ෂා කිරීම් පහසු කිරීමට
        if ip == '127.0.0.1' or ip.startswith('192.168.'):
            return "Localhost (Colombo, LK)"
        
        # නොමිලේ ලැබෙන GeoIP API එකක් භාවිතා කිරීම
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=4).json()
        if response.get('status') == 'success':
            return f"{response.get('city')}, {response.get('country')}"
        return "Unknown Location"
    except:
        return "Unknown Location"

def get_db_connection():
    db_path = '/tmp/database.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # පරිශීලක වගුව (known_location එකතු කර ඇත)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT,
            known_ip TEXT,
            known_device TEXT,
            known_location TEXT
        )
    ''')
    
    # ඇඩ්මින්ගේ අනුමැතිය සඳහා වන වගුව (Admin Approval Table)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS admin_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            location TEXT,
            device TEXT,
            status TEXT DEFAULT 'PENDING'
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            username TEXT,
            ip_address TEXT,
            device TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    return conn

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = 'user' 
        
        # Vercel හි සැබෑ IP එක ලබාගැනීම
        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if user_ip and ',' in user_ip:
            user_ip = user_ip.split(',')[0].strip()
            
        user_device = request.headers.get('User-Agent')
        user_location = get_location_from_ip(user_ip)

        conn = get_db_connection()
        try:
            conn.execute('''INSERT INTO users (username, email, password, role, known_ip, known_device, known_location) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)''',
                         (username, email, password, role, user_ip, user_device, user_location))
            conn.commit()
            conn.close()
            return "<h1 style='color: green;'>Registration Successful!</h1> <br> <a href='/'>Go to Login</a>"
        except sqlite3.IntegrityError:
            conn.close()
            return "<h1 style='color: red;'>Username already exists!</h1>"

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    current_time_obj = datetime.now()
    current_hour = current_time_obj.hour
    
    current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if current_ip and ',' in current_ip:
        current_ip = current_ip.split(',')[0].strip()
        
    current_device = request.headers.get('User-Agent')
    current_location = get_location_from_ip(current_ip)
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    
    if user:
        # ඇඩ්මින් කෙනෙක් නම් කෙලින්ම ඇඩ්මින් පැනල් එකට යැවීම
        if user['role'] == 'admin' or username.lower() == 'admin':
            conn.close()
            session['admin_user'] = username
            return redirect(url_for('admin_dashboard'))
        
        # ස්ථානය හෝ උපකරණය වෙනස් වී ඇත්දැයි බැලීම (Location or IP Anomaly)
        is_different_location = (current_location != user['known_location']) and (user['known_location'] is not None)
        is_different_ip = (current_ip != user['known_ip']) and (user['known_ip'] is not None)
        
        if is_different_location or is_different_ip:
            # ඇඩ්මින් පැනල් එකට Approval Request එකක් දැමීම
            conn.execute('''INSERT INTO admin_approvals (username, ip_address, location, device, status) 
                            VALUES (?, ?, ?, ?, 'PENDING')''', 
                         (username, current_ip, current_location, current_device))
            conn.commit()
            conn.close()
            
            session['pending_username'] = username
            return "<h1>Access Blocked! Different Location/IP Detected. Your request sent to Security Admin. Please wait for approval.</h1>"
        
        # සාමාන්‍ය Zero Trust සීමාවන් පරීක්ෂාව
        is_valid_time = ALLOWED_START_TIME <= current_hour < ALLOWED_END_TIME
        if is_valid_time:
            conn.close()
            return render_template('dashboard.html', username=username)
        else:
            # වෙලාව වෙනස් නම් OTP පිටුවට
            generated_otp = str(random.randint(100000, 999999))
            session['valid_otp'] = generated_otp 
            session['temp_user'] = username
            conn.close()
            
            # send_otp_email(user['email'], generated_otp) # අවශ්‍ය නම් සක්‍රිය කරගන්න
            return render_template('otp.html') 
            
    else:
        conn.close()
        return "<h1 style='color: red;'>Login Failed! Invalid Credentials.</h1>"

# --- Security Admin Dashboard ---
@app.route('/admin/dashboard')
def admin_dashboard():
    conn = get_db_connection()
    requests_list = conn.execute("SELECT * FROM admin_approvals WHERE status = 'PENDING'").fetchall()
    conn.close()
    return render_template('admin_dashboard.html', requests=requests_list)

# --- Admin Approval Action ---
@app.route('/admin/approve/<int:request_id>')
def approve_user(request_id):
    conn = get_db_connection()
    req = conn.execute("SELECT * FROM admin_approvals WHERE id = ?", (request_id,)).fetchone()
    
    if req:
        # පරිශීලකයාගේ නව තොරතුරු සුරක්ෂිත දත්ත ලෙස යාවත්කාලීන කිරීම
        conn.execute('''UPDATE users SET known_ip = ?, known_location = ?, known_device = ? 
                        WHERE username = ?''', (req['ip_address'], req['location'], req['device'], req['username']))
        # ඉල්ලීමේ තත්ත්වය වෙනස් කිරීම
        conn.execute("UPDATE admin_approvals SET status = 'APPROVED' WHERE id = ?", (request_id,))
        conn.commit()
        
    conn.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)