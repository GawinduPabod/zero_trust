import os
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import random
import sqlite3
import requests
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
application = app
app.secret_key = "Super_secret_zero_trust_key"

ALLOWED_START_TIME = 8
ALLOWED_END_TIME = 18

# --- Email Configuration ---
SENDER_EMAIL = os.environ.get('SENDER_EMAIL') or "your_email@gmail.com"
APP_PASSWORD = os.environ.get('APP_PASSWORD') or "your_app_password"

def get_location_from_ip(ip):
    try:
        if ip == '127.0.0.1' or ip.startswith('192.168.'):
            return "Colombo, Sri Lanka (Local)"
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        if response.get('status') == 'success':
            return f"{response.get('city')}, {response.get('country')}"
        return "Unknown Location"
    except:
        return "Colombo, Sri Lanka"

def get_db_connection():
    db_path = '/tmp/database.db'
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # 1. පරිශීලක වගුව (failed_attempts සහ is_locked ඇතුළත් කර ඇත)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT,
            known_ip TEXT,
            known_device TEXT,
            known_location TEXT,
            failed_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0
        )
    ''')
    
    # 2. ඇඩ්මින් අනුමැති වගුව
    conn.execute('''
        CREATE TABLE IF NOT EXISTS admin_approvals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            location TEXT,
            device TEXT,
            timestamp TEXT,
            status TEXT DEFAULT 'PENDING'
        )
    ''')
    
    # 3. පූර්ණ විගණන ලොග් වගුව (Audit Logs)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            location TEXT,
            device TEXT,
            timestamp TEXT,
            status TEXT
        )
    ''')
    conn.commit()
    return conn

def send_otp_email(receiver_email, otp):
    try:
        msg = MIMEText(f"Your Zero Trust Security Verification Code is: {otp}\n\nThis code was triggered because you are attempting to login outside of standard office hours.")
        msg['Subject'] = '🔒 Zero Trust Alert - OTP Verification'
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        print(f"OTP sent successfully to {receiver_email}")
        return True
    except Exception as e:
        print(f"SMTP Error: {e}")
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # ටෙස්ට් කිරීම පහසු කිරීමට 'admin' නමින් රෙජිස්ටර් වුවහොත් ස්වයංක්‍රීයවම admin රෝල් එක ලැබේ
        role = 'admin' if username.lower() == 'admin' else 'user'
        
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
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            conn.close()
            return "<h1 style='color: red; text-align:center;'>Username already exists!</h1>"

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    current_hour = datetime.now().hour
    
    current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if current_ip and ',' in current_ip:
        current_ip = current_ip.split(',')[0].strip()
        
    current_device = request.headers.get('User-Agent')
    current_location = get_location_from_ip(current_ip)
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    
    if user:
        if user['is_locked'] == 1:
            conn.close()
            return "<h1 style='color: red; text-align:center;'>🔒 Security Alert: Your account is locked due to multiple failed attempts.</h1>"
        
        if user['password'] == password:
            # සාර්ථක ලොගින් එකකදී වැරදුණු වාර ගණන බිංදුව කරනු ලැබේ
            conn.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
            conn.commit()
            
            # ඇඩ්මින් පරිශීලකයෙක් නම් කෙලින්ම පැනල් එකට
            if user['role'] == 'admin':
                conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                             (username, current_ip, current_location, current_device, current_time_str, "SUCCESS_ADMIN"))
                conn.commit()
                conn.close()
                session['admin_user'] = username
                return redirect(url_for('admin_dashboard'))
            
            # ස්ථානය හෝ උපකරණය වෙනස් වී ඇත්නම් (Adaptive Anomaly Blocking)
            if (user['known_location'] and current_location != user['known_location']) or (user['known_ip'] and current_ip != user['known_ip']):
                conn.execute('''INSERT INTO admin_approvals (username, ip_address, location, device, timestamp, status) 
                                VALUES (?, ?, ?, ?, ?, 'PENDING')''', 
                             (username, current_ip, current_location, current_device, current_time_str))
                conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                             (username, current_ip, current_location, current_device, current_time_str, "BLOCKED_ANOMALY"))
                conn.commit()
                conn.close()
                return render_template('blocked.html', location=current_location, ip=current_ip)
            
            # ඔෆිස් වේලාවෙන් පසුව ලොග් වීමට උත්සාහ කරන්නේ නම් (Office Hours Verification)
            is_outside_office_hours = not (ALLOWED_START_TIME <= current_hour < ALLOWED_END_TIME)
            if is_outside_office_hours:
                generated_otp = str(random.randint(100000, 999999))
                session['valid_otp'] = generated_otp 
                session['temp_user'] = username
                
                conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                             (username, current_ip, current_location, current_device, current_time_str, "MFA_TRIGGERED_OUTSIDE_HOURS"))
                conn.commit()
                conn.close()
                
                send_otp_email(user['email'], generated_otp)
                return render_template('otp.html') 
            
            # සියල්ල නිවැරදි නම් කෙලින්ම ඇතුළු වීමට ඉඩ දීම
            conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                         (username, current_ip, current_location, current_device, current_time_str, "SUCCESS_DIRECT"))
            conn.commit()
            conn.close()
            return render_template('dashboard.html', username=username)
            
        else:
            # මුරපදය වැරදුණු වාර ගණන ගණනය කිරීම
            new_attempts = user['failed_attempts'] + 1
            if new_attempts >= 3:
                conn.execute('UPDATE users SET failed_attempts = ?, is_locked = 1 WHERE username = ?', (new_attempts, username))
                log_status = "ACCOUNT_LOCKED"
            else:
                conn.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (new_attempts, username))
                log_status = "FAILED_WRONG_PASSWORD"
                
            conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                         (username, current_ip, current_location, current_device, current_time_str, log_status))
            conn.commit()
            conn.close()
            
            if new_attempts >= 3:
                return "<h1 style='color: red; text-align:center;'>🔒 Account Locked! You have exceeded maximum password attempts.</h1>"
            return f"<h1 style='color: orange; text-align:center;'>Invalid Password! Attempts remaining: {3 - new_attempts}</h1> <br><table style='margin:0 auto;'><tr><td><a href='/'>Try Again</a></td></tr></table>"
    else:
        conn.close()
        return "<h1 style='color: red; text-align:center;'>User not found!</h1>"

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_otp = request.form.get('otp_code')
    valid_otp = session.get('valid_otp')
    username = session.get('temp_user')
    
    current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    current_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    current_device = request.headers.get('User-Agent')
    current_location = get_location_from_ip(current_ip)
    
    if user_otp == valid_otp:
        conn = get_db_connection()
        conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                     (username, current_ip, current_location, current_device, current_time_str, "SUCCESS_MFA_VERIFIED"))
        conn.commit()
        conn.close()
        return render_template('dashboard.html', username=username)
    else:
        conn = get_db_connection()
        conn.execute('INSERT INTO access_logs (username, ip_address, location, device, timestamp, status) VALUES (?, ?, ?, ?, ?, ?)',
                     (username, current_ip, current_location, current_device, current_time_str, "FAILED_INVALID_MFA"))
        conn.commit()
        conn.close()
        return "<h1 style='color: red; text-align:center;'>Access Denied! Incorrect OTP code.</h1>"

@app.route('/admin/dashboard')
def admin_dashboard():
    conn = get_db_connection()
    approvals = conn.execute("SELECT * FROM admin_approvals WHERE status = 'PENDING'").fetchall()
    logs = conn.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT 20").fetchall()
    users_list = conn.execute("SELECT username, email, role, is_locked FROM users").fetchall()
    conn.close()
    return render_template('admin_dashboard.html', approvals=approvals, logs=logs, users=users_list)

@app.route('/admin/approve/<int:request_id>')
def approve_user(request_id):
    conn = get_db_connection()
    req = conn.execute("SELECT * FROM admin_approvals WHERE id = ?", (request_id,)).fetchone()
    if req:
        conn.execute('UPDATE users SET known_ip = ?, known_location = ?, known_device = ? WHERE username = ?', 
                     (req['ip_address'], req['location'], req['device'], req['username']))
        conn.execute("UPDATE admin_approvals SET status = 'APPROVED' WHERE id = ?", (request_id,))
        conn.commit()
    conn.close()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)