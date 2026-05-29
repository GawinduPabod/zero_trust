import os
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import random
import sqlite3
import smtplib
from email.mime.text import MIMEText

app = Flask(__name__)
application = app
app.secret_key = "Super_secret_zero_trust_key"

ALLOWED_START_TIME = 8
ALLOWED_END_TIME = 18

# --- Email Configuration ---
# Vercel Environment Variables වල SENDER_EMAIL සහ APP_PASSWORD සකස් කරන්න 
# නැතහොත් කෙලින්ම ඔබේ තොරතුරු මෙතනට ලබාදෙන්න
SENDER_EMAIL = os.environ.get('SENDER_EMAIL') or "ඔබේ_gmail_ලිපිනය@gmail.com"
APP_PASSWORD = os.environ.get('APP_PASSWORD') or "ගූගල්_ඇප්_පාස්වර්ඩ්_කේතය"

def send_otp_email(receiver_email, otp):
    try:
        msg = MIMEText(f"Your Zero Trust Security OTP code is: {otp}\n\nThis code is valid for single use login.")
        msg['Subject'] = 'Zero Trust Security - OTP Verification'
        msg['From'] = SENDER_EMAIL
        msg['To'] = receiver_email

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(SENDER_EMAIL, APP_PASSWORD)
        server.sendmail(SENDER_EMAIL, receiver_email, msg.as_string())
        server.quit()
        print(f"OTP sent successfully via Email to {receiver_email}")
    except Exception as e:
        print(f"Error sending email: {e}")

def get_db_connection():
    # Vercel හි දත්ත ලිවිය හැකි එකම ස්ථානය /tmp ෆෝල්ඩරයයි
    db_path = '/tmp/database.db'
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # /tmp ෆෝල්ඩරය මුලින් හිස්ව පවතින බැවින්, අලුතින් Tables නිර්මාණය කිරීම
    # මෙහි phone_number වෙනුවට email ලෙස වෙනස් කර ඇත
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT UNIQUE,
            email TEXT,
            password TEXT,
            role TEXT,
            known_ip TEXT,
            known_device TEXT
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

def log_access(username, ip, device, status):
    conn = get_db_connection()
    conn.execute('INSERT INTO access_logs (username, ip_address, device, status) VALUES (?, ?, ?, ?)',
                 (username, ip, device, status))
    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') # ඊමේල් ලිපිනය ලබාගැනීම
        password = request.form.get('password')
        role = 'user' 
        user_ip = request.remote_addr
        user_device = request.headers.get('User-Agent')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, email, password, role, known_ip, known_device) VALUES (?, ?, ?, ?, ?, ?)',
                         (username, email, password, role, user_ip, user_device))
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
    current_ip = request.remote_addr
    current_device = request.headers.get('User-Agent')
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
    conn.close()
    
    if user:
        if user['role'] == 'admin':
            log_access(username, current_ip, current_device, "SUCCESS_ADMIN")
            return render_template('dashboard.html', username=username + " (Admin)")
        
        is_valid_time = ALLOWED_START_TIME <= current_hour < ALLOWED_END_TIME
        is_known_ip = (current_ip == user['known_ip'])
        is_known_device = (current_device == user['known_device'])
        
        if is_valid_time and is_known_ip and is_known_device:
            log_access(username, current_ip, current_device, "SUCCESS_DIRECT")
            return render_template('dashboard.html', username=username)
        else:
            log_access(username, current_ip, current_device, "WARNING_MFA_TRIGGERED")
            generated_otp = str(random.randint(100000, 999999))
            session['valid_otp'] = generated_otp 
            session['temp_user'] = username
            
            # ඊමේල් එක හරහා OTP යැවීම
            user_email = user['email']
            send_otp_email(user_email, generated_otp)
            
            return render_template('otp.html') 
            
    else:
        log_access(username, current_ip, current_device, "FAILED_INVALID_CREDENTIALS")
        return "<h1 style='color: red;'>Login Failed! Invalid Credentials.</h1>"

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    user_otp = request.form.get('otp_code')
    valid_otp = session.get('valid_otp')
    username = session.get('temp_user')
    current_ip = request.remote_addr
    current_device = request.headers.get('User-Agent')
    
    if user_otp == valid_otp:
        log_access(username, current_ip, current_device, "SUCCESS_MFA_VERIFIED")
        
        conn = get_db_connection()
        conn.execute('UPDATE users SET known_ip = ?, known_device = ? WHERE username = ?', (current_ip, current_device, username))
        conn.commit()
        conn.close()
        
        return render_template('dashboard.html', username=username)
    else:
        log_access(username, current_ip, current_device, "FAILED_INCORRECT_OTP")
        return "<h1 style='color: red;'>Access Denied! Incorrect OTP.</h1>"

if __name__ == '__main__':
    app.run(debug=True)