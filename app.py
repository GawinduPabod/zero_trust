import os
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import random
import sqlite3
from twilio.rest import Client

app = Flask(__name__)
application = app
app.secret_key = "Super_secret_zero_trust_key"

ALLOWED_START_TIME = 8
ALLOWED_END_TIME = 18

# --- Twilio SMS Configuration ---
TWILIO_ACCOUNT_SID = "ඔබගේ_SID_එක_මෙහි_ලබාදෙන්න"
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = "+123456789" # ඔබේ Twilio අංකය

def send_otp_sms(receiver_number, otp):
    try:
        client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Your Zero Trust Security OTP is: {otp}",
            from_=TWILIO_PHONE_NUMBER,
            to=receiver_number
        )
        print(f"OTP sent successfully via SMS to {receiver_number}")
    except Exception as e:
        print(f"Error sending SMS: {e}")

def get_db_connection():
    # Vercel හි නිවැරදිව file එක සොයාගැනීමට absolute path එකක් සෑදීම
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_path = os.path.join(base_dir, 'database.db')
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
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
        phone_number = request.form.get('phone_number') # ෆෝන් නම්බර් එක ලබාගැනීම
        password = request.form.get('password')
        role = 'user' 
        user_ip = request.remote_addr
        user_device = request.headers.get('User-Agent')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, phone_number, password, role, known_ip, known_device) VALUES (?, ?, ?, ?, ?, ?)',
                         (username, phone_number, password, role, user_ip, user_device))
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
            
            # SMS එක හරහා OTP යැවීම
            user_phone = user['phone_number']
            send_otp_sms(user_phone, generated_otp)
            
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