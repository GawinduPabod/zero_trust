from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import random
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'zero_trust_super_secret_key' # Session දත්ත සුරක්ෂිත කිරීම සඳහා

# ඔබගේ Gmail සහ App Password එක මෙහි ඇතුළත් කරන්න
SENDER_EMAIL = "gapabod@gmail.com"
APP_PASSWORD = "euxhigenrqqltudi"

def send_otp_email(receiver_email, otp):
    msg = EmailMessage()
    msg['Subject'] = 'Your Zero Trust Security OTP'
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver_email
    msg.set_content(f"Your Zero Trust Security OTP is: {otp}")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"OTP Email sent successfully to {receiver_email}")
    except Exception as e:
        print(f"Error sending Email: {e}")

def get_db_connection():
    # Vercel හි දත්ත ලිවිය හැකි එකම ස්ථානය /tmp ෆෝල්ඩරයයි
    db_path = '/tmp/database.db'
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # අලුතින් Tables නිර්මාණය කිරීම (phone_number වෙනුවට email යොදා ඇත)
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
    # ඔබගේ මුල් පිටුවට අදාළ HTML ගොනුවේ නම මෙහි ලබා දෙන්න (login.html හෝ index.html)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email') # දුරකථන අංකය වෙනුවට ඊමේල් ලිපිනය ලබාගැනීම
        password = request.form.get('password')
        role = 'user'
        user_ip = request.remote_addr
        user_device = request.headers.get('User-Agent')
        
        # දත්ත ගබඩාවේ මෙම පරිශීලකයා දැනටමත් සිටීදැයි පරීක්ෂා කිරීම
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            conn.close()
            flash('Username already exists! Please try another.')
            return redirect(url_for('register'))
            
        # OTP එකක් ජනනය කිරීම
        otp = str(random.randint(100000, 999999))
        
        # තාවකාලිකව දත්ත session එකේ සුරැකීම
        session['reg_username'] = username
        session['reg_email'] = email
        session['reg_password'] = password
        session['reg_role'] = role
        session['reg_ip'] = user_ip
        session['reg_device'] = user_device
        session['otp'] = otp
        
        # ඊමේල් හරහා OTP එක යැවීම
        send_otp_email(email, otp)
        
        conn.close()
        # OTP ඇතුළත් කරන පිටුවට යොමු කිරීම (මෙම පිටුව ඔබ සතුව ඇතැයි උපකල්පනය කෙරේ)
        return redirect(url_for('verify_otp'))
        
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if 'otp' in session and user_otp == session['otp']:
            # OTP නිවැරදි නම්, දත්ත ගබඩාවට පරිශීලකයා ඇතුළත් කිරීම
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password, role, known_ip, known_device) VALUES (?, ?, ?, ?, ?, ?)',
                         (session['reg_username'], session['reg_email'], session['reg_password'], 
                          session['reg_role'], session['reg_ip'], session['reg_device']))
            conn.commit()
            conn.close()
            
            # Session දත්ත මකා දැමීම
            session.clear()
            flash('Registration successful! Please login.')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('verify_otp'))
            
    # otp.html නමින් HTML ගොනුවක් ඔබ සාදා තිබිය යුතුය
    return render_template('otp.html')

if __name__ == '__main__':
    app.run(debug=True)