from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import random
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = 'zero_trust_super_secret_key'

# ඔබගේ Gmail සහ App Password එක මෙහි ඇතුළත් කරන්න
SENDER_EMAIL = "YOUR_EMAIL@gmail.com"
APP_PASSWORD = "YOUR_APP_PASSWORD"

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
    db_path = '/tmp/database.db'
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
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
        user_ip = request.remote_addr
        user_device = request.headers.get('User-Agent')
        
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            conn.close()
            flash('Username already exists! Please try another.')
            return redirect(url_for('register'))
            
        otp = str(random.randint(100000, 999999))
        
        session['reg_username'] = username
        session['reg_email'] = email
        session['reg_password'] = password
        session['reg_role'] = role
        session['reg_ip'] = user_ip
        session['reg_device'] = user_device
        session['otp'] = otp
        
        send_otp_email(email, otp)
        
        conn.close()
        return redirect(url_for('verify_otp'))
        
    return render_template('register.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        
        if 'otp' in session and user_otp == session['otp']:
            conn = get_db_connection()
            conn.execute('INSERT INTO users (username, email, password, role, known_ip, known_device) VALUES (?, ?, ?, ?, ?, ?)',
                         (session['reg_username'], session['reg_email'], session['reg_password'], 
                          session['reg_role'], session['reg_ip'], session['reg_device']))
            conn.commit()
            conn.close()
            
            session.clear()
            flash('Registration successful! Please login.')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.')
            return redirect(url_for('verify_otp'))
            
    return render_template('otp.html')

@app.route('/resend_otp')
def resend_otp():
    if 'reg_email' in session:
        new_otp = str(random.randint(100000, 999999))
        session['otp'] = new_otp
        send_otp_email(session['reg_email'], new_otp)
        
        flash('A new OTP has been sent to your email. Please check your Spam folder too.')
        return redirect(url_for('verify_otp'))
    else:
        flash('Session expired. Please register again.')
        return redirect(url_for('register'))

if __name__ == '__main__':
    app.run(debug=True)