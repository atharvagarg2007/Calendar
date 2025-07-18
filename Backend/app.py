from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = 'Project@1'

# Configure Flask-Mail
app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='yourpersonalcalendar2025@gmail.com',  
    MAIL_PASSWORD='qtws boba rzxd lzdw'               
)
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

# ---------- Database Setup ----------
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT,
            password TEXT NOT NULL
        )
    ''')
    # Events table
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            start TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# ---------- Helper Function ----------
def email_exists(email):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = c.fetchone()
    conn.close()
    return user is not None

# ---------- Routes ----------

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            return redirect(url_for('calendar_page'))
        else:
            flash('Invalid credentials.', 'error')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm-password']

        if password != confirm:
            return render_template('register.html', error="Passwords do not match!")

        if email_exists(email):
            return render_template('register.html', error="Email already registered.")

        hashed_password = generate_password_hash(password)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO users (email, username, password) VALUES (?, ?, ?)',
                  (email, username, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    message = ''
    if request.method == 'POST':
        email = request.form['email']
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            reset_link = url_for('reset_password', token=token, _external=True)

            msg = Message('Password Reset Request',
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f'Hi,\n\nTo reset your password, click the following link:\n{reset_link}\n\nIf you didn\'t request this, ignore this email.'

            mail.send(msg)
            message = 'Password reset link sent! Please check your email.'
        else:
            message = 'Email not found.'

    return render_template('forgot_password.html', message=message)

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # valid for 1 hour
    except SignatureExpired:
        return '<h2>The reset link has expired. Please try again.</h2>'
    except BadSignature:
        return '<h2>Invalid reset link.</h2>'

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password.html')

        hashed_password = generate_password_hash(new_password)

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()

        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('home'))

    return render_template('reset_password.html')

@app.route('/calendar')
def calendar_page():
    if 'user_id' not in session:
        return redirect(url_for('home'))
    return render_template('calender2.html')

@app.route('/events')
def get_events():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, title, start FROM events')
    rows = c.fetchall()
    conn.close()
    events = [{'id': row[0], 'title': row[1], 'start': row[2]} for row in rows]
    return jsonify(events)

@app.route('/add-event', methods=['POST'])
def add_event():
    data = request.get_json()
    title = data.get('title')
    start = data.get('start')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO events (title, start) VALUES (?, ?)', (title, start))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/add-events', methods=['POST'])
def delete_event():
    data = request.get_json()
    event_id = data.get('id')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM events WHERE id = ?', (event_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
