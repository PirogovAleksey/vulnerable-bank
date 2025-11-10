"""
Vulnerable Bank Web Application
================================
WARNING: This application contains INTENTIONAL security vulnerabilities
for educational purposes. DO NOT use in production!

Vulnerabilities included:
1. SQL Injection
2. Race Conditions
3. IDOR (Insecure Direct Object Reference)
4. XSS (Cross-Site Scripting)
5. Missing Authorization
6. Weak JWT Implementation
7. CSRF (Cross-Site Request Forgery)
8. Information Disclosure
9. Insecure Password Storage
10. Client-Side Security Controls
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
import mysql.connector
import os
import jwt
import datetime
import hashlib
import time
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_123')  # VULNERABILITY: Weak secret

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'db'),
    'user': os.environ.get('DB_USER', 'bankuser'),
    'password': os.environ.get('DB_PASSWORD', 'weak_password_123'),
    'database': os.environ.get('DB_NAME', 'vulnerable_bank')
}

def get_db_connection():
    """Create database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return None

def get_cursor():
    """Get database cursor"""
    conn = get_db_connection()
    if conn:
        return conn, conn.cursor(dictionary=True)
    return None, None

# VULNERABILITY 9: Insecure password "hashing" using MD5
def hash_password(password):
    """Weak password hashing using MD5 - VULNERABLE!"""
    return hashlib.md5(password.encode()).hexdigest()

# VULNERABILITY 6: Weak JWT implementation with 'none' algorithm support
def create_token(user_id, username, role):
    """Create JWT token - VULNERABLE to algorithm confusion!"""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    # VULNERABILITY: Algorithm can be changed to 'none'
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token

def verify_token(token):
    """Verify JWT token - VULNERABLE!"""
    try:
        # VULNERABILITY: Accepts 'none' algorithm
        payload = jwt.decode(token, app.secret_key, algorithms=['HS256', 'none'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    """Landing page"""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint - VULNERABILITY 1: SQL Injection"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn, cursor = get_cursor()
        if not conn:
            return render_template('login.html', error='Database connection failed')

        # VULNERABILITY 1: SQL Injection via string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

        try:
            cursor.execute(query)
            user = cursor.fetchone()

            if user:
                # Set session
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['account_number'] = user['account_number']

                # VULNERABILITY 8: Information Disclosure - expose sensitive data
                session['balance'] = float(user['balance'])
                session['ssn'] = user['ssn']

                # Create JWT token
                token = create_token(user['id'], user['username'], user['role'])

                # Update last login
                cursor.execute(f"UPDATE users SET last_login=NOW() WHERE id={user['id']}")
                conn.commit()

                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie('auth_token', token)

                cursor.close()
                conn.close()
                return response
            else:
                cursor.close()
                conn.close()
                return render_template('login.html', error='Невірний логін або пароль')

        except mysql.connector.Error as err:
            # VULNERABILITY 8: Information Disclosure - expose SQL errors
            cursor.close()
            conn.close()
            return render_template('login.html', error=f'Database error: {str(err)}')

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout endpoint"""
    session.clear()
    response = make_response(redirect(url_for('login')))
    response.set_cookie('auth_token', '', expires=0)
    return response

@app.route('/dashboard')
def dashboard():
    """Dashboard - requires login"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cursor = get_cursor()
    if not conn:
        return "Database connection failed", 500

    # VULNERABILITY 3: IDOR - using predictable ID from session
    user_id = session['user_id']

    # Get user details
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()

    # Get recent transactions
    account_number = session['account_number']
    cursor.execute(f"""
        SELECT * FROM transactions
        WHERE from_account='{account_number}' OR to_account='{account_number}'
        ORDER BY created_at DESC LIMIT 10
    """)
    transactions = cursor.fetchall()

    # Get loans
    cursor.execute(f"SELECT * FROM loans WHERE account_number='{account_number}'")
    loans = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('dashboard.html', user=user, transactions=transactions, loans=loans)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """Money transfer - VULNERABILITY 2: Race Condition"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        from_account = session['account_number']
        to_account = request.form.get('to_account')
        amount = float(request.form.get('amount'))
        description = request.form.get('description', '')

        conn, cursor = get_cursor()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        # VULNERABILITY 2: Race Condition - No transaction locking!
        # Check balance
        cursor.execute(f"SELECT balance FROM users WHERE account_number='{from_account}'")
        result = cursor.fetchone()
        current_balance = float(result['balance'])

        # Simulate processing delay (makes race condition easier to exploit)
        time.sleep(0.1)

        if current_balance >= amount:
            # VULNERABILITY 2: No atomic transaction or locking
            cursor.execute(f"UPDATE users SET balance = balance - {amount} WHERE account_number = '{from_account}'")
            cursor.execute(f"UPDATE users SET balance = balance + {amount} WHERE account_number = '{to_account}'")

            # Log transaction
            cursor.execute(f"""
                INSERT INTO transactions (from_account, to_account, amount, description, transaction_type)
                VALUES ('{from_account}', '{to_account}', {amount}, '{description}', 'transfer')
            """)

            conn.commit()
            cursor.close()
            conn.close()

            return redirect(url_for('dashboard'))
        else:
            cursor.close()
            conn.close()
            return render_template('transfer.html', error='Insufficient balance')

    return render_template('transfer.html')

@app.route('/account/<int:account_id>')
def view_account(account_id):
    """View account details - VULNERABILITY 3: IDOR"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    # VULNERABILITY 3: IDOR - No authorization check!
    # Any logged-in user can view ANY account
    cursor.execute(f"SELECT * FROM users WHERE id={account_id}")
    account = cursor.fetchone()

    if account:
        # VULNERABILITY 8: Information Disclosure - expose sensitive data
        cursor.close()
        conn.close()
        return jsonify({
            'id': account['id'],
            'username': account['username'],
            'email': account['email'],
            'account_number': account['account_number'],
            'balance': float(account['balance']),
            'ssn': account['ssn'],  # Exposing SSN!
            'phone': account['phone'],
            'address': account['address'],
            'role': account['role']
        })

    cursor.close()
    conn.close()
    return jsonify({'error': 'Account not found'}), 404

@app.route('/search')
def search():
    """Search transactions - VULNERABILITY 4: XSS"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = request.args.get('q', '')

    # VULNERABILITY 4: XSS - No sanitization of user input
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search Results</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="container">
            <h1>Результати пошуку для: {query}</h1>
            <p>Ваш запит: {query}</p>
            <a href="/dashboard">Повернутися до панелі</a>
        </div>
    </body>
    </html>
    """

@app.route('/admin/users')
def admin_users():
    """Admin panel - VULNERABILITY 5: Missing Authorization"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 5: Missing Authorization - No role check!
    # Any logged-in user can access admin functionality

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor.execute("SELECT id, username, email, account_number, balance, role, ssn FROM users")
    users = cursor.fetchall()

    cursor.close()
    conn.close()

    # VULNERABILITY 8: Information Disclosure - expose all user data including SSN
    return jsonify({'users': users})

@app.route('/admin/update_balance', methods=['POST'])
def admin_update_balance():
    """Update user balance - VULNERABILITY 5 & 7: Missing Authorization + CSRF"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 5: Missing Authorization - No role check!
    # VULNERABILITY 7: No CSRF protection

    account_number = request.form.get('account_number')
    new_balance = request.form.get('balance')

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor.execute(f"UPDATE users SET balance={new_balance} WHERE account_number='{account_number}'")
    conn.commit()

    cursor.close()
    conn.close()

    return jsonify({'success': True, 'message': 'Balance updated'})

@app.route('/api/balance')
def api_balance():
    """API endpoint for balance - VULNERABILITY 10: Client-side security"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 10: Balance stored in session (client-side)
    # Can be manipulated via session cookies
    balance = session.get('balance', 0)

    return jsonify({'balance': balance})

@app.route('/debug/info')
def debug_info():
    """Debug endpoint - VULNERABILITY 8: Information Disclosure"""
    # VULNERABILITY 8: Exposing sensitive configuration and environment
    info = {
        'database': DB_CONFIG,
        'secret_key': app.secret_key,
        'environment': dict(os.environ),
        'session': dict(session)
    }
    return jsonify(info)

@app.route('/sql_debug')
def sql_debug():
    """SQL debug endpoint - VULNERABILITY 8: Information Disclosure"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 8: Allow arbitrary SQL queries (for debugging only!)
    query = request.args.get('query', 'SELECT 1')

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cursor.execute(query)
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'query': query, 'results': results})
    except Exception as e:
        cursor.close()
        conn.close()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
