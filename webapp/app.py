"""
Vulnerable Bank Web Application - EXTENDED VERSION
===================================================
WARNING: This application contains INTENTIONAL security vulnerabilities
for educational purposes. DO NOT use in production!

NEW Vulnerabilities added (v2.0):
11. File Upload Vulnerability
12. XXE (XML External Entity)
13. SSRF (Server-Side Request Forgery)
14. Command Injection
15. Path Traversal
16. Insecure Deserialization
17. Authentication Bypass (Predictable Tokens)
18. Business Logic Flaws
19. Mass Assignment
20. Template Injection
21. No Rate Limiting
22. Insecure Direct Object References (expanded)
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, send_file, send_from_directory
import mysql.connector
import os
import jwt
import datetime
import hashlib
import time
import pickle
import subprocess
import xml.etree.ElementTree as ET
import requests
import csv
import io
import json
import random
from functools import wraps
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_key_123')  # VULNERABILITY: Weak secret
app.config['UPLOAD_FOLDER'] = '/app/uploads'
app.config['DOCUMENTS_FOLDER'] = '/app/documents'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['JSON_AS_ASCII'] = False  # Support non-ASCII characters in JSON

# Database configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'db'),
    'user': os.environ.get('DB_USER', 'bankuser'),
    'password': os.environ.get('DB_PASSWORD', 'weak_password_123'),
    'database': os.environ.get('DB_NAME', 'vulnerable_bank'),
    'charset': 'utf8mb4',
    'use_unicode': True
}

def get_db_connection():
    """Create database connection"""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        # Set character encoding
        cursor = conn.cursor()
        cursor.execute("SET NAMES utf8mb4")
        cursor.execute("SET CHARACTER SET utf8mb4")
        cursor.execute("SET character_set_connection=utf8mb4")
        cursor.close()
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

@app.after_request
def after_request(response):
    """Set UTF-8 encoding for all responses"""
    if response.content_type and response.content_type.startswith('text/html'):
        response.headers['Content-Type'] = 'text/html; charset=utf-8'
    return response

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

    # Get notifications (NEW)
    cursor.execute(f"SELECT * FROM notifications WHERE user_id={user_id} ORDER BY created_at DESC LIMIT 5")
    notifications = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('dashboard.html', user=user, transactions=transactions, loans=loans, notifications=notifications)

@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    """Money transfer - VULNERABILITY 2: Race Condition + VULNERABILITY 18: Business Logic Flaw"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        from_account = session['account_number']
        to_account = request.form.get('to_account')
        amount = float(request.form.get('amount'))
        description = request.form.get('description', '')

        # VULNERABILITY 18: Business Logic Flaw - allow negative amounts!
        # No validation if amount is negative

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

    # Get user's account number
    conn, cursor = get_cursor()
    if not conn:
        return "Database connection failed", 500

    cursor.execute("SELECT account_number FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()

    if not user:
        cursor.close()
        conn.close()
        return redirect(url_for('login'))

    account_number = user['account_number']

    # Search for transactions (VULNERABLE: XSS in query display)
    results = []
    if query:
        # Search in transactions related to user's account
        search_sql = """
            SELECT t.id, t.from_account, t.to_account, t.amount, t.description,
                   t.created_at, t.status
            FROM transactions t
            WHERE (t.from_account = %s OR t.to_account = %s)
            AND (t.description LIKE %s
                 OR t.from_account LIKE %s
                 OR t.to_account LIKE %s
                 OR CAST(t.amount AS CHAR) LIKE %s)
            ORDER BY t.created_at DESC
            LIMIT 50
        """
        search_pattern = f'%{query}%'
        cursor.execute(search_sql, (account_number, account_number,
                                   search_pattern, search_pattern,
                                   search_pattern, search_pattern))
        results = cursor.fetchall()

    cursor.close()
    conn.close()

    # Build results HTML (VULNERABILITY 4: XSS - No sanitization of query in output)
    results_html = ""
    if results:
        results_html = """
        <table class="transactions-table">
            <thead>
                <tr>
                    <th>Дата</th>
                    <th>Від рахунку</th>
                    <th>До рахунку</th>
                    <th>Сума</th>
                    <th>Опис</th>
                    <th>Статус</th>
                </tr>
            </thead>
            <tbody>
        """
        for t in results:
            from_acc = t['from_account']
            to_acc = t['to_account']
            amount = t['amount']
            desc = t['description']
            created = t['created_at']
            status = t['status']

            amount_class = "amount-negative" if from_acc == account_number else "amount-positive"
            amount_sign = "-" if from_acc == account_number else "+"

            # Map status to Ukrainian
            status_map = {
                'completed': 'Виконано',
                'pending': 'В обробці',
                'failed': 'Не вдалося'
            }
            status_ua = status_map.get(status, status)
            status_badge = 'success' if status == 'completed' else 'warning' if status == 'pending' else 'danger'

            results_html += f"""
                <tr>
                    <td>{created.strftime('%d.%m.%Y %H:%M')}</td>
                    <td>{from_acc}</td>
                    <td>{to_acc}</td>
                    <td><span class="amount {amount_class}">{amount_sign}₴{abs(amount):.2f}</span></td>
                    <td>{desc}</td>
                    <td><span class="badge badge-{status_badge}">{status_ua}</span></td>
                </tr>
            """
        results_html += """
            </tbody>
        </table>
        """
    elif query:
        results_html = '<p class="no-results">Транзакції не знайдено</p>'

    # VULNERABILITY 4: XSS - query is directly inserted without sanitization
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Пошук транзакцій</title>
        <link rel="stylesheet" href="/static/style.css">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 Пошук транзакцій</h1>
                <a href="/dashboard" class="btn">← Повернутися</a>
            </div>

            <div class="search-form">
                <form method="get" action="/search">
                    <input type="text" name="q" value="{query}"
                           placeholder="Пошук за описом, рахунком, сумою..."
                           class="search-input" autofocus>
                    <button type="submit" class="btn btn-primary">Пошук</button>
                </form>
            </div>

            <div class="search-info">
                <p>Результати пошуку для: <strong>{query}</strong></p>
                <p class="results-count">Знайдено: {len(results)} транзакцій</p>
            </div>

            {results_html}
        </div>

        <style>
            .search-form {{
                margin: 30px 0;
                padding: 20px;
                background: #f8f9fa;
                border-radius: 8px;
            }}
            .search-input {{
                width: 70%;
                padding: 12px;
                font-size: 16px;
                border: 2px solid #ddd;
                border-radius: 4px;
                margin-right: 10px;
            }}
            .search-input:focus {{
                outline: none;
                border-color: #007bff;
            }}
            .search-info {{
                margin: 20px 0;
                padding: 15px;
                background: #e7f3ff;
                border-left: 4px solid #007bff;
                border-radius: 4px;
            }}
            .results-count {{
                color: #666;
                font-size: 14px;
                margin-top: 5px;
            }}
            .no-results {{
                text-align: center;
                padding: 40px;
                color: #666;
                font-size: 18px;
            }}
            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }}
        </style>
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

# ==================== NEW FEATURES & VULNERABILITIES ====================

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile management - VULNERABILITY 11: File Upload + VULNERABILITY 19: Mass Assignment"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cursor = get_cursor()
    if not conn:
        return "Database connection failed", 500

    user_id = session['user_id']

    if request.method == 'POST':
        # VULNERABILITY 19: Mass Assignment - User can set any field including role!
        username = request.form.get('username')
        email = request.form.get('email')
        phone = request.form.get('phone')
        address = request.form.get('address')
        role = request.form.get('role')  # VULNERABILITY: User can change their own role!

        # Update user info
        update_query = f"""
            UPDATE users SET
            username='{username}',
            email='{email}',
            phone='{phone}',
            address='{address}'
        """

        # VULNERABILITY 19: If role is provided, update it (mass assignment)
        if role:
            update_query += f", role='{role}'"

        update_query += f" WHERE id={user_id}"

        cursor.execute(update_query)
        conn.commit()

        return redirect(url_for('profile'))

    # Get user info
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()

    # Get profile info
    cursor.execute(f"SELECT * FROM user_profiles WHERE user_id={user_id}")
    profile = cursor.fetchone()

    cursor.close()
    conn.close()

    return render_template('profile.html', user=user, profile=profile)

@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    """Upload profile picture - VULNERABILITY 11: File Upload Vulnerability"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']

    # VULNERABILITY 11: No file type validation!
    # VULNERABILITY 11: No file size validation!
    # VULNERABILITY 11: Can upload ANY file type including .php, .jsp, .asp, etc.

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # VULNERABILITY: Using original filename without proper sanitization
    filename = file.filename
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)

    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(upload_path), exist_ok=True)

    file.save(upload_path)

    # Update database
    conn, cursor = get_cursor()
    if conn:
        user_id = session['user_id']
        avatar_path = f'/uploads/avatars/{filename}'
        cursor.execute(f"""
            INSERT INTO user_profiles (user_id, avatar_path)
            VALUES ({user_id}, '{avatar_path}')
            ON DUPLICATE KEY UPDATE avatar_path='{avatar_path}'
        """)
        conn.commit()
        cursor.close()
        conn.close()

    return jsonify({'success': True, 'path': avatar_path})

@app.route('/upload_avatar_url', methods=['POST'])
def upload_avatar_url():
    """Upload profile picture from URL - VULNERABILITY 13: SSRF"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    url = request.form.get('url')

    # VULNERABILITY 13: SSRF - No URL validation!
    # Can access internal services: http://localhost, http://192.168.x.x, http://169.254.169.254 (AWS metadata)
    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            # Save the image
            filename = f"avatar_{session['user_id']}.jpg"
            upload_path = os.path.join(app.config['UPLOAD_FOLDER'], 'avatars', filename)

            os.makedirs(os.path.dirname(upload_path), exist_ok=True)

            with open(upload_path, 'wb') as f:
                f.write(response.content)

            # Update database
            conn, cursor = get_cursor()
            if conn:
                avatar_path = f'/uploads/avatars/{filename}'
                cursor.execute(f"""
                    INSERT INTO user_profiles (user_id, avatar_path)
                    VALUES ({session['user_id']}, '{avatar_path}')
                    ON DUPLICATE KEY UPDATE avatar_path='{avatar_path}'
                """)
                conn.commit()
                cursor.close()
                conn.close()

            return jsonify({'success': True, 'message': 'Avatar uploaded from URL'})
        else:
            return jsonify({'error': f'Failed to fetch URL: {response.status_code}'}), 400

    except Exception as e:
        # VULNERABILITY 8: Information disclosure in error message
        return jsonify({'error': f'Error fetching URL: {str(e)}'}), 500

@app.route('/import_transactions', methods=['POST'])
def import_transactions():
    """Import transactions from XML - VULNERABILITY 12: XXE (XML External Entity)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    xml_data = request.form.get('xml_data')

    # VULNERABILITY 12: XXE - Parsing XML without disabling external entities
    try:
        # This is vulnerable to XXE attacks
        root = ET.fromstring(xml_data)

        transactions = []
        for trans in root.findall('transaction'):
            transactions.append({
                'to_account': trans.find('to_account').text,
                'amount': trans.find('amount').text,
                'description': trans.find('description').text
            })

        return jsonify({'success': True, 'imported': len(transactions), 'data': transactions})

    except ET.ParseError as e:
        return jsonify({'error': f'XML Parse Error: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': f'Error: {str(e)}'}), 500

@app.route('/admin/ping', methods=['POST'])
def admin_ping():
    """Ping a server - VULNERABILITY 14: Command Injection"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 5: No admin check

    host = request.form.get('host', 'localhost')

    # VULNERABILITY 14: Command Injection - No input validation!
    # Can execute arbitrary commands: localhost; ls -la
    try:
        cmd = f"ping -c 4 {host}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

        return jsonify({
            'success': True,
            'output': result.stdout,
            'error': result.stderr
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download_document/<int:doc_id>')
def download_document(doc_id):
    """Download document - VULNERABILITY 15: Path Traversal"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    # VULNERABILITY 3: IDOR - No ownership check
    cursor.execute(f"SELECT * FROM documents WHERE id={doc_id}")
    document = cursor.fetchone()

    cursor.close()
    conn.close()

    if not document:
        return jsonify({'error': 'Document not found'}), 404

    # VULNERABILITY 15: Path Traversal - Using user-controlled file path
    file_path = document['file_path']

    # No validation! Can use ../../../etc/passwd
    try:
        return send_file(file_path, as_attachment=True, download_name=document['filename'])
    except Exception as e:
        return jsonify({'error': f'File not found: {str(e)}'}), 404

@app.route('/download_document_by_name')
def download_document_by_name():
    """Download document by filename - VULNERABILITY 15: Path Traversal (Alternative)"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # VULNERABILITY 15: Direct path traversal via query parameter
    filename = request.args.get('file', '')

    # No sanitization! Can use ../../../../etc/passwd
    try:
        return send_from_directory(app.config['DOCUMENTS_FOLDER'], filename)
    except Exception as e:
        return jsonify({'error': f'File not found: {str(e)}'}), 404

@app.route('/export_transactions')
def export_transactions():
    """Export transactions to CSV/JSON/XML"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    format_type = request.args.get('format', 'csv')
    account_number = session['account_number']

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor.execute(f"""
        SELECT * FROM transactions
        WHERE from_account='{account_number}' OR to_account='{account_number}'
        ORDER BY created_at DESC
    """)
    transactions = cursor.fetchall()

    cursor.close()
    conn.close()

    if format_type == 'csv':
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=['id', 'from_account', 'to_account', 'amount', 'description', 'created_at'])
        writer.writeheader()
        writer.writerows(transactions)

        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = 'attachment; filename=transactions.csv'
        return response

    elif format_type == 'json':
        return jsonify(transactions)

    elif format_type == 'xml':
        # VULNERABILITY 12: Generated XML can be used for XXE when imported back
        xml_output = '<?xml version="1.0" encoding="UTF-8"?>\n<transactions>\n'
        for trans in transactions:
            xml_output += f'  <transaction>\n'
            xml_output += f'    <id>{trans["id"]}</id>\n'
            xml_output += f'    <from_account>{trans["from_account"]}</from_account>\n'
            xml_output += f'    <to_account>{trans["to_account"]}</to_account>\n'
            xml_output += f'    <amount>{trans["amount"]}</amount>\n'
            xml_output += f'    <description>{trans["description"]}</description>\n'
            xml_output += f'  </transaction>\n'
        xml_output += '</transactions>'

        response = make_response(xml_output)
        response.headers['Content-Type'] = 'application/xml'
        response.headers['Content-Disposition'] = 'attachment; filename=transactions.xml'
        return response

    return jsonify({'error': 'Invalid format'}), 400

@app.route('/password_reset', methods=['GET', 'POST'])
def password_reset():
    """Password reset - VULNERABILITY 17: Predictable Reset Tokens"""
    if request.method == 'POST':
        email = request.form.get('email')

        conn, cursor = get_cursor()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        cursor.execute(f"SELECT * FROM users WHERE email='{email}'")
        user = cursor.fetchone()

        if user:
            # VULNERABILITY 17: Predictable token generation
            # Using sequential or timestamp-based tokens
            timestamp = int(time.time())
            token = f"reset_{user['id']}_{timestamp}"

            expires_at = datetime.datetime.now() + datetime.timedelta(hours=24)

            cursor.execute(f"""
                INSERT INTO password_reset_tokens (user_id, token, expires_at)
                VALUES ({user['id']}, '{token}', '{expires_at}')
            """)
            conn.commit()

            cursor.close()
            conn.close()

            # VULNERABILITY 8: Information disclosure - return token directly
            return jsonify({
                'success': True,
                'message': 'Password reset token generated',
                'token': token,  # Should never return this!
                'reset_link': f'/reset_password?token={token}'
            })
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Email not found'}), 404

    return render_template('password_reset.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Reset password using token - VULNERABILITY 17"""
    token = request.args.get('token')

    if request.method == 'POST':
        new_password = request.form.get('new_password')

        conn, cursor = get_cursor()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        cursor.execute(f"SELECT * FROM password_reset_tokens WHERE token='{token}' AND used=FALSE")
        reset_token = cursor.fetchone()

        if reset_token and reset_token['expires_at'] > datetime.datetime.now():
            user_id = reset_token['user_id']

            # Update password
            cursor.execute(f"UPDATE users SET password='{new_password}' WHERE id={user_id}")
            cursor.execute(f"UPDATE password_reset_tokens SET used=TRUE WHERE token='{token}'")
            conn.commit()

            cursor.close()
            conn.close()

            return jsonify({'success': True, 'message': 'Password reset successful'})
        else:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Invalid or expired token'}), 400

    return render_template('reset_password.html', token=token)

@app.route('/apply_loan', methods=['GET', 'POST'])
def apply_loan():
    """Apply for a loan - VULNERABILITY 18: Business Logic Flaw"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        conn, cursor = get_cursor()
        if not conn:
            return jsonify({'error': 'Database connection failed'}), 500

        user_id = session['user_id']
        account_number = session['account_number']
        requested_amount = float(request.form.get('amount'))  # VULNERABILITY: No validation!
        loan_type = request.form.get('loan_type', 'personal')
        purpose = request.form.get('purpose', '')

        # VULNERABILITY 18: Business Logic Flaw - Can request negative loan amount!
        # This would result in the bank owing money to the user

        cursor.execute(f"""
            INSERT INTO loan_applications
            (user_id, account_number, requested_amount, loan_type, purpose, status, submitted_at)
            VALUES ({user_id}, '{account_number}', {requested_amount}, '{loan_type}', '{purpose}', 'submitted', NOW())
        """)
        conn.commit()

        cursor.close()
        conn.close()

        return redirect(url_for('my_loans'))

    return render_template('apply_loan.html')

@app.route('/my_loans')
def my_loans():
    """View user's loan applications"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cursor = get_cursor()
    if not conn:
        return "Database connection failed", 500

    user_id = session['user_id']

    cursor.execute(f"SELECT * FROM loan_applications WHERE user_id={user_id} ORDER BY created_at DESC")
    applications = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('my_loans.html', applications=applications)

@app.route('/api/v2/balance')
def api_v2_balance():
    """API v2 - Get balance - VULNERABILITY 21: No Rate Limiting"""
    # VULNERABILITY 21: No rate limiting, no authentication required!

    account_number = request.args.get('account')

    if not account_number:
        return jsonify({'error': 'Account number required'}), 400

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    # VULNERABILITY 3: IDOR
    cursor.execute(f"SELECT balance FROM users WHERE account_number='{account_number}'")
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    if result:
        return jsonify({'account': account_number, 'balance': float(result['balance'])})
    else:
        return jsonify({'error': 'Account not found'}), 404

@app.route('/api/v2/transfer', methods=['POST'])
def api_v2_transfer():
    """API v2 - Transfer money - VULNERABILITY 21: No Rate Limiting"""
    # Check for API key
    api_key = request.headers.get('X-API-Key')

    if not api_key:
        return jsonify({'error': 'API key required'}), 401

    conn, cursor = get_cursor()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    # VULNERABILITY: Weak API key validation
    cursor.execute(f"SELECT * FROM api_keys WHERE api_key='{api_key}' AND is_active=TRUE")
    key_record = cursor.fetchone()

    if not key_record:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Invalid API key'}), 401

    # VULNERABILITY 21: Rate limit is stored but not enforced!

    data = request.get_json()
    from_account = data.get('from_account')
    to_account = data.get('to_account')
    amount = float(data.get('amount'))

    # Perform transfer (with race condition vulnerability)
    cursor.execute(f"SELECT balance FROM users WHERE account_number='{from_account}'")
    result = cursor.fetchone()

    if result and float(result['balance']) >= amount:
        cursor.execute(f"UPDATE users SET balance = balance - {amount} WHERE account_number = '{from_account}'")
        cursor.execute(f"UPDATE users SET balance = balance + {amount} WHERE account_number = '{to_account}'")
        cursor.execute(f"""
            INSERT INTO transactions (from_account, to_account, amount, description, transaction_type)
            VALUES ('{from_account}', '{to_account}', {amount}, 'API Transfer', 'transfer')
        """)

        # Update API key last used
        cursor.execute(f"UPDATE api_keys SET last_used_at=NOW() WHERE api_key='{api_key}'")

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({'success': True, 'message': 'Transfer completed'})
    else:
        cursor.close()
        conn.close()
        return jsonify({'error': 'Insufficient balance'}), 400

@app.route('/notifications')
def notifications():
    """View notifications - VULNERABILITY 20: Template Injection"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn, cursor = get_cursor()
    if not conn:
        return "Database connection failed", 500

    user_id = session['user_id']

    cursor.execute(f"SELECT * FROM notifications WHERE user_id={user_id} ORDER BY created_at DESC")
    notifications = cursor.fetchall()

    cursor.close()
    conn.close()

    # VULNERABILITY 20: Template Injection - rendering user-controlled content
    # Messages can contain template syntax like {{7*7}} or {{config}}

    html_output = """
    <!DOCTYPE html>
    <html>
    <head><title>Notifications</title></head>
    <body>
        <h1>Your Notifications</h1>
    """

    for notif in notifications:
        # VULNERABILITY 20: Eval-like behavior by rendering template strings
        message = notif['message']
        # In a real exploit, this would use template.render() with user data
        html_output += f"<div class='notification'><h3>{notif['title']}</h3><p>{message}</p></div>"

    html_output += """
        <a href="/dashboard">Back to Dashboard</a>
    </body>
    </html>
    """

    return html_output

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
        'session': dict(session),
        'upload_folder': app.config['UPLOAD_FOLDER']
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
    # Create upload directories
    os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'avatars'), exist_ok=True)
    os.makedirs(app.config['DOCUMENTS_FOLDER'], exist_ok=True)

    app.run(host='0.0.0.0', port=5000, debug=True)
