-- Vulnerable Bank Database Initialization Script
-- WARNING: This database contains intentional security vulnerabilities for educational purposes

CREATE DATABASE IF NOT EXISTS vulnerable_bank CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vulnerable_bank;

-- Users table with plain text passwords (VULNERABILITY)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,  -- Storing plain text passwords!
    email VARCHAR(100),
    account_number VARCHAR(20) NOT NULL UNIQUE,
    balance DECIMAL(15, 2) DEFAULT 0.00,
    role ENUM('user', 'admin', 'teller') DEFAULT 'user',
    ssn VARCHAR(11),  -- Storing SSN in plain text!
    phone VARCHAR(20),
    address TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    from_account VARCHAR(20) NOT NULL,
    to_account VARCHAR(20) NOT NULL,
    amount DECIMAL(15, 2) NOT NULL,
    transaction_type ENUM('transfer', 'deposit', 'withdrawal') DEFAULT 'transfer',
    description VARCHAR(255),
    status ENUM('pending', 'completed', 'failed') DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_from_account (from_account),
    INDEX idx_to_account (to_account),
    INDEX idx_created_at (created_at)
);

-- Loans table
CREATE TABLE IF NOT EXISTS loans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_number VARCHAR(20) NOT NULL,
    loan_amount DECIMAL(15, 2) NOT NULL,
    interest_rate DECIMAL(5, 2) NOT NULL,
    loan_type ENUM('personal', 'mortgage', 'auto', 'business') DEFAULT 'personal',
    status ENUM('pending', 'approved', 'rejected', 'active', 'paid') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL,
    FOREIGN KEY (account_number) REFERENCES users(account_number)
);

-- Session tokens table (vulnerable JWT storage)
CREATE TABLE IF NOT EXISTS session_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(500) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Admin actions log
CREATE TABLE IF NOT EXISTS admin_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id INT NOT NULL,
    action VARCHAR(255) NOT NULL,
    target_user_id INT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id)
);

-- User profiles table (NEW - for file upload vulnerability)
CREATE TABLE IF NOT EXISTS user_profiles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    avatar_path VARCHAR(255),  -- VULNERABILITY: No validation on file path
    bio TEXT,
    date_of_birth DATE,
    nationality VARCHAR(50),
    occupation VARCHAR(100),
    annual_income DECIMAL(15, 2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY (user_id)
);

-- Password reset tokens (NEW - predictable tokens vulnerability)
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(100) NOT NULL,  -- VULNERABILITY: Predictable token generation
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_token (token)
);

-- Documents/Files table (NEW - path traversal vulnerability)
CREATE TABLE IF NOT EXISTS documents (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    document_type ENUM('statement', 'contract', 'receipt', 'certificate', 'other') DEFAULT 'other',
    filename VARCHAR(255) NOT NULL,  -- VULNERABILITY: No sanitization
    file_path VARCHAR(500) NOT NULL,  -- VULNERABILITY: Path traversal possible
    file_size INT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_user (user_id)
);

-- API Keys table (NEW - weak key generation)
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    api_key VARCHAR(64) NOT NULL,  -- VULNERABILITY: Predictable keys
    api_secret VARCHAR(64) NOT NULL,  -- VULNERABILITY: Weak secrets
    is_active BOOLEAN DEFAULT TRUE,
    rate_limit INT DEFAULT 1000,  -- VULNERABILITY: No actual rate limiting implemented
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY (api_key)
);

-- Loan applications (NEW - expanded for business logic flaws)
CREATE TABLE IF NOT EXISTS loan_applications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    account_number VARCHAR(20) NOT NULL,
    requested_amount DECIMAL(15, 2) NOT NULL,  -- VULNERABILITY: Can be negative!
    loan_type ENUM('personal', 'mortgage', 'auto', 'business') DEFAULT 'personal',
    purpose TEXT,
    employment_status VARCHAR(100),
    monthly_income DECIMAL(15, 2),
    status ENUM('draft', 'submitted', 'under_review', 'approved', 'rejected') DEFAULT 'draft',
    admin_notes TEXT,
    submitted_at TIMESTAMP NULL,
    reviewed_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Notifications table (NEW - for template injection vulnerability)
CREATE TABLE IF NOT EXISTS notifications (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,  -- VULNERABILITY: Can contain template code
    notification_type ENUM('info', 'warning', 'success', 'error') DEFAULT 'info',
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_user_unread (user_id, is_read)
);

-- Insert test users with WEAK passwords (intentional vulnerability)
INSERT INTO users (username, password, email, account_number, balance, role, ssn, phone, address) VALUES
('admin', 'admin123', 'admin@bank.local', '1000000001', 1000000.00, 'admin', '123-45-6789', '+380501234567', 'Київ, вул. Банківська 1'),
('john', 'password', 'john@example.com', '1000000002', 5000.00, 'user', '234-56-7890', '+380501234568', 'Київ, вул. Хрещатик 10'),
('jane', '123456', 'jane@example.com', '1000000003', 10000.00, 'user', '345-67-8901', '+380501234569', 'Львів, пр. Свободи 5'),
('bob', 'qwerty', 'bob@example.com', '1000000004', 2500.00, 'user', '456-78-9012', '+380501234570', 'Одеса, вул. Дерибасівська 15'),
('alice', 'letmein', 'alice@example.com', '1000000005', 15000.00, 'teller', '567-89-0123', '+380501234571', 'Харків, пр. Науки 20'),
('charlie', 'password123', 'charlie@example.com', '1000000006', 500.00, 'user', '678-90-1234', '+380501234572', 'Дніпро, вул. Соборна 8'),
('david', 'admin', 'david@example.com', '1000000007', 7500.00, 'user', '789-01-2345', '+380501234573', 'Запоріжжя, пр. Соборний 12'),
('eve', 'password1', 'eve@example.com', '1000000008', 3000.00, 'user', '890-12-3456', '+380501234574', 'Вінниця, вул. Соборна 3');

-- Insert sample transactions
INSERT INTO transactions (from_account, to_account, amount, transaction_type, description) VALUES
('1000000002', '1000000003', 500.00, 'transfer', 'Повернення боргу'),
('1000000003', '1000000004', 1000.00, 'transfer', 'Оплата за послуги'),
('1000000002', '1000000005', 250.00, 'transfer', 'Подарунок'),
('1000000004', '1000000002', 100.00, 'transfer', 'Комісія'),
('1000000006', '1000000003', 200.00, 'transfer', 'Оренда'),
('1000000007', '1000000008', 1500.00, 'transfer', 'Заробітна плата'),
('1000000003', '1000000007', 750.00, 'transfer', 'Покупка товарів');

-- Insert sample loans
INSERT INTO loans (account_number, loan_amount, interest_rate, loan_type, status, approved_at) VALUES
('1000000002', 50000.00, 12.5, 'personal', 'active', NOW()),
('1000000003', 200000.00, 10.0, 'mortgage', 'active', NOW()),
('1000000004', 15000.00, 15.0, 'auto', 'active', NOW()),
('1000000006', 5000.00, 18.0, 'personal', 'pending', NULL),
('1000000007', 100000.00, 11.5, 'business', 'approved', NOW());

-- Insert admin logs
INSERT INTO admin_logs (admin_id, action, target_user_id, details, ip_address) VALUES
(1, 'USER_CREATED', 2, 'Created user john', '192.168.1.100'),
(1, 'USER_UPDATED', 3, 'Updated balance for jane', '192.168.1.100'),
(1, 'LOAN_APPROVED', NULL, 'Approved loan #1', '192.168.1.100'),
(1, 'USER_DELETED', NULL, 'Attempted to delete inactive user', '192.168.1.100');

-- Insert user profiles (NEW)
INSERT INTO user_profiles (user_id, avatar_path, bio, date_of_birth, nationality, occupation, annual_income) VALUES
(1, '/uploads/avatars/admin.jpg', 'Bank Administrator', '1980-01-15', 'Ukrainian', 'Administrator', 100000.00),
(2, '/uploads/avatars/john.jpg', 'Software Engineer', '1990-05-20', 'Ukrainian', 'Developer', 60000.00),
(3, '/uploads/avatars/jane.jpg', 'Business Analyst', '1988-03-10', 'Ukrainian', 'Analyst', 55000.00),
(4, '/uploads/avatars/bob.jpg', 'Student', '1999-12-01', 'Ukrainian', 'Student', 12000.00),
(5, '/uploads/avatars/alice.jpg', 'Bank Teller', '1992-07-15', 'Ukrainian', 'Teller', 30000.00);

-- Insert sample documents (NEW)
INSERT INTO documents (user_id, account_number, document_type, filename, file_path, file_size) VALUES
(2, '1000000002', 'statement', 'statement_2024_01.pdf', '/documents/statements/2024/statement_2024_01.pdf', 45678),
(2, '1000000002', 'contract', 'loan_contract.pdf', '/documents/contracts/loan_contract_002.pdf', 123456),
(3, '1000000003', 'statement', 'statement_2024_01.pdf', '/documents/statements/2024/statement_2024_01_003.pdf', 42000),
(4, '1000000004', 'receipt', 'transfer_receipt.pdf', '/documents/receipts/transfer_20240115.pdf', 8900),
(1, '1000000001', 'certificate', 'admin_cert.pdf', '/documents/admin/certificate.pdf', 234567);

-- Insert API keys (NEW - intentionally weak)
INSERT INTO api_keys (user_id, api_key, api_secret, is_active, rate_limit) VALUES
(1, 'admin_key_12345678901234567890123456789012', 'admin_secret_98765432109876543210987654321098', TRUE, 10000),
(2, 'user_key_11111111111111111111111111111111', 'user_secret_22222222222222222222222222222222', TRUE, 1000),
(3, 'user_key_33333333333333333333333333333333', 'user_secret_44444444444444444444444444444444', TRUE, 1000);

-- Insert loan applications (NEW)
INSERT INTO loan_applications (user_id, account_number, requested_amount, loan_type, purpose, employment_status, monthly_income, status, submitted_at) VALUES
(2, '1000000002', 25000.00, 'personal', 'Home renovation', 'Full-time', 5000.00, 'under_review', NOW()),
(3, '1000000003', 150000.00, 'mortgage', 'Purchase apartment', 'Full-time', 8000.00, 'submitted', NOW()),
(4, '1000000004', 10000.00, 'auto', 'Buy used car', 'Part-time', 1500.00, 'draft', NULL),
(6, '1000000006', -5000.00, 'personal', 'Exploit negative amount', 'Unemployed', 0.00, 'draft', NULL);

-- Insert sample notifications (NEW - for template injection)
INSERT INTO notifications (user_id, title, message, notification_type, is_read) VALUES
(2, 'Welcome!', 'Welcome to Vulnerable Bank, {{username}}!', 'info', FALSE),
(2, 'Transfer Complete', 'Your transfer of $500 was successful', 'success', TRUE),
(3, 'Loan Application', 'Your loan application is under review', 'info', FALSE),
(4, 'Low Balance Warning', 'Your balance is below $1000', 'warning', FALSE),
(1, 'Admin Alert', 'System maintenance scheduled for {{maintenance_date}}', 'warning', FALSE);

-- Grant permissions (overly permissive - vulnerability)
GRANT ALL PRIVILEGES ON vulnerable_bank.* TO 'bankuser'@'%';
FLUSH PRIVILEGES;

-- Display setup completion message
SELECT 'Database initialized successfully!' AS message;
SELECT CONCAT('Total users: ', COUNT(*)) AS user_count FROM users;
SELECT CONCAT('Total transactions: ', COUNT(*)) AS transaction_count FROM transactions;
