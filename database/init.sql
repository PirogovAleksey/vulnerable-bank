-- Vulnerable Bank Database Initialization Script
-- WARNING: This database contains intentional security vulnerabilities for educational purposes

CREATE DATABASE IF NOT EXISTS vulnerable_bank;
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

-- Grant permissions (overly permissive - vulnerability)
GRANT ALL PRIVILEGES ON vulnerable_bank.* TO 'bankuser'@'%';
FLUSH PRIVILEGES;

-- Display setup completion message
SELECT 'Database initialized successfully!' AS message;
SELECT CONCAT('Total users: ', COUNT(*)) AS user_count FROM users;
SELECT CONCAT('Total transactions: ', COUNT(*)) AS transaction_count FROM transactions;
