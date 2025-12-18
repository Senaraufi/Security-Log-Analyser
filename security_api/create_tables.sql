-- ============================================
-- Security Log Analyzer Database Schema
-- Run this in MySQL Workbench or command line
-- ============================================

USE security_LogsDB;

-- 1. LOG UPLOADS TABLE
CREATE TABLE IF NOT EXISTS log_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    file_size_bytes BIGINT,
    total_lines INT,
    parsed_lines INT,
    failed_lines INT,
    analysis_mode ENUM('standard', 'ai') NOT NULL,
    processing_time_ms INT,
    user_ip VARCHAR(45),
    INDEX idx_upload_date (upload_date),
    INDEX idx_analysis_mode (analysis_mode)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. ANALYSIS RESULTS TABLE
CREATE TABLE IF NOT EXISTS analysis_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    upload_id INT NOT NULL,
    risk_level ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    total_threats INT DEFAULT 0,
    threat_score INT DEFAULT 0,
    sql_injection_count INT DEFAULT 0,
    xss_count INT DEFAULT 0,
    path_traversal_count INT DEFAULT 0,
    command_injection_count INT DEFAULT 0,
    suspicious_patterns_count INT DEFAULT 0,
    format_quality_percentage DECIMAL(5,2),
    perfect_format_count INT DEFAULT 0,
    minor_issues_count INT DEFAULT 0,
    major_issues_count INT DEFAULT 0,
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE CASCADE,
    INDEX idx_risk_level (risk_level),
    INDEX idx_upload_id (upload_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. DETECTED THREATS TABLE
CREATE TABLE IF NOT EXISTS detected_threats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id INT NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    description TEXT,
    log_line_number INT,
    log_entry TEXT,
    timestamp TIMESTAMP,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_results(id) ON DELETE CASCADE,
    INDEX idx_threat_type (threat_type),
    INDEX idx_severity (severity),
    INDEX idx_analysis_id (analysis_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. IP ANALYSIS TABLE
CREATE TABLE IF NOT EXISTS ip_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    analysis_id INT NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    request_count INT DEFAULT 0,
    threat_count INT DEFAULT 0,
    risk_level ENUM('low', 'medium', 'high') NOT NULL,
    is_vpn BOOLEAN DEFAULT FALSE,
    country_code VARCHAR(2),
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    FOREIGN KEY (analysis_id) REFERENCES analysis_results(id) ON DELETE CASCADE,
    INDEX idx_ip_address (ip_address),
    INDEX idx_risk_level (risk_level),
    INDEX idx_analysis_id (analysis_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. AI ANALYSIS TABLE
CREATE TABLE IF NOT EXISTS ai_analysis (
    id INT AUTO_INCREMENT PRIMARY KEY,
    upload_id INT NOT NULL,
    threat_level VARCHAR(50),
    summary TEXT,
    total_logs_analyzed INT,
    suspicious_logs_count INT,
    confidence_score DECIMAL(5,2),
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processing_time_ms INT,
    tokens_used INT,
    FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE CASCADE,
    INDEX idx_upload_id (upload_id),
    INDEX idx_threat_level (threat_level)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. AI FINDINGS TABLE
CREATE TABLE IF NOT EXISTS ai_findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ai_analysis_id INT NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    confidence DECIMAL(5,2),
    description TEXT,
    finding_order INT,
    FOREIGN KEY (ai_analysis_id) REFERENCES ai_analysis(id) ON DELETE CASCADE,
    INDEX idx_ai_analysis_id (ai_analysis_id),
    INDEX idx_attack_type (attack_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. AI RECOMMENDATIONS TABLE
CREATE TABLE IF NOT EXISTS ai_recommendations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ai_analysis_id INT NOT NULL,
    recommendation TEXT NOT NULL,
    priority ENUM('low', 'medium', 'high', 'critical'),
    recommendation_order INT,
    FOREIGN KEY (ai_analysis_id) REFERENCES ai_analysis(id) ON DELETE CASCADE,
    INDEX idx_ai_analysis_id (ai_analysis_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. THREAT PATTERNS TABLE
CREATE TABLE IF NOT EXISTS threat_patterns (
    id INT AUTO_INCREMENT PRIMARY KEY,
    pattern_type VARCHAR(100) NOT NULL,
    pattern_signature VARCHAR(500) NOT NULL,
    severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    occurrence_count INT DEFAULT 1,
    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    false_positive_rate DECIMAL(5,2) DEFAULT 0.00,
    UNIQUE KEY unique_pattern (pattern_type, pattern_signature),
    INDEX idx_pattern_type (pattern_type),
    INDEX idx_occurrence_count (occurrence_count)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. RAW LOGS TABLE (Optional)
CREATE TABLE IF NOT EXISTS raw_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    upload_id INT NOT NULL,
    line_number INT NOT NULL,
    timestamp TIMESTAMP NULL,
    ip_address VARCHAR(45),
    http_method VARCHAR(10),
    request_path VARCHAR(1000),
    status_code INT,
    response_size INT,
    user_agent TEXT,
    raw_entry TEXT NOT NULL,
    is_suspicious BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE CASCADE,
    INDEX idx_upload_id (upload_id),
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip_address (ip_address),
    INDEX idx_is_suspicious (is_suspicious)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Verify tables were created
SHOW TABLES;

SELECT 'Database setup complete! All tables created successfully.' AS Status;
