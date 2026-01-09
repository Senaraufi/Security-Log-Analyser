# Setup and Testing Guide

> **Complete guide for installation, configuration, testing, and troubleshooting**

---

## 📦 Installation

### Prerequisites

**Required:**
- Rust (latest stable) - [Install from rustup.rs](https://rustup.rs/)
- Cargo (comes with Rust)

**Optional:**
- MySQL 8.0+ (for database features)
- Claude API key (for AI analysis)

### Install Rust

```bash
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version
cargo --version
```

### Clone and Build

```bash
# Navigate to project
cd /Users/senaraufi/Desktop/Startup/security_api

# Build project
cargo build --release

# Run tests
cargo test
```

---

## ⚙️ Configuration

### 1. Create `.env` File

Create `.env` in the `security_api/` directory:

```bash
# Claude AI API Key (Required for AI analysis)
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here

# Database Connection (Optional)
DATABASE_URL=mysql://root:your_password@localhost:3306/security_LogsDB

# Server Configuration
RUST_LOG=info
SERVER_PORT=3000

# Optional: Use mock analyzer for testing without API costs
USE_MOCK_ANALYZER=false
```

### 2. Get Claude API Key

1. Visit [console.anthropic.com](https://console.anthropic.com/)
2. Sign up or log in
3. Navigate to API Keys
4. Create new key
5. Copy to `.env` file

**Cost:** ~$0.01-0.05 per analysis (small log files)

### 3. Setup MySQL Database (Optional)

#### Install MySQL

**macOS:**
```bash
brew install mysql
brew services start mysql
```

**Linux:**
```bash
sudo apt-get install mysql-server
sudo systemctl start mysql
```

#### Create Database

```bash
# Login to MySQL
mysql -u root -p

# Create database
CREATE DATABASE security_LogsDB;

# Verify
SHOW DATABASES;
```

#### Run Schema

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
mysql -u root -p security_LogsDB < schema.sql
```

#### Update `.env`

```bash
DATABASE_URL=mysql://root:YOUR_PASSWORD@localhost:3306/security_LogsDB
```

---

## 🧪 Testing

### Quick Test Methods

#### 1. Interactive Demo (Recommended First Test)

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run --example demo_analyzer
```

**What it does:**
- Shows step-by-step log processing
- Demonstrates threat detection
- Interactive (press Enter to continue)
- No API calls needed

**Time:** ~2 minutes

---

#### 2. Mock AI Analyzer Test

```bash
cargo run --example test_llm_analyzer
```

**What it does:**
- Parses sample logs
- Simulates AI analysis (no API costs)
- Shows full security report
- Tests all components except Claude API

**Time:** ~30 seconds

---

#### 3. Real Claude API Test

```bash
cargo run --example test_parser
```

**What it does:**
- Uses your actual API key
- Sends logs to Claude
- Gets real AI analysis
- **Costs:** ~$0.01-0.05

**Time:** ~1-2 minutes

---

#### 4. Database Integration Test

```bash
cargo run --example test_database
```

**What it does:**
- Tests database connection
- Saves sample analysis
- Retrieves data
- Verifies schema

**Requirements:** MySQL running and configured

---

#### 5. Web Interface Test

```bash
# Start server
cargo run --release

# Open browser
open http://localhost:3000
```

**What to test:**
1. Upload `apache_combined_test.log`
2. Try Standard Analysis
3. Try AI Analysis (uses API key)
4. Check results display
5. Test with different log files

---

### Test Files

**Included Sample Logs:**

1. **`apache_combined_test.log`** (20 lines)
   - Various threat types
   - SQL injection examples
   - XSS attempts
   - Path traversal
   - Scanner activity

2. **`apache_sample.log`** (larger file)
   - Performance testing
   - Multiple IPs
   - Mixed normal/suspicious traffic

3. **`test_logs.txt`**
   - All 7 threat types
   - Known threat counts
   - Validation testing

4. **`bad_format_test.txt`**
   - Malformed logs
   - Edge cases
   - Parser robustness testing

---

### Expected Results

#### Standard Analysis Output

```
============================================================
📊 SECURITY ANALYSIS SUMMARY
============================================================

🔢 Threat Statistics:
   SQL Injection: 5
   XSS Attempts: 3
   Path Traversal: 2
   Scanner Activity: 1
   Failed Logins: 10
   Root Attempts: 2
   Suspicious File Access: 1

🎯 IP Address Analysis:
   🚨 High-Risk IPs (3+ occurrences):
      192.168.1.100 - 15 occurrences
      172.16.0.25 - 8 occurrences

⚖️  Overall Risk Assessment:
   🔴 HIGH - Immediate action required
   Threat Score: 85/100
   Total Threats: 24
============================================================
```

#### AI Analysis Output

```
📋 EXECUTIVE SUMMARY
Multiple critical security threats detected including SQL injection 
attempts and path traversal from IP 192.168.1.100. Coordinated 
attack pattern suggests automated scanning followed by exploitation.

🎯 OVERALL THREAT LEVEL: Critical

🔍 KEY FINDINGS

1. SQL Injection (Critical)
   Confidence: 95%
   MITRE ATT&CK: T1190 - Exploit Public-Facing Application
   Description: Classic UNION-based SQL injection in /api/users
   Affected Resources: /api/users, /api/products
   IOCs: UNION SELECT, -- comment sequences

2. Path Traversal (High)
   Confidence: 88%
   OWASP: A01:2021 - Broken Access Control
   Description: Directory traversal attempt to access /etc/passwd
   Affected Resources: /files/download
   IOCs: ../, /etc/passwd patterns

🔗 ATTACK CHAINS DETECTED
- 192.168.1.100: Reconnaissance → SQL Injection → Privilege Escalation

💡 RECOMMENDATIONS
1. [IMMEDIATE] Block IP 192.168.1.100
2. [HIGH] Implement parameterized queries for all database access
3. [HIGH] Enable WAF rules for SQL injection and path traversal
4. [MEDIUM] Add rate limiting to API endpoints
5. [MEDIUM] Review access controls on file download functionality
```

---

## 🔍 Verification

### Verify Parser Works

```bash
# Should parse successfully
cargo test test_parse_apache_combined

# Should detect threats
cargo test test_threat_detection
```

### Verify Database Connection

```bash
# Check connection
cargo run --example test_database

# Expected output:
# ✅ Database connected successfully!
# ✅ Test data saved
# ✅ Test data retrieved
```

### Verify Claude API

```bash
# Set API key in .env first
cargo run --example test_parser

# Expected output:
# 🤖 Connecting to Claude API...
# ✅ Analysis complete!
# 📋 Summary: [AI-generated summary]
```

### Verify Web Server

```bash
# Start server
cargo run

# In another terminal:
curl http://localhost:3000

# Should return HTML
```

---

## 🚨 Troubleshooting

### Common Issues

#### 1. "Failed to compile"

**Cause:** Missing dependencies or Rust version

**Fix:**
```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build
```

---

#### 2. "Port 3000 already in use"

**Cause:** Another process using port 3000

**Fix:**
```bash
# Find process
lsof -ti:3000

# Kill it
lsof -ti:3000 | xargs kill -9

# Or change port in .env
SERVER_PORT=3001
```

---

#### 3. "API key not found"

**Cause:** `.env` file missing or incorrect

**Fix:**
```bash
# Check .env exists
ls -la .env

# Verify content
cat .env | grep ANTHROPIC_API_KEY

# Should show: ANTHROPIC_API_KEY=sk-ant-...
```

---

#### 4. "Failed to connect to database"

**Cause:** MySQL not running or wrong credentials

**Fix:**
```bash
# Check MySQL is running
mysql.server status  # macOS
sudo systemctl status mysql  # Linux

# Start MySQL
mysql.server start  # macOS
sudo systemctl start mysql  # Linux

# Test connection
mysql -u root -p

# Verify database exists
SHOW DATABASES;
```

---

#### 5. "Claude API rate limit exceeded"

**Cause:** Too many requests in short time

**Fix:**
```bash
# Use mock analyzer for testing
USE_MOCK_ANALYZER=true

# Or wait a few minutes and retry
```

---

#### 6. "Failed to parse log file"

**Cause:** Unsupported log format

**Fix:**
- Check log format matches Apache Combined or Common
- Try sample logs first: `apache_combined_test.log`
- Check for encoding issues (should be UTF-8)

---

#### 7. "Cargo build takes forever"

**Cause:** First build compiles all dependencies

**Fix:**
- Be patient (first build: 5-10 minutes)
- Subsequent builds are much faster
- Use `cargo build` (not `--release`) for faster dev builds

---

### Debug Mode

Enable detailed logging:

```bash
# In .env
RUST_LOG=debug

# Or run with:
RUST_LOG=debug cargo run
```

---

## 📊 Performance Testing

### Test with Large Files

```bash
# Generate large test file
for i in {1..10000}; do 
  cat apache_combined_test.log >> large_test.log
done

# Test parsing performance
time cargo run --release -- large_test.log
```

**Expected Performance:**
- **Small files** (<100 lines): <1 second
- **Medium files** (1K lines): 1-2 seconds
- **Large files** (10K lines): 5-10 seconds
- **Very large** (100K lines): 30-60 seconds

### Memory Usage

```bash
# Monitor during processing
/usr/bin/time -l cargo run --release

# Check for memory leaks
valgrind --leak-check=full ./target/release/security_api
```

---

## 🔐 Security Testing

### Test SQL Injection Detection

```bash
# Create test log
echo '192.168.1.1 - - [15/Dec/2025:10:15:23 +0000] "GET /api/users?id=1\' UNION SELECT * FROM passwords-- HTTP/1.1" 500 0 "-" "curl/7.68.0"' > sql_test.log

# Should detect SQL injection
cargo run -- sql_test.log
```

### Test XSS Detection

```bash
echo '192.168.1.1 - - [15/Dec/2025:10:15:23 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1234 "-" "Mozilla/5.0"' > xss_test.log

cargo run -- xss_test.log
```

### Test Path Traversal Detection

```bash
echo '192.168.1.1 - - [15/Dec/2025:10:15:23 +0000] "GET /files/../../../../etc/passwd HTTP/1.1" 403 0 "-" "curl/7.68.0"' > path_test.log

cargo run -- path_test.log
```

---

## 📈 Monitoring

### Application Logs

```bash
# View logs in real-time
tail -f logs/security_api.log

# Search for errors
grep ERROR logs/security_api.log

# Count requests
grep "POST /api/analyze" logs/security_api.log | wc -l
```

### Database Monitoring

```sql
-- Check recent uploads
SELECT * FROM log_uploads 
ORDER BY upload_date DESC 
LIMIT 10;

-- Threat statistics
SELECT 
    DATE(upload_date) as date,
    COUNT(*) as uploads,
    AVG(threat_score) as avg_threat_score,
    SUM(total_threats) as total_threats
FROM analysis_results
GROUP BY DATE(upload_date)
ORDER BY date DESC;

-- High-risk IPs
SELECT ip_address, occurrence_count, risk_level
FROM ip_analysis
WHERE risk_level = 'high'
ORDER BY occurrence_count DESC;
```

---

## 🎯 Quick Command Reference

```bash
# Development
cargo build                    # Build (debug mode)
cargo build --release         # Build (optimized)
cargo run                     # Run server
cargo test                    # Run tests
cargo clean                   # Clean build artifacts

# Testing
cargo run --example demo_analyzer          # Interactive demo
cargo run --example test_llm_analyzer      # Mock AI test
cargo run --example test_parser            # Real Claude test
cargo run --example test_database          # Database test

# Database
mysql -u root -p security_LogsDB          # Connect to DB
mysql -u root -p security_LogsDB < schema.sql  # Run schema

# Server Management
lsof -ti:3000 | xargs kill -9             # Kill port 3000
curl http://localhost:3000                # Test server
curl -X POST http://localhost:3000/api/analyze -F "file=@test.log"  # Test API

# Debugging
RUST_LOG=debug cargo run                  # Debug logging
cargo run -- --help                       # Show help
cargo check                               # Fast syntax check
```

---

## 📚 Additional Resources

### Documentation
- **README.md** - Project overview
- **TECHNICAL_GUIDE.md** - Architecture details
- **This file** - Setup and testing

### External Resources
- [Rust Book](https://doc.rust-lang.org/book/)
- [Axum Documentation](https://docs.rs/axum/)
- [Claude API Docs](https://docs.anthropic.com/)
- [SQLx Documentation](https://docs.rs/sqlx/)

### Sample Logs
- `apache_combined_test.log` - Basic testing
- `apache_sample.log` - Performance testing
- `test_logs.txt` - Validation testing

---

## ✅ Pre-Deployment Checklist

- [ ] All tests passing: `cargo test`
- [ ] Release build works: `cargo build --release`
- [ ] Database connection configured
- [ ] API key set in `.env`
- [ ] `.env` in `.gitignore`
- [ ] Sample logs tested successfully
- [ ] Web interface loads correctly
- [ ] API endpoints respond correctly
- [ ] Error handling tested
- [ ] Logs directory created
- [ ] Backup strategy in place

---

## 🆘 Getting Help

### Check Logs First
```bash
# Application logs
tail -f logs/security_api.log

# Cargo build logs
cargo build 2>&1 | tee build.log
```

### Common Solutions
1. **Clean rebuild:** `cargo clean && cargo build`
2. **Update dependencies:** `cargo update`
3. **Check .env file:** `cat .env`
4. **Verify MySQL:** `mysql.server status`
5. **Test API key:** Use mock analyzer first

### Debug Steps
1. Enable debug logging: `RUST_LOG=debug`
2. Run examples to isolate issue
3. Check error messages carefully
4. Verify prerequisites installed
5. Test with sample logs first

---

**Last Updated:** January 2026  
**Status:** Production-ready  
**Support:** Check documentation or review code comments
