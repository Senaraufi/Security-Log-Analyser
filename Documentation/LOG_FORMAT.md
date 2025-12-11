# Log Format Requirements

## 📋 Expected Format

The analyzer expects logs in this **exact format**:

```
YYYY-MM-DD HH:MM:SS [LEVEL] message
```

### **Format Breakdown:**

| Component | Description | Example |
|-----------|-------------|---------|
| `YYYY-MM-DD` | Date (4-digit year, 2-digit month, 2-digit day) | `2024-01-15` |
| `HH:MM:SS` | Time (24-hour format) | `10:30:45` |
| `[LEVEL]` | Severity level in square brackets | `[ERROR]`, `[INFO]`, `[WARN]`, `[CRITICAL]` |
| `message` | The log message (can contain anything) | `Failed login attempt from 192.168.1.100` |

---

## ✅ Valid Examples

```
2024-01-15 10:30:45 [ERROR] Failed login attempt from 192.168.1.100 user: admin
2024-01-15 10:31:12 [INFO] Successful login from 10.0.0.50 user: john.doe
2024-01-15 10:32:03 [WARN] Multiple failed attempts from 192.168.1.100
2024-01-15 10:33:21 [CRITICAL] Brute force attack detected
2024-12-09 14:22:15 [ERROR] SQL injection attempt: SELECT * FROM users
```

---

## ❌ Invalid Examples (Will Be Skipped)

### **Wrong Date Format:**
```
01/15/2024 10:30:45 [ERROR] Failed login  ❌ (MM/DD/YYYY instead of YYYY-MM-DD)
15-01-2024 10:30:45 [ERROR] Failed login  ❌ (DD-MM-YYYY)
2024/01/15 10:30:45 [ERROR] Failed login  ❌ (slashes instead of dashes)
```

### **Wrong Time Format:**
```
2024-01-15 10:30 [ERROR] Failed login     ❌ (missing seconds)
2024-01-15 10:30:45PM [ERROR] Failed login ❌ (12-hour format)
```

### **Missing or Wrong Brackets:**
```
2024-01-15 10:30:45 ERROR Failed login    ❌ (no brackets)
2024-01-15 10:30:45 (ERROR) Failed login  ❌ (parentheses instead of brackets)
```

### **No Level:**
```
2024-01-15 10:30:45 Failed login          ❌ (missing level)
```

### **Extra Spaces:**
```
2024-01-15  10:30:45 [ERROR] Failed login ❌ (double space before time)
```

---

## 🔍 How to Check Your Logs

### **Method 1: Use the Web Interface**

1. Upload your `.log` file
2. Check the **"Parsing Information"** section at the bottom
3. Look for:
   - **Total Lines** - How many lines in your file
   - **Parsed Successfully** - How many matched the format
   - **Skipped/Failed** - How many were invalid

**Example Output:**
```
📄 Parsing Information
Total Lines: 100
Parsed Successfully: 95
Skipped/Failed: 5

⚠️ Warning: 5 lines (5.0%) could not be parsed.
Expected format: YYYY-MM-DD HH:MM:SS [LEVEL] message
```

### **Method 2: Test with Sample File**

Use the provided `test_logs.txt` which has the correct format:
```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run
# Upload test_logs.txt in browser
```

---

## 🛠️ Converting Your Logs

If your logs don't match the format, you have options:

### **Option 1: Modify Your Logs**

Use a script to convert them:

```bash
# Example: Convert from syslog format
# From: Jan 15 10:30:45 server ERROR: Failed login
# To:   2024-01-15 10:30:45 [ERROR] Failed login

sed 's/Jan/2024-01/' your.log | sed 's/\([0-9]\{2\}\) \([0-9:]\{8\}\) .* \([A-Z]*\):/\1 \2 [\3]/' > converted.log
```

### **Option 2: Modify the Parser**

Edit `src/main.rs` line 632 to match your format:

```rust
// Current regex (strict):
r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<message>.*)"

// Example: Support parentheses instead of brackets:
r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \((?P<level>\w+)\) (?P<message>.*)"

// Example: Make level optional:
r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?: \[(?P<level>\w+)\])? (?P<message>.*)"
```

---

## 📊 Common Log Formats

### **Our Format (Custom):**
```
2024-01-15 10:30:45 [ERROR] Failed login
```

### **Syslog:**
```
Jan 15 10:30:45 hostname program[pid]: message
```
**Not compatible** - needs conversion

### **Apache/Nginx:**
```
192.168.1.1 - - [15/Jan/2024:10:30:45 +0000] "GET /page HTTP/1.1" 200 1234
```
**Not compatible** - needs conversion

### **Windows Event Log:**
```
2024-01-15 10:30:45 ERROR Application message
```
**Almost compatible** - just needs brackets around ERROR

### **JSON Logs:**
```json
{"timestamp": "2024-01-15T10:30:45Z", "level": "ERROR", "message": "Failed login"}
```
**Not compatible** - needs conversion

---

## 🔧 Troubleshooting

### **Problem: All lines are skipped**

**Cause:** Your log format doesn't match at all

**Solution:**
1. Check the first line of your log file
2. Compare it to the expected format
3. Either convert your logs or modify the regex

### **Problem: Some lines are skipped**

**Cause:** Inconsistent formatting in your log file

**Solution:**
1. Check which lines are failing (look at line numbers)
2. Common issues:
   - Empty lines (automatically skipped)
   - Header/footer lines
   - Malformed timestamps
   - Missing brackets

### **Problem: Threats not detected**

**Cause:** Lines are parsed but don't match detection patterns

**Solution:**
1. Check that parsing is working (Parsed Successfully > 0)
2. Verify your logs contain the detection keywords
3. See `DETECTION_RULES.md` for patterns

---

## 📝 Creating Test Logs

To test the analyzer, create a file with this format:

```bash
cat > my_test.log << 'EOF'
2024-12-09 19:00:00 [ERROR] Failed login attempt from 192.168.1.100 user: admin
2024-12-09 19:00:15 [ERROR] Failed login attempt from 192.168.1.100 user: root
2024-12-09 19:00:30 [CRITICAL] Brute force attack detected from 192.168.1.100
2024-12-09 19:01:00 [WARN] Port scan detected from 203.0.113.45
2024-12-09 19:01:30 [ERROR] SQL injection attempt: SELECT * FROM users
2024-12-09 19:02:00 [CRITICAL] Malware detected in uploaded file
EOF
```

---

## 🚀 Future Improvements

Planned enhancements:
- [ ] Support multiple log formats
- [ ] Auto-detect log format
- [ ] Custom regex patterns via config
- [ ] Better error messages for invalid lines
- [ ] Line-by-line parsing feedback

---

**Last Updated:** December 9, 2025  
**Version:** 0.3.0
