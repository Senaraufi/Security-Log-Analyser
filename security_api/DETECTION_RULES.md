# Threat Detection Rules

This document lists all the security threats detected by the analyzer.

## 📊 Current Detection Rules (7 Total)

### **1. Failed Login Attempts** 🔐
**Pattern:** ERROR level + "Failed login" in message  
**Example:** `[ERROR] Failed login attempt from 192.168.1.100 user: admin`  
**Risk:** Indicates brute force attacks

---

### **2. Root User Access Attempts** ⚠️
**Pattern:** "user: root" in message  
**Example:** `[ERROR] Failed login attempt from 192.168.1.100 user: root`  
**Risk:** Privilege escalation attempts - very dangerous

---

### **3. Suspicious File Access** 📁
**Patterns:**
- `/etc/passwd` - User account information
- `/etc/shadow` - Encrypted passwords
- "Suspicious file" - Pre-flagged files

**Example:** `[WARN] Suspicious file access: /etc/passwd by user: www-data`  
**Risk:** Credential theft attempts

---

### **4. Critical Alerts** 🚨
**Pattern:** CRITICAL severity level  
**Example:** `[CRITICAL] Brute force attack detected from 192.168.1.100`  
**Risk:** Highest severity events requiring immediate action

---

### **5. SQL Injection Attempts** 💉
**Patterns:**
- `SELECT` - SQL query keyword
- `DROP TABLE` - Database deletion command
- `UNION SELECT` - SQL injection technique

**Example:** `[ERROR] SQL injection attempt detected: SELECT * FROM users`  
**Risk:** Database compromise, data theft

---

### **6. Port Scanning** 🔍
**Patterns:**
- `port scan` - Generic port scanning
- `nmap` - Popular scanning tool

**Example:** `[WARN] Port scan detected from 203.0.113.45`  
**Risk:** Reconnaissance for future attacks

---

### **7. Malware Detection** 🦠
**Patterns:**
- `malware` - Generic malware
- `trojan` - Trojan horses
- `virus` - Computer viruses
- `ransomware` - Ransomware attacks

**Example:** `[CRITICAL] Malware signature detected in uploaded file`  
**Risk:** System compromise, data encryption

---

## 🎯 Risk Level Calculation

**Total Threats** = Sum of all 7 detection types

| Total Threats | Risk Level | Action Required |
|--------------|------------|-----------------|
| 10+          | 🔴 HIGH    | Immediate action required |
| 5-9          | 🟡 MEDIUM  | Monitor closely |
| 0-4          | 🟢 LOW     | Normal activity |

---

## 📈 IP Address Analysis

**High-Risk IPs:** 3+ occurrences in logs  
**Tracking:** All IPs sorted by frequency

---

## 🔧 Adding New Rules

To add a new detection rule:

1. **Add counter variable:**
```rust
let mut new_threat_type = 0;
```

2. **Add detection logic in loop:**
```rust
if entry.message.contains("pattern") {
    new_threat_type += 1;
}
```

3. **Update ThreatStats struct:**
```rust
struct ThreatStats {
    // ... existing fields
    new_threat_type: usize,
}
```

4. **Update total calculation:**
```rust
let total_threats = ... + new_threat_type;
```

5. **Update return statement:**
```rust
ThreatStats {
    // ... existing fields
    new_threat_type,
}
```

6. **Add HTML element:**
```html
<div class="stat-box">
    <div class="stat-value" id="new-threat">0</div>
    <div class="stat-label">New Threat</div>
</div>
```

7. **Update JavaScript:**
```javascript
document.getElementById('new-threat').textContent = 
    data.threat_statistics.new_threat_type;
```

---

## 🧪 Testing

Use `test_logs.txt` which includes samples of all threat types:
- 5 failed logins
- 2 root attempts
- 1 suspicious file access
- 3 critical alerts
- 3 SQL injection attempts
- 2 port scans
- 4 malware detections

**Expected Result:** 20 total threats = HIGH risk

---

## 🚀 Future Detection Ideas

- **XSS Attacks** - `<script>`, `javascript:`
- **Command Injection** - `; rm -rf`, `&& cat`
- **Path Traversal** - `../`, `..\\`
- **DDoS Indicators** - High request rate
- **Credential Stuffing** - Multiple usernames from same IP
- **API Abuse** - Excessive API calls
- **Geo-location** - Requests from suspicious countries
- **Time-based** - Attacks during off-hours

---

## 📝 Notes

- All patterns are case-sensitive
- Patterns use simple string matching (not regex)
- Detection happens in real-time during analysis
- No machine learning (yet!)
- False positives possible with simple matching

---

**Last Updated:** November 30, 2025  
**Total Rules:** 7  
**Version:** 0.2.0
