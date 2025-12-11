# Log Parser Features

## 🎯 What's New in Version 2

### Enhanced Threat Detection

Your parser now detects **4 types of security threats**:

#### 1. **Failed Login Attempts**
```rust
if entry.level == "ERROR" && entry.message.contains("Failed login")
```
- Counts all failed authentication attempts
- Common indicator of brute force attacks

#### 2. **Root User Access Attempts** ⚠️
```rust
if entry.message.contains("user: root")
```
- Flags any attempt to access the root/admin account
- **High risk** - attackers often target root
- Prints immediate warning when detected

#### 3. **Suspicious File Access** 🔍
```rust
if entry.message.contains("/etc/passwd") || 
   entry.message.contains("/etc/shadow") ||
   entry.message.contains("Suspicious file")
```
- Detects access to sensitive system files
- `/etc/passwd` and `/etc/shadow` contain user credentials
- Common target for privilege escalation attacks

#### 4. **Critical Alerts** 🚨
```rust
if entry.level == "CRITICAL"
```
- Flags the highest severity events
- Requires immediate attention

---

## 📊 IP Frequency Analysis

### What It Does
Tracks how many times each IP address appears in the logs using a **HashMap**.

### How It Works
```rust
// HashMap: Key = IP address, Value = count
let mut ip_frequency: HashMap<String, usize> = HashMap::new();

// For each log entry with an IP:
ip_frequency.entry(ip.clone())
    .and_modify(|count| *count += 1)  // Increment if exists
    .or_insert(1);  // Set to 1 if new
```

### Why It Matters
- **Single failed login:** Could be a typo
- **3+ failed logins from same IP:** Likely an attack
- **5+ occurrences:** High-risk attacker

### Risk Thresholds
- 🔴 **High Risk:** 3+ occurrences
- 🟢 **Normal:** 1-2 occurrences

---

## 🎨 Improved Output

### Before:
```
Analysis Summary:
   Failed login attempts: 4
   Suspicious IPs: ["192.168.1.100", "192.168.1.100", ...]
```

### After:
```
============================================================
📊 SECURITY ANALYSIS SUMMARY
============================================================

🔢 Threat Statistics:
   Failed login attempts: 4
   Root user attempts: 2
   Suspicious file access: 1
   Critical alerts: 1

🎯 IP Address Analysis:
   🚨 High-Risk IPs (3+ occurrences):
      192.168.1.100 - 5 occurrences

   All IP Activity:
      🔴 192.168.1.100 - 5 occurrences
      🟢 203.0.113.45 - 2 occurrences
      🟢 10.0.0.50 - 1 occurrences

⚖️  Overall Risk Level:
   🟡 MEDIUM - Monitor closely
   Total threat indicators: 8
============================================================
```

---

## 🧮 Risk Scoring System

The parser calculates an overall risk level based on total threats:

```rust
let total_threats = failed_logins + root_attempts + 
                    suspicious_file_access + critical_alerts;

let risk_level = if total_threats >= 10 {
    "🔴 HIGH - Immediate action required"
} else if total_threats >= 5 {
    "🟡 MEDIUM - Monitor closely"
} else {
    "🟢 LOW - Normal activity"
};
```

### Risk Levels:
- **🔴 HIGH (10+):** Immediate action required
- **🟡 MEDIUM (5-9):** Monitor closely
- **🟢 LOW (0-4):** Normal activity

---

## 🔑 Key Rust Concepts Used

### 1. HashMap for Counting
```rust
use std::collections::HashMap;

let mut ip_frequency: HashMap<String, usize> = HashMap::new();
```
- **Key-value pairs:** IP address → count
- **O(1) lookup:** Very fast
- **Dynamic:** Grows as needed

### 2. Entry API Pattern
```rust
ip_frequency.entry(ip.clone())
    .and_modify(|count| *count += 1)
    .or_insert(1);
```
- **Efficient:** Single lookup instead of two
- **Safe:** No risk of overwriting
- **Idiomatic:** The "Rust way" to update HashMaps

### 3. Sorting and Filtering
```rust
// Convert HashMap to Vec for sorting
let mut ip_vec: Vec<_> = ip_frequency.iter().collect();

// Sort by count (highest first)
ip_vec.sort_by(|a, b| b.1.cmp(a.1));

// Filter for high-risk IPs
let high_risk_ips: Vec<_> = ip_vec.iter()
    .filter(|(_, count)| **count >= 3)
    .collect();
```

### 4. Multiple Conditions with ||
```rust
if entry.message.contains("/etc/passwd") || 
   entry.message.contains("/etc/shadow") ||
   entry.message.contains("Suspicious file") {
    // Matches if ANY condition is true
}
```

---

## 🎓 What You're Learning

### Week 1-2 Concepts (Covered):
- ✅ Structs and data structures
- ✅ Pattern matching with `if let`
- ✅ Error handling with `Option`
- ✅ String operations
- ✅ Vectors and iteration

### Week 2-3 Concepts (Now Added):
- ✅ **HashMap** - Key-value storage
- ✅ **Entry API** - Efficient HashMap updates
- ✅ **Sorting** - Ordering data
- ✅ **Filtering** - Selecting specific items
- ✅ **Multiple counters** - Tracking different metrics

---

## 🚀 Next Steps to Enhance

### Easy Additions:
1. **Time-based analysis** - Detect attacks in 5-minute windows
2. **Username tracking** - Count failed attempts per user
3. **Export to JSON** - Save results to a file
4. **Command-line arguments** - Accept file path as input

### Medium Additions:
5. **Regex-based rules** - Load detection rules from a file
6. **Multiple file support** - Analyze entire directories
7. **Real-time monitoring** - Watch log files as they grow
8. **Color output** - Use terminal colors instead of emojis

### Advanced Additions:
9. **Async processing** - Handle multiple files concurrently
10. **Database storage** - Save results to SQLite
11. **Web API** - Expose analysis via HTTP endpoint
12. **AI integration** - Send summaries to OpenAI for analysis

---

## 📝 Try These Experiments

### 1. Add More Sample Logs
```bash
echo "2024-01-15 11:00:00 [ERROR] Failed login attempt from 192.168.1.100 user: admin" >> sample_logs.txt
echo "2024-01-15 11:01:00 [ERROR] Failed login attempt from 192.168.1.100 user: admin" >> sample_logs.txt
cargo run
```
Watch the IP count increase and risk level change!

### 2. Create Your Own Detection Rule
Add this after line 117:
```rust
// DETECTION RULE 5: SQL Injection attempts
if entry.message.contains("SELECT") || entry.message.contains("DROP TABLE") {
    println!("💉 SQL Injection attempt detected: {}", entry.message);
}
```

### 3. Track Failed Attempts Per User
Add this after line 56:
```rust
let mut user_failures: HashMap<String, usize> = HashMap::new();
```

Then update the failed login detection to track by username!

---

## 🎯 Current Capabilities

Your parser can now:
- ✅ Parse structured log files
- ✅ Extract timestamps, IPs, usernames, severity
- ✅ Detect 4 types of security threats
- ✅ Count IP occurrences
- ✅ Identify high-risk attackers
- ✅ Calculate overall risk level
- ✅ Generate professional security reports

**You're building a real security tool!** 🦀🔒
