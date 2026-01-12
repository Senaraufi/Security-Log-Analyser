# Test Log Files - Usage Guide

I've created two test log files to demonstrate the analyzer's capabilities.

---

## 📁 Files Created

### 1. `test_logs_standard.txt`
**Purpose:** Optimized for Standard Analysis Mode  
**Location:** `/Users/senaraufi/Desktop/Startup/test_logs_standard.txt`

**Contains:**
- ✅ **50 log entries** with various threat types
- ✅ **SQL Injection attacks** (7 instances) - CVSS 9.8 Critical
- ✅ **Failed login attempts** (15 instances) - CVSS 5.3 Medium
- ✅ **Root access attempts** (5 instances) - CVSS 8.8 High
- ✅ **Suspicious file access** (5 instances) - CVSS 7.5 High
- ✅ **Malware detections** (4 instances) - CVSS 9.8 Critical
- ✅ **Port scanning** (4 instances) - CVSS 5.3 Medium
- ✅ **Critical alerts** (3 instances) - CVSS 8.0 High
- ✅ **Multiple malicious IPs** for IP analysis

**Expected CVSS Score:** 10.0 (Critical)

---

### 2. `test_logs_claude.txt`
**Purpose:** Optimized for Claude AI Analysis Mode  
**Location:** `/Users/senaraufi/Desktop/Startup/test_logs_claude.txt`

**Contains:**
- ✅ **65 log entries** with complex attack scenarios
- ✅ **Multi-stage attack chain** (reconnaissance → exploitation → persistence)
- ✅ **Advanced SQL Injection** with second-order attacks
- ✅ **Ransomware infection** with detailed behavior
- ✅ **Credential stuffing & password spraying**
- ✅ **Web shell deployment**
- ✅ **Lateral movement attempts**
- ✅ **Data exfiltration attempts**
- ✅ **MITRE ATT&CK technique references**
- ✅ **APT group attribution**
- ✅ **Detailed attack timeline**

**Expected CVSS Score:** 10.0 (Critical)

---

## 🚀 How to Use

### Standard Analysis Mode

1. **Start the server:**
   ```bash
   cd /Users/senaraufi/Desktop/Startup/security_api
   cargo run --release
   ```

2. **Open browser:**
   ```
   http://localhost:3000
   ```

3. **Select mode:**
   - Click **"Analyse Logs"** (Standard Analysis)

4. **Upload file:**
   - Click "Upload Log File"
   - Select `test_logs_standard.txt`
   - Wait for analysis (instant)

5. **View results:**
   - ✅ CVSS Score: **10.0** (Critical)
   - ✅ Threat cards with individual CVSS scores
   - ✅ Color-coded severity indicators
   - ✅ Vector strings for each threat
   - ✅ IP analysis showing malicious IPs

---

### Claude AI Analysis Mode

1. **Start the server:**
   ```bash
   cd /Users/senaraufi/Desktop/Startup/security_api
   cargo run --release
   ```

2. **Open browser:**
   ```
   http://localhost:3000
   ```

3. **Select mode:**
   - Click **"Analyse Logs with Claude"** (AI-Powered)

4. **Upload file:**
   - Click "Upload Log File"
   - Select `test_logs_claude.txt`
   - Wait for AI analysis (10-30 seconds)

5. **View results:**
   - ✅ CVSS Score: **10.0** (Critical)
   - ✅ Claude AI Security Analysis section
   - ✅ Executive summary of the attack
   - ✅ Attack chain detection
   - ✅ MITRE ATT&CK mappings
   - ✅ Actionable recommendations
   - ✅ Threat intelligence insights

---

## 📊 What You'll See

### Standard Analysis Dashboard

**Metrics:**
- Total Events: 50
- Threats Detected: 43
- Blocked IPs: 4
- CVSS Score: **10.0** (Critical - Red)

**Threat Distribution:**
Each threat card shows:
```
┌────────────────────────────────────────┐
│ SQL Injection              9.8         │
│ 7 instances detected       Critical    │
│                                        │
│ CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/...  │
│                                        │
│ Network-accessible SQL injection...    │
└────────────────────────────────────────┘
```

**IP Analysis:**
- `203.0.113.45` - 15 requests (Brute force)
- `198.51.100.23` - 7 requests (SQL Injection)
- `198.51.100.88` - 4 requests (Malware)
- `192.168.1.200` - 5 requests (Privilege escalation)

---

### Claude AI Analysis Dashboard

**Everything from Standard Mode PLUS:**

**AI Security Analysis Section:**
- 🤖 Executive Summary
- 🔗 Attack Chain Detection
- 🎯 MITRE ATT&CK Techniques
- 💡 Contextual Insights
- ✅ Actionable Recommendations

**Example AI Insights:**
```
Executive Summary:
Critical multi-stage attack detected involving:
1. Initial access via SQL injection
2. Privilege escalation attempts
3. Ransomware deployment
4. Data exfiltration attempts

Attack Chain:
Reconnaissance (14:36) → Exploitation (14:32) → 
Persistence (14:39) → Impact (14:35)

MITRE ATT&CK:
- T1190: Exploit Public-Facing Application
- T1078: Valid Accounts
- T1486: Data Encrypted for Impact

Recommendations:
1. Immediately isolate affected systems
2. Reset all credentials
3. Restore from clean backups
4. Engage incident response team
```

---

## 🎯 Key Differences

| Feature | Standard Mode | Claude AI Mode |
|---------|--------------|----------------|
| **Speed** | Instant | 10-30 seconds |
| **CVSS Scores** | ✅ Yes | ✅ Yes |
| **Threat Detection** | ✅ Pattern-based | ✅ AI-powered |
| **Attack Chains** | ❌ No | ✅ Yes |
| **MITRE Mapping** | ❌ No | ✅ Yes |
| **Recommendations** | ❌ No | ✅ Yes |
| **Context Analysis** | ❌ No | ✅ Yes |

---

## 💡 Testing Tips

### For Standard Mode:
- Focus on **CVSS scores** and color coding
- Check that all threat types are detected
- Verify IP analysis shows high-risk IPs
- Confirm vector strings are displayed

### For Claude AI Mode:
- Look for **attack chain detection**
- Check MITRE ATT&CK technique mapping
- Review AI-generated recommendations
- Verify contextual insights about the attack

---

## 🔍 Expected CVSS Breakdown

### Standard Log File:
```
SQL Injection:        9.8 (Critical) × 7 instances
Malware:             9.8 (Critical) × 4 instances
Root Access:         8.8 (High)     × 5 instances
Critical Alert:      8.0 (High)     × 3 instances
Suspicious Files:    7.5 (High)     × 5 instances
Failed Logins:       5.3 (Medium)   × 15 instances
Port Scanning:       5.3 (Medium)   × 4 instances

Aggregate CVSS: 10.0 (Critical)
```

### Claude Log File:
```
SQL Injection:        9.8 (Critical) × 6 instances
Malware:             9.8 (Critical) × 8 instances
Root Access:         8.8 (High)     × 4 instances
Critical Alert:      8.0 (High)     × 12 instances
Suspicious Files:    7.5 (High)     × 3 instances
Failed Logins:       5.3 (Medium)   × 10 instances
Port Scanning:       5.3 (Medium)   × 4 instances

Aggregate CVSS: 10.0 (Critical)
```

---

## ✅ Success Indicators

You'll know it's working when you see:

**Standard Mode:**
- ✅ CVSS metric card shows **10.0** in red
- ✅ Risk indicator says **"CRITICAL RISK | CVSS 10.0"**
- ✅ Threat cards are color-coded (red for critical)
- ✅ Vector strings displayed for each threat
- ✅ All 7 threat types detected

**Claude AI Mode:**
- ✅ Everything from Standard Mode
- ✅ AI Analysis section appears
- ✅ Attack chain timeline shown
- ✅ MITRE ATT&CK techniques listed
- ✅ Recommendations provided
- ✅ Natural language explanations

---

## 🚨 Troubleshooting

**If CVSS scores don't appear:**
- Make sure you're using the updated code
- Check browser console for errors
- Refresh the page and try again

**If Claude analysis fails:**
- Verify `ANTHROPIC_API_KEY` is set in `.env`
- Check API quota/limits
- Review server logs for errors

**If no threats detected:**
- Verify you uploaded the correct file
- Check file format (should be .txt)
- Ensure file isn't empty

---

## 📝 Next Steps

After testing with these files:
1. Try uploading your own log files
2. Compare Standard vs Claude analysis
3. Export results for reporting
4. Integrate with your security workflow

---

**Happy Testing! 🎉**

Both log files are ready to use and will showcase all the CVSS scoring features you just implemented.
