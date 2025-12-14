# 🧪 Testing Guide - New Features

## 🎯 What You're Testing

1. **Alert Rules Engine** - Automated threat detection
2. **Geolocation** - IP country/city lookup
3. **VPN Detection** - Identify proxy/VPN IPs
4. **CSV Export** - Data export capability

---

## 🚀 Quick Start

### **Step 1: Make sure server is running**
```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run
```

You should see:
```
Security API Server running on http://localhost:3000
```

### **Step 2: Open the dashboard**
Open your browser to: **http://localhost:3000**

---

## 📋 Test Scenarios

### **Test 1: Basic Alert Generation**

**File to upload:** `test_alerts.txt` (I just created this)

**What it contains:**
- 6 failed login attempts (triggers Rule 1)
- 4 root access attempts (triggers Rule 2)
- 2 SQL injection attempts (triggers Rule 3)
- 1 malware detection (triggers Rule 4)
- 12 requests from one IP (triggers Rule 5)
- 15+ total threats (triggers Rule 6)

**Steps:**
1. Go to http://localhost:3000
2. Click "Upload Log File"
3. Select `test_alerts.txt`
4. Wait for analysis

**Expected Results:**
- ✅ **6 alerts generated** (one for each rule)
- ✅ Risk level: **HIGH** or **CRITICAL**
- ✅ Total threats: **~20+**

**How to see alerts:**
Open browser console (F12) and look at the API response:
```javascript
{
  "alerts": [
    {
      "id": "ALERT-xxxxxxxx",
      "severity": "HIGH",
      "title": "Multiple Failed Login Attempts",
      "description": "6 failed login attempts detected...",
      ...
    },
    // ... more alerts
  ]
}
```

---

### **Test 2: VPN Detection**

**What to check:**
The test file includes these IPs:
- `185.220.101.5` - Common VPN range → should be flagged
- `45.142.120.10` - Common VPN range → should be flagged
- `104.28.5.100` - Cloud/VPN range → should be flagged
- `192.168.1.100` - Private IP → not VPN
- `10.0.0.50` - Private IP → not VPN

**Steps:**
1. Upload `test_alerts.txt`
2. Open browser console
3. Look at `ip_analysis.all_ips` in the response

**Expected Results:**
```javascript
{
  "ip_analysis": {
    "all_ips": [
      {
        "ip": "185.220.101.5",
        "count": 4,
        "risk_level": "high",
        "country": null,  // Will be populated if geolocation works
        "city": null,
        "is_vpn": true    // ← Should be TRUE
      },
      {
        "ip": "192.168.1.100",
        "count": 6,
        "risk_level": "high",
        "country": null,
        "city": null,
        "is_vpn": false   // ← Should be FALSE
      }
    ]
  }
}
```

---

### **Test 3: Geolocation (Optional)**

**Note:** Geolocation is currently set up but not actively called (to avoid API rate limits during development).

**To test geolocation:**
The function `get_geolocation()` is ready but not integrated into the main flow yet. This is intentional because:
- IP-API has rate limits (45 requests/minute)
- Batch processing would be needed for production
- Frontend can call it on-demand

**Manual test (if you want):**
You can test the function by temporarily adding it to the code, but for now, the infrastructure is ready.

---

### **Test 4: Alert Severity Levels**

**Upload:** `test_alerts.txt`

**Check alert severities:**
```javascript
// In browser console, after upload:
const response = await fetch('/api/analyze', {
  method: 'POST',
  body: formData
});
const data = await response.json();

// Check alerts
data.alerts.forEach(alert => {
  console.log(`${alert.severity}: ${alert.title}`);
});
```

**Expected output:**
```
HIGH: Multiple Failed Login Attempts
CRITICAL: Root Access Attempts
CRITICAL: SQL Injection Attempt
CRITICAL: Malware Detected
HIGH: Suspicious IP Activity
CRITICAL: High Threat Level
```

---

### **Test 5: Alert Details**

**What to verify:**
Each alert should have:
- ✅ Unique ID (starts with "ALERT-")
- ✅ Severity (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ Title (descriptive)
- ✅ Description (detailed explanation)
- ✅ Timestamp (ISO 8601 format)
- ✅ IP address (when applicable)
- ✅ Triggered by (rule name)

**Example alert:**
```json
{
  "id": "ALERT-a1b2c3d4",
  "severity": "CRITICAL",
  "title": "SQL Injection Attempt",
  "description": "2 SQL injection patterns detected in logs.",
  "timestamp": "2024-12-14T17:30:00Z",
  "ip_address": null,
  "triggered_by": "SQL Injection Detection"
}
```

---

### **Test 6: CSV Export (Manual)**

**Current status:** Backend ready, frontend button not yet added.

**To test CSV generation manually:**

1. Upload `test_alerts.txt`
2. Copy the JSON response from browser console
3. Use this JavaScript in console:

```javascript
// Assuming 'data' is your API response
function exportToCSV(data) {
    let csv = 'Category,Metric,Value\n';
    
    // Threats
    csv += `Threats,Failed Logins,${data.threat_statistics.failed_logins}\n`;
    csv += `Threats,Root Attempts,${data.threat_statistics.root_attempts}\n`;
    csv += `Threats,SQL Injection,${data.threat_statistics.sql_injection_attempts}\n`;
    csv += `Threats,Malware,${data.threat_statistics.malware_detections}\n`;
    
    // IPs
    csv += '\nIP Address,Count,Risk Level,VPN\n';
    data.ip_analysis.all_ips.forEach(ip => {
        csv += `${ip.ip},${ip.count},${ip.risk_level},${ip.is_vpn ? 'Yes' : 'No'}\n`;
    });
    
    // Alerts
    if (data.alerts.length > 0) {
        csv += '\nAlert ID,Severity,Title,Description\n';
        data.alerts.forEach(alert => {
            csv += `${alert.id},${alert.severity},${alert.title},"${alert.description}"\n`;
        });
    }
    
    // Download
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'security_analysis.csv';
    a.click();
}

// Run it
exportToCSV(data);
```

This will download a CSV file!

---

## 🔍 Detailed Inspection

### **View Full API Response**

After uploading a file, open browser console and run:

```javascript
// Get the file input
const fileInput = document.getElementById('file-input');

// Upload and inspect
fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch('/api/analyze', {
        method: 'POST',
        body: formData
    });
    
    const data = await response.json();
    
    console.log('=== FULL RESPONSE ===');
    console.log(JSON.stringify(data, null, 2));
    
    console.log('\n=== ALERTS ===');
    console.table(data.alerts);
    
    console.log('\n=== IPs WITH VPN ===');
    console.table(data.ip_analysis.all_ips);
});
```

---

## ✅ Verification Checklist

After uploading `test_alerts.txt`, verify:

### **Alerts:**
- [ ] 6 alerts generated
- [ ] Each alert has unique ID
- [ ] Severities are correct (CRITICAL/HIGH)
- [ ] Descriptions are meaningful
- [ ] Timestamps are present
- [ ] "Triggered by" field shows rule name

### **VPN Detection:**
- [ ] IPs starting with 185.x marked as VPN
- [ ] IPs starting with 45.x marked as VPN
- [ ] IPs starting with 104.x marked as VPN
- [ ] Private IPs (192.168.x, 10.x) NOT marked as VPN

### **IP Analysis:**
- [ ] All IPs detected
- [ ] Counts are correct
- [ ] Risk levels assigned (high/low)
- [ ] VPN flags present

### **Threat Statistics:**
- [ ] Failed logins: 6
- [ ] Root attempts: 4
- [ ] SQL injection: 2
- [ ] Malware: 1
- [ ] Port scanning: 3

---

## 🐛 Troubleshooting

### **No alerts showing?**
- Check browser console for errors
- Verify API response includes `alerts` array
- Make sure thresholds are met (e.g., ≥5 failed logins)

### **VPN detection not working?**
- Check `is_vpn` field in IP data
- Verify IP addresses in test file
- Function only checks specific ranges (185.x, 45.x, 104.x)

### **Server not running?**
```bash
# Check if port 3000 is in use
lsof -ti:3000

# Kill existing process
lsof -ti:3000 | xargs kill -9

# Restart
cargo run
```

---

## 📊 Expected Test Results

### **test_alerts.txt Analysis:**

**Threats Detected:**
- Failed Logins: 6
- Root Attempts: 4
- SQL Injection: 2
- Malware: 1
- Port Scanning: 3
- File Access: 2
- **Total: 18 threats**

**Alerts Generated:**
1. HIGH: Multiple Failed Login Attempts (6 attempts)
2. CRITICAL: Root Access Attempts (4 attempts)
3. CRITICAL: SQL Injection Attempt (2 patterns)
4. CRITICAL: Malware Detected (1 signature)
5. HIGH: Suspicious IP Activity (12 requests from 10.0.0.50)
6. CRITICAL: High Threat Level (18 total threats)

**IPs Analyzed:**
- 192.168.1.100 (6 requests, high risk, not VPN)
- 185.220.101.5 (4 requests, high risk, **VPN detected**)
- 45.142.120.10 (2 requests, low risk, **VPN detected**)
- 104.28.5.100 (3 requests, high risk, **VPN detected**)
- 10.0.0.50 (12 requests, high risk, not VPN)
- 172.16.0.100 (1 request, low risk, not VPN)

**Risk Assessment:**
- Level: **HIGH** or **CRITICAL**
- Total Threats: 18
- Description: "Immediate action required"

---

## 🎯 Quick Test Commands

### **Test 1: Upload via curl**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@test_alerts.txt" \
  | jq '.alerts'
```

### **Test 2: Check alert count**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@test_alerts.txt" \
  | jq '.alerts | length'
```

### **Test 3: List VPN IPs**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@test_alerts.txt" \
  | jq '.ip_analysis.all_ips[] | select(.is_vpn == true) | .ip'
```

### **Test 4: Show critical alerts**
```bash
curl -X POST http://localhost:3000/api/analyze \
  -F "file=@test_alerts.txt" \
  | jq '.alerts[] | select(.severity == "CRITICAL") | .title'
```

---

## 📝 Notes

- **Geolocation:** Currently not actively called to avoid API rate limits. Infrastructure is ready.
- **CSV Export:** Backend ready, frontend button coming next.
- **Alert Thresholds:** Can be adjusted in `check_alert_rules()` function.
- **VPN Detection:** Basic heuristic, can be enhanced with proper VPN database.

---

## 🎉 Success Criteria

Your implementation is working if:
- ✅ Alerts are generated automatically
- ✅ VPN IPs are flagged correctly
- ✅ Alert severities match threat levels
- ✅ All data is in API response
- ✅ No errors in console

**Ready to test?** Upload `test_alerts.txt` and check the browser console! 🚀
