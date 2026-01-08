# 🤖 How Claude AI Analysis Works - Simple Explanation

## 📊 Question 1: What Logs Does Claude Analyze?

**Answer: YOUR logs - the exact file you upload!**

### The Flow:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. YOU upload "apache_combined_test.log" on website        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Basic Analysis (Pattern Matching)                        │
│    - Checks for SQL injection patterns                      │
│    - Checks for XSS patterns                                │
│    - Checks for path traversal                              │
│    - Fast, simple rules                                     │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. YOU click "Analyze with Claude AI" button               │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Backend receives THE SAME FILE again                     │
│    - Parses it line by line                                 │
│    - Extracts: IP, timestamp, method, path, status, etc.    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. Backend sends YOUR PARSED LOGS to Claude                │
│    Example data sent:                                       │
│    "192.168.1.100 - GET /api/users?id=1' UNION SELECT..."  │
│    "172.16.0.25 - GET /etc/passwd..."                      │
│    "10.0.0.50 - POST /login..."                            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. Claude AI analyzes YOUR SPECIFIC LOGS                   │
│    - Understands context                                    │
│    - Correlates events                                      │
│    - Identifies attack chains                               │
│    - Provides expert recommendations                        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. Results come back to YOU                                │
│    - Summary of YOUR logs                                   │
│    - Threats found in YOUR logs                             │
│    - Recommendations for YOUR system                        │
└─────────────────────────────────────────────────────────────┘
```

### Example:

If you upload a file with these 3 lines:
```
192.168.1.100 - - [15/Dec/2025:10:15:23 +0000] "GET /index.html HTTP/1.1" 200 2326
172.16.0.25 - - [15/Dec/2025:10:15:26 +0000] "GET /api/users?id=1' UNION SELECT * FROM passwords-- HTTP/1.1" 500 0
10.0.0.50 - - [15/Dec/2025:10:15:30 +0000] "POST /login HTTP/1.1" 401 0
```

Claude will analyze **these exact 3 lines** and tell you:
- Line 1: Normal traffic ✅
- Line 2: SQL injection attempt! 🚨
- Line 3: Failed login attempt ⚠️

---

## 📝 Question 2: What Are Prompts and Why Are They There?

### What is a Prompt?

A **prompt** is like a job description you give to Claude. It tells Claude:
- **WHO** to be (a senior security analyst)
- **WHAT** to analyze (your logs)
- **HOW** to analyze (using MITRE ATT&CK, OWASP Top 10)
- **WHAT FORMAT** to return (summary, findings, recommendations)

### Why Do We Need Prompts?

Without a prompt, Claude wouldn't know what to do with your logs. It's like hiring someone without telling them their job!

### The Prompt Structure:

```
┌─────────────────────────────────────────────────────────────┐
│ SECTION 1: ROLE DEFINITION                                  │
│ "You are a senior SOC analyst with 10+ years experience"   │
│                                                             │
│ WHY: Makes Claude think like a security expert             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SECTION 2: YOUR LOGS                                        │
│ "Analyze these Apache logs:"                                │
│ - 192.168.1.100 GET /index.html...                         │
│ - 172.16.0.25 GET /api/users?id=1' UNION...               │
│                                                             │
│ WHY: Gives Claude the actual data to analyze               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SECTION 3: ANALYSIS FRAMEWORK                               │
│ "Use MITRE ATT&CK Framework:"                               │
│ - T1190: Exploit Public-Facing Application                 │
│ - T1059: Command Injection                                  │
│ "Use OWASP Top 10:"                                         │
│ - A03: Injection                                            │
│ - A07: Authentication Failures                              │
│                                                             │
│ WHY: Tells Claude WHAT to look for (industry standards)    │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SECTION 4: ATTACK PATTERNS                                  │
│ "Look for:"                                                 │
│ - SQL Injection: UNION SELECT, OR 1=1                      │
│ - XSS: <script>, javascript:                               │
│ - Path Traversal: ../, /etc/passwd                         │
│                                                             │
│ WHY: Teaches Claude specific attack signatures             │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│ SECTION 5: OUTPUT FORMAT                                    │
│ "Provide:"                                                  │
│ - Executive Summary                                         │
│ - Threat Level                                              │
│ - Key Findings                                              │
│ - Recommendations                                           │
│                                                             │
│ WHY: Ensures consistent, structured responses               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Real Example

### Your Log File:
```
172.16.0.25 - - [15/Dec/2025:10:15:26 +0000] "GET /api/users?id=1' UNION SELECT * FROM passwords-- HTTP/1.1" 500 0
```

### What Gets Sent to Claude:

```
You are a senior SOC analyst with 10+ years of experience.

Analyze these logs:
- IP: 172.16.0.25
- Request: GET /api/users?id=1' UNION SELECT * FROM passwords--
- Status: 500 (Server Error)

Look for SQL injection patterns like:
- UNION SELECT
- OR 1=1
- Comment sequences (--, /*)

Provide:
1. Executive Summary
2. Threat Level
3. Key Findings
4. Recommendations
```

### What Claude Returns:

```json
{
  "summary": "Critical SQL injection attempt detected from IP 172.16.0.25",
  "threat_level": "Critical",
  "findings": [
    {
      "attack_type": "SQL Injection",
      "severity": "Critical",
      "description": "Classic UNION-based SQL injection attempting to extract password data",
      "confidence": 0.95,
      "affected_resources": ["/api/users"]
    }
  ],
  "recommendations": [
    "Block IP 172.16.0.25 immediately",
    "Implement parameterized queries",
    "Enable WAF rules for SQL injection"
  ]
}
```

---

## 🧠 Why Prompts Are Your Competitive Advantage

### Without Good Prompts:
```
You: "Analyze these logs"
Claude: "I see some HTTP requests. Some look suspicious."
```
❌ Vague, not useful

### With Expert Prompts (What You Have):
```
You: "You are a senior SOC analyst. Use MITRE ATT&CK. Look for SQL injection, XSS, path traversal. Provide executive summary, threat level, findings with confidence scores, IOCs, and actionable recommendations."

Claude: "Critical SQL injection detected. MITRE ATT&CK T1190. Confidence 95%. Immediate action: Block IP 172.16.0.25. Evidence: UNION SELECT pattern in /api/users endpoint. Recommendation: Implement parameterized queries and WAF rules."
```
✅ Specific, actionable, expert-level

---

## 📚 Summary

### What Logs Does Claude Analyze?
**YOUR logs** - the exact file you upload on the website.

### What Are Prompts?
**Instructions** that tell Claude:
1. **WHO** to be (security expert)
2. **WHAT** to analyze (your logs)
3. **HOW** to analyze (MITRE, OWASP)
4. **WHAT** to return (structured report)

### Why Are Prompts Important?
They turn Claude from a generic AI into a **specialized security analyst** that gives you expert-level insights about YOUR specific logs.

---

## 🎯 The Magic Formula

```
Your Logs + Expert Prompts + Claude AI = Professional Security Analysis
```

Without prompts, Claude is just an AI.
With expert prompts, Claude becomes your senior security analyst! 🚀
