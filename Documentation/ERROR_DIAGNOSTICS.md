# Error Diagnostics System

## 🎯 Overview

The analyzer now includes an **intelligent error detection system** that identifies exactly why log lines fail to parse and provides specific suggestions for fixing them.

---

## ✨ Features

### **1. Line-by-Line Error Detection**
- Identifies the specific line number that failed
- Shows the actual content of the problematic line
- Explains what's wrong with the format
- Provides actionable fix suggestions

### **2. Smart Pattern Recognition**
The system checks for:
- ✅ Date format (YYYY-MM-DD vs MM/DD/YYYY vs DD-MM-YYYY)
- ✅ Time format (HH:MM:SS with seconds required)
- ✅ Log level brackets ([ERROR] vs ERROR)
- ✅ Spacing issues
- ✅ Missing components

### **3. User-Friendly Display**
- Visual error cards in the UI
- Color-coded severity
- Monospace font for log content
- Green "Fix" suggestions
- Shows first 10 errors to avoid overwhelming

---

## 🔍 Error Types Detected

### **1. Missing Timestamp**
**Example:**
```
Just a random line with no format
```
**Error:** Missing timestamp  
**Fix:** Add timestamp in format: YYYY-MM-DD HH:MM:SS

---

### **2. Wrong Date Format (MM/DD/YYYY)**
**Example:**
```
01/15/2024 10:30:45 [ERROR] Failed login
```
**Error:** Wrong date format (MM/DD/YYYY)  
**Fix:** Use YYYY-MM-DD format instead of MM/DD/YYYY

---

### **3. Wrong Date Format (DD-MM-YYYY)**
**Example:**
```
15-01-2024 10:30:45 [ERROR] Failed login
```
**Error:** Wrong date format (DD-MM-YYYY)  
**Fix:** Use YYYY-MM-DD format instead of DD-MM-YYYY

---

### **4. Invalid Date Format (Slashes)**
**Example:**
```
2024/12/09 10:30:45 [ERROR] Failed login
```
**Error:** Invalid date format  
**Fix:** Date must be YYYY-MM-DD (e.g., 2024-12-09)

---

### **5. Invalid Time Format**
**Example:**
```
2024-01-15 10:30 [ERROR] Missing seconds
```
**Error:** Invalid time format  
**Fix:** Time must be HH:MM:SS in 24-hour format (e.g., 14:30:45)

---

### **6. Missing Brackets Around Level**
**Example:**
```
2024-01-15 10:30:45 ERROR Failed login
```
**Error:** Missing brackets around level  
**Fix:** Level must be in square brackets: [ERROR], [WARN], [INFO], [CRITICAL]

---

### **7. Missing or Invalid Log Level**
**Example:**
```
2024-01-15 10:30:45 Failed login attempt
```
**Error:** Missing or invalid log level  
**Fix:** Add log level in brackets after timestamp: [ERROR], [WARN], [INFO], [CRITICAL]

---

### **8. Incorrect Spacing or Format**
**Example:**
```
2024-01-15  10:30:45 [ERROR] Double space
```
**Error:** Incorrect spacing or format  
**Fix:** Format must be: YYYY-MM-DD HH:MM:SS [LEVEL] message (check spaces)

---

## 📊 How It Works

### **Backend (Rust)**

1. **Parse Attempt:**
```rust
if let Some(entry) = parse_log_line(line) {
    // Success - process the entry
} else {
    // Failed - diagnose the error
    let (error_type, suggestion) = diagnose_parse_error(line);
}
```

2. **Diagnostic Function:**
```rust
fn diagnose_parse_error(line: &str) -> (String, String) {
    // Check for various patterns
    // Return (error_type, suggestion)
}
```

3. **Error Collection:**
- Stores first 10 errors only (to avoid overwhelming UI)
- Truncates long lines to 100 characters
- Includes line number for easy reference

### **Frontend (JavaScript)**

Displays errors in a structured format:
```javascript
Line 5: Wrong date format (MM/DD/YYYY)
┌─────────────────────────────────────
│ 01/15/2024 10:30:45 [ERROR] Failed login
└─────────────────────────────────────
💡 Fix: Use YYYY-MM-DD format instead of MM/DD/YYYY
```

---

## 🧪 Testing the System

### **Test File Included: `bad_format_test.txt`**

This file contains 15 lines with various format errors:
- 4 correct lines
- 11 lines with different errors

**Run the test:**
```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run
# Upload bad_format_test.txt in browser
```

**Expected Output:**
- Total Lines: 15
- Parsed Successfully: 4
- Skipped/Failed: 11
- Shows 10 specific errors with fixes

---

## 📋 Example Error Display

When you upload a file with errors, you'll see:

```
📄 Parsing Information

Total Lines: 100
Parsed Successfully: 85
Skipped/Failed: 15

⚠️ Warning: 15 lines (15.0%) could not be parsed.
Expected format: YYYY-MM-DD HH:MM:SS [LEVEL] message

🔍 Parsing Errors (showing first 10):

┌─────────────────────────────────────────────────────────
│ Line 2: Wrong date format (MM/DD/YYYY)
│ 01/15/2024 10:30:45 [ERROR] Failed login
│ 💡 Fix: Use YYYY-MM-DD format instead of MM/DD/YYYY
└─────────────────────────────────────────────────────────

┌─────────────────────────────────────────────────────────
│ Line 3: Missing brackets around level
│ 2024-01-15 10:30:45 ERROR Failed login
│ 💡 Fix: Level must be in square brackets: [ERROR]
└─────────────────────────────────────────────────────────

... and 5 more errors
```

---

## 🎯 Benefits

### **For Users:**
- ✅ Instant feedback on what's wrong
- ✅ No guessing about format issues
- ✅ Specific line numbers to fix
- ✅ Clear, actionable suggestions
- ✅ Learn the correct format quickly

### **For Developers:**
- ✅ Reduces support requests
- ✅ Self-documenting system
- ✅ Easy to add new error types
- ✅ Scalable (only shows first 10)

---

## 🔧 Adding New Error Types

To add a new error detection:

1. **Add pattern check in `diagnose_parse_error()`:**
```rust
let new_pattern = Regex::new(r"your_pattern").unwrap();
if new_pattern.is_match(line) {
    return (
        "Your error type".to_string(),
        "Your fix suggestion".to_string()
    );
}
```

2. **Test with sample data**
3. **Update this documentation**

---

## 📈 Performance

- **Overhead:** Minimal (only runs on failed lines)
- **Memory:** Stores max 10 errors per file
- **Speed:** Regex patterns are compiled once
- **Scalability:** Handles large files efficiently

---

## 🚀 Future Enhancements

Planned improvements:
- [ ] Export errors to CSV
- [ ] Auto-fix suggestions (convert format)
- [ ] Batch line correction
- [ ] Custom error patterns via config
- [ ] Error statistics dashboard
- [ ] Integration with log converters

---

## 💡 Pro Tips

### **Tip 1: Test with Small Files First**
Upload a small sample (10-20 lines) to see errors quickly

### **Tip 2: Fix Common Errors First**
If you see the same error type multiple times, fix all instances at once

### **Tip 3: Use Find & Replace**
For systematic errors (like date format), use your editor's find & replace:
- Find: `(\d{2})/(\d{2})/(\d{4})`
- Replace: `$3-$1-$2`

### **Tip 4: Check Empty Lines**
Empty lines are automatically skipped (not counted as errors)

### **Tip 5: Validate Before Upload**
Use the format checker in `LOG_FORMAT.md` to validate your logs first

---

## 🐛 Troubleshooting

### **Problem: No errors shown but lines are skipped**

**Cause:** More than 10 errors exist

**Solution:** Fix the first 10 errors shown, then re-upload to see more

---

### **Problem: Error says "Unknown format error"**

**Cause:** The line has a complex issue not covered by specific checks

**Solution:** 
1. Compare line to expected format manually
2. Check for unusual characters or encoding issues
3. Report the issue for new error type to be added

---

### **Problem: Correct lines marked as errors**

**Cause:** Possible bug in diagnostic logic

**Solution:**
1. Verify the line truly matches: `YYYY-MM-DD HH:MM:SS [LEVEL] message`
2. Check for invisible characters (copy to text editor)
3. Report the false positive

---

## 📝 Example Workflow

1. **Upload log file**
2. **Check parsing info:**
   - If 100% parsed → Great! ✅
   - If errors exist → Continue ↓
3. **Review error list:**
   - Note common patterns
   - Identify systematic issues
4. **Fix errors:**
   - Use editor find & replace for common issues
   - Fix individual lines as needed
5. **Re-upload and verify:**
   - Should see fewer errors
   - Repeat until 100% parsed

---

**Last Updated:** December 9, 2025  
**Version:** 0.4.0  
**Feature:** Intelligent Error Diagnostics
