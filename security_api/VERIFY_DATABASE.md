# ✅ How to Verify Database Connection

## 🎯 Quick Verification Steps

### **Step 1: Update Your Password**

Edit `.env` file and replace `your_password`:

```bash
# Before:
DATABASE_URL=mysql://root:your_password@localhost:3306/security_LogsDB

# After (use YOUR actual password):
DATABASE_URL=mysql://root:MyActualPassword123@localhost:3306/security_LogsDB
```

---

### **Step 2: Run the Database Test**

```bash
cd /Users/senaraufi/Desktop/Startup/security_api
cargo run --example test_database
```

**What you should see:**

```
🔍 Testing Database Connection...

✅ DATABASE_URL found in .env
   URL: mysql://root:****@localhost:3306/security_LogsDB

🔌 Attempting to connect to database...
✅ Database connection successful!

🧪 Running test query...
✅ Test query successful!

📋 Checking for tables...
✅ Found 9 tables:

   - log_uploads
   - analysis_results
   - ai_analysis
   - ai_findings
   - ai_recommendations
   - detected_threats
   - ip_analysis
   - threat_patterns
   - raw_logs

🔍 Checking log_uploads table...
✅ log_uploads table exists!
   Total uploads: 0

🎉 Database test complete!

📝 Your database is ready to use!
   Run: cargo run
```

---

### **Step 3: Run the Main Server**

```bash
cargo run
```

**What you should see:**

```
🚀 Starting Security API Server...
🔌 Connecting to database...
✅ Database connected successfully!
✅ Database connection test passed!
✅ Security API Server running on http://localhost:3000
📁 Upload logs at: http://localhost:3000
```

---

### **Step 4: Upload a File and Verify**

1. **Open browser:** http://localhost:3000
2. **Upload a log file** (either Standard or AI mode)
3. **Watch the terminal** - you should see:

```
✅ Log upload saved to database (ID: 1)
✅ Analysis result saved to database
```

4. **Check in MySQL Workbench:**

```sql
-- See your upload
SELECT * FROM log_uploads ORDER BY upload_date DESC LIMIT 1;

-- See the analysis
SELECT * FROM analysis_results ORDER BY analysis_date DESC LIMIT 1;
```

---

## 🚨 Common Issues & Fixes

### ❌ "Access denied for user 'root'"

**Problem:** Wrong password in `.env`

**Fix:**
1. Find your MySQL password
2. Update `.env` file
3. Try again

**Test your password:**
```bash
mysql -u root -p
# Enter your password
# If it works, use that password in .env
```

---

### ❌ "Can't connect to MySQL server"

**Problem:** MySQL is not running

**Fix:**
```bash
# Mac
mysql.server start

# Or with Homebrew
brew services start mysql

# Check status
mysql.server status
```

---

### ❌ "Unknown database 'security_LogsDB'"

**Problem:** Database doesn't exist

**Fix:**
```bash
# Option 1: Command line
mysql -u root -p -e "CREATE DATABASE security_LogsDB;"

# Option 2: MySQL Workbench
# Run: CREATE DATABASE security_LogsDB;
# Then run your SQL schema to create tables
```

---

### ❌ "Table 'log_uploads' doesn't exist"

**Problem:** Tables not created

**Fix:**
1. Open MySQL Workbench
2. Connect to `security_LogsDB`
3. Run the SQL schema (the one with CREATE TABLE statements)
4. Verify tables exist: `SHOW TABLES;`

---

## 🎨 Visual Verification

### **Terminal Output When Working:**

```
┌─────────────────────────────────────────┐
│ 🚀 Starting Security API Server...     │
│ 🔌 Connecting to database...           │
│ ✅ Database connected successfully!    │
│ ✅ Database connection test passed!    │
│ ✅ Security API Server running          │
└─────────────────────────────────────────┘

When you upload a file:
┌─────────────────────────────────────────┐
│ ✅ Log upload saved to database (ID: 1) │
│ ✅ Analysis result saved to database    │
└─────────────────────────────────────────┘
```

### **MySQL Workbench Verification:**

```sql
-- Quick check
SELECT 
    COUNT(*) as total_uploads,
    MAX(upload_date) as last_upload
FROM log_uploads;

-- Should return:
-- total_uploads | last_upload
-- 1             | 2025-12-18 15:30:00
```

---

## 📋 Checklist

- [ ] MySQL is running
- [ ] Database `security_LogsDB` exists
- [ ] Tables are created (9 tables)
- [ ] `.env` file has correct password
- [ ] `cargo run --example test_database` passes
- [ ] `cargo run` shows database connected
- [ ] File upload shows "saved to database" message
- [ ] Data visible in MySQL Workbench

---

## 🎯 Success Indicators

✅ **Connection Working:**
- Test script shows all green checkmarks
- Server starts without database errors
- Terminal shows "Database connected successfully!"

✅ **Saving Working:**
- Upload shows "saved to database" messages
- Data appears in MySQL Workbench
- `log_uploads` table has rows

✅ **Ready for Production:**
- All tests pass
- Multiple uploads work
- Both Standard and AI modes save data

---

**Need help? Check the terminal output - it will tell you exactly what's wrong!**
