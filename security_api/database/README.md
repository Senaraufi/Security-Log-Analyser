# Database Setup and Scripts

This folder contains all database-related configuration and setup files for the Security Log Analyzer.

---

## Files

### `create_tables.sql`
SQL schema for creating the MySQL database tables:
- `log_uploads` - Tracks uploaded log files
- `analysis_results` - Stores analysis results with CVSS scores
- `threats` - Individual threat detections
- `ip_addresses` - IP reputation tracking

### `test_db_connection.sh`
Script to test MySQL database connectivity and verify configuration.

### `check_database.sh`
Script to check database status and verify tables exist.

---

## Quick Start

### 1. Install MySQL

**macOS:**
```bash
brew install mysql
brew services start mysql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mysql-server
sudo systemctl start mysql
```

### 2. Create Database

```bash
# Login to MySQL
mysql -u root -p

# Create database
CREATE DATABASE security_LogsDB;
exit;
```

### 3. Run Schema

```bash
# From the security_api directory
mysql -u root -p security_LogsDB < database/create_tables.sql
```

### 4. Configure Environment

Update `.env` in the project root:
```bash
DATABASE_URL=mysql://root:your_password@localhost:3306/security_LogsDB
```

### 5. Test Connection

```bash
# From the security_api directory
bash database/test_db_connection.sh
```

---

## Database Schema

### `log_uploads`
```sql
- id (INT, PRIMARY KEY)
- filename (VARCHAR)
- upload_time (DATETIME)
- file_size (INT)
- line_count (INT)
```

### `analysis_results`
```sql
- id (INT, PRIMARY KEY)
- upload_id (INT, FOREIGN KEY)
- analysis_time (DATETIME)
- total_threats (INT)
- cvss_score (FLOAT)
- severity (VARCHAR)
```

### `threats`
```sql
- id (INT, PRIMARY KEY)
- analysis_id (INT, FOREIGN KEY)
- threat_type (VARCHAR)
- count (INT)
- cvss_score (FLOAT)
- severity (VARCHAR)
```

---

## Optional Feature

Database integration is **optional**. The application works without MySQL but provides enhanced features when configured:

- ✅ Audit trail of all analyses
- ✅ Historical trend analysis
- ✅ Compliance reporting
- ✅ Long-term threat tracking

---

## Troubleshooting

### Connection Refused
```bash
# Check if MySQL is running
brew services list  # macOS
sudo systemctl status mysql  # Linux

# Start MySQL if stopped
brew services start mysql  # macOS
sudo systemctl start mysql  # Linux
```

### Access Denied
```bash
# Reset MySQL root password
mysql -u root
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_password';
FLUSH PRIVILEGES;
```

### Database Doesn't Exist
```bash
mysql -u root -p -e "CREATE DATABASE security_LogsDB;"
```

---

## Security Notes

- Never commit database credentials to Git
- Use `.env` file for configuration (already in `.gitignore`)
- Use strong passwords for production databases
- Restrict database access to localhost in development
