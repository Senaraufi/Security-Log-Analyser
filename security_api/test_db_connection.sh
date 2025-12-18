#!/bin/bash

# Test MySQL Database Connection
# This script helps you verify your database is accessible

echo "🔍 Testing MySQL Database Connection..."
echo ""

# Test 1: Check if MySQL is running
echo "1️⃣  Checking if MySQL is running..."
if pgrep -x "mysqld" > /dev/null; then
    echo "   ✅ MySQL server is running"
else
    echo "   ❌ MySQL server is NOT running"
    echo "   💡 Start it with: mysql.server start"
    exit 1
fi

echo ""

# Test 2: Try to connect to MySQL
echo "2️⃣  Testing MySQL connection..."
echo "   Enter your MySQL root password when prompted:"
if mysql -u root -p -e "SELECT 1;" > /dev/null 2>&1; then
    echo "   ✅ MySQL connection successful"
else
    echo "   ❌ Could not connect to MySQL"
    echo "   💡 Check your password"
    exit 1
fi

echo ""

# Test 3: Check if database exists
echo "3️⃣  Checking if security_LogsDB database exists..."
DB_EXISTS=$(mysql -u root -p -e "SHOW DATABASES LIKE 'security_LogsDB';" 2>/dev/null | grep security_LogsDB)

if [ -n "$DB_EXISTS" ]; then
    echo "   ✅ Database 'security_LogsDB' exists"
else
    echo "   ❌ Database 'security_LogsDB' does NOT exist"
    echo "   💡 Create it in MySQL Workbench or run:"
    echo "      mysql -u root -p -e 'CREATE DATABASE security_LogsDB;'"
    exit 1
fi

echo ""

# Test 4: Check tables
echo "4️⃣  Checking database tables..."
TABLE_COUNT=$(mysql -u root -p security_LogsDB -e "SHOW TABLES;" 2>/dev/null | wc -l)

if [ "$TABLE_COUNT" -gt 1 ]; then
    echo "   ✅ Found $((TABLE_COUNT - 1)) tables in database"
    echo ""
    echo "   📋 Tables:"
    mysql -u root -p security_LogsDB -e "SHOW TABLES;" 2>/dev/null
else
    echo "   ⚠️  No tables found in database"
    echo "   💡 Run the SQL schema from the database design in MySQL Workbench"
fi

echo ""
echo "✅ Database connection test complete!"
echo ""
echo "📝 Next step: Update your .env file with the correct password:"
echo "   DATABASE_URL=mysql://root:YOUR_PASSWORD@localhost:3306/security_LogsDB"
