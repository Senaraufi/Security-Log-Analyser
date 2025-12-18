/// Test database connection
/// Run with: cargo run --example test_database

use sqlx::{mysql::MySqlPoolOptions, Row};
use std::env;

#[tokio::main]
async fn main() {
    // Load .env file
    dotenv::dotenv().ok();
    
    println!(" Testing Database Connection...\n");
    
    // Get database URL
    let database_url = match env::var("DATABASE_URL") {
        Ok(url) => {
            println!(" DATABASE_URL found in .env");
            println!("   URL: {}\n", url.replace(|c: char| c.is_ascii_digit() && url.contains(&c.to_string()), "*"));
            url
        }
        Err(_) => {
            eprintln!(" DATABASE_URL not found in .env file");
            eprintln!(" Add this to your .env file:");
            eprintln!("   DATABASE_URL=mysql://root:YOUR_PASSWORD@localhost:3306/security_LogsDB\n");
            return;
        }
    };
    
    // Try to connect
    println!("🔌 Attempting to connect to database...");
    
    match MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
    {
        Ok(pool) => {
            println!("✅ Database connection successful!\n");
            
            // Test query
            println!(" Running test query...");
            match sqlx::query("SELECT 1 as test")
                .fetch_one(&pool)
                .await
            {
                Ok(_) => {
                    println!(" Test query successful!\n");
                }
                Err(e) => {
                    eprintln!(" Test query failed: {}\n", e);
                }
            }
            
            // Check tables
            println!(" Checking for tables...");
            match sqlx::query("SHOW TABLES")
                .fetch_all(&pool)
                .await
            {
                Ok(rows) => {
                    if rows.is_empty() {
                        println!(" No tables found in database");
                        println!(" Run the SQL schema in MySQL Workbench\n");
                    } else {
                        println!(" Found {} tables:\n", rows.len());
                        for row in rows {
                            let table_name: String = row.try_get(0).unwrap_or_default();
                            println!("   - {}", table_name);
                        }
                        println!();
                    }
                }
                Err(e) => {
                    eprintln!(" Could not list tables: {}\n", e);
                }
            }
            
            // Try to query log_uploads table
            println!(" Checking log_uploads table...");
            match sqlx::query("SELECT COUNT(*) as count FROM log_uploads")
                .fetch_one(&pool)
                .await
            {
                Ok(row) => {
                    let count: i64 = row.try_get("count").unwrap_or(0);
                    println!(" log_uploads table exists!");
                    println!(" Total uploads: {}\n", count);
                }
                Err(e) => {
                    eprintln!(" log_uploads table not found: {}", e);
                    eprintln!(" Make sure you've run the SQL schema\n");
                }
            }
            
            println!(" Database test complete!");
            println!("\n Your database is ready to use!");
            println!(" Run: cargo run");
            
        }
        Err(e) => {
            eprintln!(" Database connection failed!");
            eprintln!(" Error: {}\n", e);
            
            eprintln!(" Troubleshooting:");
            eprintln!(" 1. Check MySQL is running: mysql.server status");
            eprintln!(" 2. Verify password in .env file");
            eprintln!(" 3. Ensure database exists: CREATE DATABASE security_LogsDB;");
            eprintln!(" 4. Check connection string format:");
            eprintln!("      DATABASE_URL=mysql://root:{{root}}@localhost:3306/security_LogsDB");
        }
    }
}
