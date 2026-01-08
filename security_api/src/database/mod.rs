use sqlx::{MySql, Pool, mysql::MySqlPoolOptions};
use std::env;

pub mod models;
pub mod queries;

// Database connection pool type
pub type DbPool = Pool<MySql>;

/// Initialize database connection pool
pub async fn init_db() -> Result<DbPool, sqlx::Error> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set in .env file");
    
    println!("🔌 Connecting to database...");
    
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;
    
    println!(" Database connected successfully!");
    Ok(pool)
}

/// Test database connection
pub async fn test_connection(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1")
        .fetch_one(pool)
        .await?;
    
    println!(" Database connection test passed!");
    Ok(())
}
