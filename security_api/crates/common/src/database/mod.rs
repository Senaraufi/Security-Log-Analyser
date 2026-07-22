use sqlx::{MySql, Pool, mysql::MySqlPoolOptions};
use std::env;
use std::time::Duration;

pub mod models;
pub mod queries;

// Database connection pool type
pub type DbPool = Pool<MySql>;

/// Initialize database connection pool
///
/// The database is optional: if `DATABASE_URL` is not set, this returns an
/// error (rather than panicking) so callers can run without a database —
/// e.g. for a hosted demo or `docker-compose up` with no MySQL service.
pub async fn init_db() -> Result<DbPool, sqlx::Error> {
    let database_url = env::var("DATABASE_URL").map_err(|_| {
        sqlx::Error::Configuration("DATABASE_URL is not set; running without a database".into())
    })?;

    println!(" Connecting to database...");
    
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
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
