// Log Parser Module
// Structured parsers for different log formats

pub mod apache;

pub use apache::{ApacheLog, parse_apache_combined};
