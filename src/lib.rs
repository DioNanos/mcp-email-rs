pub mod attachments;
pub mod config;
pub mod error;
pub mod folder;
pub mod message;
pub mod pool;
pub mod provider;
mod recipients;
pub mod search_boundary;
pub mod server;

pub use config::EmailConfig;
pub use server::EmailServer;
