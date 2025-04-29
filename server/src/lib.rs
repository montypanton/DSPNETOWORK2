// server/src/lib.rs
// This file exports the server components as a library

pub mod api;
pub mod auth;
pub mod db;
pub mod error;
pub mod message;
pub mod models;
pub mod topic;

// Re-export important modules for easier use
pub use api::configure as configure_api;
pub use auth::Authentication;
pub use error::ServerError;