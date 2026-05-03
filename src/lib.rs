
mod config;
mod domain;
mod handlers;
mod auth2;
mod models;
#[cfg(feature="passkey")]
mod passkey;
mod passwdless;
mod user_id;
pub use config::{AuthModule as Module, SetupError};
