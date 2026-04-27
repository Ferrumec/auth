use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ── Command types (inputs) ────────────────────────────────────────────────────

/// Password-based login.
#[derive(Debug, Deserialize)]
pub struct PasswordLoginCmd {
    pub username: String,
    pub password: String,
}

/// Passwordless login confirmation (link token or numeric OTP).
#[derive(Debug)]
pub enum PasswdlessConfirmCmd {
    Link(String),
    Otp(u32),
}

/// Refresh an access token using a long-lived refresh token.
#[derive(Debug, Deserialize)]
pub struct RefreshCmd {
    pub refresh_token: String,
}

/// Revoke a refresh token (logout).
#[derive(Debug, Deserialize)]
pub struct LogoutCmd {
    pub refresh_token: String,
}

/// Change the current user's password.
#[derive(Debug, Deserialize)]
pub struct ChangePasswordCmd {
    pub user_id: String,
    pub current_password: String,
    pub new_password: String,
}

/// Request a password-reset email.
#[derive(Debug, Deserialize)]
pub struct RequestPasswordResetCmd {
    pub email: String,
}

/// Confirm a password reset using the token from the email.
#[derive(Debug, Deserialize)]
pub struct ConfirmPasswordResetCmd {
    pub token: String,
    pub new_password: String,
}

// ── Result types (outputs) ────────────────────────────────────────────────────

/// Returned after any successful authentication flow.
#[derive(Debug, Serialize)]
pub struct AuthResult {
    pub access_token: String,
    pub refresh_token: String,
    /// Seconds until the access token expires.
    pub expires_in: u64,
}

// ── DB row types ──────────────────────────────────────────────────────────────

/// A row from the `users` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A row from the `refresh_tokens` table.
/// `token_hash` is SHA-256(raw_token). The raw token is **never** stored.
#[derive(Debug, Clone)]
pub struct RefreshTokenRow {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub issuer: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// A row from the `password_resets` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

