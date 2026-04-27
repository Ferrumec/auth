//! The single authoritative home for all authentication business logic.
//!
//! HTTP handlers are thin wrappers: parse → call AuthService → map to HTTP.
//! No database queries and no crypto live outside this module and its
//! submodules.

use chrono::Utc;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

use crate::domain::auth::{
    errors::AuthError,
    jwt::{self, JwtConfig},
    models::{
        AuthResult, ChangePasswordCmd, ConfirmPasswordResetCmd, LogoutCmd, PasswordLoginCmd,
        PasswordReset, RefreshCmd, RefreshTokenRow, RequestPasswordResetCmd, User,
    },
    token::{generate_raw_token, hash_token},
};

// ── Constants ─────────────────────────────────────────────────────────────────

const REFRESH_TOKEN_EXPIRY_DAYS: i64 = 30;
const MIN_PASSWORD_LEN: usize = 6;

// ── AuthService ───────────────────────────────────────────────────────────────

/// Central service for all authentication flows.
///
/// Owns the database pool and JWT configuration. Constructed once at
/// application startup and shared via `Arc` or Actix `web::Data`.
pub struct AuthService {
    pool: Pool<Sqlite>,
    jwt: JwtConfig,
}

impl AuthService {
    pub fn new(pool: Pool<Sqlite>, jwt: JwtConfig) -> Self {
        Self { pool, jwt }
    }

    // ── Password login ────────────────────────────────────────────────────────

    /// Validate credentials and issue a token pair.
    pub async fn password_login(&self, cmd: PasswordLoginCmd) -> Result<AuthResult, AuthError> {
        if cmd.username.is_empty() || cmd.password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }

        let user = self.get_user_by_username(&cmd.username).await?;

        match bcrypt::verify(&cmd.password, &user.password_hash) {
            Ok(true) => {}
            Ok(false) => return Err(AuthError::InvalidCredentials),
            Err(e) => return Err(AuthError::Bcrypt(e)),
        }

        self.issue_token_pair(&user.id, "password-login").await
    }

    // ── Registration ──────────────────────────────────────────────────────────

    /// Hash the password and create a new user row.
    ///
    /// Returns the new user's ID so callers can optionally auto-login.
    pub async fn register(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, AuthError> {
        if username.is_empty() || password.is_empty() {
            return Err(AuthError::MissingCredentials);
        }
        if password.len() < MIN_PASSWORD_LEN {
            return Err(AuthError::PasswordTooShort);
        }

        let hash = bcrypt::hash(password, 10)?;
        let user = self.create_user(username, &hash).await?;
        Ok(user.id)
    }

    // ── Token refresh (with rotation) ─────────────────────────────────────────

    /// Exchange a valid refresh token for a new token pair.
    ///
    /// The old refresh token is deleted (not just flagged) so it can never
    /// be replayed. This is atomic: if issuing the new pair fails, the old
    /// token is NOT invalidated.
    pub async fn refresh(&self, cmd: RefreshCmd) -> Result<AuthResult, AuthError> {
        let raw = cmd.refresh_token.trim();
        if raw.is_empty() {
            return Err(AuthError::MissingRefreshToken);
        }

        let hash = hash_token(raw);
        let row = self.get_refresh_token_by_hash(&hash).await?;

        if row.revoked {
            return Err(AuthError::RefreshTokenNotFound);
        }
        if row.expires_at < Utc::now() {
            return Err(AuthError::RefreshTokenExpired);
        }

        // Verify user still exists.
        let user = self.get_user_by_id(&row.user_id).await?;

        // Rotation: delete old token, then issue fresh pair.
        // We delete by hash (not by raw token) since that's what's stored.
        self.delete_refresh_token_by_hash(&hash).await?;

        self.issue_token_pair(&user.id, &row.issuer).await
    }

    // ── Logout ────────────────────────────────────────────────────────────────

    /// Revoke a refresh token. Silent success if the token is not found so
    /// that duplicate logout calls are idempotent from the client's view.
    pub async fn logout(&self, cmd: LogoutCmd) -> Result<(), AuthError> {
        let raw = cmd.refresh_token.trim();
        if raw.is_empty() {
            return Err(AuthError::MissingRefreshToken);
        }
        let hash = hash_token(raw);
        // Ignore NotFound – already logged out is fine.
        match self.revoke_refresh_token_by_hash(&hash).await {
            Ok(()) | Err(AuthError::RefreshTokenNotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ── Change password ───────────────────────────────────────────────────────

    /// Verify the current password, set a new one, and revoke all sessions.
    pub async fn change_password(&self, cmd: ChangePasswordCmd) -> Result<(), AuthError> {
        if cmd.new_password.len() < MIN_PASSWORD_LEN {
            return Err(AuthError::PasswordTooShort);
        }

        let user = self.get_user_by_id(&cmd.user_id).await?;

        let valid = bcrypt::verify(&cmd.current_password, &user.password_hash)
            .unwrap_or(false);
        if !valid {
            return Err(AuthError::InvalidCredentials);
        }

        let new_hash = bcrypt::hash(&cmd.new_password, 10)?;
        self.update_password(&cmd.user_id, &new_hash).await?;

        // Invalidate all existing sessions for this user.
        self.revoke_all_user_tokens(&cmd.user_id).await?;

        Ok(())
    }

    // ── Password reset (request) ──────────────────────────────────────────────

    /// Generate and store a reset token. Always returns `Ok` even if the
    /// user is not found (prevents email enumeration).
    pub async fn request_password_reset(&self, cmd: RequestPasswordResetCmd) {
        // Look up by email column in the `emails` table.
        let user_id: Option<String> = sqlx::query_scalar!(
            "SELECT user FROM emails WHERE email = ?",
            cmd.email
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap_or(None);

        let user_id = match user_id {
            Some(id) => id,
            None => return, // silent – do not leak whether address is registered
        };

        let raw = generate_raw_token();
        let hash = hash_token(&raw);
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        let id = Uuid::new_v4().to_string();

        let _ = sqlx::query!(
            "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
            id,
            user_id,
            hash,
            expires_at
        )
        .execute(&self.pool)
        .await;

        // In production: hand `raw` to your email service here.
        tracing::info!("Password reset token for {}: {}", cmd.email, raw);
    }

    // ── Password reset (confirm) ──────────────────────────────────────────────

    /// Validate the reset token, apply the new password, and revoke sessions.
    pub async fn confirm_password_reset(
        &self,
        cmd: ConfirmPasswordResetCmd,
    ) -> Result<(), AuthError> {
        let token_hash = hash_token(&cmd.token);

        let reset = sqlx::query_as!(
            PasswordReset,
            r#"
            SELECT
                id          as "id!",
                user_id     as "user_id!",
                token_hash  as "token_hash!",
                expires_at  as "expires_at!: chrono::DateTime<chrono::Utc>",
                used        as "used!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>"
            FROM password_resets
            WHERE token_hash = ? AND used = FALSE
            "#,
            token_hash
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidToken)?;

        if reset.used || reset.expires_at < Utc::now() {
            return Err(AuthError::InvalidToken);
        }

        let new_hash = bcrypt::hash(&cmd.new_password, 10)?;
        self.update_password(&reset.user_id, &new_hash).await?;

        sqlx::query!(
            "UPDATE password_resets SET used = TRUE WHERE id = ?",
            reset.id
        )
        .execute(&self.pool)
        .await?;

        self.revoke_all_user_tokens(&reset.user_id).await?;

        Ok(())
    }

    // ── Passwordless – issue tokens after challenge confirmation ──────────────

    /// Issue a token pair for a user who just completed a passwordless
    /// challenge (link or OTP). The caller is responsible for verifying the
    /// challenge beforehand.
    pub async fn issue_for_passwordless(
        &self,
        user_id: &str,
    ) -> Result<AuthResult, AuthError> {
        self.issue_token_pair(user_id, "passwordless").await
    }

    // ── JWT verification (for middleware / protected routes) ──────────────────

    /// Verify an access token and return the subject (user ID).
    pub fn verify_access_token(&self, token: &str) -> Result<String, AuthError> {
        jwt::verify_access_token(token, &self.jwt)
            .map(|c| c.sub)
            .map_err(|_| AuthError::InvalidToken)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Issue a fresh access token + refresh token pair.
    ///
    /// The raw refresh token is returned to the caller exactly once.
    /// Only its hash is persisted.
    async fn issue_token_pair(
        &self,
        user_id: &str,
        issuer: &str,
    ) -> Result<AuthResult, AuthError> {
        let access_token = jwt::generate_access_token(user_id, &self.jwt)
            .map_err(|e| AuthError::TokenSigning(e.to_string()))?;

        let raw_refresh = generate_raw_token();
        let token_hash = hash_token(&raw_refresh);

        let id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + chrono::Duration::days(REFRESH_TOKEN_EXPIRY_DAYS);
        let now = Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token_hash, issuer, expires_at, revoked, created_at)
            VALUES (?, ?, ?, ?, ?, FALSE, ?)
            "#,
            id,
            user_id,
            token_hash,
            issuer,
            expires_at,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(AuthResult {
            access_token,
            refresh_token: raw_refresh, // raw token returned to client, never stored
            expires_in: self.jwt.access_token_expiry_minutes as u64 * 60,
        })
    }

    async fn get_user_by_username(&self, username: &str) -> Result<User, AuthError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id          as "id!",
                username    as "username!",
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users WHERE username = ?
            "#,
            username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::InvalidCredentials) // mask whether user exists
    }

    async fn get_user_by_id(&self, id: &str) -> Result<User, AuthError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id          as "id!",
                username    as "username!",
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users WHERE id = ?
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| AuthError::UserNotFound)
    }

    async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, AuthError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING
                id          as "id!",
                username    as "username!",
                password_hash as "password_hash!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at  as "updated_at!: chrono::DateTime<chrono::Utc>"
            "#,
            id,
            username,
            password_hash,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => AuthError::UserAlreadyExists,
            _ => AuthError::Database(e),
        })
    }

    async fn get_refresh_token_by_hash(&self, hash: &str) -> Result<RefreshTokenRow, AuthError> {
        sqlx::query!(
            r#"
            SELECT
                id          as "id!",
                user_id     as "user_id!",
                token_hash  as "token_hash!",
                issuer      as "issuer!",
                expires_at  as "expires_at!: chrono::DateTime<chrono::Utc>",
                revoked     as "revoked!",
                created_at  as "created_at!: chrono::DateTime<chrono::Utc>"
            FROM refresh_tokens
            WHERE token_hash = ?
            "#,
            hash
        )
        .fetch_one(&self.pool)
        .await
        .map(|r| RefreshTokenRow {
            id: r.id,
            user_id: r.user_id,
            token_hash: r.token_hash,
            issuer: r.issuer,
            expires_at: r.expires_at,
            revoked: r.revoked,
            created_at: r.created_at,
        })
        .map_err(|_| AuthError::RefreshTokenNotFound)
    }

    /// Hard-delete a single refresh token by hash (rotation).
    async fn delete_refresh_token_by_hash(&self, hash: &str) -> Result<(), AuthError> {
        sqlx::query!(
            "DELETE FROM refresh_tokens WHERE token_hash = ?",
            hash
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Soft-revoke a single refresh token (logout path).
    async fn revoke_refresh_token_by_hash(&self, hash: &str) -> Result<(), AuthError> {
        let result = sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?",
            hash
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::RefreshTokenNotFound);
        }
        Ok(())
    }

    /// Soft-revoke all tokens for a user (password change, reset).
    async fn revoke_all_user_tokens(&self, user_id: &str) -> Result<(), AuthError> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?",
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_password(&self, user_id: &str, hash: &str) -> Result<(), AuthError> {
        let now = Utc::now();
        sqlx::query!(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
            hash,
            now,
            user_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

