use std::fmt::Display;

use anyhow::Error;
use libsigners::Signer;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};
use thiserror::Error;
use uuid::Uuid;

use crate::auth2::{TokenPair, create_access_token, random_token};

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),

    #[error("User already exists")]
    UserExists,

    #[error("User not found")]
    UserNotFound,

    #[error("Refresh token not found")]
    RefreshTokenNotFound,

    #[error("Database error")]
    DatabaseError,
}

#[derive(Debug, Error)]
pub enum TokenPairError {
    Access(Error),
    Refresh(DbError),
}
impl Display for TokenPairError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenPairError::Access(error) => write!(f, "{}", error),
            TokenPairError::Refresh(db_error) => write!(f, "{}", db_error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PasswordReset {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RefreshToken {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub issuerer: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let result = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)
            RETURNING
                id as "id!",
                username as "username!",
                password_hash as "password_hash!",
                created_at as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at!: chrono::DateTime<chrono::Utc>"
            "#,
            id,
            username,
            password_hash,
            now,
            now
        )
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(user) => Ok(user),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(DbError::UserExists)
            }
            Err(e) => Err(DbError::SqlxError(e)),
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, DbError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id as "id!",
                username as "username!",
                password_hash as "password_hash!",
                created_at as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users
            WHERE username = ?
            "#,
            username
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DbError::UserNotFound)
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<User, DbError> {
        sqlx::query_as!(
            User,
            r#"
            SELECT
                id as "id!",
                username as "username!",
                password_hash as "password_hash!",
                created_at as "created_at!: chrono::DateTime<chrono::Utc>",
                updated_at as "updated_at!: chrono::DateTime<chrono::Utc>"
            FROM users
            WHERE id = ?
            "#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DbError::UserNotFound)
    }

    pub async fn create_refresh_token(
        &self,
        user_id: &str,
        expires_in_days: i64,
        issuerer: String,
    ) -> Result<RefreshToken, DbError> {
        let token = random_token();
        let id = Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(expires_in_days);
        let created_at = chrono::Utc::now();

        sqlx::query!(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token, expires_at, issuerer, revoked, created_at)
            VALUES (?, ?,?, ?, ?, FALSE, ?)
            "#,
            id,
            user_id,
            token,
            expires_at,
            issuerer,
            created_at
        )
        .execute(&self.pool)
        .await?;

        Ok(RefreshToken {
            id,
            user_id: user_id.to_string(),
            token: token.to_string(),
            expires_at,
            issuerer,
            revoked: false,
            created_at,
        })
    }

    pub async fn get_refresh_token(&self, token: &str) -> Result<RefreshToken, DbError> {
        sqlx::query_as!(
            RefreshToken,
            r#"
        SELECT
            id as "id!",
            user_id as "user_id!",
            token as "token!",
            issuerer,
            expires_at as "expires_at!: chrono::DateTime<chrono::Utc>",
            revoked as "revoked!",
            created_at as "created_at!: chrono::DateTime<chrono::Utc>"
        FROM refresh_tokens
        WHERE token = ? AND revoked = FALSE
        "#,
            token
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => DbError::RefreshTokenNotFound,
            other => {
                tracing::warn!("SQLx error: {:?}", other);
                DbError::DatabaseError
            }
        })
    }

    pub async fn revoke_user_refresh_tokens(&self, user_id: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?",
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    pub async fn revoke_refresh_token(&self, token: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE refresh_tokens SET revoked = TRUE WHERE token = ?",
            token
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            password_hash,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::DatabaseError)?;

        Ok(())
    }

    pub async fn create_password_reset(
        &self,
        user_id: &str,
        token_hash: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), DbError> {
        let id = Uuid::new_v4().to_string();
        sqlx::query!(
            r#"
        INSERT INTO password_resets (id, user_id, token_hash, expires_at)
        VALUES (?, ?, ?, ?)
        "#,
            id,
            user_id,
            token_hash,
            expires_at
        )
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::DatabaseError)?;

        Ok(())
    }

    pub async fn mark_reset_used(&self, reset_id: &str) -> Result<(), DbError> {
        sqlx::query!(
            "UPDATE password_resets SET used = TRUE WHERE id = ?",
            reset_id
        )
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::DatabaseError)?;

        Ok(())
    }

    pub async fn get_password_reset(&self, token_hash: &str) -> Result<PasswordReset, DbError> {
        sqlx::query_as!(
            PasswordReset,
            r#"
        SELECT
            id as "id!",
            user_id as "user_id!",
            token_hash as "token_hash!",
            expires_at as "expires_at!: chrono::DateTime<chrono::Utc>",
            used as "used!",
            created_at as "created_at!: chrono::DateTime<chrono::Utc>"
        FROM password_resets
        WHERE token_hash = ? AND used = FALSE
        "#,
            token_hash
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DbError::RefreshTokenNotFound)
    }

    pub async fn create_token_pair(
        &self,
        signer: &dyn Signer,
        user_id: &str,
        issuerer: String,
    ) -> Result<TokenPair, TokenPairError> {
        let access = create_access_token(signer, user_id)
            .await
            .map_err(TokenPairError::Access)?;
        let rt = self
            .create_refresh_token(user_id, 1, issuerer)
            .await
            .map_err(TokenPairError::Refresh)?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: rt.token,
        })
    }
}
