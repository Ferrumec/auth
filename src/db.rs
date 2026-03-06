use std::fmt::Display;

use anyhow::Error;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool, sqlite::SqliteRow};
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
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub revoked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl<'r> FromRow<'r, SqliteRow> for User {
    fn from_row(row: &'r SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(User {
            id: row.get("id"),
            username: row.get("username"),
            password_hash: row.get("password_hash"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn init(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Create refresh_tokens table
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at DATETIME NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
    CREATE TABLE IF NOT EXISTS password_resets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        expires_at DATETIME NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    "#,
        )
        .execute(&self.pool)
        .await?;

        // Create indexes
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_user(&self, username: &str, password_hash: &str) -> Result<User, DbError> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"
            INSERT INTO users (id, username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&id)
        .bind(username)
        .bind(password_hash)
        .bind(now)
        .bind(now)
        .fetch_one(&self.pool)
        .await;

        match result {
            Ok(row) => Ok(User::from_row(&row)?),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(DbError::UserExists)
            }
            Err(e) => Err(DbError::SqlxError(e)),
        }
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<User, DbError> {
        sqlx::query("SELECT * FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| DbError::UserNotFound)
            .and_then(|row| Ok(User::from_row(&row)?))
    }

    pub async fn get_user_by_id(&self, id: &str) -> Result<User, DbError> {
        sqlx::query("SELECT * FROM users WHERE id = ?")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(|_| DbError::UserNotFound)
            .and_then(|row| Ok(User::from_row(&row)?))
    }

    pub async fn create_refresh_token(
        &self,
        user_id: &str,
        expires_in_days: i64,
    ) -> Result<RefreshToken, DbError> {
        let token = random_token();
        let id = Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(expires_in_days);
        let created_at = chrono::Utc::now();

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token, expires_at, revoked, created_at)
            VALUES (?, ?, ?, ?, FALSE, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(&token)
        .bind(expires_at)
        .bind(created_at)
        .execute(&self.pool)
        .await?;

        Ok(RefreshToken {
            id,
            user_id: user_id.to_string(),
            token: token.to_string(),
            expires_at,
            revoked: false,
            created_at,
        })
    }

    pub async fn get_refresh_token(&self, token: &str) -> Result<RefreshToken, DbError> {
        sqlx::query_as::<_, RefreshToken>(
            r#"
        SELECT * FROM refresh_tokens
        WHERE token = ? AND revoked = FALSE
        "#,
        )
        .bind(token)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| match err {
            sqlx::Error::RowNotFound => DbError::RefreshTokenNotFound,
            other => {
                eprintln!("SQLx error: {:?}", other);
                DbError::DatabaseError
            }
        })
    }

    pub async fn revoke_refresh_token(&self, token: &str) -> Result<(), DbError> {
        let result = sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            Err(DbError::RefreshTokenNotFound)
        } else {
            Ok(())
        }
    }

    pub async fn update_password(&self, user_id: &str, password_hash: &str) -> Result<(), DbError> {
        sqlx::query(r#"UPDATE users SET password_hash = $1 WHERE id = $2"#)
            .bind(password_hash)
            .bind(user_id)
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
        sqlx::query(
            r#"
        INSERT INTO password_resets (user_id, token_hash, expires_at)
        VALUES ($1, $2, $3)
        "#,
        )
        .bind(user_id)
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(|_| DbError::DatabaseError)?;

        Ok(())
    }

    pub async fn mark_reset_used(&self, reset_id: &str) -> Result<(), DbError> {
        sqlx::query("UPDATE password_resets SET used = TRUE WHERE id = $1")
            .bind(reset_id)
            .execute(&self.pool)
            .await
            .map_err(|_| DbError::DatabaseError)?;

        Ok(())
    }

    pub async fn get_password_reset(&self, token_hash: &str) -> Result<PasswordReset, DbError> {
        sqlx::query_as::<_, PasswordReset>(
            r#"
        SELECT *
        FROM password_resets
        WHERE token_hash = ? AND used = FALSE
        "#,
        )
        .bind(token_hash)
        .fetch_one(&self.pool)
        .await
        .map_err(|_| DbError::RefreshTokenNotFound)
    }

    pub async fn create_token_pair(
        &self,
        signer: libsigners::HS256Signer,
        user_id: &str,
    ) -> Result<TokenPair, TokenPairError> {
        let access = create_access_token(signer, user_id)
            .await
            .map_err(TokenPairError::Access)?;
        let rt = self
            .create_refresh_token(user_id, 1)
            .await
            .map_err(TokenPairError::Refresh)?;
        Ok(TokenPair {
            access_token: access,
            refresh_token: rt.token,
        })
    }
}
