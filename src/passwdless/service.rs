use moka::future::Cache;
use sqlx::{Pool, Sqlite, query, query_scalar};
use std::time::Duration;
use uuid::Uuid;

use crate::auth2::random_token;

#[derive(Debug)]
pub enum PasswdlessError {
    DbError,
    EmailUsed,
    BadToken,
    UserNotFound,
}

pub struct Caches {
    tokens: Cache<String, String>,
    accounts: Cache<String, String>,
}

impl Caches {
    pub fn new() -> Self {
        let tokens = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        let accounts = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        Self { tokens, accounts }
    }
}

pub struct PasswdlessService {
    pub db: Pool<Sqlite>,
    pub caches: Caches,
}

fn send_email(addr: String, text: String) {
    println!("Email sent:{{ addr: {}, message: {} }}", addr, text)
}

/// Generate a random token and keep it in the tokens cache with the email as the key
/// Then email the token to the address
async fn release_token(email: String, tokens: &Cache<String, String>) {
    let token = random_token();
    tokens.insert(token.clone(), email.clone()).await;
    send_email(email, token);
}

pub async fn create_tables(db: &sqlx::Pool<sqlx::Sqlite>) -> Result<(), sqlx::Error> {
    // Create the emails table if it doesn't exist
    query(
        "CREATE TABLE IF NOT EXISTS emails (
            user TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            PRIMARY KEY (user, email)
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

impl PasswdlessService {
    pub async fn new(db: sqlx::Pool<sqlx::Sqlite>) -> Result<Self, sqlx::Error> {
        create_tables(&db).await?;
        Ok(Self {
            db,
            caches: Caches::new(),
        })
    }
    pub async fn create(&self, email: String) -> Result<String, PasswdlessError> {
        // Check if the email already exists
        let stored_email: Option<String> =
            match query_scalar("SELECT email FROM emails WHERE email = ?")
                .bind(email.clone())
                .fetch_optional(&self.db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error getting email address: {}", e);
                    return Err(PasswdlessError::DbError);
                }
            };
        if stored_email.is_some() {
            return Err(PasswdlessError::EmailUsed);
        }

        // Create a pending account and return the user_id so the client can request a challenge.
        let user_id = Uuid::new_v4().to_string();
        self.caches
            .accounts
            .insert(email.clone(), user_id.clone())
            .await;

        release_token(email.clone(), &self.caches.tokens).await;
        Ok(user_id)
    }

    pub async fn confirm_registration(&self, token: String) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let email = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };

        // Check for a pending account (email -> user_id). If present, persist it.
        match self.caches.accounts.remove(&email).await {
            Some(pending_user_id) => {
                // Attach email to user
                if let Err(e) = query("INSERT INTO emails (user, email) VALUES (?, ?)")
                    .bind(pending_user_id.clone())
                    .bind(email.clone())
                    .execute(&self.db)
                    .await
                {
                    eprintln!("Error inserting email: {}", e);
                    return Err(PasswdlessError::DbError);
                }
                Ok(pending_user_id)
            }
            None => return Err(PasswdlessError::UserNotFound),
        }
    }

    pub async fn add(&self, email: String, user_id: String) -> Result<(), PasswdlessError> {
        // Ensure this email is not already used by any account.
        let stored_email: Option<String> =
            match query_scalar("SELECT email FROM emails WHERE email = ?")
                .bind(email.clone())
                .fetch_optional(&self.db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error getting email address: {}", e);
                    return Err(PasswdlessError::DbError);
                }
            };
        if stored_email.is_some() {
            return Err(PasswdlessError::EmailUsed);
        }

        // Store pending email -> user_id for confirmation.
        self.caches.accounts.insert(email.clone(), user_id).await;
        Ok(())
    }

    pub async fn confirm(&self, token: String) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let email = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        Ok(email)
    }

    pub async fn challenge(&self, user_id: String) -> Result<(), PasswdlessError> {
        // Check the emails table for email with this user_id
        let email: Option<String> = match query_scalar("SELECT email FROM emails WHERE user = ?")
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error getting email: {}", e);
                return Err(PasswdlessError::DbError);
            }
        };
        let email = match email {
            Some(e) => e,
            None => return Err(PasswdlessError::UserNotFound),
        };

        // Generate a random token and keep it in the pending tokens cache with the email as the key
        let token = random_token();
        self.caches
            .tokens
            .insert(token.clone(), email.clone())
            .await;
        send_email(email, token);
        Ok(())
    }
}
