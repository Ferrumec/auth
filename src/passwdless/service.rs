use moka::future::Cache;
use rand::random;
use sqlx::{Pool, Sqlite, query, query_scalar};
use std::time::Duration;
use uuid::Uuid;

use crate::{auth2::random_token, domain::auth::AuthService};

#[derive(Debug, Clone)]
pub enum PasswdlessError {
    DbError,
    EmailUsed,
    BadToken,
    UserNotFound,
}

pub struct Caches {
    links: Cache<String, FA2Entry>,
    tokens: Cache<u32, FA2Entry>,
    accounts: Cache<String, String>,
}

#[derive(Clone, PartialEq, Hash, Eq)]
struct FA2Entry {
    link: String,
    token: u32,
    email: String,
}

impl Caches {
    pub fn new() -> Self {
        let tokens = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        let links = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        let accounts = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        Self {
            tokens,
            accounts,
            links,
        }
    }
}

pub struct PasswdlessService {
    pub db: Pool<Sqlite>,
    pub auth_service: AuthService,
    pub caches: Caches,
}

fn send_email(addr: String, text: String) {
    println!(
        "Email sent: click this link to confirm email {}. \nOr you can use this token on the login page: {} }}",
        addr, text
    )
}

fn random_int(minimum: u32) -> u32 {
    let mut number = 1;
    while number < minimum {
        number *= random::<u32>();
    }
    number
}

async fn release_pair(email: String, caches: &Caches) {
    let link = random_token();
    let token = random_int(100000);
    let fa2 = FA2Entry {
        link,
        token,
        email: email.clone(),
    };
    caches.tokens.insert(token.clone(), fa2.clone()).await;
    send_email(
        email,
        format!("use link: {} or token: {}", fa2.link, fa2.token),
    );
}

impl PasswdlessService {
    pub fn new(db: Pool<Sqlite>, auth_service: AuthService) -> Self {
        Self {
            db,
            auth_service,
            caches: Caches::new(),
        }
    }
    pub async fn create(&self, email: String) -> Result<String, PasswdlessError> {
        // Check if the email already exists
        let stored_email: Option<String> =
            match query_scalar!("SELECT email FROM users WHERE email = ?", email)
                .fetch_optional(&self.db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Error getting email address: {}", e);
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

        release_pair(email.clone(), &self.caches).await;
        Ok(user_id)
    }

    pub async fn confirm_registration(&self, token: String) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let email = match self.caches.links.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        }
        .email;

        // Check for a pending account (email -> user_id). If present, persist it.
        match self.caches.accounts.remove(&email).await {
            Some(pending_user_id) => {
                // remove the associated token
                // Attach email to user
                match self.auth_service.register(&email, "password").await {
                    Err(e) => {
                        tracing::warn!("Error inserting email: {}", e);
                        return Err(PasswdlessError::DbError);
                    }
                    Ok(r) => r,
                };
                Ok(pending_user_id)
            }
            None => return Err(PasswdlessError::UserNotFound),
        }
    }

    pub async fn confirm_registration_token(&self, token: u32) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let email = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        }
        .email;

        // Check for a pending account (email -> user_id). If present, persist it.
        match self.caches.accounts.remove(&email).await {
            Some(pending_user_id) => {
                // Attach email to user
                match self.auth_service.register(&email, "password").await {
                    Err(e) => {
                        tracing::warn!("Error inserting email: {}", e);
                        return Err(PasswdlessError::DbError);
                    }
                    Ok(_) => (),
                };
                Ok(pending_user_id)
            }
            None => return Err(PasswdlessError::UserNotFound),
        }
    }

    pub async fn add(&self, email: String, user_id: String) -> Result<(), PasswdlessError> {
        // Ensure this email is not already used by any account.
        let stored_email: Option<String> =
            match query_scalar!("SELECT email FROM users WHERE email = ?", email)
                .fetch_optional(&self.db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Error getting email address: {}", e);
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

    pub async fn confirm_link(&self, token: String) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.links.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.tokens.remove(&fa2.token).await;
        Ok(fa2.email)
    }

    pub async fn confirm_token(&self, token: u32) -> Result<String, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.links.remove(&fa2.link).await;
        Ok(fa2.email)
    }

    pub async fn challenge(&self, user_id: String) -> Result<(), PasswdlessError> {
        // Check the emails table for email with this user_id
        let email: Option<String> =
            match query_scalar!("SELECT email FROM users WHERE id = ?", user_id)
                .fetch_optional(&self.db)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Error getting email: {}", e);
                    return Err(PasswdlessError::DbError);
                }
            };
        let email = match email {
            Some(e) => e,
            None => return Err(PasswdlessError::UserNotFound),
        };

        release_pair(email, &self.caches).await;
        Ok(())
    }
}
