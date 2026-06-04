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

impl From<sqlx::Error> for PasswdlessError {
    fn from(_value: sqlx::Error) -> Self {
        PasswdlessError::DbError
    }
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
    email: Uuid,
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

fn random_int(minimum: u32) -> u32 {
    let mut number = 1;
    while number < minimum {
        number *= random::<u32>();
    }
    number
}

async fn release_pair(email: Uuid, caches: &Caches) -> (u32, String) {
    let link = random_token();
    let token = random_int(100000);
    let fa2 = FA2Entry {
        link: link.clone(),
        token,
        email: email.clone(),
    };
    caches.tokens.insert(token, fa2.clone()).await;
    (token, link)
}

impl PasswdlessService {
    pub fn new(db: Pool<Sqlite>, auth_service: AuthService) -> Self {
        Self {
            db,
            auth_service,
            caches: Caches::new(),
        }
    }

    pub async fn confirm_link(&self, token: String) -> Result<Uuid, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.links.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.tokens.remove(&fa2.token).await;
        Ok(fa2.email)
    }

    pub async fn confirm_token(&self, token: u32) -> Result<Uuid, PasswdlessError> {
        // Check the email for this token and invalidate the token on success
        let fa2 = match self.caches.tokens.remove(&token).await {
            None => return Err(PasswdlessError::BadToken),
            Some(e) => e,
        };
        self.caches.links.remove(&fa2.link).await;
        Ok(fa2.email)
    }

    pub async fn challenge(&self, user_id: Uuid) -> Result<(u32, String), PasswdlessError> {
        Ok(release_pair(user_id, &self.caches).await)
    }
}
