use crate::{db::UserRepository, passwdless::PasswdlessService};
use anyhow::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libsigners::{Claims, Sign, Validate};
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::{
    env::{self, VarError},
    sync::Arc,
};

pub struct AppState {
    pub user_repo: UserRepository,
    pub signer: Arc<dyn Sign>,
    pub validator: Arc<dyn Validate>,
    pub config: Config,
    pub passwdless_service: PasswdlessService,
}

impl AppState {
    pub fn new(
        pool: Pool<Sqlite>,
        signer: Arc<dyn Sign>,
        validator: Arc<dyn Validate>,
        passwdless_service: PasswdlessService,
    ) -> Self {
        let config = Config::from_env();
        Self {
            user_repo: UserRepository::new(pool.clone()),
            signer,
            config,
            passwdless_service,
            validator,
        }
    }
}

pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct Config {
    pub access_token_expiry_minutes: i64,
    pub admin_pass: String,
    pub admin_user: String,
}

fn print_varerror(var: &str) -> Result<String, VarError> {
    match env::var(var) {
        Ok(r) => Ok(r),
        Err(e) => {
            tracing::error!("error in getting {} env var: {}", var, e);
            Err(e)
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let admin_user = print_varerror("ADMIN_USERNAME").unwrap();
        let admin_pass = print_varerror("ADMIN_PASSWORD").unwrap();
        Config {
            access_token_expiry_minutes: env::var("ACCESS_TOKEN_EXPIRY_MINUTES")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),

            admin_user,
            admin_pass,
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, 10)
}

/// Generate a secure random refresh token.
/// 32 bytes → 256-bit token → encoded URL-safe.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    OsRng.fill_bytes(&mut bytes);

    let token = URL_SAFE_NO_PAD.encode(&bytes);

    token
}

pub async fn create_access_token(signer: &dyn Sign, user_id: &str) -> Result<String, Error> {
    let claims = Claims::default(user_id.to_owned(), user_id.to_owned(), "*".to_string());
    signer.sign(&claims)
}
