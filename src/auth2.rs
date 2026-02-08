use crate::db::UserRepository;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libsigners::{Claims, HS256Signer, Signer};
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::SqlitePool;
use std::env::{self, VarError};

pub struct AppState {
    pub user_repo: UserRepository,
    pub signer: HS256Signer,
    pub config: JwtConfig,
}

impl AppState {
    pub fn new(pool: SqlitePool) -> Result<Self, VarError> {
        let secret = match env::var("SECRET") {
            Ok(r) => Ok(r),
            Err(e) => {
                eprintln!("env var SECRET not set");
                Err(e)
            }
        }?;
        let config = JwtConfig::from_env();
        Ok(Self {
            user_repo: UserRepository::new(pool),
            signer: HS256Signer::new(secret),
            config,
        })
    }
}

pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

pub struct JwtConfig {
    pub access_token_expiry_minutes: i64,
    pub refresh_token_expiry_days: i64,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        JwtConfig {
            access_token_expiry_minutes: env::var("ACCESS_TOKEN_EXPIRY_MINUTES")
                .unwrap_or_else(|_| "15".to_string())
                .parse()
                .unwrap_or(15),
            refresh_token_expiry_days: env::var("REFRESH_TOKEN_EXPIRY_DAYS")
                .unwrap_or_else(|_| "7".to_string())
                .parse()
                .unwrap_or(7),
        }
    }
}

pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, 10)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    bcrypt::verify(password, hash)
}

/// Generate a secure random refresh token.
/// 32 bytes → 256-bit token → encoded URL-safe.
pub fn create_refresh_token(_username: &str, _user_id: &str) -> Result<String, anyhow::Error> {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    OsRng.fill_bytes(&mut bytes);

    let token = URL_SAFE_NO_PAD.encode(&bytes);

    Ok(token)
}

pub async fn create_token_pair(
    signer: HS256Signer,
    username: &str,
    user_id: &str,
) -> Result<TokenPair, anyhow::Error> {
    let access_token = create_access_token(signer, username, user_id).await?;
    let refresh_token = create_refresh_token(username, user_id)?;

    Ok(TokenPair {
        access_token,
        refresh_token,
    })
}

pub async fn create_access_token(
    signer: HS256Signer,
    username: &str,
    user_id: &str,
) -> Result<String, anyhow::Error> {
    let claims = Claims::new(username.to_owned(), user_id.to_owned());
    signer.sign(&claims)
}
