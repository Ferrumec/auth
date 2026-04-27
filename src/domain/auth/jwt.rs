//! JWT utilities.
//!
//! Access tokens are short-lived JWTs (default 15 minutes).
//! Refresh tokens are **not** JWTs – they are opaque random strings
//! stored (hashed) in the database.

use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Token is expired")]
    Expired,
    #[error("Token signature is invalid")]
    InvalidSignature,
    #[error("Token is malformed")]
    Malformed,
    #[error("JWT encoding failed: {0}")]
    Encoding(String),
}

impl From<jsonwebtoken::errors::Error> for JwtError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => JwtError::Expired,
            ErrorKind::InvalidSignature
            | ErrorKind::InvalidAlgorithmName
            | ErrorKind::InvalidKeyFormat => JwtError::InvalidSignature,
            _ => JwtError::Malformed,
        }
    }
}

// ── Claims ────────────────────────────────────────────────────────────────────

/// The payload embedded in every access token.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject – the user's UUID.
    pub sub: String,
    /// Issued-at (Unix seconds).
    pub iat: usize,
    /// Expiry (Unix seconds).
    pub exp: usize,
}

// ── Config ────────────────────────────────────────────────────────────────────

/// JWT configuration loaded once at startup from environment variables.
///
/// Required env vars:
///   `JWT_SECRET`                 – HS256 signing key (min 32 chars recommended)
///   `ACCESS_TOKEN_EXPIRY_MINUTES`– optional, defaults to 15
pub struct JwtConfig {
    pub secret: String,
    pub access_token_expiry_minutes: i64,
}

impl JwtConfig {
    /// Load from environment. Panics at startup if `JWT_SECRET` is absent,
    /// which is intentional – a service with no secret must not start.
    pub fn from_env() -> Self {
        let secret = std::env::var("JWT_SECRET")
            .expect("JWT_SECRET env var is required");

        assert!(
            secret.len() >= 32,
            "JWT_SECRET must be at least 32 characters"
        );

        let expiry = std::env::var("ACCESS_TOKEN_EXPIRY_MINUTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15);

        Self {
            secret,
            access_token_expiry_minutes: expiry,
        }
    }

    /// Create a new JwtConfig with explicit values (useful for testing)
    pub fn new(secret: String, access_token_expiry_minutes: i64) -> Self {
        assert!(
            secret.len() >= 32,
            "JWT_SECRET must be at least 32 characters"
        );
        
        Self {
            secret,
            access_token_expiry_minutes,
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Sign a new access token for `user_id`.
///
/// Sets `iat` to now and `exp` to now + `expiry_minutes`.
pub fn generate_access_token(user_id: &str, cfg: &JwtConfig) -> Result<String, JwtError> {
    let now = Utc::now().timestamp() as usize;
    let exp = now + (cfg.access_token_expiry_minutes as usize) * 60;

    let claims = Claims {
        sub: user_id.to_owned(),
        iat: now,
        exp,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(cfg.secret.as_bytes()),
    )
    .map_err(|e| JwtError::Encoding(e.to_string()))
}

/// Verify an access token and return its claims.
///
/// Rejects expired tokens and invalid signatures.
pub fn verify_access_token(token: &str, cfg: &JwtConfig) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true; // enforce `exp`

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(cfg.secret.as_bytes()),
        &validation,
    )?;

    Ok(data.claims)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg() -> JwtConfig {
        JwtConfig::new(
            "a-test-secret-that-is-long-enough!!".to_owned(),
            15,
        )
    }

    #[test]
    fn round_trip() {
        let cfg = test_cfg();
        let token = generate_access_token("user-123", &cfg).unwrap();
        let claims = verify_access_token(&token, &cfg).unwrap();
        assert_eq!(claims.sub, "user-123");
    }

    #[test]
    fn rejects_expired_token() {
        // Build a token that expired 1 second ago.
        let cfg = test_cfg();
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "user-123".to_owned(),
            iat: now - 10,
            exp: now - 1, // already expired
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(cfg.secret.as_bytes()),
        )
        .unwrap();

        let err = verify_access_token(&token, &cfg).unwrap_err();
        assert!(matches!(err, JwtError::Expired));
    }

    #[test]
    fn rejects_wrong_secret() {
        let cfg = test_cfg();
        let token = generate_access_token("user-123", &cfg).unwrap();

        let bad_cfg = JwtConfig::new(
            "completely-different-secret-value!!".to_owned(),
            15,
        );
        let err = verify_access_token(&token, &bad_cfg).unwrap_err();
        assert!(matches!(err, JwtError::InvalidSignature));
    }

    #[test]
    fn test_custom_expiry() {
        let cfg = JwtConfig::new(
            "a-test-secret-that-is-long-enough!!".to_owned(),
            5, // 5 minutes
        );
        let token = generate_access_token("user-456", &cfg).unwrap();
        let claims = verify_access_token(&token, &cfg).unwrap();
        
        // Verify the expiry is approximately 5 minutes from now
        let now = Utc::now().timestamp() as usize;
        let expected_exp = now + 300; // 5 minutes in seconds
        assert!(claims.exp >= expected_exp - 5 && claims.exp <= expected_exp + 5);
    }
}
