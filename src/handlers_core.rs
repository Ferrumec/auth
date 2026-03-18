use crate::auth2;
use crate::db::DbError;
use crate::models::{
    ChangePasswordRequest, LoginRequest, LogoutRequest, LogoutResponse,
    PasswordResetConfirmRequest, PasswordResetRequest, ProtectedResponse, RefreshRequest,
    RegisterRequest,
};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use libsigners::{Claims, Signer};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};

pub struct AuthTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

pub enum HandlerError {
    BadRequest(&'static str),
    Unauthorized(&'static str),
    UnauthorizedEmpty,
    Conflict(&'static str),
    NotFound(&'static str),
    Internal(&'static str),
    InternalEmpty,
}

pub fn protected_response(claims: Claims) -> ProtectedResponse {
    ProtectedResponse {
        user_id: claims.user_id.clone(),
        message: "Access granted to protected route".to_string(),
    }
}

pub async fn register_impl(
    state: &auth2::AppState,
    req: &RegisterRequest,
) -> Result<String, HandlerError> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(HandlerError::BadRequest(
            "Username and password are required",
        ));
    }

    if req.password.len() < 6 {
        return Err(HandlerError::BadRequest(
            "Password must be at least 6 characters",
        ));
    }

    let password_hash = auth2::hash_password(&req.password).map_err(|error| {
        eprint!(
            "Error in hashing password: {{password: {}, error: {}}}",
            req.password, error
        );
        HandlerError::InternalEmpty
    })?;

    match state
        .user_repo
        .create_user(&req.username, &password_hash)
        .await
    {
        Ok(user) => {
            println!("User created: {}", user.username);
            Ok(format!("User '{}' registered successfully", req.username))
        }
        Err(DbError::UserExists) => Err(HandlerError::Conflict("Username already exists")),
        Err(error) => {
            println!("Database error: {:?}", error);
            Err(HandlerError::Internal("Database error"))
        }
    }
}

pub async fn login_impl(
    state: &auth2::AppState,
    req: &LoginRequest,
) -> Result<AuthTokens, HandlerError> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(HandlerError::BadRequest(
            "Username and password are required",
        ));
    }

    let user = match state.user_repo.get_user_by_username(&req.username).await {
        Ok(user) => user,
        Err(DbError::UserNotFound) => {
            return Err(HandlerError::Unauthorized("Invalid credentials"));
        }
        Err(error) => {
            println!("Database error: {:?}", error);
            return Err(HandlerError::Internal("Database error"));
        }
    };

    match bcrypt::verify(&req.password, &user.password_hash) {
        Ok(true) => {}
        Ok(false) => return Err(HandlerError::Unauthorized("Invalid credentials")),
        Err(error) => {
            println!("Password verification error: {:?}", error);
            return Err(HandlerError::Internal("Failed to verify password"));
        }
    }

    state
        .user_repo
        .create_token_pair(state.signer.clone(), &user.id, "username-login".to_string())
        .await
        .map(|tokens| AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: state.config.access_token_expiry_minutes as u64 * 60,
        })
        .map_err(|error| {
            eprintln!("Error in creating token pair: {}", error);
            HandlerError::InternalEmpty
        })
}

pub async fn refresh_impl(
    state: &auth2::AppState,
    req: &RefreshRequest,
) -> Result<AuthTokens, HandlerError> {
    let refresh_token = req.refresh_token.trim();

    if refresh_token.is_empty() {
        return Err(HandlerError::BadRequest("Refresh token is required"));
    }

    let db_token = match state.user_repo.get_refresh_token(refresh_token).await {
        Ok(token) => token,
        Err(DbError::RefreshTokenNotFound) => {
            return Err(HandlerError::Unauthorized(
                "Refresh token not found or revoked",
            ));
        }
        Err(error) => {
            println!("Database error: {:?}", error);
            return Err(HandlerError::Internal("Database error"));
        }
    };

    if db_token.expires_at < Utc::now() {
        return Err(HandlerError::Unauthorized("Refresh token expired"));
    }

    if db_token.revoked {
        return Err(HandlerError::Unauthorized("Refresh token revoked"));
    }

    let user = match state.user_repo.get_user_by_id(&db_token.user_id).await {
        Ok(user) => user,
        Err(DbError::UserNotFound) => return Err(HandlerError::Unauthorized("User not found")),
        Err(error) => {
            println!("Database error: {:?}", error);
            return Err(HandlerError::Internal("Database error"));
        }
    };

    state
        .user_repo
        .revoke_refresh_token(refresh_token)
        .await
        .map_err(|error| {
            eprintln!("Error in revoking refresh token: {}", error);
            HandlerError::InternalEmpty
        })?;

    state
        .user_repo
        .create_token_pair(state.signer.clone(), &user.id, db_token.issuerer)
        .await
        .map(|tokens| AuthTokens {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: state.config.access_token_expiry_minutes as u64 * 60,
        })
        .map_err(|error| {
            eprintln!("Error in creating token pair: {}", error);
            HandlerError::InternalEmpty
        })
}

pub async fn logout_impl(
    state: &auth2::AppState,
    req: &LogoutRequest,
) -> Result<LogoutResponse, HandlerError> {
    let refresh_token = req.refresh_token.trim();

    if refresh_token.is_empty() {
        return Err(HandlerError::BadRequest("Refresh token is required"));
    }

    match state.user_repo.revoke_refresh_token(refresh_token).await {
        Ok(_) => Ok(LogoutResponse {
            message: "Logged out successfully".to_string(),
        }),
        Err(DbError::RefreshTokenNotFound) => {
            Err(HandlerError::NotFound("Refresh token not found"))
        }
        Err(error) => {
            println!("Database error: {:?}", error);
            Err(HandlerError::Internal("Database error"))
        }
    }
}

pub async fn change_password_impl(
    state: &auth2::AppState,
    user_id: &str,
    req: &ChangePasswordRequest,
) -> Result<(), HandlerError> {
    println!("attempting update password for user {}", user_id);

    if req.new_password.len() < 6 {
        return Err(HandlerError::BadRequest("Password too short"));
    }

    let user = state
        .user_repo
        .get_user_by_id(user_id)
        .await
        .map_err(|_| HandlerError::UnauthorizedEmpty)?;

    let valid = bcrypt::verify(&req.current_password, &user.password_hash).unwrap_or(false);

    if !valid {
        return Err(HandlerError::Unauthorized("Invalid current password"));
    }

    let new_hash =
        auth2::hash_password(&req.new_password).map_err(|_| HandlerError::InternalEmpty)?;

    if let Err(error) = state.user_repo.update_password(user_id, &new_hash).await {
        println!("Password update failed: {:?}", error);
        return Err(HandlerError::InternalEmpty);
    }

    println!("updated password for user {}", user_id);
    let _ = state.user_repo.revoke_user_refresh_tokens(user_id).await;

    Ok(())
}

pub async fn confirm_password_reset_impl(
    state: &auth2::AppState,
    req: &PasswordResetConfirmRequest,
) -> Result<(), HandlerError> {
    // let token_hash = auth2::hash_password(&req.token).map_err(|_| HandlerError::InternalEmpty)?;
    let mut hasher = Sha256::new();
    hasher.update(&req.token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());
    let reset = match state.user_repo.get_password_reset(&token_hash).await {
        Ok(reset) if !reset.used && reset.expires_at > Utc::now() => reset,
        _ => return Err(HandlerError::Unauthorized("Invalid or expired token")),
    };

    let new_hash =
        auth2::hash_password(&req.new_password).map_err(|_| HandlerError::InternalEmpty)?;

    let _ = state
        .user_repo
        .update_password(&reset.user_id, &new_hash)
        .await;
    let _ = state.user_repo.mark_reset_used(&reset.id).await;
    let _ = state.user_repo.revoke_refresh_token(&reset.user_id).await;

    Ok(())
}

pub async fn request_password_reset_impl(state: &auth2::AppState, req: &PasswordResetRequest) {
    if let Ok(user) = state.user_repo.get_user_by_id(&req.email).await {
        let (token, token_hash) = generate_reset_token();

        let _ = state
            .user_repo
            .create_password_reset(
                &user.id,
                &token_hash,
                Utc::now() + chrono::Duration::minutes(30),
            )
            .await;

        println!("Email sent {} : token {}", &user.id, &token);
    }
}

pub fn admin_login_impl(
    state: &auth2::AppState,
    req: &LoginRequest,
) -> Result<String, HandlerError> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(HandlerError::BadRequest(
            "Username and password are required",
        ));
    }

    if !(req.username == state.config.admin_user && req.password == state.config.admin_pass) {
        return Err(HandlerError::UnauthorizedEmpty);
    }

    let claims = Claims::for_admin(state.config.admin_user.clone());
    state
        .signer
        .sign(&claims)
        .map_err(|_| HandlerError::InternalEmpty)
}

fn generate_reset_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = format!("{:x}", hasher.finalize());

    (token, token_hash)
}
