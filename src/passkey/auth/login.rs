use crate::passkey::{error::ErrorResponse, lock, models::UsernameRequest, state::AppState};
use actix_web::{HttpResponse, web};
use webauthn_rs::prelude::PublicKeyCredential;

pub async fn start(data: web::Data<AppState>, req: web::Json<UsernameRequest>) -> HttpResponse {
    let username = req.username.trim().to_string();

    let credentials = {
        let users = lock!(data.users);
        match users.get(&username) {
            Some(u) => u.credentials.clone(),
            None => return ErrorResponse::not_found("User not found"),
        }
    };

    if credentials.is_empty() {
        return ErrorResponse::bad_request("User has no registered passkeys");
    }

    let (options, state) = match data.webauthn.start_passkey_authentication(&credentials) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn start_passkey_authentication: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    lock!(data.auth_states).insert(username.clone(), state);

    tracing::info!("Authentication started for user: {}", username);
    HttpResponse::Ok().json(options)
}

pub async fn finish(
    data: web::Data<AppState>,
    credential: web::Json<PublicKeyCredential>,
    query: web::Query<UsernameRequest>,
) -> HttpResponse {
    let username = query.username.trim().to_string();

    let state = match lock!(data.auth_states).remove(&username) {
        Some(s) => s,
        None => return ErrorResponse::bad_request("No authentication in progress for this user"),
    };

    let result = match data
        .webauthn
        .finish_passkey_authentication(&credential, &state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn finish_passkey_authentication: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    tracing::info!(
        "Authentication successful for user: {} (verified: {})",
        username,
        result.user_verified()
    );

    HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": format!("Logged in successfully"),
        "user_verified": result.user_verified(),
    }))
}
