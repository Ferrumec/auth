use crate::passkey::{
    error::ErrorResponse,
    lock,
    models::{User, UsernameRequest},
    state::AppState,
};
use actix_web::{HttpResponse, web};
use webauthn_rs::prelude::RegisterPublicKeyCredential;

pub async fn start(data: web::Data<AppState>, req: web::Json<UsernameRequest>) -> HttpResponse {
    let username = req.username.trim().to_string();

    if username.len() < 3 {
        return ErrorResponse::bad_request("Username must be at least 3 characters");
    }

    let mut users = lock!(data.users);

    let user = users
        .entry(username.clone())
        .or_insert_with(|| User::new(&username));

    let (options, state) = match data.webauthn.start_passkey_registration(
        user.id,
        &user.username,
        &user.username,
        None,
    ) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("WebAuthn start_passkey_registration: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    // Drop users lock before acquiring reg_states
    drop(users);

    lock!(data.reg_states).insert(username.clone(), state);

    tracing::info!("Registration started for user: {}", username);
    HttpResponse::Ok().json(options)
}

pub async fn finish(
    data: web::Data<AppState>,
    credential: web::Json<RegisterPublicKeyCredential>,
    query: web::Query<UsernameRequest>,
) -> HttpResponse {
    let username = query.username.trim().to_string();

    let state = match lock!(data.reg_states).remove(&username) {
        Some(s) => s,
        None => return ErrorResponse::bad_request("No registration in progress for this user"),
    };

    let passkey = match data
        .webauthn
        .finish_passkey_registration(&credential, &state)
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("WebAuthn finish_passkey_registration: {}", e);
            return ErrorResponse::bad_request(format!("WebAuthn error: {}", e));
        }
    };

    let mut users = lock!(data.users);
    match users.get_mut(&username) {
        Some(user) => {
            user.credentials.push(passkey);
            tracing::info!("Passkey registered for user: {}", username);
            HttpResponse::Ok().json(serde_json::json!({
                "status": "success",
                "message": "Passkey registered"
            }))
        }
        None => ErrorResponse::not_found("User not found"),
    }
}
