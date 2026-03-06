use crate::auth2;
use crate::db::DbError;
use crate::models::{
    ApiResponse, ChangePasswordRequest, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse,
    PasswordResetConfirmRequest, PasswordResetRequest, ProtectedResponse, RefreshRequest, RegisterRequest,
};
use actix_web::cookie::Cookie;
use actix_web::{HttpResponse, Responder, web};
use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use libsigners::{Claims, Signer};
use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use sha2::{Digest, Sha256};
pub async fn register(
    data: web::Data<auth2::AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Username and password are required",
        ));
    }

    if req.password.len() < 6 {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Password must be at least 6 characters",
        ));
    }
    // Hash password
    let password_hash = match auth2::hash_password(&req.password) {
        Ok(hash) => hash,
        Err(e) => {
            eprint!(
                "Error in hashing password: {{password: {}, error: {}}}",
                req.password, e
            );
            return HttpResponse::InternalServerError().finish();
        }
    };
    // Create user in database
    match data
        .user_repo
        .create_user(&req.username, &password_hash)
        .await
    {
        Ok(user) => {
            println!("User created: {}", user.username);
            HttpResponse::Created().json(ApiResponse::success(
                (),
                &format!("User '{}' registered successfully", req.username),
            ))
        }
        Err(DbError::UserExists) => {
            HttpResponse::Conflict().json(ApiResponse::<()>::error("Username already exists"))
        }
        Err(e) => {
            println!("Database error: {:?}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"))
        }
    }
}

fn access_cookie(token: String) -> Cookie<'static> {
    Cookie::build("access_token", token.clone())
        .path("/")
        .http_only(true)
        .secure(true)
        .domain("localhost")
        .finish()
}

pub async fn login(
    data: web::Data<auth2::AppState>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Username and password are required",
        ));
    }

    // Get user from database
    let user = match data.user_repo.get_user_by_username(&req.username).await {
        Ok(user) => user,
        Err(DbError::UserNotFound) => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Invalid credentials"));
        }
        Err(e) => {
            println!("Database error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Verify password
    match bcrypt::verify(&req.password, &user.password_hash) {
        Ok(is_valid) => {
            if !is_valid {
                return HttpResponse::Unauthorized()
                    .json(ApiResponse::<()>::error("Invalid credentials"));
            }
        }
        Err(e) => {
            println!("Password verification error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to verify password"));
        }
    }

    match data
        .user_repo
        .create_token_pair(data.signer.clone(), &user.id)
        .await
    {
        Ok(tp) => {
            HttpResponse::Ok()
                .cookie(access_cookie(tp.access_token.clone()))
                .json(ApiResponse::success(
                    LoginResponse {
                        access_token: tp.access_token,
                        refresh_token: tp.refresh_token,
                        expires_in: data.config.access_token_expiry_minutes as u64 * 60, // Convert to seconds
                    },
                    "Login successful",
                ))
        }
        Err(e) => {
            eprintln!("Error in creating token pair: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn protected(claims: web::ReqData<Claims>) -> impl Responder {
    let claims = claims.into_inner();
    HttpResponse::Ok().json(ApiResponse::success(
        ProtectedResponse {
            user_id: claims.user_id.clone(),
            message: "Access granted to protected route".to_string(),
        },
        "Protected data retrieved successfully",
    ))
}

pub async fn refresh(
    data: web::Data<auth2::AppState>,
    req: web::Json<RefreshRequest>,
) -> impl Responder {
    let refresh_token = req.refresh_token.trim();

    if refresh_token.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Refresh token is required"));
    }

    // Check if refresh token exists and is valid in database
    let db_token = match data.user_repo.get_refresh_token(refresh_token).await {
        Ok(token) => token,
        Err(DbError::RefreshTokenNotFound) => {
            return HttpResponse::Unauthorized().json(ApiResponse::<()>::error(
                "Refresh token not found or revoked",
            ));
        }
        Err(e) => {
            println!("Database error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Check if token is expired
    if db_token.expires_at < chrono::Utc::now() {
        return HttpResponse::Unauthorized()
            .json(ApiResponse::<()>::error("Refresh token expired"));
    }

    // Check if token is revoked
    if db_token.revoked {
        return HttpResponse::Unauthorized()
            .json(ApiResponse::<()>::error("Refresh token revoked"));
    }

    // Get user to verify they still exist
    let user = match data.user_repo.get_user_by_id(&db_token.user_id).await {
        Ok(user) => user,
        Err(DbError::UserNotFound) => {
            return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("User not found"));
        }
        Err(e) => {
            println!("Database error: {:?}", e);
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Database error"));
        }
    };

    // Revoke the old refresh token (optional: you can keep it or revoke it)
    // For better security, revoke the old token (one-time use)
    if let Err(e) = data.user_repo.revoke_refresh_token(refresh_token).await {
        println!("Failed to revoke old refresh token: {:?}", e);
        // Continue anyway - the token will still expire
    }

    // Create new token pair
    match data
        .user_repo
        .create_token_pair(data.signer.clone(), &user.id)
        .await
    {
        Ok(tp) => {
            HttpResponse::Ok()
                .cookie(access_cookie(tp.access_token.clone()))
                .json(ApiResponse::success(
                    LoginResponse {
                        access_token: tp.access_token,
                        refresh_token: tp.refresh_token,
                        expires_in: data.config.access_token_expiry_minutes as u64 * 60, // Convert to seconds
                    },
                    "Refresh successful",
                ))
        }
        Err(e) => {
            eprintln!("Error in creating token pair: {}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

pub async fn logout(
    data: web::Data<auth2::AppState>,
    req: web::Json<LogoutRequest>,
) -> impl Responder {
    let refresh_token = req.refresh_token.trim();

    if refresh_token.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Refresh token is required"));
    }

    // Revoke the refresh token
    match data.user_repo.revoke_refresh_token(refresh_token).await {
        Ok(_) => {
            let response = LogoutResponse {
                message: "Logged out successfully".to_string(),
            };

            HttpResponse::Ok().json(ApiResponse::success(response, "Logout successful"))
        }
        Err(DbError::RefreshTokenNotFound) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Refresh token not found"))
        }
        Err(e) => {
            println!("Database error: {:?}", e);
            HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"))
        }
    }
}

pub async fn change_password(
    data: web::Data<auth2::AppState>,
    claims: web::ReqData<Claims>,
    req: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    println!("attempting update password for user {}", &claims.user_id);
    if req.new_password.len() < 6 {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Password too short"));
    }

    let user_id = &claims.user_id;

    let user = match data.user_repo.get_user_by_id(&user_id).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().finish(),
    };

    let valid = bcrypt::verify(&req.current_password, &user.password_hash).unwrap_or(false);

    if !valid {
        return HttpResponse::Unauthorized()
            .json(ApiResponse::<()>::error("Invalid current password"));
    }

    let new_hash = match auth2::hash_password(&req.new_password) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().finish(),
    };

    if let Err(e) = data.user_repo.update_password(&user_id, &new_hash).await {
        println!("Password update failed: {:?}", e);
        return HttpResponse::InternalServerError().finish();
    }
    println!("updated password for user {}", &user_id);
    // 🔥 revoke all sessions
    let _ = data.user_repo.revoke_refresh_token(&user_id).await;

    HttpResponse::Ok().json(ApiResponse::success((), "Password changed successfully"))
}

pub async fn confirm_password_reset(
    data: web::Data<auth2::AppState>,
    req: web::Json<PasswordResetConfirmRequest>,
) -> impl Responder {
    let token_hash = auth2::hash_password(&req.token).unwrap();

    let reset = match data.user_repo.get_password_reset(&token_hash).await {
        Ok(r) if !r.used && r.expires_at > Utc::now() => r,
        _ => {
            return HttpResponse::Unauthorized()
                .json(ApiResponse::<()>::error("Invalid or expired token"));
        }
    };

    let new_hash = auth2::hash_password(&req.new_password).unwrap();

    let _ = data
        .user_repo
        .update_password(&reset.user_id, &new_hash)
        .await;
    let _ = data.user_repo.mark_reset_used(&reset.id).await;

    // 🔥 revoke all sessions
    let _ = data.user_repo.revoke_refresh_token(&reset.user_id).await;

    HttpResponse::Ok().json(ApiResponse::success((), "Password reset successful"))
}

pub async fn request_password_reset(
    data: web::Data<auth2::AppState>,
    req: web::Json<PasswordResetRequest>,
) -> impl Responder {
    if let Ok(user) = data.user_repo.get_user_by_id(&req.email).await {
        let (token, token_hash) = generate_reset_token();

        let _ = data
            .user_repo
            .create_password_reset(
                &user.id,
                &token_hash,
                chrono::Utc::now() + chrono::Duration::minutes(30),
            )
            .await;

        // send email
        //data.mailer.send_reset_email(&user.email, &token);
        println!("Email sent {} : token {}", &user.id, &token);
    }

    // Always success
    HttpResponse::Ok().json(ApiResponse::success(
        (),
        "If the account exists, a reset link has been sent",
    ))
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

pub async fn admin_login(
    data: web::Data<auth2::AppState>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    // Validate input
    if req.username.is_empty() || req.password.is_empty() {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            "Username and password are required",
        ));
    }

    // Validate admin username and password
    if !(req.username == data.config.admin_user && req.password == data.config.admin_pass) {
        return HttpResponse::Unauthorized().finish();
    }

    let claims = Claims::for_admin(data.config.admin_user.clone());
    HttpResponse::Ok().json(json!({"token":data.signer.sign(&claims).unwrap()}))
}
