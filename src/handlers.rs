//! HTTP handlers.

use actix_web::cookie::{Cookie, SameSite};
use actix_web::{HttpResponse, Responder, web};
use actixutils::{Identity,Auth};
use uuid::Uuid;

use crate::domain::auth::{
    AuthService,
    errors::AuthError,
    models::{
        AuthResult, ChangePasswordCmd, ConfirmPasswordResetCmd, LogoutCmd, PasswordLoginCmd,
        RefreshCmd, RequestPasswordResetCmd,
    },
};
use crate::models::{
    ApiResponse, ChangePasswordRequest, LoginRequest, LoginResponse, LogoutRequest,
    PasswordResetConfirmRequest, PasswordResetRequest, RefreshRequest, RegisterRequest,
};

// ── Error → HTTP ──────────────────────────────────────────────────────────────

fn auth_error_to_response(e: AuthError) -> HttpResponse {
    match e {
        AuthError::MissingCredentials
        | AuthError::PasswordTooShort
        | AuthError::MissingRefreshToken => {
            HttpResponse::BadRequest().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::InvalidCredentials
        | AuthError::RefreshTokenNotFound
        | AuthError::RefreshTokenExpired
        | AuthError::InvalidToken
        | AuthError::UserNotFound => {
            HttpResponse::Unauthorized().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::UserAlreadyExists => {
            HttpResponse::Conflict().json(ApiResponse::<()>::error(&e.to_string()))
        }
        AuthError::Database(_) | AuthError::Bcrypt(_) | AuthError::TokenSigning(_) => {
            tracing::error!("Internal auth error: {:?}", e);
            HttpResponse::InternalServerError().finish()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn auth_result_to_login_response(r: AuthResult) -> LoginResponse {
    LoginResponse {
        access_token: r.access_token,
        refresh_token: r.refresh_token,
        expires_in: r.expires_in,
    }
}

pub fn access_cookie(token: &str) -> Cookie<'static> {
    Cookie::build("access_token", token.to_owned())
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .finish()
}

pub async fn register(
    svc: web::Data<AuthService>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    match svc.register(&req.username, &req.password).await {
        Ok(_user_id) => {
            HttpResponse::Created().json(ApiResponse::success((), "User registered successfully"))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn login(svc: web::Data<AuthService>, req: web::Json<LoginRequest>) -> impl Responder {
    let cmd = PasswordLoginCmd {
        username: req.username.clone(),
        password: req.password.clone(),
    };
    match svc.password_login(cmd).await {
        Ok(result) => {
            let cookie = access_cookie(&result.access_token);
            HttpResponse::Ok().cookie(cookie).json(ApiResponse::success(
                auth_result_to_login_response(result),
                "Login successful",
            ))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn refresh(
    svc: web::Data<AuthService>,
    req: web::Json<RefreshRequest>,
) -> impl Responder {
    let cmd = RefreshCmd {
        refresh_token: req.refresh_token.clone(),
    };
    match svc.refresh(cmd).await {
        Ok(result) => {
            let cookie = access_cookie(&result.access_token);
            HttpResponse::Ok().cookie(cookie).json(ApiResponse::success(
                auth_result_to_login_response(result),
                "Refresh successful",
            ))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn logout(svc: web::Data<AuthService>, req: web::Json<LogoutRequest>) -> impl Responder {
    let cmd = LogoutCmd {
        refresh_token: req.refresh_token.clone(),
    };
    match svc.logout(cmd).await {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::success((), "Logged out successfully")),
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn change_password(
    svc: web::Data<AuthService>,
    // The user_id comes from a validated JWT via your existing middleware.
    user_id: web::Path<Uuid>,
    req: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    let user_id = user_id.into_inner();
    let cmd = ChangePasswordCmd {
        user_id,
        current_password: req.current_password.clone(),
        new_password: req.new_password.clone(),
    };
    match svc.change_password(cmd).await {
        Ok(()) => {
            HttpResponse::Ok().json(ApiResponse::success((), "Password changed successfully"))
        }
        Err(e) => auth_error_to_response(e),
    }
}

pub async fn request_password_reset(
    svc: web::Data<AuthService>,
    req: web::Json<PasswordResetRequest>,
) -> impl Responder {
    // Always return 200 regardless of whether the email was found.
    svc.request_password_reset(RequestPasswordResetCmd {
        email: req.email.clone(),
    })
    .await;
    HttpResponse::Ok().json(ApiResponse::success(
        (),
        "If the account exists, a reset link has been sent",
    ))
}

pub async fn confirm_password_reset(
    svc: web::Data<AuthService>,
    req: web::Json<PasswordResetConfirmRequest>,
) -> impl Responder {
    let cmd = ConfirmPasswordResetCmd {
        token: req.token.clone(),
        new_password: req.new_password.clone(),
    };
    match svc.confirm_password_reset(cmd).await {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::success((), "Password reset successful")),
        Err(e) => auth_error_to_response(e),
    }
}

/// Protected route: validates the JWT from the middleware and echoes the
/// user ID back. Kept on `AppState` so the existing `actixutils::Access`
/// extractor + `libsigners` validator continue to work unchanged.
pub async fn protected(Auth(id): Auth<Identity>) -> impl Responder {
    HttpResponse::Ok().json(ApiResponse::success(
        crate::models::ProtectedResponse {
            user_id: id.sub,
            message: "Access granted to protected route".to_string(),
        },
        "Protected data retrieved successfully",
    ))
}
