use crate::auth2::{self, AppState};
use crate::handlers_core::{
    HandlerError, admin_login_impl, change_password_impl, confirm_password_reset_impl, login_impl,
    logout_impl, protected_response, refresh_impl, register_impl, request_password_reset_impl,
};
use crate::models::{
    ApiResponse, ChangePasswordRequest, LoginRequest, LoginResponse, LogoutRequest,
    PasswordResetConfirmRequest, PasswordResetRequest, RefreshRequest, RegisterRequest,
};
use actix_web::cookie::Cookie;
use actix_web::{HttpResponse, Responder, web};
use actixutils::Access;
use libsigners::Claims;
use serde_json::json;

impl HandlerError {
    fn into_http_response(self) -> HttpResponse {
        match self {
            Self::BadRequest(message) => {
                HttpResponse::BadRequest().json(ApiResponse::<()>::error(message))
            }
            Self::Unauthorized(message) => {
                HttpResponse::Unauthorized().json(ApiResponse::<()>::error(message))
            }
            Self::UnauthorizedEmpty => HttpResponse::Unauthorized().finish(),
            Self::Conflict(message) => {
                HttpResponse::Conflict().json(ApiResponse::<()>::error(message))
            }
            Self::NotFound(message) => {
                HttpResponse::NotFound().json(ApiResponse::<()>::error(message))
            }
            Self::Internal(message) => {
                HttpResponse::InternalServerError().json(ApiResponse::<()>::error(message))
            }
            Self::InternalEmpty => HttpResponse::InternalServerError().finish(),
        }
    }
}

pub async fn register(
    data: web::Data<auth2::AppState>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    match register_impl(data.get_ref(), &req).await {
        Ok(message) => HttpResponse::Created().json(ApiResponse::success((), &message)),
        Err(error) => error.into_http_response(),
    }
}

pub async fn login(
    data: web::Data<auth2::AppState>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    match login_impl(data.get_ref(), &req).await {
        Ok(tokens) => HttpResponse::Ok()
            .cookie(access_cookie(tokens.access_token.clone()))
            .json(ApiResponse::success(
                LoginResponse {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    expires_in: tokens.expires_in,
                },
                "Login successful",
            )),
        Err(error) => error.into_http_response(),
    }
}

pub async fn protected(claims: Access, state: web::Data<AppState>) -> impl Responder {
    if let Ok(claims) = state.signer.validate(&claims.token) {
        HttpResponse::Ok().json(ApiResponse::success(
            protected_response(claims),
            "Protected data retrieved successfully",
        ))
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

pub async fn refresh(
    data: web::Data<auth2::AppState>,
    req: web::Json<RefreshRequest>,
) -> impl Responder {
    match refresh_impl(data.get_ref(), &req).await {
        Ok(tokens) => HttpResponse::Ok()
            .cookie(access_cookie(tokens.access_token.clone()))
            .json(ApiResponse::success(
                LoginResponse {
                    access_token: tokens.access_token,
                    refresh_token: tokens.refresh_token,
                    expires_in: tokens.expires_in,
                },
                "Refresh successful",
            )),
        Err(error) => error.into_http_response(),
    }
}

pub async fn logout(
    data: web::Data<auth2::AppState>,
    req: web::Json<LogoutRequest>,
) -> impl Responder {
    match logout_impl(data.get_ref(), &req).await {
        Ok(response) => {
            HttpResponse::Ok().json(ApiResponse::success(response, "Logout successful"))
        }
        Err(error) => error.into_http_response(),
    }
}

pub async fn change_password(
    data: web::Data<auth2::AppState>,
    access: Access,
    req: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    if let Ok(claims) = data.signer.validate(&access.token) {
        match change_password_impl(data.get_ref(), claims.user_id.as_str(), &req).await {
            Ok(()) => {
                HttpResponse::Ok().json(ApiResponse::success((), "Password changed successfully"))
            }
            Err(error) => error.into_http_response(),
        }
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

pub async fn confirm_password_reset(
    data: web::Data<auth2::AppState>,
    req: web::Json<PasswordResetConfirmRequest>,
) -> impl Responder {
    match confirm_password_reset_impl(data.get_ref(), &req).await {
        Ok(()) => HttpResponse::Ok().json(ApiResponse::success((), "Password reset successful")),
        Err(error) => error.into_http_response(),
    }
}

pub async fn request_password_reset(
    data: web::Data<auth2::AppState>,
    req: web::Json<PasswordResetRequest>,
) -> impl Responder {
    let _ = request_password_reset_impl(data.get_ref(), &req).await;

    HttpResponse::Ok().json(ApiResponse::success(
        (),
        "If the account exists, a reset link has been sent",
    ))
}

pub async fn admin_login(
    data: web::Data<auth2::AppState>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    match admin_login_impl(data.get_ref(), &req) {
        Ok(token) => HttpResponse::Ok()
            .cookie(access_cookie(token.clone()))
            .json(json!({ "token": token })),
        Err(error) => error.into_http_response(),
    }
}

pub fn access_cookie(token: String) -> Cookie<'static> {
    Cookie::build("access_token", token)
        .path("/")
        .http_only(true)
        .secure(true)
        .domain("localhost")
        .finish()
}
