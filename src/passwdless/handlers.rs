use actix_web::{
    HttpResponse, Responder, ResponseError, get, post,
    web::{self, ServiceConfig},
};
use actixutils::Access;
use serde::Deserialize;
use std::fmt::Display;

use crate::{
    auth2::{AppState, random_token},
    handlers::access_cookie,
    models::LoginResponse,
    passwdless::PasswdlessError,
};

fn translate_error(error: PasswdlessError) -> HttpResponse {
    match error {
        PasswdlessError::DbError => HttpResponse::InternalServerError().finish(),
        PasswdlessError::EmailUsed => HttpResponse::Conflict().body("Email used"),
        PasswdlessError::BadToken => HttpResponse::BadRequest().body("Invalid or expired token"),
        PasswdlessError::UserNotFound => HttpResponse::NotFound().body("User not found"),
    }
}
impl Display for PasswdlessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match self {
            PasswdlessError::DbError => "service unavailable, please try again later",
            PasswdlessError::EmailUsed => "Email used",
            PasswdlessError::BadToken => "Invalid or expired token",
            PasswdlessError::UserNotFound => "User not found",
        };
        write!(f, "{}", r)
    }
}
impl ResponseError for PasswdlessError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        translate_error(self.clone()).status()
    }

    fn error_response(&self) -> HttpResponse<actix_web::body::BoxBody> {
        return translate_error(self.clone());
    }
}

#[derive(Deserialize)]
struct AddEmailReq {
    email: String,
}

#[derive(Deserialize)]
struct Token {
    token: u32,
}

#[post("/register/start")]
async fn create(data: web::Data<AppState>, json: web::Json<AddEmailReq>) -> impl Responder {
    data.passwdless_service.create(json.email.clone()).await
}

#[get("/register/confirm_link/{link}")]
async fn confirm_registration(
    data: web::Data<AppState>,
    token: web::Path<String>,
) -> impl Responder {
    let pending_user_id = match data
        .passwdless_service
        .confirm_registration(token.into_inner())
        .await
    {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    // Create user
    let id = match data
        .user_repo
        .create_user(&pending_user_id, &random_token())
        .await
    {
        Ok(u) => u.id,
        Err(e) => {
            tracing::warn!("Error in creating user: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Token pair generation
    let tp = match data
        .user_repo
        .create_token_pair(&*data.signer, &id, "confirm_registration".to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Error in creating token pair: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let cookie = access_cookie(tp.access_token.clone());
    HttpResponse::Ok().cookie(cookie).json(LoginResponse {
        access_token: tp.access_token,
        refresh_token: tp.refresh_token,
        expires_in: 300,
    })
}

#[post("/register/confirm_token/")]
async fn confirm_registration_token(
    data: web::Data<AppState>,
    token: web::Json<Token>,
) -> impl Responder {
    let pending_user_id = match data
        .passwdless_service
        .confirm_registration_token(token.token)
        .await
    {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };

    // Create user
    let id = match data
        .user_repo
        .create_user(&pending_user_id, &random_token())
        .await
    {
        Ok(u) => u.id,
        Err(e) => {
            tracing::warn!("Error in creating user: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Token pair generation
    let tp = match data
        .user_repo
        .create_token_pair(&*data.signer, &id, "confirm_registration".to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Error in creating token pair: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    let cookie = access_cookie(tp.access_token.clone());
    HttpResponse::Ok().cookie(cookie).json(LoginResponse {
        access_token: tp.access_token,
        refresh_token: tp.refresh_token,
        expires_in: 300,
    })
}

#[post("/add_email")]
async fn add(
    data: web::Data<AppState>,
    claims: Access,
    json: web::Json<AddEmailReq>,
) -> impl Responder {
    let claims = data.signer.validate(&claims.token).unwrap();
    match data
        .passwdless_service
        .add(json.email.clone(), claims.as_user.clone())
        .await
    {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };
    HttpResponse::Created().finish()
}

#[get("/challenge/{user_id}")]
async fn challenge(data: web::Data<AppState>, user_id: web::Path<String>) -> impl Responder {
    match data
        .passwdless_service
        .challenge(user_id.into_inner())
        .await
    {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    }
    HttpResponse::Created().finish()
}

#[get("/confirm_link/{link}")]
async fn confirm(data: web::Data<AppState>, token: web::Path<String>) -> impl Responder {
    let token = token.into_inner();
    let user_id = match data.passwdless_service.confirm_link(token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };
    // Create token pair

    let tp = match data
        .user_repo
        .create_token_pair(&*data.signer, &user_id, "confirm".to_string())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Error in creating token pair: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    HttpResponse::Ok().json(LoginResponse {
        access_token: tp.access_token,
        refresh_token: tp.refresh_token,
        expires_in: 300,
    })
}

pub fn config(cfg: &mut ServiceConfig) {
    cfg.service(
        web::scope("")
            .service(confirm)
            .service(challenge)
            .service(add)
            .service(create)
            .service(confirm_registration)
            .service(confirm_registration_token),
    );
}
