use actix_web::{
    HttpResponse, Responder, get, post,
    web::{self, ServiceConfig},
};
use libsigners::Claims;
use serde::Deserialize;

use crate::{
    auth2::{AppState, random_token},
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

#[derive(Deserialize)]
struct AddEmailReq {
    email: String,
}

#[post("/register/start")]
async fn create(data: web::Data<AppState>, json: web::Json<AddEmailReq>) -> impl Responder {
    let user_id = match data.passwdless_service.create(json.email.clone()).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };
    HttpResponse::Created().body(user_id)
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
            eprintln!("Error in creating user: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Token pair generation
    let tp = match data
        .user_repo
        .create_token_pair(data.signer.clone(), &id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error in creating token pair: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    HttpResponse::Ok().json(LoginResponse {
        access_token: tp.access_token,
        refresh_token: tp.refresh_token,
        expires_in: 300,
    })
}

#[post("/add_email")]
async fn add(
    data: web::Data<AppState>,
    claims: web::ReqData<Claims>,
    json: web::Json<AddEmailReq>,
) -> impl Responder {
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
    let user_id = match data.passwdless_service.confirm(token).await {
        Ok(r) => r,
        Err(e) => return translate_error(e),
    };
    // Create token pair

    let tp = match data
        .user_repo
        .create_token_pair(data.signer.clone(), &user_id)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error in creating token pair: {}", e);
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
            .service(confirm_registration),
    );
}
