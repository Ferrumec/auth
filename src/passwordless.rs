use std::time::Duration;

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{self, ServiceConfig},
};
use libsigners::Claims;
use moka::future::Cache;
use serde::Deserialize;
use sqlx::query_scalar;
use uuid::Uuid;

use crate::{
    auth2::{AppState, random_token},
    models::LoginResponse,
};

pub struct Caches {
    tokens: Cache<String, String>,
    accounts: Cache<String, String>,
}

impl Caches {
    pub fn new() -> Self {
        let tokens = Cache::builder()
            .time_to_live(Duration::from_mins(2))
            .build();
        let accounts = Cache::builder()
            .time_to_live(Duration::from_mins(2))
            .build();
        return Self { tokens, accounts };
    }
}

#[derive(Deserialize)]
struct AddEmailReq {
    email: String,
}

fn send_email(addr: String, text: String) {
    println!("Email sent:{{ addr: {}, message: {} }}", addr, text)
}

#[post("/register")]
async fn create(data: web::Data<AppState>, json: web::Json<AddEmailReq>) -> impl Responder {
    // Check if the email already added
    let email: Option<String> = match query_scalar("SELECT address FROM emails WHERE address = ?")
        .bind(json.email.clone())
        .fetch_optional(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error getting email address: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    // Return error email used if email exists
    match email {
        Some(_) => return HttpResponse::NotAcceptable().body("email already used"),
        None => (),
    }
    // Else, add this email to pending additions cache
    let user_id = Uuid::new_v4().to_string();
    data.caches
        .accounts
        .insert(json.email.clone(), json.email.clone())
        .await;
    HttpResponse::Created().finish()
}

#[post("/add_email")]
async fn add(
    data: web::Data<AppState>,
    claims: web::ReqData<Claims>,
    json: web::Json<AddEmailReq>,
) -> impl Responder {
    // Check if email already added
    let email: Option<String> = match query_scalar("SELECT address FROM emails WHERE user = ?")
        .bind(claims.as_user.clone())
        .fetch_optional(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error getting email address: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };

    // Return error, email used if email exists
    match email {
        Some(e) => {
            if e == json.email {
                return HttpResponse::NotAcceptable().body("email already used");
            }
        }
        None => (),
    }

    HttpResponse::Created().finish()
}

#[get("/challange/{user_id}")]
async fn challange(data: web::Data<AppState>, user_id: web::Path<String>) -> impl Responder {
    let user_id = user_id.into_inner();
    // Check the emails table for email with this user_id
    let email: Option<String> = match query_scalar("SELECT email FROM emails WHERE user = ?")
        .bind(user_id)
        .fetch_optional(&data.db)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error getting email: {}", e);
            return HttpResponse::InternalServerError().finish();
        }
    };
    // If a match is not found, return error, invalid user_id
    let email = match email {
        Some(e) => e,
        None => return HttpResponse::BadRequest().body("invalid user id"),
    };
    // Generate a random token and keep it in the pending tokens cache with the email as the key
    let token = random_token();
    data.caches
        .tokens
        .insert(token.clone(), email.clone())
        .await;
    // Email the token to the email address
    send_email(email, token);
    HttpResponse::Created().finish()
}

#[get("/confirm_link/{link}")]
async fn confirm(data: web::Data<AppState>, token: web::Path<String>) -> impl Responder {
    let token = token.into_inner();

    // Check the email for this token from the pending tokens cache
    // If no email found, return error, invalid or expired token
    let email = match data.caches.tokens.get(&token).await {
        None => return HttpResponse::Unauthorized().body("invalid or expired token"),
        Some(e) => e,
    };
    // Check the temporary accounts for the user_id associated with this email
    let user_id: String = match data.caches.accounts.remove(&email).await {
        Some(r) => match data.user_repo.create_user(&r, &random_token()).await {
            Ok(_) => r,
            Err(e) => {
                eprintln!("Error in creating user: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
        },
        None => match query_scalar::<_, String>("SELECT user FROM emails WHERE email = ?")
            .bind(email)
            .fetch_optional(&data.db)
            .await
        {
            Ok(e) => match e {
                Some(r) => r,
                None => return HttpResponse::NotFound().body("user id not found"),
            },
            Err(e) => {
                eprintln!("Error in getting user id: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
        },
    };
    // If found, create a permanent account with the user_id as username and random password

    // If no temporary account found, check the permanent accounts for the user_id associated with this email
    // in all cases so far, you should end up with a user_id
    // create an access token for this user_id
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
    // return access token and the user_id
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
            .service(challange)
            .service(add)
            .service(create),
    );
}
