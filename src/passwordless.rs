use std::time::Duration;

use actix_web::{
    HttpResponse, Responder, get, post,
    web::{self, ServiceConfig},
};
use libsigners::Claims;
use moka::future::Cache;
use serde::Deserialize;
use sqlx::{query, query_scalar};
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
            .time_to_live(Duration::from_secs(120))
            .build();
        let accounts = Cache::builder()
            .time_to_live(Duration::from_secs(120))
            .build();
        Self { tokens, accounts }
    }
}

#[derive(Deserialize)]
struct AddEmailReq {
    email: String,
}

pub async fn create_tables(db: &sqlx::Pool<sqlx::Sqlite>) -> Result<(), sqlx::Error> {
    // Create the emails table if it doesn't exist
    query(
        "CREATE TABLE IF NOT EXISTS emails (
            user TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            PRIMARY KEY (user, email)
        )",
    )
    .execute(db)
    .await?;
    Ok(())
}

/// Generate a random token and keep it in the tokens cache with the email as the key
/// Then email the token to the address
async fn release_token(email: String, tokens: &Cache<String, String>) {
    let token = random_token();
    tokens.insert(token.clone(), email.clone()).await;
    send_email(email, token);
}

fn send_email(addr: String, text: String) {
    println!("Email sent:{{ addr: {}, message: {} }}", addr, text)
}

#[post("/register/start")]
async fn create(data: web::Data<AppState>, json: web::Json<AddEmailReq>) -> impl Responder {
    // Check if the email already exists
    let email: Option<String> = match query_scalar("SELECT email FROM emails WHERE email = ?")
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
    if email.is_some() {
        return HttpResponse::NotAcceptable().body("email already used");
    }

    // Create a pending account and return the user_id so the client can request a challenge.
    let user_id = Uuid::new_v4().to_string();
    data.caches
        .accounts
        .insert(json.email.clone(), user_id.clone())
        .await;

    release_token(json.email.clone(), &data.caches.tokens).await;
    HttpResponse::Created().body(user_id)
}

#[get("/register/confirm_link/{link}")]
async fn confirm_registration(
    data: web::Data<AppState>,
    token: web::Path<String>,
) -> impl Responder {
    let token = token.into_inner();

    // Check the email for this token and invalidate the token on success
    let email = match data.caches.tokens.remove(&token).await {
        None => return HttpResponse::Unauthorized().body("invalid or expired token"),
        Some(e) => e,
    };

    // Check for a pending account (email -> user_id). If present, persist it.
    let user_id: String = match data.caches.accounts.remove(&email).await {
        Some(pending_user_id) => {
            // Ensure the user exists
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
            // Attach email to user
            if let Err(e) = query("INSERT INTO emails (user, email) VALUES (?, ?)")
                .bind(pending_user_id.clone())
                .bind(email.clone())
                .execute(&data.db)
                .await
            {
                eprintln!("Error inserting email: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
            id
        }
        None => return HttpResponse::BadRequest().body("user id not found"),
    };

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

#[post("/add_email")]
async fn add(
    data: web::Data<AppState>,
    claims: web::ReqData<Claims>,
    json: web::Json<AddEmailReq>,
) -> impl Responder {
    // Ensure this email is not already used by any account.
    let email: Option<String> = match query_scalar("SELECT email FROM emails WHERE email = ?")
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
    if email.is_some() {
        return HttpResponse::NotAcceptable().body("email already used");
    }

    // Store pending email -> user_id for confirmation.
    data.caches
        .accounts
        .insert(json.email.clone(), claims.as_user.clone())
        .await;
    HttpResponse::Created().finish()
}

#[get("/challenge/{user_id}")]
async fn challenge(data: web::Data<AppState>, user_id: web::Path<String>) -> impl Responder {
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
    send_email(email, token);
    HttpResponse::Created().finish()
}

#[get("/confirm_link/{link}")]
async fn confirm(data: web::Data<AppState>, token: web::Path<String>) -> impl Responder {
    let token = token.into_inner();

    // Check the email for this token and invalidate the token on success
    let email = match data.caches.tokens.remove(&token).await {
        None => return HttpResponse::Unauthorized().body("invalid or expired token"),
        Some(e) => e,
    };

    // Check for a pending account (email -> user_id). If present, persist it.
    let user_id: String = match data.caches.accounts.remove(&email).await {
        Some(pending_user_id) => {
            // Ensure the user exists
            if let Err(e) = data
                .user_repo
                .create_user(&pending_user_id, &random_token())
                .await
            {
                eprintln!("Error in creating user: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
            // Attach email to user
            if let Err(e) = query("INSERT INTO emails (user, email) VALUES (?, ?)")
                .bind(pending_user_id.clone())
                .bind(email.clone())
                .execute(&data.db)
                .await
            {
                eprintln!("Error inserting email: {}", e);
                return HttpResponse::InternalServerError().finish();
            }
            pending_user_id
        }
        None => match query_scalar::<_, String>("SELECT user FROM emails WHERE email = ?")
            .bind(email.clone())
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
