mod auth;
mod config;
mod error;
mod models;
mod state;

use actix_web::{App, HttpResponse, HttpServer, web};
use state::AppState;

use crate::lock;

// ── Debug-only: list registered users ────────────────────────────────────────

async fn list_users(data: web::Data<AppState>) -> HttpResponse {
    let users = lock!(data.users);
    let names: Vec<&str> = users.keys().map(String::as_str).collect();
    HttpResponse::Ok().json(serde_json::json!({ "users": names }))
}
