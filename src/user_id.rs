use actix_web::{HttpResponse, Responder, get, web};

use crate::auth2::AppState;
#[get("/user_id/username/{username}")]
pub async fn username2userid(
    state: web::Data<AppState>,
    username: web::Path<String>,
) -> impl Responder {
    let username = username.into_inner();
    match state.user_repo.get_user_by_username(&username).await {
        Ok(r) => HttpResponse::Ok().body(r.id),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}
