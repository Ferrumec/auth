pub mod login;
pub mod register;

use actix_web::web;

/// Mount all passkey routes under a given scope prefix.
/// In main, use: `App::new().service(auth::routes("/auth"))`
pub fn routes(prefix: &str) -> actix_web::Scope {
    web::scope(prefix)
        .route("/register/start",  web::post().to(register::start))
        .route("/register/finish", web::post().to(register::finish))
        .route("/login/start",     web::post().to(login::start))
        .route("/login/finish",    web::post().to(login::finish))
}

