use crate::{
    auth2::AppState,
    handlers,
    passwordless::{config, create_tables},
};
use actix_web::web::{self, ServiceConfig};
use auth_middleware::Auth;
use sqlx::{Error, sqlite::SqlitePoolOptions};
use std::env::{self, VarError};

#[derive(Clone)]
pub struct AuthModule {
    state: web::Data<AppState>,
}

pub enum SetupError {
    Db(Error),
    Var(VarError),
}

impl AuthModule {
    pub async fn new() -> Result<Self, SetupError> {
        // Database connection
        let database_url =
            env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:auth.db?mode=rwc".to_string());

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .map_err(SetupError::Db)?;
        let app_state = AppState::new(pool.clone()).map_err(SetupError::Var)?;
        let _ = create_tables(&pool).await.map_err(SetupError::Db);
        let _ = app_state.user_repo.init().await.map_err(SetupError::Db);
        Ok(Self {
            state: web::Data::new(app_state),
        })
    }
    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
                .app_data(self.state.clone())
                .service(
                    web::scope("/auth")
                        .route("/register", web::post().to(handlers::register))
                        .route("/login", web::post().to(handlers::login))
                        .route("/refresh", web::post().to(handlers::refresh))
                        .route("/logout", web::post().to(handlers::logout))
                        .route(
                            "/request_password_reset",
                            web::post().to(handlers::request_password_reset),
                        )
                        .route(
                            "/confirm_password_reset",
                            web::post().to(handlers::confirm_password_reset),
                        )
                        .route("/admin/login", web::post().to(handlers::admin_login)),
                )
                // 🔐 PROTECTED ROUTES
                .service(
                    web::scope("/me")
                        .wrap(Auth)
                        .route("/protected", web::get().to(handlers::protected))
                        .route(
                            "/change_password",
                            web::post().to(handlers::change_password),
                        ),
                )
                .service(web::scope("/passwordless").configure(config)),
        );
    }
}
