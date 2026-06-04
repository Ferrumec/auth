use crate::{
    auth2::AppState,
    handlers, //passkey,
    passwdless::config,
    user_id::username2userid,
};
use actix_web::web::{self, Data, ServiceConfig};
use actixutils::{Identity, Sign, Validate};
use event_stream::EventStream;
use sqlx::{Error, Pool, Sqlite};
use std::{env::VarError, sync::Arc};

#[derive(Clone)]
pub struct AuthModule {
    state: web::Data<AppState>,
}

#[derive(Debug)]
pub enum SetupError {
    Db(Error),
    Var(VarError),
}

impl ToString for SetupError {
    fn to_string(&self) -> String {
        match self {
            SetupError::Db(error) => error.to_string(),
            SetupError::Var(var_error) => var_error.to_string(),
        }
    }
}

impl From<VarError> for SetupError {
    fn from(value: VarError) -> Self {
        SetupError::Var(value)
    }
}

impl From<Error> for SetupError {
    fn from(value: Error) -> Self {
        SetupError::Db(value)
    }
}

impl Validate<Identity> for AppState {
    fn validate(&self, token: &str) -> anyhow::Result<Identity> {
        self.validator.validate(token)
    }
}

impl AuthModule {
    pub async fn new(
        pool: Pool<Sqlite>,
        signer: Arc<dyn Sign<Identity>>,
        validator: Arc<dyn Validate<Identity>>,
        es: Arc<dyn EventStream>,
    ) -> Self {
        let app_state = AppState::new(pool.clone(), signer, validator, es);
        Self {
            state: web::Data::new(app_state),
        }
    }
    pub fn config(&self, cfg: &mut ServiceConfig, namespace: &str) {
        cfg.service(
            web::scope(namespace)
                .app_data(Data::new(self.state.auth_service.clone()))
                .service(username2userid)
                //.service(passkey::routes("/passkey"))
                .service(
                    web::scope("/auth")
                        .route("/register", web::post().to(handlers::register))
                        .route("/login/email", web::post().to(handlers::login))
                        .route("/login/username", web::post().to(handlers::username_login))
                        .route("/refresh", web::post().to(handlers::refresh))
                        .route("/logout", web::post().to(handlers::logout))
                        .route(
                            "/request_password_reset",
                            web::post().to(handlers::request_password_reset),
                        )
                        .route(
                            "/confirm_password_reset",
                            web::post().to(handlers::confirm_password_reset),
                        ),
                )
                // 🔐 PROTECTED ROUTES
                .service(
                    web::scope("/me")
                        .route("/account", web::get().to(handlers::protected))
                        .route(
                            "/change_password",
                            web::post().to(handlers::change_password),
                        ),
                )
                .service(web::scope("/passwordless").configure(config)),
            //.configure(pubkey::configure),
        );
    }
}
