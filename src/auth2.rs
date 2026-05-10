use crate::domain::auth::service::AuthService;
use crate::domain::auth::token::generate_raw_token;
use crate::passwdless::PasswdlessService;
use actixutils::Identity;
use actixutils::{Sign, Validate};
use event_stream::EventStream;
use sqlx::Pool;
use std::sync::Arc;

pub struct AppState {
    pub pool: Pool<sqlx::Sqlite>,
    pub signer: Arc<dyn Sign<Identity>>,
    pub validator: Arc<dyn Validate<Identity>>,
    pub passwdless_service: PasswdlessService,
    pub auth_service: AuthService,
    pub config: AppConfig,
}

pub struct AppConfig {
    pub admin_user: String,
    pub admin_pass: String,
}

impl AppState {
    pub fn new(
        pool: Pool<sqlx::Sqlite>,
        signer: Arc<dyn Sign<Identity>>,
        validator: Arc<dyn Validate<Identity>>,
        es: Arc<dyn EventStream>,
    ) -> Self {
        let auth_service = AuthService::new(pool.clone(), signer.clone(), validator.clone(), es);
        let passwdless_service = PasswdlessService::new(pool.clone(), auth_service.clone());
        let config = AppConfig {
            admin_user: std::env::var("ADMIN_USER").expect("ADMIN_USER must be set"),
            admin_pass: std::env::var("ADMIN_PASS").expect("ADMIN_PASS must be set"),
        };

        Self {
            pool,
            signer,
            validator,
            passwdless_service,
            auth_service,
            config,
        }
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}
