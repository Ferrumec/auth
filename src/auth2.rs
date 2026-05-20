use crate::domain::auth::service::AuthService;
use crate::domain::auth::token::generate_raw_token;
use crate::passwdless::PasswdlessService;
use actixutils::{Identity, Provider};
use actixutils::{Sign, Validate};
use event_stream::EventStream;
use sqlx::Pool;
use std::sync::Arc;

pub struct AppState {
    pub pool: Pool<sqlx::Sqlite>,
    pub validator: Arc<dyn Validate<Identity>>,
    pub passwdless_service: PasswdlessService,
    pub auth_service: AuthService,
}

impl AppState {
    pub fn new(
        pool: Pool<sqlx::Sqlite>,
        signer: Arc<dyn Sign<Identity>>,
        validator: Arc<dyn Validate<Identity>>,
        es: Arc<dyn EventStream>,
    ) -> Self {
        let auth_service = AuthService::new(pool.clone(), signer.clone(), es);
        let passwdless_service = PasswdlessService::new(pool.clone(), auth_service.clone());

        Self {
            pool,
            validator,
            passwdless_service,
            auth_service,
        }
    }
}

impl Provider<Arc<dyn Validate<Identity>>> for AppState {
    fn provide(&self) -> Arc<dyn Validate<Identity>> {
        self.validator.clone()
    }
}

pub fn random_token() -> String {
    generate_raw_token()
}
