use crate::domain::auth::service::AuthService;
use crate::domain::auth::token::generate_raw_token;
use crate::passwdless::PasswdlessService;
use actixutils::{Identity, Provider};
use actixutils::{Sign, Validate};
use event_stream::{EventStream, Handler};
use serde::Deserialize;
use serde_json::Value;
use sqlx::{Pool, Sqlite, query};
use std::sync::Arc;

pub struct AppState {
    pub pool: Pool<sqlx::Sqlite>,
    pub validator: Arc<dyn Validate<Identity>>,
    pub passwdless_service: PasswdlessService,
    pub auth_service: AuthService,
}

impl AppState {
    pub async fn new(
        pool: Pool<sqlx::Sqlite>,
        signer: Arc<dyn Sign<Identity>>,
        validator: Arc<dyn Validate<Identity>>,
        es: Arc<dyn EventStream>,
    ) -> Self {
        let auth_service = AuthService::new(pool.clone(), signer.clone(), es.clone());
        let passwdless_service = PasswdlessService::new(auth_service.clone());
        subscribe(es.clone(), pool.clone()).await;
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

#[derive(Deserialize)]
struct ChannelConfirmed {
    user: String,
    address: String,
}

struct OnChannelConfirmed {
    db: Pool<Sqlite>,
}

#[async_trait::async_trait]
impl Handler for OnChannelConfirmed {
    async fn handle(&self, _subject: String, message: Vec<u8>) {
        let message = String::from_utf8(message).unwrap();
        let event: Value = serde_json::from_str(&message).unwrap();
        let payload = event.get("payload").unwrap();
        let event: ChannelConfirmed = serde_json::from_value(payload.clone()).unwrap();
        if let Err(e) = query!(
            "UPDATE users SET email = ? WHERE id = ?",
            event.address,
            event.user,
        )
        .execute(&self.db)
        .await
        {
            eprintln!("error in saving contact info: {e}");
        };
    }
}

async fn subscribe(es: Arc<dyn EventStream>, db: Pool<Sqlite>) {
    if let Err(e) = es.subscribe(
        "contact.channel.confirmed".to_string(),
        Arc::new(OnChannelConfirmed { db }),
    )
    .await{
eprintln!("Error in subscribing to contact.channel.confirmed: {e} . This is critical!");
};
}
