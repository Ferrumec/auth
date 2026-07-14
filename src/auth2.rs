use crate::domain::auth::service::AuthService;
use crate::domain::auth::token::generate_raw_token;
use crate::passwdless::PasswdlessService;
use actixutils::{Identity, Provider};
use actixutils::{Sign, Validate};
use typed_eventbus::{EventStream, Subscribable, Subscriber, Event};
use serde::Deserialize;
use sqlx::{Pool, Sqlite, query};
use std::sync::Arc;
use uuid::Uuid;

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
    user: Uuid,
    address: String,
    channel: String
}

struct OnChannelConfirmed {
    db: Pool<Sqlite>,
}

#[async_trait::async_trait]
impl Subscriber<ChannelConfirmed> for OnChannelConfirmed {
    async fn on_message(&self, event:Event<ChannelConfirmed>, _subject: &str) {
        // this is to ensure that email, or any other primary contact info, can only be confirme through a specific channel
        // set to console for development purposes only, 
        // TODO please change to a better channel in production
        if event.payload.channel!="console".to_string(){
            return
        }
        if let Err(e) = query!(
            "UPDATE users SET email = ? WHERE id = ?",
            event.payload.address,
            event.payload.user,
        )
        .execute(&self.db)
        .await
        {
            tracing::warn!("error in saving contact info: {e}");
        };
    }
}

impl Subscribable for ChannelConfirmed{
    const SUBJECT: &'static str = "contact.channel.confirmed";
}

async fn subscribe(es: Arc<dyn EventStream>, db: Pool<Sqlite>) {
    let subscriber = OnChannelConfirmed { db };
    if let Err(e) = subscriber
        .subscribe(es.clone())
        .await
    {
        tracing::error!("Error in subscribing to contact.channel.confirmed: {e} . This is critical!");
    };
}
