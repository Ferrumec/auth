use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

#[derive(Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub credentials: Vec<Passkey>,
}

impl User {
    pub fn new(username: impl Into<String>) -> Self {
        let username = username.into();
        Self {
            id: Uuid::new_v4(),
            username,
            credentials: vec![],
        }
    }
}

#[derive(Deserialize)]
pub struct UsernameRequest {
    pub username: String,
}

