use crate::passkey::models::User;
use std::collections::HashMap;
use std::sync::Mutex;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration, Webauthn};

pub struct AppState {
    pub webauthn: Webauthn,
    pub users: Mutex<HashMap<String, User>>,
    pub reg_states: Mutex<HashMap<String, PasskeyRegistration>>,
    pub auth_states: Mutex<HashMap<String, PasskeyAuthentication>>,
}

impl AppState {
    pub fn new(webauthn: Webauthn) -> Self {
        Self {
            webauthn,
            users: Mutex::new(HashMap::new()),
            reg_states: Mutex::new(HashMap::new()),
            auth_states: Mutex::new(HashMap::new()),
        }
    }
}
