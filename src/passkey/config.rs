use url::Url;
use webauthn_rs::prelude::{Webauthn, WebauthnBuilder};

pub struct Config {
    pub host: &'static str,
    pub port: u16,
    pub rp_id: &'static str,
    pub origin: Url,
}

impl Config {
    pub fn from_env() -> Self {
        // In a real project, pull these from env vars or a config file.
        let origin_str = std::env::var("ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8000".to_string());

        Self {
            host: "127.0.0.1",
            port: 8080,
            rp_id: "localhost",
            origin: Url::parse(&origin_str).expect("Invalid ORIGIN URL"),
        }
    }

    pub fn build_webauthn(&self) -> Webauthn {
        WebauthnBuilder::new(self.rp_id, &self.origin)
            .expect("Invalid WebAuthn config")
            .build()
            .expect("Failed to build Webauthn")
    }
}

