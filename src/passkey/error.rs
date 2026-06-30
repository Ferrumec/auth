use actix_web::HttpResponse;
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl ErrorResponse {
    pub fn bad_request(msg: impl Into<String>) -> HttpResponse {
        HttpResponse::BadRequest().json(Self { error: msg.into() })
    }

    pub fn not_found(msg: impl Into<String>) -> HttpResponse {
        HttpResponse::NotFound().json(Self { error: msg.into() })
    }

    pub fn internal() -> HttpResponse {
        HttpResponse::InternalServerError().json(Self {
            error: "Internal server error".to_string(),
        })
    }
}

/// Unwrap a Mutex lock or return a 500.
/// Usage: `let guard = lock!(mutex, return_expr)` — but we use a macro so
/// the early-return happens in the *caller's* function.
#[macro_export]
macro_rules! lock {
    ($mutex:expr) => {
        match $mutex.lock() {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("Mutex poisoned: {}", e);
                return $crate::passkey::error::ErrorResponse::internal();
            }
        }
    };
}
