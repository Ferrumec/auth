-- Add migration script here
-- Stores one row per registered WebAuthn/passkey credential.
-- `passkey_data` holds the serialized webauthn-rs `Passkey` (public key,
-- sign counter, transports, etc). It is opaque application state, not raw
-- key material, and is updated in place after every successful login so
-- the stored signature counter stays in sync (clone-detection).
CREATE TABLE IF NOT EXISTS passkey_credentials (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                credential_id TEXT UNIQUE NOT NULL,
                passkey_data TEXT NOT NULL,
                label TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_user_id ON passkey_credentials(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_passkey_credentials_credential_id ON passkey_credentials(credential_id);
