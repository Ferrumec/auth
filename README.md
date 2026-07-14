# auth

A reusable authentication microservice module (Actix Web + SQLx/SQLite) providing:

- **Password auth** — register, login (by email or username), refresh, logout, change password
- **Password reset** — request/confirm flow with hashed, expiring tokens
- **Passwordless auth** — email/username "magic link" + one-time code challenges
- **Passkey auth (WebAuthn)** — register a passkey on an existing account and log in with it, no password required
- **JWT sessions** — short-lived signed access tokens + long-lived, rotating, hashed refresh tokens
- **Event publishing** — domain events (`auth.user.created`, `auth.2fa.challenge.requested`, ...) published via `typed-eventbus` for other services to react to

This crate is designed to be mounted into a larger Actix Web application as a module: it exposes a `Module` (aliased from `AuthModule`) that you construct once at startup and mount under a namespace via `.configure(...)`.

## Table of contents

- [Architecture](#architecture)
- [Getting started](#getting-started)
- [Configuration (environment variables)](#configuration-environment-variables)
- [Mounting the module](#mounting-the-module)
- [The passkey feature](#the-passkey-feature)
- [Database schema](#database-schema)
- [Known pre-existing issue](#known-pre-existing-issue)
- [API documentation](#api-documentation)

## Architecture

```
src/
├── lib.rs              Crate root — module declarations, public exports
├── config.rs            AuthModule — builds AppState, mounts routes
├── auth2.rs              The shared AppState (pool, services, validator)
├── handlers.rs           HTTP handlers for password-based auth
├── models.rs              Request/response DTOs for handlers.rs
├── user_id.rs              username → user id lookup route
├── domain/
│   └── auth/
│       ├── service.rs      AuthService — the single source of truth for
│       │                   auth business logic (DB queries, hashing,
│       │                   token issuance). HTTP handlers are thin
│       │                   wrappers around this.
│       ├── models.rs        Command/result/DB-row types
│       ├── errors.rs         AuthError
│       └── token.rs           Random token generation + hashing helpers
├── passwdless/            Passwordless (magic-link / OTP) challenge flow
└── passkey/                WebAuthn / passkey module (feature = "passkey")
    ├── state.rs             Webauthn config + in-memory ceremony state
    ├── repository.rs         DB access for stored credentials
    ├── models.rs               Request DTOs
    ├── error.rs                 JSON error responses
    └── auth/
        ├── register.rs          start/finish/list/remove a passkey
        └── login.rs               start/finish passkey login
```

**Design principle carried through the whole crate:** HTTP handlers parse the request and map errors to status codes — they never touch the database or run crypto directly. All of that lives in `domain::auth::service::AuthService` (for password/token logic) and `passkey::repository` (for credential storage). This keeps the business logic testable independent of Actix and keeps every entry point (password, passwordless, passkey) converging on the same token-issuance code path.

## Getting started

```bash
# 1. Install the sqlx CLI if you don't have it
cargo install sqlx-cli --no-default-features --features sqlite

# 2. Set your database URL and run migrations
export DATABASE_URL="sqlite://auth.db"
sqlx database create
sqlx migrate run

# 3. Set the required env vars (see below), then build
cargo build --features passkey
```

sqlx's `query!`/`query_as!`/`query_scalar!` macros are compile-time checked against a real database (or an offline `.sqlx` cache). If you don't keep an `.sqlx` directory checked into the repo, make sure `DATABASE_URL` points at an up-to-date, migrated database whenever you build.

## Configuration (environment variables)

| Variable | Required | Used by | Description |
|---|---|---|---|
| `DATABASE_URL` | ✅ | sqlx | SQLite connection string, e.g. `sqlite://auth.db` |
| `AUD` | ✅ | `AuthService` | Comma-separated list of JWT audiences to embed in access tokens |
| `WEBAUTHN_RP_ID` | ✅ (passkey feature) | passkey | Relying Party ID — your domain, e.g. `example.com` (`localhost` for local dev) |
| `WEBAUTHN_RP_ORIGIN` | ✅ (passkey feature) | passkey | The exact origin the browser sends, e.g. `https://example.com` or `http://localhost:5173` |
| `WEBAUTHN_RP_NAME` | optional | passkey | Human-readable name shown in the OS/browser passkey prompt. Defaults to `WEBAUTHN_RP_ID` |

All of these are read once at startup (inside `AuthModule::new` / `AppState::new`) and the process panics immediately with a clear message if a required one is missing — the module is deliberately fail-fast rather than failing later on the first request.

> **`WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGIN` must match where the browser actually loads your frontend from.** Passkeys are bound to the origin they were registered on; mismatches show up as WebAuthn errors during registration/login, not as silent failures.

## Mounting the module

This crate exposes `Module` (an alias for `AuthModule`) plus `SetupError` from `lib.rs`. A consuming binary wires it up something like:

```rust
use auth::Module as AuthModule;

let auth_module = AuthModule::new(pool, signer, validator, event_stream).await;

HttpServer::new(move || {
    App::new().configure(|cfg| auth_module.config(cfg, "/api/v1"))
})
.bind(("0.0.0.0", 8080))?
.run()
.await
```

Every route in this crate is mounted under whatever `namespace` you pass to `.config(cfg, namespace)`, e.g. `/api/v1/auth/login/email`, `/api/v1/passkey/login/start`.

## The passkey feature

Build with `--features passkey` to compile this module in (it's optional so consumers who don't need WebAuthn don't pull in `webauthn-rs`).

**Design decision:** passkeys are *added to* an existing account, not used to create one. `POST /passkey/register/start` and `/finish` require a valid access token (the same `Auth<Identity>` extractor `/me/account` uses) — you register a passkey from an already-authenticated session, the same way you'd add a security key in any account-settings page. `POST /passkey/login/start` and `/finish` are public, since by definition you have no session yet when logging in.

Typical client flow:

1. **User is logged in (password or otherwise).** Call `POST /passkey/register/start` → get back WebAuthn `CredentialCreationOptions`. Pass these to `navigator.credentials.create()` in the browser.
2. Send the browser's response to `POST /passkey/register/finish?label=My%20Laptop`. The credential is now stored against the account.
3. **Later, logged out.** Call `POST /passkey/login/start` with `{ "username": "..." }` → get back WebAuthn `CredentialRequestOptions`. Pass these to `navigator.credentials.get()`.
4. Send the browser's response to `POST /passkey/login/finish?username=...`. On success you get the same `{ access_token, refresh_token, expires_in }` shape every other login method returns, plus the `access_token` set as an httpOnly cookie.

See [API.md](./API.md) for full request/response shapes.

### Security notes

- Registration ceremony state (the in-progress challenge) is kept in memory, keyed by user id, and expires after 5 minutes if never completed — it is never written to the database.
- Login ceremony state is kept in memory keyed by username, same 5-minute expiry.
- Only the finished, verified credential (public key + metadata, no private key material — that never leaves the user's device/authenticator) is persisted, as JSON in the `passkey_credentials` table.
- After every successful login, the credential's signature counter is re-verified and persisted (`Passkey::update_credential`). This is WebAuthn's built-in clone-detection mechanism — losing this would silently disable it.
- `register/start` excludes the user's already-registered credentials from the ceremony (`exclude_credentials`) so the same physical key/device can't be registered twice on one account.
- `login/start` returns the same error for "no such username" and "username exists but has no passkeys" to avoid leaking which usernames are registered.
- The in-memory ceremony-state maps use a single process's memory. If you run this service behind a load balancer with multiple instances and no sticky sessions, a `register/start` on instance A followed by `register/finish` routed to instance B will fail with "no registration in progress" — either enable sticky sessions on `/passkey/*` or move this state to a shared store (e.g. Redis) if you scale horizontally.

## Database schema

Two tables are relevant to passkeys:

- `users` — unchanged, existing table. Passkeys are looked up via `users.username`.
- `passkey_credentials` (new, this change) — one row per registered credential:

  | column | type | notes |
  |---|---|---|
  | `id` | TEXT (UUID) | primary key, used by the list/delete endpoints |
  | `user_id` | TEXT (UUID) | FK → `users.id`, `ON DELETE CASCADE` |
  | `credential_id` | TEXT | base64url WebAuthn credential ID, unique |
  | `passkey_data` | TEXT | JSON-serialized `webauthn_rs::Passkey` (public key + counter) |
  | `label` | TEXT, nullable | optional user-facing device name |
  | `created_at` | DATETIME | |
  | `last_used_at` | DATETIME, nullable | updated on every successful login |

Run `sqlx migrate run` to apply `migrations/20260714090000_create_passkey_credentials.sql`.

## Known pre-existing issue

While integrating passkeys I noticed `AuthService::create_user` (in `domain/auth/service.rs`) inserts a new row into `users` without an `email` value, but the `users` table (`migrations/20260307091148_create_users.sql`) defines `email TEXT UNIQUE NOT NULL` with no default. As written, `POST /auth/register` will fail with a `NOT NULL constraint failed: users.email` error at the database level — this predates the passkey work and I left it as-is since it's outside what was asked, but it will block end-to-end testing of *any* login method (password, passwordless, or passkey) until either the column allows `NULL` (matching the deferred "confirm your email later" flow implied by the `contact.channel.confirmed` event subscriber in `auth2.rs`) or the insert is updated to populate `email`. Happy to fix this too if you'd like.

## API documentation

See [API.md](./API.md).
