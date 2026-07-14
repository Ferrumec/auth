# API Documentation

All routes below are relative to the namespace this module is mounted under (see `AuthModule::config(cfg, namespace)` in the [README](./README.md)). Examples assume a namespace of `/api/v1`.

Unless noted otherwise, responses use this envelope (`ApiResponse<T>`):

```json
{
  "success": true,
  "message": "human-readable summary",
  "data": { }
}
```

On error, `success` is `false`, `data` is `null`, and `message` describes the problem. Passkey-specific error responses (see below) instead return `{ "error": "..." }` — these are the prototype's original shape and haven't been changed to avoid a breaking change to that module's contract.

Routes marked 🔐 require a valid access token. This module doesn't dictate how the token is transmitted (bearer header vs. cookie) — that's handled by whatever `Validate<Identity>` implementation and middleware the consuming app wires up around `actixutils::Auth`.

---

## Password authentication

### `POST /auth/register`

Create a new account.

**Body**
```json
{ "username": "alice", "password": "hunter2plus" }
```

**201 Created**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "access_token": "…",
    "refresh_token": "…",
    "expires_in": 600
  }
}
```

**Errors:** `400` missing credentials / password under 6 characters, `409` username already exists.

Publishes an `auth.user.created` event.

---

### `POST /auth/login/email`

**Body**
```json
{ "identifier": "alice@example.com", "password": "hunter2plus" }
```

**200 OK** — same `AuthResult` shape as register. Also sets an `access_token` httpOnly cookie.

**Errors:** `401` invalid credentials.

---

### `POST /auth/login/username`

Identical contract to `/auth/login/email`, but looks the account up by `username` instead of `email`.

---

### `POST /auth/refresh`

Exchange a refresh token for a new access/refresh pair. The old refresh token is deleted (rotation) — it cannot be reused even if the request otherwise fails partway.

**Body**
```json
{ "refresh_token": "…" }
```

**200 OK** — new `AuthResult`.

**Errors:** `401` token not found, revoked, or expired.

---

### `POST /auth/logout`

Revokes a refresh token. Idempotent — calling it twice with the same (now-revoked) token still returns success.

**Body**
```json
{ "refresh_token": "…" }
```

**200 OK**, empty `data`.

---

### `POST /auth/request_password_reset`

**Body**
```json
{ "email": "alice@example.com" }
```

**200 OK** always, regardless of whether the email exists — this endpoint never reveals whether an address is registered.

---

### `POST /auth/confirm_password_reset`

**Body**
```json
{ "token": "…", "new_password": "newpassword123" }
```

**200 OK** on success. Revokes all of the user's existing sessions (refresh tokens) as a side effect.

**Errors:** `400` password too short, `401` invalid/expired/already-used token.

---

## Protected account routes 🔐

### `GET /me/account`

Returns the identity embedded in the caller's access token.

**200 OK**
```json
{
  "success": true,
  "message": "Protected data retrieved successfully",
  "data": { "user_id": "…", "message": "Access granted to protected route" }
}
```

### `POST /me/change_password`

**Body**
```json
{ "current_password": "hunter2plus", "new_password": "newpassword123" }
```

**200 OK** on success. Revokes all existing sessions.

**Errors:** `400` new password too short, `401` current password incorrect.

---

## Passwordless authentication

Base path: `/passwordless`. Challenges are short-lived (2 minutes) and held in memory (not the database).

### `GET /passwordless/challenge/email`

**Body**
```json
{ "email": "alice@example.com" }
```

**201 Created** on success — a challenge token/link pair is generated and published as an `auth.2fa.challenge.requested` event for your notification service to deliver (email/SMS/etc). Nothing is returned in the HTTP response body itself.

**Errors:** `404` user not found.

### `GET /passwordless/challenge/username/{username}`

Same as above, looked up by username instead of email.

### `GET /passwordless/confirm_link/{link}`

Confirm via the link half of the challenge pair.

**200 OK**
```json
{ "access_token": "…", "refresh_token": "…", "expires_in": 600 }
```

**Errors:** `400` invalid/expired link.

### `POST /passwordless/confirm_token`

Confirm via the numeric one-time code half of the pair.

**Body**
```json
{ "token": 123456 }
```

**200 OK** — same shape as `confirm_link`.

---

## Passkey authentication (`--features passkey`)

Base path: `/passkey`. All bodies are the standard [WebAuthn Level 2/3 JSON](https://www.w3.org/TR/webauthn-2/) shapes produced by `navigator.credentials.create()` / `.get()` — pass what the browser gives you straight through, no reshaping needed.

Error responses on this sub-module use `{ "error": "message" }` rather than the `ApiResponse` envelope.

### `POST /passkey/register/start` 🔐

Begin registering a new passkey for the calling account.

**Body:** none.

**200 OK** — a WebAuthn `PublicKeyCredentialCreationOptions` object. Pass directly to:
```js
const options = await res.json();
const credential = await navigator.credentials.create({ publicKey: options.publicKey });
```

**Errors:** `400` WebAuthn/config error, `401` missing/invalid access token, `500` internal error.

### `POST /passkey/register/finish?label=My%20Laptop` 🔐

Complete registration and store the credential. `label` is optional.

**Body:** the `PublicKeyCredential` object returned by `navigator.credentials.create()`, JSON-serialized (typically via a small helper that base64url-encodes the `ArrayBuffer` fields).

**200 OK**
```json
{ "status": "success", "message": "Passkey registered" }
```

**Errors:** `400` no registration in progress / expired (registrations expire after 5 minutes) or the authenticator's response failed verification.

### `GET /passkey/register` 🔐

List the calling account's registered passkeys.

**200 OK**
```json
[
  {
    "id": "5a4e...",
    "label": "My Laptop",
    "created_at": "2026-07-10T12:00:00Z",
    "last_used_at": "2026-07-14T08:30:00Z"
  }
]
```

### `DELETE /passkey/register/{id}` 🔐

Remove a passkey by its `id` (from the list endpoint above).

**200 OK** `{ "status": "success" }` · **404** if that id doesn't belong to the caller.

### `POST /passkey/login/start`

Begin a passkey login. Public — no access token required or available yet.

**Body**
```json
{ "username": "alice" }
```

**200 OK** — a WebAuthn `PublicKeyCredentialRequestOptions` object:
```js
const options = await res.json();
const credential = await navigator.credentials.get({ publicKey: options.publicKey });
```

**Errors:** `400` unknown username or the account has no passkeys registered (same message either way, to avoid username enumeration).

### `POST /passkey/login/finish?username=alice`

Complete the login.

**Body:** the `PublicKeyCredential` object returned by `navigator.credentials.get()`, JSON-serialized.

**200 OK**
```json
{
  "success": true,
  "message": "Passkey login successful",
  "data": { "access_token": "…", "refresh_token": "…", "expires_in": 600 }
}
```
Also sets the `access_token` httpOnly cookie, same as password login.

**Errors:** `400` no login in progress for that username / expired (5 minute window) / assertion failed verification.

---

## Utility

### `GET /user_id/username/{username}`

Look up a user's id by username. Returns the raw id as the response body (not JSON-wrapped).

**200 OK** — plain text UUID · **404** if not found.
