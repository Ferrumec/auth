
# API Documentation - Ferrumec/auth

## Overview
**Ferrumec/auth** is an authentication service built with **Actix-web** and Rust. It provides user registration, login, token management, password reset functionality, and supports multiple authentication methods including passkeys and passwordless authentication.

### Core Architecture
- **Framework:** Actix-web 4.4 with Tokio async runtime
- **Database:** SQLite with SQLx query builder
- **Authentication:** JWT tokens with bcrypt password hashing
- **Additional Features:** Passkey authentication, password reset, token refresh

---

## API Endpoints

### 1. User Registration
**Endpoint:** `POST /register`

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Validation:**
- Username and password are required
- Password must be at least 6 characters long

**Responses:**
- **201 Created:** User registered successfully
  ```json
  {
    "success": true,
    "message": "User '{username}' registered successfully",
    "data": {}
  }
  ```
- **400 Bad Request:** Validation failed
  ```json
  {
    "success": false,
    "message": "Username and password are required" | "Password must be at least 6 characters",
    "data": null
  }
  ```
- **409 Conflict:** Username already exists
  ```json
  {
    "success": false,
    "message": "Username already exists",
    "data": null
  }
  ```
- **500 Internal Server Error:** Database error

---

### 2. User Login
**Endpoint:** `POST /login`

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Responses:**
- **200 OK:** Login successful
  ```json
  {
    "success": true,
    "message": "Login successful",
    "data": {
      "access_token": "jwt_token_string",
      "refresh_token": "refresh_token_string",
      "expires_in": 3600
    }
  }
  ```
  **Set-Cookie Header:** `access_token` (HttpOnly, Secure, Domain: localhost)

- **400 Bad Request:** Missing credentials
- **401 Unauthorized:** Invalid credentials
- **500 Internal Server Error:** Database or token generation error

---

### 3. Protected Route
**Endpoint:** `GET /protected`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Responses:**
- **200 OK:** Access granted
  ```json
  {
    "success": true,
    "message": "Protected data retrieved successfully",
    "data": {
      "user_id": "uuid_string",
      "message": "Access granted to protected route"
    }
  }
  ```
- **401 Unauthorized:** Invalid or missing token

---

### 4. Refresh Token
**Endpoint:** `POST /refresh`

**Request Body:**
```json
{
  "refresh_token": "string"
}
```

**Responses:**
- **200 OK:** New tokens generated
  ```json
  {
    "success": true,
    "message": "Refresh successful",
    "data": {
      "access_token": "new_jwt_token",
      "refresh_token": "new_refresh_token",
      "expires_in": 3600
    }
  }
  ```
  **Set-Cookie Header:** `access_token` (HttpOnly, Secure)

- **400 Bad Request:** Refresh token is required
- **401 Unauthorized:** 
  - Refresh token not found or revoked
  - Refresh token expired
- **500 Internal Server Error:** Database error

---

### 5. Logout
**Endpoint:** `POST /logout`

**Request Body:**
```json
{
  "refresh_token": "string"
}
```

**Responses:**
- **200 OK:** Logout successful
  ```json
  {
    "success": true,
    "message": "Logout successful",
    "data": {
      "message": "Logged out successfully"
    }
  }
  ```
- **400 Bad Request:** Refresh token is required
- **404 Not Found:** Refresh token not found
- **500 Internal Server Error:** Database error

---

### 6. Change Password
**Endpoint:** `POST /change-password`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request Body:**
```json
{
  "current_password": "string",
  "new_password": "string"
}
```

**Validation:**
- New password must be at least 6 characters long

**Responses:**
- **200 OK:** Password changed successfully
  ```json
  {
    "success": true,
    "message": "Password changed successfully",
    "data": {}
  }
  ```
- **401 Unauthorized:** 
  - Invalid current password
  - Missing/invalid access token
- **400 Bad Request:** Password too short
- **500 Internal Server Error:** Password update failed

**Side Effect:** All refresh tokens for the user are revoked upon successful password change

---

### 7. Request Password Reset
**Endpoint:** `POST /password-reset/request`

**Request Body:**
```json
{
  "email": "string"
}
```

**Response:**
- **200 OK:** Always returns success (for security, doesn't reveal if email exists)
  ```json
  {
    "success": true,
    "message": "If the account exists, a reset link has been sent",
    "data": {}
  }
  ```

**Note:** If the user exists, a password reset token is generated and logged to console. Token expires in 30 minutes.

---

### 8. Confirm Password Reset
**Endpoint:** `POST /password-reset/confirm`

**Request Body:**
```json
{
  "token": "string",
  "new_password": "string"
}
```

**Responses:**
- **200 OK:** Password reset successful
  ```json
  {
    "success": true,
    "message": "Password reset successful",
    "data": {}
  }
  ```
- **401 Unauthorized:** Invalid or expired token
- **500 Internal Server Error:** Database error

**Side Effect:** All refresh tokens for the user are revoked

---

### 9. Admin Login
**Endpoint:** `POST /admin/login`

**Request Body:**
```json
{
  "username": "string",
  "password": "string"
}
```

**Responses:**
- **200 OK:** Admin login successful
  ```json
  {
    "token": "jwt_admin_token"
  }
  ```
  **Set-Cookie Header:** `access_token` (HttpOnly, Secure)

- **400 Bad Request:** Missing credentials
- **401 Unauthorized:** Invalid credentials or not admin
- **500 Internal Server Error:** Token signing error

---

## Data Models

### RegisterRequest
```rust
{
  "username": String,
  "password": String
}
```

### LoginRequest / Admin Login Request
```rust
{
  "username": String,
  "password": String
}
```

### LoginResponse
```rust
{
  "access_token": String,
  "refresh_token": String,
  "expires_in": u64  // seconds
}
```

### User (Database)
```rust
{
  "id": UUID,
  "username": String,
  "password_hash": String,
  "created_at": DateTime<UTC>,
  "updated_at": DateTime<UTC>
}
```

### RefreshToken (Database)
```rust
{
  "id": UUID,
  "user_id": UUID,
  "token": String,
  "issuer": String,
  "expires_at": DateTime<UTC>,
  "revoked": bool,
  "created_at": DateTime<UTC>
}
```

### PasswordReset (Database)
```rust
{
  "id": UUID,
  "user_id": UUID,
  "token_hash": String,
  "expires_at": DateTime<UTC>,
  "used": bool,
  "created_at": DateTime<UTC>
}
```

---

## Error Handling

All error responses follow this format:
```json
{
  "success": false,
  "message": "error description",
  "data": null
}
```

### HTTP Status Codes
- **200 OK:** Successful request
- **201 Created:** Resource created successfully
- **400 Bad Request:** Validation failure or missing required fields
- **401 Unauthorized:** Authentication failure or invalid credentials
- **404 Not Found:** Resource not found
- **409 Conflict:** Resource already exists (e.g., duplicate username)
- **500 Internal Server Error:** Server error

---

## Authentication & Security

### Token Management
- **Access Token:** JWT token with short expiry (configurable, default appears to be ~1 hour)
- **Refresh Token:** Long-lived token stored in database, expires after 1 day
- **Token Pair:** Generated on login and refresh operations

### Password Security
- Passwords hashed using **bcrypt** (cost factor 0.15)
- Passwords minimum 6 characters required
- Current password verification on change

### Cookie Settings
- **HttpOnly:** true (prevents JavaScript access)
- **Secure:** true (HTTPS only)
- **Domain:** localhost
- **Path:** /

### Additional Features
- Password reset tokens hashed with **SHA256**
- Token refresh invalidates old refresh token
- Token revocation on password change
- Password reset tokens expire after 30 minutes

---

## Configuration

The service reads from environment variables or `.env` file:
- `ADMIN_USER`: Admin username
- `ADMIN_PASS`: Admin password
- `ACCESS_TOKEN_EXPIRY_MINUTES`: Access token expiry time
- Database connection details

---

## Dependencies

Key dependencies (from Cargo.toml):
- **actix-web:** 4.4 - Web framework
- **tokio:** 1.37 - Async runtime
- **sqlx:** 0.8.6 - Database query builder
- **bcrypt:** 0.15 - Password hashing
- **webauthn-rs:** 0.5.4 - Passkey support
- **uuid:** 1.7 - User IDs
- **serde:** 1.0 - Serialization
- **chrono:** 0.4 - Timestamps

---

## Additional Features (In Development)

- **Passkey Authentication:** Located in `/src/passkey/`
- **Passwordless Authentication:** Located in `/src/passwdless/`
- Custom auth middleware integration
- Token signing utilities

---

## Project Structure

```
src/
├── main.rs              # Application entry point
├── auth2.rs             # Core authentication logic
├── handlers.rs          # HTTP request handlers
├── handlers_core.rs     # Core handler implementations
├── models.rs            # Request/Response models
├── db.rs               # Database operations
├── config.rs           # Configuration management
├── logging.rs          # Logging setup
├── user_id.rs          # User ID utilities
├── lib.rs              # Library exports
├── passkey/            # Passkey authentication
│   ├── auth/
│   ├── config.rs
│   ├── error.rs
│   ├── models.rs
│   ├── state.rs
│   └── mod.rs
└── passwdless/         # Passwordless authentication
```

---

## Getting Started

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Ferrumec/auth.git
   cd auth
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Run migrations:**
   ```bash
   sqlx migrate run
   ```

4. **Build and run:**
   ```bash
   cargo build
   cargo run
   ```

5. **The server will start on:** `http://localhost:8080`

---

## Example Usage

### Register a User
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure_password"}'
```

### Login
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "secure_password"}'
```

### Access Protected Route
```bash
curl -X GET http://localhost:8080/protected \
  -H "Authorization: Bearer <access_token>"
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'
```

---

## License
This project is part of the Ferrumec organization. See LICENSE file for details.

## Support
For issues, questions, or contributions, please visit the [GitHub repository](https://github.com/Ferrumec/auth).
```

