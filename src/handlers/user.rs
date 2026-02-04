use crate::models::*;
use crate::utils::*;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use worker::*;

pub async fn get_user_profile(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env;
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_response("database connection failed", 500),
    };
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return error_response("missing token", 401);
    }

    let token = auth.trim_start_matches("Bearer ").trim();
    let secret = get_jwt_secret(&env)?;
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| Error::RustError("invalid token".into()))?;

    let stmt = db.prepare("SELECT username, avatar_url FROM users WHERE id = ?1");
    let profile = match stmt.bind(&[(data.claims.uid as i32).into()]) {
        Ok(s) => match s.first::<UserProfileRow>(None).await {
            Ok(Some(r)) => r,
            Ok(None) => return error_response("user not found", 404),
            Err(e) => return error_response(&format!("database query error: {}", e), 500),
        },
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    json_response(
        &serde_json::json!({
            "user_id": data.claims.uid,
            "username": profile.username,
            "avatar_url": profile.avatar_url
        }),
        200,
    )
}

pub async fn change_password_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env;
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_response("database connection failed", 500),
    };

    // Verify JWT token
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return error_response("missing token", 401);
    }

    let token = auth.trim_start_matches("Bearer ").trim();
    let secret = match get_jwt_secret(&env) {
        Ok(s) => s,
        Err(_) => return error_response("internal error: jwt secret missing", 500),
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(_) => return error_response("invalid or expired token", 401),
    };

    // Parse request body
    let body: ChangePasswordRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    if body.new_password.trim().is_empty() {
        return error_response("new password cannot be empty", 400);
    }

    // Get current user's password hash
    let stmt =
        db.prepare("SELECT id, username, password_hash, avatar_url FROM users WHERE id = ?1");
    let user: UserAuthRow = match stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => match s.first::<UserAuthRow>(None).await {
            Ok(Some(u)) => u,
            Ok(None) => return error_response("user not found", 404),
            Err(_) => return error_response("database error", 500),
        },
        Err(_) => return error_response("database error", 500),
    };

    // Verify current password
    let parsed_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(_) => return error_response("internal error", 500),
    };

    if Argon2::default()
        .verify_password(body.current_password.as_bytes(), &parsed_hash)
        .is_err()
    {
        return error_response("current password is incorrect", 401);
    }

    // Hash new password
    let salt = SaltString::generate(&mut rand::thread_rng());
    let new_hash = match Argon2::default().hash_password(body.new_password.as_bytes(), &salt) {
        Ok(h) => h.to_string(),
        Err(_) => return error_response("failed to hash password", 500),
    };

    // Update password in database
    let update_stmt = db.prepare("UPDATE users SET password_hash = ?1 WHERE id = ?2");
    match update_stmt.bind(&[new_hash.into(), (claims.uid as i32).into()]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to update password", 500);
            }
        }
        Err(_) => return error_response("database error", 500),
    };

    json_response(
        &serde_json::json!({"ok": true, "message": "password changed successfully"}),
        200,
    )
}

pub async fn change_username_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env;
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_response("database connection failed", 500),
    };

    // Verify JWT token
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return error_response("missing token", 401);
    }

    let token = auth.trim_start_matches("Bearer ").trim();
    let secret = match get_jwt_secret(&env) {
        Ok(s) => s,
        Err(_) => return error_response("internal error: jwt secret missing", 500),
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(_) => return error_response("invalid or expired token", 401),
    };

    // Parse body
    let body: ChangeUsernameRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    let new_username = body.new_username.trim();
    if new_username.len() < 3 {
        return error_response("username must be at least 3 characters", 400);
    }

    // Check if exists
    let stmt = db.prepare("SELECT id FROM users WHERE username = ?1");
    match stmt.bind(&[new_username.into()]) {
        Ok(s) => match s.first::<UserIdRow>(None).await {
            Ok(Some(_)) => return error_response("username already exists", 409),
            Ok(None) => {} // ok to proceed
            Err(e) => return error_response(&format!("database check query error: {}", e), 500),
        },
        Err(e) => return error_response(&format!("database check bind error: {}", e), 500),
    };

    // Update user
    let update_stmt = db.prepare("UPDATE users SET username = ?1 WHERE id = ?2");
    match update_stmt.bind(&[new_username.into(), (claims.uid as i32).into()]) {
        Ok(s) => match s.run().await {
            Ok(_) => {}
            Err(e) => return error_response(&format!("failed to update username: {}", e), 500),
        },
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    // Issue new token
    let now = Utc::now();
    let exp = now + Duration::days(365);
    let issuer = env
        .var("JWT_ISSUER")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "exia-backend".to_string());

    let new_claims = Claims {
        sub: new_username.to_string(),
        uid: claims.uid,
        iat: now.timestamp(),
        exp: exp.timestamp(),
        iss: issuer,
    };

    let new_token = match encode(
        &Header::default(),
        &new_claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(_) => return error_response("failed to generate token", 500),
    };

    json_response(
        &serde_json::json!({
            "ok": true,
            "message": "username changed successfully",
            "token": new_token,
            "username": new_username
        }),
        200,
    )
}

pub async fn change_avatar_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env;
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_response("database connection failed", 500),
    };

    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return error_response("missing token", 401);
    }

    let token = auth.trim_start_matches("Bearer ").trim();
    let secret = match get_jwt_secret(&env) {
        Ok(s) => s,
        Err(_) => return error_response("internal error: jwt secret missing", 500),
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(_) => return error_response("invalid or expired token", 401),
    };

    let body: ChangeAvatarRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    let avatar_url = body.avatar_url.trim();
    if avatar_url.is_empty() {
        return error_response("avatar url cannot be empty", 400);
    }

    let update_stmt = db.prepare("UPDATE users SET avatar_url = ?1 WHERE id = ?2");
    match update_stmt.bind(&[avatar_url.into(), (claims.uid as i32).into()]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to update avatar", 500);
            }
        }
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    json_response(
        &serde_json::json!({
            "ok": true,
            "avatar_url": avatar_url
        }),
        200,
    )
}

pub async fn delete_account_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let env = ctx.env;
    let db = match env.d1("DB") {
        Ok(d) => d,
        Err(_) => return error_response("database connection failed", 500),
    };

    // Verify JWT token
    let auth = req.headers().get("Authorization")?.unwrap_or_default();
    if !auth.starts_with("Bearer ") {
        return error_response("missing token", 401);
    }

    let token = auth.trim_start_matches("Bearer ").trim();
    let secret = match get_jwt_secret(&env) {
        Ok(s) => s,
        Err(_) => return error_response("internal error: jwt secret missing", 500),
    };
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let claims = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(data) => data.claims,
        Err(_) => return error_response("invalid or expired token", 401),
    };

    // Delete user from database
    let stmt = db.prepare("DELETE FROM users WHERE id = ?1");
    match stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to delete account", 500);
            }
        }
        Err(_) => return error_response("database error", 500),
    };

    json_response(
        &serde_json::json!({"ok": true, "message": "account deleted successfully"}),
        200,
    )
}
