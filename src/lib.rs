use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use worker::*;

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct ChangeUsernameRequest {
    new_username: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct UserRow {
    id: i64,
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct RaidPlanRow {
    plan_data: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct SaveRaidPlanRequest {
    plan_data: serde_json::Value,
}

#[derive(Deserialize)]
struct TeamTemplateRow {
    template_data: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct SaveTeamTemplateRequest {
    template_data: serde_json::Value,
}

#[derive(Deserialize)]
struct UserAccountsRow {
    account_data: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct SaveAccountsRequest {
    account_data: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String,
    uid: i64,
    iat: i64,
    exp: i64,
    iss: String,
}

fn cors_headers() -> Headers {
    let headers = Headers::new();
    headers.set("Access-Control-Allow-Origin", "*").ok();
    headers
        .set(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        )
        .ok();
    headers
        .set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        .ok();
    headers
}

fn json_response<T: Serialize>(value: &T, status: u16) -> Result<Response> {
    let mut res = Response::from_json(value)?;
    res = res.with_status(status);
    res.headers_mut().set("Content-Type", "application/json")?;
    let cors = cors_headers();
    for (k, v) in cors.entries() {
        res.headers_mut().set(&k, &v)?;
    }
    Ok(res)
}

fn error_response(message: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({"error": message});
    json_response(&body, status)
}

fn get_jwt_secret(env: &Env) -> Result<String> {
    Ok(env.secret("JWT_SECRET")?.to_string())
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .options_async("/*path", |_req, _ctx| async move {
            let mut res = Response::empty()?;
            res = res.with_status(204);
            let cors = cors_headers();
            for (k, v) in cors.entries() {
                res.headers_mut().set(&k, &v)?;
            }
            Ok(res)
        })
        .get_async("/health", |_req, _ctx| async move {
            json_response(&serde_json::json!({"ok": true}), 200)
        })
        .post_async("/login", |mut req, ctx| async move {
            let env = ctx.env;
            let db = match env.d1("DB") {
                Ok(d) => d,
                Err(e) => {
                    console_error!("D1 binding error: {:?}", e);
                    return error_response("database connection failed", 500);
                }
            };

            let body: LoginRequest = match req.json().await {
                Ok(b) => b,
                Err(e) => {
                    console_error!("JSON parse error: {:?}", e);
                    return error_response("invalid json format", 400);
                }
            };

            if body.username.trim().is_empty() || body.password.trim().is_empty() {
                return error_response("missing credentials", 400);
            }

            let stmt = db.prepare(
                "SELECT id, username, password_hash FROM users WHERE username = ?1 LIMIT 1",
            );
            let row = match stmt.bind(&[body.username.clone().into()]) {
                Ok(s) => match s.first::<UserRow>(None).await {
                    Ok(r) => r,
                    Err(e) => {
                        console_error!("D1 query error: {:?}", e);
                        return error_response(&format!("database query failed: {}", e), 500);
                    }
                },
                Err(e) => {
                    console_error!("D1 bind error: {:?}", e);
                    return error_response(&format!("database bind failed: {}", e), 500);
                }
            };

            let user = match row {
                Some(u) => u,
                None => return error_response("user not found", 401),
            };

            let parsed_hash = match PasswordHash::new(&user.password_hash) {
                Ok(h) => h,
                Err(e) => {
                    console_error!("Password hash parse error: {:?}", e);
                    return error_response("internal error: invalid password hash", 500);
                }
            };

            if Argon2::default()
                .verify_password(body.password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return error_response("incorrect password", 401);
            }

            let now = Utc::now();
            let exp = now + Duration::days(365);
            let secret = match get_jwt_secret(&env) {
                Ok(s) => s,
                Err(e) => {
                    console_error!("JWT secret error: {:?}", e);
                    return error_response("internal error: jwt secret not configured", 500);
                }
            };
            let issuer = env
                .var("JWT_ISSUER")
                .map(|v| v.to_string())
                .unwrap_or_else(|_| "exia-backend".to_string());

            let claims = Claims {
                sub: user.username.clone(),
                uid: user.id,
                iat: now.timestamp(),
                exp: exp.timestamp(),
                iss: issuer,
            };

            let token = match encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            ) {
                Ok(t) => t,
                Err(e) => {
                    console_error!("Token encode error: {:?}", e);
                    return error_response("internal error: token generation failed", 500);
                }
            };

            json_response(
                &LoginResponse {
                    token,
                    expires_at: exp.timestamp(),
                },
                200,
            )
        })
        .post_async("/register", |mut req, ctx| async move {
            let env = ctx.env;
            let db = env.d1("DB")?;

            let body: RegisterRequest = req
                .json()
                .await
                .map_err(|_| Error::RustError("invalid json".into()))?;
            if body.username.trim().is_empty() || body.password.trim().is_empty() {
                return error_response("missing credentials", 400);
            }

            let salt = SaltString::generate(&mut rand::thread_rng());
            let password_hash = Argon2::default()
                .hash_password(body.password.as_bytes(), &salt)
                .map_err(|_| Error::RustError("password hash failed".into()))?
                .to_string();

            let created_at = Utc::now().timestamp() as f64;
            let stmt = db.prepare(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
            );
            let result = stmt
                .bind(&[
                    body.username.clone().into(),
                    password_hash.into(),
                    created_at.into(),
                ])?
                .run()
                .await;

            if result.is_err() {
                return error_response("username already exists", 409);
            }

            json_response(&serde_json::json!({"ok": true}), 201)
        })
        .get_async("/me", |req, ctx| async move {
            let env = ctx.env;
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

            json_response(
                &serde_json::json!({
                    "user_id": data.claims.uid,
                    "username": data.claims.sub
                }),
                200,
            )
        })
        .post_async("/change-password", |mut req, ctx| async move {
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
            let stmt = db.prepare("SELECT id, username, password_hash FROM users WHERE id = ?1");
            let user: UserRow = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<UserRow>(None).await {
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
            let new_hash =
                match Argon2::default().hash_password(body.new_password.as_bytes(), &salt) {
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
        })
        .post_async("/change-username", |mut req, ctx| async move {
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
                Ok(s) => match s.first::<UserRow>(None).await {
                    Ok(Some(_)) => return error_response("username already exists", 409),
                    Ok(None) => {} // ok to proceed
                    Err(e) => {
                        return error_response(&format!("database check query error: {}", e), 500)
                    }
                },
                Err(e) => return error_response(&format!("database check bind error: {}", e), 500),
            };

            // Update user
            let update_stmt = db.prepare("UPDATE users SET username = ?1 WHERE id = ?2");
            match update_stmt.bind(&[new_username.into(), (claims.uid as i32).into()]) {
                Ok(s) => match s.run().await {
                    Ok(_) => {}
                    Err(e) => {
                        return error_response(&format!("failed to update username: {}", e), 500)
                    }
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
        })
        .delete_async("/account", |req, ctx| async move {
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
        })
        .get_async("/raid-plan", |req, ctx| async move {
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

            let stmt = db.prepare("SELECT plan_data, updated_at FROM raid_plans WHERE user_id = ?1");
            let row = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<RaidPlanRow>(None).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return error_response("no cloud data found", 404),
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            // Parse plan_data string back to JSON
            let plan_json: serde_json::Value = match serde_json::from_str(&row.plan_data) {
                Ok(v) => v,
                Err(_) => return error_response("stored data corruption", 500),
            };

            json_response(
                &serde_json::json!({
                    "plan_data": plan_json,
                    "updated_at": row.updated_at
                }),
                200,
            )
        })
        .post_async("/raid-plan", |mut req, ctx| async move {
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

            let body: SaveRaidPlanRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return error_response("invalid json format", 400),
            };

            let plan_str = body.plan_data.to_string();
            let now = Utc::now().timestamp() as f64;

            let stmt = db.prepare("INSERT OR REPLACE INTO raid_plans (user_id, plan_data, updated_at) VALUES (?1, ?2, ?3)");
            match stmt.bind(&[(claims.uid as i32).into(), plan_str.into(), now.into()]) {
                Ok(s) => {
                    if s.run().await.is_err() {
                        return error_response("failed to save data", 500);
                    }
                }
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            json_response(
                &serde_json::json!({"ok": true, "message": "data saved to cloud"}),
                200,
            )
        })
        .get_async("/team-template", |req, ctx| async move {
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

            let stmt = db.prepare("SELECT template_data, updated_at FROM team_templates WHERE user_id = ?1");
            let row = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<TeamTemplateRow>(None).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return error_response("no cloud data found", 404),
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            // Parse template_data string back to JSON
            let tmpl_json: serde_json::Value = match serde_json::from_str(&row.template_data) {
                Ok(v) => v,
                Err(_) => return error_response("stored data corruption", 500),
            };

            json_response(
                &serde_json::json!({
                    "template_data": tmpl_json,
                    "updated_at": row.updated_at
                }),
                200,
            )
        })
        .post_async("/team-template", |mut req, ctx| async move {
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

            let body: SaveTeamTemplateRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return error_response("invalid json format", 400),
            };

            let plan_str = body.template_data.to_string();
            let now = Utc::now().timestamp() as f64;

            let stmt = db.prepare("INSERT OR REPLACE INTO team_templates (user_id, template_data, updated_at) VALUES (?1, ?2, ?3)");
            match stmt.bind(&[(claims.uid as i32).into(), plan_str.into(), now.into()]) {
                Ok(s) => {
                    if s.run().await.is_err() {
                        return error_response("failed to save data", 500);
                    }
                }
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            json_response(
                &serde_json::json!({"ok": true, "message": "data saved to cloud"}),
                200,
            )
        })
        .get_async("/accounts", |req, ctx| async move {
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

            let stmt = db.prepare("SELECT account_data, updated_at FROM user_accounts WHERE user_id = ?1");
            let row = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<UserAccountsRow>(None).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return error_response("no cloud data found", 404),
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            // Parse account_data string back to JSON
            let acc_json: serde_json::Value = match serde_json::from_str(&row.account_data) {
                Ok(v) => v,
                Err(_) => return error_response("stored data corruption", 500),
            };

            json_response(
                &serde_json::json!({
                    "account_data": acc_json,
                    "updated_at": row.updated_at
                }),
                200,
            )
        })
        .post_async("/accounts", |mut req, ctx| async move {
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

            let body: SaveAccountsRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return error_response("invalid json format", 400),
            };

            let acc_str = body.account_data.to_string();
            let now = Utc::now().timestamp() as f64;

            let stmt = db.prepare("INSERT OR REPLACE INTO user_accounts (user_id, account_data, updated_at) VALUES (?1, ?2, ?3)");
            match stmt.bind(&[(claims.uid as i32).into(), acc_str.into(), now.into()]) {
                Ok(s) => {
                    if s.run().await.is_err() {
                        return error_response("failed to save data", 500);
                    }
                }
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            json_response(
                &serde_json::json!({"ok": true, "message": "data saved to cloud"}),
                200,
            )
        })
        .run(req, env)
        .await
}
