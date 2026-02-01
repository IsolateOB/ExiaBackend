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

#[derive(Deserialize)]
struct ChangeAvatarRequest {
    avatar_url: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: i64,
    username: String,
    avatar_url: Option<String>,
    game_accounts: Vec<GameAccountPayload>,
}

#[derive(Deserialize)]
struct UserAuthRow {
    id: i64,
    username: String,
    password_hash: String,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct UserProfileRow {
    username: String,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct UserIdRow {
    id: i64,
}

#[derive(Serialize, Deserialize)]
struct GameAccountPayload {
    game_uid: String,
    cookie: Option<String>,
    updated_at: i64,
}

#[derive(Deserialize)]
struct RaidPlanMetaRow {
    plan_id: String,
    plan_name: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct RaidPlanSlotRow {
    plan_id: String,
    account_key: String,
    slot_index: i64,
    step: i64,
    predicted_damage: f64,
    predicted_damage_input: String,
}

#[derive(Deserialize)]
struct RaidPlanSlotCharRow {
    plan_id: String,
    account_key: String,
    slot_index: i64,
    position: i64,
    character_id: i64,
}

#[derive(Deserialize)]
struct SaveRaidPlanRequest {
    plan_data: serde_json::Value,
}

#[derive(Deserialize)]
struct RaidPlanPayload {
    id: String,
    name: String,
    data: serde_json::Value,
    #[serde(rename = "updatedAt")]
    updated_at: Option<i64>,
}

#[derive(Deserialize)]
struct PlanSlotPayload {
    step: Option<i64>,
    #[serde(default, rename = "characterIds")]
    character_ids: Vec<i64>,
    #[serde(default, rename = "predictedDamage")]
    predicted_damage: Option<f64>,
    #[serde(default, rename = "predictedDamageInput")]
    predicted_damage_input: Option<String>,
}

#[derive(Deserialize)]
struct TeamTemplateMetaRow {
    template_id: String,
    name: String,
    created_at: i64,
    total_damage_coefficient: f64,
    updated_at: i64,
}

#[derive(Deserialize)]
struct TeamTemplateMemberRow {
    template_id: String,
    position: i64,
    character_id: String,
    damage_coefficient: f64,
    coefficients_json: String,
}

#[derive(Deserialize)]
struct SaveTeamTemplateRequest {
    template_data: serde_json::Value,
}

#[derive(Deserialize)]
struct TeamTemplatePayload {
    id: String,
    name: String,
    #[serde(rename = "createdAt")]
    created_at: i64,
    #[serde(rename = "totalDamageCoefficient")]
    total_damage_coefficient: f64,
    #[serde(default)]
    members: Vec<TeamTemplateMemberPayload>,
}

#[derive(Deserialize)]
struct TeamTemplateMemberPayload {
    position: i64,
    #[serde(rename = "characterId")]
    character_id: Option<String>,
    #[serde(rename = "damageCoefficient")]
    damage_coefficient: f64,
    #[serde(default)]
    coefficients: serde_json::Value,
}

#[derive(Deserialize)]
struct UserAccountsRow {
    account_data: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct UserCharactersRow {
    character_data: String,
    updated_at: i64,
}

#[derive(Deserialize)]
struct SaveAccountsRequest {
    account_data: serde_json::Value,
}

#[derive(Deserialize)]
struct SaveCharactersRequest {
    character_data: serde_json::Value,
}

#[derive(Deserialize)]
struct GameAccountLookupRow {
    game_uid: String,
    cookie: Option<String>,
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

fn parse_cookie_digits(cookie: &str, key: &str) -> Option<String> {
    let start = cookie.find(key)? + key.len();
    let mut end = start;
    let bytes = cookie.as_bytes();
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end > start {
        Some(cookie[start..end].to_string())
    } else {
        None
    }
}

fn parse_game_openid(cookie: &str) -> Option<String> {
    parse_cookie_digits(cookie, "game_openid=")
}

fn parse_game_uid(cookie: &str) -> Option<String> {
    parse_cookie_digits(cookie, "game_uid=")
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
                "SELECT id, username, password_hash, avatar_url FROM users WHERE username = ?1 LIMIT 1",
            );
            let row = match stmt.bind(&[body.username.clone().into()]) {
                Ok(s) => match s.first::<UserAuthRow>(None).await {
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

            let mut game_accounts: Vec<GameAccountPayload> = Vec::new();
            let stmt = db.prepare("SELECT game_uid, cookie, updated_at FROM game_accounts WHERE user_id = ?1 ORDER BY updated_at DESC");
            if let Ok(s) = stmt.bind(&[(user.id as i32).into()]) {
                if let Ok(rows) = s.all().await {
                    if let Ok(list) = rows.results::<GameAccountPayload>() {
                        game_accounts = list;
                    }
                }
            }

            json_response(
                &LoginResponse {
                    token,
                    expires_at: exp.timestamp(),
                    username: user.username.clone(),
                    avatar_url: user.avatar_url.clone(),
                    game_accounts,
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
            let stmt = db.prepare("SELECT id, username, password_hash, avatar_url FROM users WHERE id = ?1");
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
                Ok(s) => match s.first::<UserIdRow>(None).await {
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
        .post_async("/change-avatar", |mut req, ctx| async move {
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

            let stmt = db.prepare("SELECT plan_id, plan_name, updated_at FROM raid_plans WHERE user_id = ?1 ORDER BY updated_at DESC");
            let plans = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<RaidPlanMetaRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            if plans.is_empty() {
                return error_response("no cloud data found", 404);
            }

            let slot_stmt = db.prepare("SELECT plan_id, account_key, slot_index, step, predicted_damage, predicted_damage_input FROM raid_plan_slots WHERE user_id = ?1");
            let slot_rows = match slot_stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<RaidPlanSlotRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            let char_stmt = db.prepare("SELECT plan_id, account_key, slot_index, position, character_id FROM raid_plan_slot_characters WHERE user_id = ?1");
            let char_rows = match char_stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<RaidPlanSlotCharRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            use std::collections::HashMap;

            #[derive(Clone)]
            struct SlotData {
                step: Option<i64>,
                predicted_damage: Option<f64>,
                predicted_damage_input: String,
                character_ids: Vec<i64>,
            }

            let mut slot_map: HashMap<String, HashMap<String, HashMap<i64, SlotData>>> = HashMap::new();

            for row in slot_rows {
                let step = if row.step <= 0 { None } else { Some(row.step) };
                let predicted_damage = if row.predicted_damage <= 0.0 {
                    None
                } else {
                    Some(row.predicted_damage)
                };
                slot_map
                    .entry(row.plan_id)
                    .or_default()
                    .entry(row.account_key)
                    .or_default()
                    .insert(
                        row.slot_index,
                        SlotData {
                            step,
                            predicted_damage,
                            predicted_damage_input: row.predicted_damage_input,
                            character_ids: Vec::new(),
                        },
                    );
            }

            for row in char_rows {
                let entry = slot_map
                    .entry(row.plan_id)
                    .or_default()
                    .entry(row.account_key)
                    .or_default()
                    .entry(row.slot_index)
                    .or_insert_with(|| SlotData {
                        step: None,
                        predicted_damage: None,
                        predicted_damage_input: String::new(),
                        character_ids: Vec::new(),
                    });

                if entry.character_ids.len() <= row.position as usize {
                    entry.character_ids.resize(row.position as usize + 1, 0);
                }
                entry.character_ids[row.position as usize] = row.character_id;
            }

            let mut plan_json_list: Vec<serde_json::Value> = Vec::new();
            let mut latest_updated_at = 0_i64;

            for plan in plans.into_iter() {
                if plan.updated_at > latest_updated_at {
                    latest_updated_at = plan.updated_at;
                }

                let mut data_obj = serde_json::Map::new();
                if let Some(account_map) = slot_map.get(&plan.plan_id) {
                    for (account_key, slots) in account_map.iter() {
                        let mut max_index = 2_i64;
                        for idx in slots.keys() {
                            if *idx > max_index {
                                max_index = *idx;
                            }
                        }
                        let target_len = (max_index + 1).max(3) as usize;
                        let mut slot_vec: Vec<serde_json::Value> = vec![serde_json::Value::Null; target_len];
                        for (idx, slot) in slots.iter() {
                            let slot_value = serde_json::json!({
                                "step": slot.step,
                                "characterIds": slot.character_ids,
                                "predictedDamage": slot.predicted_damage,
                                "predictedDamageInput": slot.predicted_damage_input
                            });
                            if (*idx as usize) < slot_vec.len() {
                                slot_vec[*idx as usize] = slot_value;
                            }
                        }
                        data_obj.insert(account_key.clone(), serde_json::Value::Array(slot_vec));
                    }
                }

                plan_json_list.push(serde_json::json!({
                    "id": plan.plan_id,
                    "name": plan.plan_name,
                    "data": serde_json::Value::Object(data_obj),
                    "updatedAt": plan.updated_at
                }));
            }

            json_response(
                &serde_json::json!({
                    "plan_data": plan_json_list,
                    "updated_at": latest_updated_at
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

            let plan_list: Vec<RaidPlanPayload> = match body.plan_data {
                serde_json::Value::Array(arr) => arr
                    .into_iter()
                    .filter_map(|val| serde_json::from_value::<RaidPlanPayload>(val).ok())
                    .collect(),
                _ => Vec::new(),
            };

            let now = Utc::now().timestamp() as f64;

            let lookup_stmt = db.prepare("SELECT game_uid, cookie FROM game_accounts WHERE user_id = ?1");
            let lookup_rows = match lookup_stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<GameAccountLookupRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            use std::collections::HashMap;
            let mut account_key_map: HashMap<String, String> = HashMap::new();
            for row in lookup_rows.into_iter() {
                let uid = row.game_uid.clone();
                account_key_map.insert(uid.clone(), uid.clone());
                if let Some(cookie) = row.cookie {
                    if let Some(openid) = parse_game_openid(&cookie) {
                        account_key_map.insert(openid, uid.clone());
                    }
                }
            }

            let del_stmt = db.prepare("DELETE FROM raid_plan_slot_characters WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old plan characters", 500);
                }
            }
            let del_stmt = db.prepare("DELETE FROM raid_plan_slots WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old plan slots", 500);
                }
            }
            let del_stmt = db.prepare("DELETE FROM raid_plan_accounts WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old plan accounts", 500);
                }
            }
            let del_stmt = db.prepare("DELETE FROM raid_plans WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old plans", 500);
                }
            }

            for plan in plan_list.into_iter() {
                let plan_updated_at = plan.updated_at.unwrap_or(now as i64) as f64;
                let insert_plan = db.prepare("INSERT OR REPLACE INTO raid_plans (user_id, plan_id, plan_name, updated_at) VALUES (?1, ?2, ?3, ?4)");
                match insert_plan.bind(&[
                    (claims.uid as i32).into(),
                    plan.id.clone().into(),
                    plan.name.clone().into(),
                    plan_updated_at.into(),
                ]) {
                    Ok(s) => {
                        if s.run().await.is_err() {
                            return error_response("failed to save plan metadata", 500);
                        }
                    }
                    Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                }

                let data_obj = match plan.data {
                    serde_json::Value::Object(map) => map,
                    _ => serde_json::Map::new(),
                };

                for (account_key, plans_value) in data_obj.into_iter() {
                    let game_uid = account_key_map
                        .get(&account_key)
                        .cloned()
                        .unwrap_or_default();

                    let insert_account = db.prepare("INSERT OR REPLACE INTO raid_plan_accounts (user_id, plan_id, account_key, game_uid, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)");
                    match insert_account.bind(&[
                        (claims.uid as i32).into(),
                        plan.id.clone().into(),
                        account_key.clone().into(),
                        game_uid.into(),
                        plan_updated_at.into(),
                    ]) {
                        Ok(s) => {
                            if s.run().await.is_err() {
                                return error_response("failed to save plan account", 500);
                            }
                        }
                        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                    }

                    let slot_arr = match plans_value {
                        serde_json::Value::Array(arr) => arr,
                        _ => Vec::new(),
                    };

                    for (idx, slot_value) in slot_arr.into_iter().enumerate() {
                        let slot_payload = if slot_value.is_null() {
                            None
                        } else {
                            serde_json::from_value::<PlanSlotPayload>(slot_value).ok()
                        };

                        let (step, predicted_damage, predicted_damage_input, character_ids) = match slot_payload {
                            Some(payload) => (
                                payload.step.unwrap_or(0),
                                payload.predicted_damage.unwrap_or(0.0),
                                payload.predicted_damage_input.unwrap_or_default(),
                                payload.character_ids,
                            ),
                            None => (0, 0.0, String::new(), Vec::new()),
                        };

                        let insert_slot = db.prepare("INSERT OR REPLACE INTO raid_plan_slots (user_id, plan_id, account_key, slot_index, step, predicted_damage, predicted_damage_input, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
                        match insert_slot.bind(&[
                            (claims.uid as i32).into(),
                            plan.id.clone().into(),
                            account_key.clone().into(),
                            (idx as i64).into(),
                            step.into(),
                            predicted_damage.into(),
                            predicted_damage_input.into(),
                            plan_updated_at.into(),
                        ]) {
                            Ok(s) => {
                                if s.run().await.is_err() {
                                    return error_response("failed to save plan slot", 500);
                                }
                            }
                            Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                        }

                        for (pos, char_id) in character_ids.into_iter().enumerate() {
                            let insert_char = db.prepare("INSERT OR REPLACE INTO raid_plan_slot_characters (user_id, plan_id, account_key, slot_index, position, character_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)");
                            match insert_char.bind(&[
                                (claims.uid as i32).into(),
                                plan.id.clone().into(),
                                account_key.clone().into(),
                                (idx as i64).into(),
                                (pos as i64).into(),
                                char_id.into(),
                            ]) {
                                Ok(s) => {
                                    if s.run().await.is_err() {
                                        return error_response("failed to save plan characters", 500);
                                    }
                                }
                                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                            }
                        }
                    }
                }
            }

            json_response(
                &serde_json::json!({
                    "ok": true,
                    "message": "data saved to cloud",
                    "updated_at": now
                }),
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

            let stmt = db.prepare("SELECT template_id, name, created_at, total_damage_coefficient, updated_at FROM team_templates WHERE user_id = ?1 ORDER BY updated_at DESC");
            let templates = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<TeamTemplateMetaRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            if templates.is_empty() {
                return error_response("no cloud data found", 404);
            }

            let member_stmt = db.prepare("SELECT template_id, position, character_id, damage_coefficient, coefficients_json FROM team_template_members WHERE user_id = ?1");
            let members = match member_stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.all().await {
                    Ok(r) => match r.results::<TeamTemplateMemberRow>() {
                        Ok(list) => list,
                        Err(e) => return error_response(&format!("database parse error: {}", e), 500),
                    },
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            use std::collections::HashMap;
            let mut member_map: HashMap<String, Vec<TeamTemplateMemberRow>> = HashMap::new();
            for row in members.into_iter() {
                member_map.entry(row.template_id.clone()).or_default().push(row);
            }

            let mut template_list: Vec<serde_json::Value> = Vec::new();
            let mut latest_updated_at = 0_i64;

            for tpl in templates.into_iter() {
                if tpl.updated_at > latest_updated_at {
                    latest_updated_at = tpl.updated_at;
                }

                let mut members_list: Vec<serde_json::Value> = Vec::new();
                if let Some(mut list) = member_map.remove(&tpl.template_id) {
                    list.sort_by_key(|m| m.position);
                    for m in list.into_iter() {
                        let coeff_value = if m.coefficients_json.trim().is_empty() {
                            serde_json::Value::Null
                        } else {
                            serde_json::from_str(&m.coefficients_json).unwrap_or(serde_json::Value::Null)
                        };
                        members_list.push(serde_json::json!({
                            "position": m.position,
                            "characterId": if m.character_id.trim().is_empty() { serde_json::Value::Null } else { serde_json::Value::String(m.character_id) },
                            "damageCoefficient": m.damage_coefficient,
                            "coefficients": coeff_value
                        }));
                    }
                }

                template_list.push(serde_json::json!({
                    "id": tpl.template_id,
                    "name": tpl.name,
                    "createdAt": tpl.created_at,
                    "totalDamageCoefficient": tpl.total_damage_coefficient,
                    "members": members_list
                }));
            }

            json_response(
                &serde_json::json!({
                    "template_data": template_list,
                    "updated_at": latest_updated_at
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

            let templates: Vec<TeamTemplatePayload> = match body.template_data {
                serde_json::Value::Array(arr) => arr
                    .into_iter()
                    .filter_map(|val| serde_json::from_value::<TeamTemplatePayload>(val).ok())
                    .collect(),
                _ => Vec::new(),
            };

            let now = Utc::now().timestamp() as f64;

            let del_stmt = db.prepare("DELETE FROM team_template_members WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old templates", 500);
                }
            }
            let del_stmt = db.prepare("DELETE FROM team_templates WHERE user_id = ?1");
            if let Ok(s) = del_stmt.bind(&[(claims.uid as i32).into()]) {
                if s.run().await.is_err() {
                    return error_response("failed to clear old templates", 500);
                }
            }

            for tpl in templates.into_iter() {
                let insert_tpl = db.prepare("INSERT OR REPLACE INTO team_templates (user_id, template_id, name, created_at, total_damage_coefficient, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)");
                match insert_tpl.bind(&[
                    (claims.uid as i32).into(),
                    tpl.id.clone().into(),
                    tpl.name.clone().into(),
                    (tpl.created_at as f64).into(),
                    tpl.total_damage_coefficient.into(),
                    now.into(),
                ]) {
                    Ok(s) => {
                        if s.run().await.is_err() {
                            return error_response("failed to save template", 500);
                        }
                    }
                    Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                }

                for member in tpl.members.into_iter() {
                    let coeff_json = if member.coefficients.is_null() {
                        String::new()
                    } else {
                        member.coefficients.to_string()
                    };
                    let insert_member = db.prepare("INSERT OR REPLACE INTO team_template_members (user_id, template_id, position, character_id, damage_coefficient, coefficients_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)");
                    match insert_member.bind(&[
                        (claims.uid as i32).into(),
                        tpl.id.clone().into(),
                        member.position.into(),
                        member.character_id.unwrap_or_default().into(),
                        member.damage_coefficient.into(),
                        coeff_json.into(),
                    ]) {
                        Ok(s) => {
                            if s.run().await.is_err() {
                                return error_response("failed to save template member", 500);
                            }
                        }
                        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                    }
                }
            }

            json_response(
                &serde_json::json!({
                    "ok": true,
                    "message": "data saved to cloud",
                    "updated_at": now
                }),
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
        .get_async("/characters", |req, ctx| async move {
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

            let stmt = db.prepare("SELECT character_data, updated_at FROM user_characters WHERE user_id = ?1");
            let row = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<UserCharactersRow>(None).await {
                    Ok(Some(r)) => r,
                    Ok(None) => return error_response("no cloud data found", 404),
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            let char_json: serde_json::Value = match serde_json::from_str(&row.character_data) {
                Ok(v) => v,
                Err(_) => return error_response("stored data corruption", 500),
            };

            json_response(
                &serde_json::json!({
                    "character_data": char_json,
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

            let now = Utc::now().timestamp() as f64;

            let account_items = match body.account_data {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![body.account_data],
                _ => vec![],
            };

            let mut sanitized_list: Vec<serde_json::Value> = Vec::new();

            for item in account_items.into_iter() {
                let cookie = item
                    .get("cookie")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if cookie.is_empty() {
                    continue;
                }

                let mut game_uid = item
                    .get("game_uid")
                    .or_else(|| item.get("gameUid"))
                    .or_else(|| item.get("gameUID"))
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default();

                if game_uid.is_empty() {
                    if let Some(uid) = parse_game_uid(&cookie) {
                        game_uid = uid;
                    }
                }

                let cookie_updated_at = item
                    .get("cookieUpdatedAt")
                    .or_else(|| item.get("cookie_updated_at"))
                    .and_then(|v| {
                        if let Some(num) = v.as_i64() {
                            Some(num)
                        } else if let Some(num) = v.as_f64() {
                            Some(num as i64)
                        } else if let Some(s) = v.as_str() {
                            s.parse::<i64>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(now as i64);

                let enabled = item
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let id_value = item.get("id").cloned().unwrap_or(serde_json::Value::Null);

                sanitized_list.push(serde_json::json!({
                    "id": id_value,
                    "game_uid": game_uid,
                    "cookie": cookie,
                    "cookieUpdatedAt": cookie_updated_at,
                    "enabled": enabled
                }));

                if game_uid.is_empty() || cookie.is_empty() {
                    continue;
                }

                let stmt = db.prepare(
                    "INSERT OR REPLACE INTO game_accounts (user_id, game_uid, cookie, updated_at) VALUES (?1, ?2, ?3, ?4)",
                );
                match stmt.bind(&[
                    (claims.uid as i32).into(),
                    game_uid.into(),
                    cookie.into(),
                    (cookie_updated_at as f64).into(),
                ]) {
                    Ok(s) => {
                        if s.run().await.is_err() {
                            return error_response("failed to save game account", 500);
                        }
                    }
                    Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                };
            }

            let acc_str = serde_json::Value::Array(sanitized_list).to_string();
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
                &serde_json::json!({
                    "ok": true,
                    "message": "data saved to cloud",
                    "updated_at": now
                }),
                200,
            )
        })
        .post_async("/characters", |mut req, ctx| async move {
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

            let body: SaveCharactersRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return error_response("invalid json format", 400),
            };

            let now = Utc::now().timestamp() as f64;
            let char_str = body.character_data.to_string();

            let stmt = db.prepare("INSERT OR REPLACE INTO user_characters (user_id, character_data, updated_at) VALUES (?1, ?2, ?3)");
            match stmt.bind(&[(claims.uid as i32).into(), char_str.into(), now.into()]) {
                Ok(s) => {
                    if s.run().await.is_err() {
                        return error_response("failed to save data", 500);
                    }
                }
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            json_response(
                &serde_json::json!({
                    "ok": true,
                    "message": "data saved to cloud",
                    "updated_at": now
                }),
                200,
            )
        })
        .post_async("/accounts/merge", |mut req, ctx| async move {
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

            let body: SaveAccountsRequest = match req.json().await {
                Ok(b) => b,
                Err(_) => return error_response("invalid json format", 400),
            };

            let incoming = match body.account_data {
                serde_json::Value::Array(arr) => arr,
                serde_json::Value::Object(_) => vec![body.account_data],
                _ => vec![],
            };

            let stmt = db.prepare("SELECT account_data FROM user_accounts WHERE user_id = ?1");
            let existing_row = match stmt.bind(&[(claims.uid as i32).into()]) {
                Ok(s) => match s.first::<UserAccountsRow>(None).await {
                    Ok(Some(r)) => Some(r),
                    Ok(None) => None,
                    Err(e) => return error_response(&format!("database query error: {}", e), 500),
                },
                Err(e) => return error_response(&format!("database bind error: {}", e), 500),
            };

            let mut existing_list: Vec<serde_json::Value> = if let Some(row) = existing_row {
                match serde_json::from_str::<serde_json::Value>(&row.account_data) {
                    Ok(serde_json::Value::Array(arr)) => arr,
                    Ok(serde_json::Value::Object(obj)) => vec![serde_json::Value::Object(obj)],
                    _ => vec![],
                }
            } else {
                vec![]
            };

            use std::collections::HashMap;
            let mut index_map: HashMap<String, usize> = HashMap::new();
            let get_key = |val: &serde_json::Value| -> Option<String> {
                if let Some(uid) = val.get("game_uid") {
                    if uid.is_string() {
                        return uid.as_str().map(|s| s.to_string());
                    }
                    return Some(uid.to_string());
                }
                if let Some(id) = val.get("id") {
                    if id.is_string() {
                        return id.as_str().map(|s| s.to_string());
                    }
                    return Some(id.to_string());
                }
                None
            };

            for (idx, item) in existing_list.iter().enumerate() {
                if let Some(key) = get_key(item) {
                    index_map.insert(key, idx);
                }
            }

            for item in incoming.into_iter() {
                if let Some(key) = get_key(&item) {
                    if let Some(idx) = index_map.get(&key).copied() {
                        existing_list[idx] = item;
                    } else {
                        existing_list.push(item);
                        index_map.insert(key, existing_list.len() - 1);
                    }
                } else {
                    existing_list.push(item);
                }
            }

            let merged_value = serde_json::Value::Array(existing_list);
            let now = Utc::now().timestamp() as f64;

            let account_items = match &merged_value {
                serde_json::Value::Array(arr) => arr.clone(),
                serde_json::Value::Object(_) => vec![merged_value.clone()],
                _ => vec![],
            };

            let mut sanitized_list: Vec<serde_json::Value> = Vec::new();

            for item in account_items.into_iter() {
                let cookie = item
                    .get("cookie")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if cookie.is_empty() {
                    continue;
                }

                let mut game_uid = item
                    .get("game_uid")
                    .or_else(|| item.get("gameUid"))
                    .or_else(|| item.get("gameUID"))
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_default();

                if game_uid.is_empty() {
                    if let Some(uid) = parse_game_uid(&cookie) {
                        game_uid = uid;
                    }
                }

                let cookie_updated_at = item
                    .get("cookieUpdatedAt")
                    .or_else(|| item.get("cookie_updated_at"))
                    .and_then(|v| {
                        if let Some(num) = v.as_i64() {
                            Some(num)
                        } else if let Some(num) = v.as_f64() {
                            Some(num as i64)
                        } else if let Some(s) = v.as_str() {
                            s.parse::<i64>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(now as i64);

                let enabled = item
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let id_value = item.get("id").cloned().unwrap_or(serde_json::Value::Null);

                sanitized_list.push(serde_json::json!({
                    "id": id_value,
                    "game_uid": game_uid,
                    "cookie": cookie,
                    "cookieUpdatedAt": cookie_updated_at,
                    "enabled": enabled
                }));

                if game_uid.is_empty() || cookie.is_empty() {
                    continue;
                }

                let stmt = db.prepare(
                    "INSERT OR REPLACE INTO game_accounts (user_id, game_uid, cookie, updated_at) VALUES (?1, ?2, ?3, ?4)",
                );
                match stmt.bind(&[
                    (claims.uid as i32).into(),
                    game_uid.into(),
                    cookie.into(),
                    (cookie_updated_at as f64).into(),
                ]) {
                    Ok(s) => {
                        if s.run().await.is_err() {
                            return error_response("failed to save game account", 500);
                        }
                    }
                    Err(e) => return error_response(&format!("database bind error: {}", e), 500),
                };
            }

            let acc_str = serde_json::Value::Array(sanitized_list).to_string();
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
                &serde_json::json!({
                    "ok": true,
                    "message": "data merged to cloud",
                    "updated_at": now
                }),
                200,
            )
        })
        .run(req, env)
        .await
}
