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
        .set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
            let db = env.d1("DB")?;

            let body: LoginRequest = req
                .json()
                .await
                .map_err(|_| Error::RustError("invalid json".into()))?;
            if body.username.trim().is_empty() || body.password.trim().is_empty() {
                return error_response("missing credentials", 400);
            }

            let stmt = db.prepare(
                "SELECT id, username, password_hash FROM users WHERE username = ?1 LIMIT 1",
            );
            let row = stmt
                .bind(&[body.username.clone().into()])?
                .first::<UserRow>(None)
                .await?;

            let user = match row {
                Some(u) => u,
                None => return error_response("invalid credentials", 401),
            };

            let parsed_hash = PasswordHash::new(&user.password_hash)
                .map_err(|_| Error::RustError("invalid password hash".into()))?;

            if Argon2::default()
                .verify_password(body.password.as_bytes(), &parsed_hash)
                .is_err()
            {
                return error_response("invalid credentials", 401);
            }

            let now = Utc::now();
            let exp = now + Duration::hours(24);
            let secret = get_jwt_secret(&env)?;
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

            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            )
            .map_err(|_| Error::RustError("token encode failed".into()))?;

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

            let created_at = Utc::now().timestamp() as i32;
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
        .run(req, env)
        .await
}
