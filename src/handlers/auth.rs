use crate::models::*;
use crate::utils::*;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{Duration, Utc};
use worker::*;

pub async fn login_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    if body.username.trim().is_empty() {
        return error_response("missing username", 400);
    }

    // Password is now always required
    if body.password.trim().is_empty() {
        return error_response("missing password", 400);
    }

    let stmt = db.prepare(
        "SELECT id, username, password_hash, restricted_password_hash, avatar_url FROM users WHERE username = ?1 LIMIT 1",
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

    // Try main password first
    let main_hash = match PasswordHash::new(&user.password_hash) {
        Ok(h) => h,
        Err(e) => {
            console_error!("Password hash parse error: {:?}", e);
            return error_response("internal error: invalid password hash", 500);
        }
    };

    let restricted;

    if Argon2::default()
        .verify_password(body.password.as_bytes(), &main_hash)
        .is_ok()
    {
        // Main password matched — full access
        restricted = false;
    } else if let Some(ref rph) = user.restricted_password_hash {
        // Try restricted password
        let restricted_hash = match PasswordHash::new(rph) {
            Ok(h) => h,
            Err(e) => {
                console_error!("Restricted password hash parse error: {:?}", e);
                return error_response("internal error", 500);
            }
        };
        if Argon2::default()
            .verify_password(body.password.as_bytes(), &restricted_hash)
            .is_ok()
        {
            restricted = true;
        } else {
            return error_response("incorrect password", 401);
        }
    } else {
        // No restricted password set, and main password didn't match
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
        restricted,
    };

    let token = match encode_claims_token(&claims, &secret) {
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
            username: user.username.clone(),
            avatar_url: user.avatar_url.clone(),
            restricted_mode: restricted,
        },
        200,
    )
}

pub async fn register_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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
    let stmt =
        db.prepare("INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)");
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
}
