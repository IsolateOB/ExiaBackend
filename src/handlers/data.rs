use crate::models::*;
use crate::utils::*;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use worker::*;

pub async fn get_accounts_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    let stmt = db.prepare("SELECT game_uid, cookie, updated_at, email, password, username FROM game_accounts WHERE user_id = ?1 ORDER BY updated_at DESC");
    let rows = match stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => match s.all().await {
            Ok(r) => match r.results::<GameAccountPayload>() {
                Ok(list) => list,
                Err(e) => return error_response(&format!("database parse error: {}", e), 500),
            },
            Err(e) => return error_response(&format!("database query error: {}", e), 500),
        },
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    if rows.is_empty() {
        return json_response(
            &serde_json::json!({
                "lists": [],
                "updated_at": 0
            }),
            200,
        );
    }

    let mut accounts: Vec<serde_json::Value> = Vec::new();
    let mut max_updated_at: i64 = 0;

    for acc in rows {
        if acc.updated_at > max_updated_at {
            max_updated_at = acc.updated_at;
        }

        if claims.restricted {
            accounts.push(serde_json::json!({
                "game_uid": acc.game_uid,
                "cookie": acc.cookie,
                "cookieUpdatedAt": acc.updated_at,
                "username": acc.username,
                // In restricted mode, we only return essential fields.
                // email, password are deliberately omitted.
            }));
        } else {
            accounts.push(serde_json::json!({
                "game_uid": acc.game_uid,
                "cookie": acc.cookie,
                "cookieUpdatedAt": acc.updated_at,
                "email": acc.email,
                "password": acc.password,
                "username": acc.username,
            }));
        }
    }

    // Wrap in a structure similar to the original "list" format to minimize frontend breakage,
    // or just return the flat list if the frontend expects it.
    // Based on previous code, frontend expects "lists": [{ "data": ... }] or similar.
    // The previous code returned "lists" array where each item had "data" JSON.
    // Since we are changing the paradigm, we'll return a single "default" list containing these accounts.

    let default_list = serde_json::json!({
        "id": "default",
        "name": "Default List",
        "data": accounts,
        "updated_at": max_updated_at
    });

    json_response(
        &serde_json::json!({
            "lists": [default_list],
            "updated_at": max_updated_at
        }),
        200,
    )
}

pub async fn get_characters_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    let stmt = db.prepare("SELECT list_id, name, data, updated_at FROM character_lists WHERE user_id = ?1 ORDER BY list_id");
    let rows = match stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => match s.all().await {
            Ok(r) => match r.results::<CharacterListRow>() {
                Ok(list) => list,
                Err(e) => return error_response(&format!("database parse error: {}", e), 500),
            },
            Err(e) => return error_response(&format!("database query error: {}", e), 500),
        },
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    if rows.is_empty() {
        return error_response("no cloud data found", 404);
    }

    let mut lists: Vec<serde_json::Value> = Vec::new();
    let mut max_updated_at: i64 = 0;
    for row in rows.into_iter() {
        let data_json: serde_json::Value = match serde_json::from_str(&row.data) {
            Ok(v) => v,
            Err(_) => return error_response("stored data corruption", 500),
        };
        if row.updated_at > max_updated_at {
            max_updated_at = row.updated_at;
        }
        lists.push(serde_json::json!({
            "id": row.list_id,
            "name": row.name,
            "data": data_json,
            "updated_at": row.updated_at
        }));
    }

    json_response(
        &serde_json::json!({
            "lists": lists,
            "updated_at": max_updated_at
        }),
        200,
    )
}

pub async fn save_accounts_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    if claims.restricted {
        return error_response("restricted mode", 403);
    }

    let body: SaveListsRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    let now = Utc::now().timestamp() as i64;
    let now_f64 = now as f64;

    // Clear existing accounts for this user to perform a full sync/replace
    // (Or we can use REPLACE INTO, but we might want to delete stale ones.
    // Given the previous logic was list-based, let's assume a full replace logic for simplicity/correctness with the new model)
    // However, if we delete all, we lose history unless the frontend sends everything.
    // The safest approach for "sync" is usually DELETE WHERE user_id=? then INSERT.
    let delete_stmt = db.prepare("DELETE FROM game_accounts WHERE user_id = ?1");
    match delete_stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to clear old accounts", 500);
            }
        }
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    // Process all lists (usually just one default list now)
    for list in body.lists {
        let account_list = match list.data {
            serde_json::Value::Array(arr) => arr,
            serde_json::Value::Object(_) => vec![list.data],
            _ => continue,
        };

        for item in account_list {
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

            if game_uid.is_empty() {
                continue;
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
                .unwrap_or(now);

            let email = item
                .get("email")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());

            let password = item
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());

            let username = item
                .get("username")
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());

            let stmt = db.prepare(
                "INSERT INTO game_accounts (user_id, game_uid, cookie, updated_at, email, password, username) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            );
            match stmt.bind(&[
                (claims.uid as i32).into(),
                game_uid.into(),
                cookie.into(),
                (cookie_updated_at as f64).into(),
                email.into(),
                password.into(),
                username.into(),
            ]) {
                Ok(s) => {
                    if s.run().await.is_err() {
                        return error_response("failed to save account", 500);
                    }
                }
                Err(e) => {
                    return error_response(&format!("database insert bind error: {}", e), 500)
                }
            };
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
}

pub async fn save_characters_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    if claims.restricted {
        return error_response("restricted mode", 403);
    }

    let body: SaveListsRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    let now = Utc::now().timestamp() as i64;

    let delete_stmt = db.prepare("DELETE FROM character_lists WHERE user_id = ?1");
    match delete_stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to clear lists", 500);
            }
        }
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    for item in body.lists.into_iter() {
        let list_id = match normalize_list_id(&item.id) {
            Some(v) => v,
            None => continue,
        };
        let name = item.name.unwrap_or_default();
        let data_str = item.data.to_string();

        let stmt = db.prepare("INSERT OR REPLACE INTO character_lists (user_id, list_id, name, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)");
        match stmt.bind(&[
            (claims.uid as i32).into(),
            list_id.into(),
            name.into(),
            data_str.into(),
            (now as f64).into(),
        ]) {
            Ok(s) => {
                if s.run().await.is_err() {
                    return error_response("failed to save list", 500);
                }
            }
            Err(e) => return error_response(&format!("database bind error: {}", e), 500),
        };
    }

    json_response(
        &serde_json::json!({
            "ok": true,
            "message": "data saved to cloud",
            "updated_at": now
        }),
        200,
    )
}
