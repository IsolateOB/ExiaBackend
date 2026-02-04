use crate::models::*;
use crate::utils::*;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use worker::*;

pub async fn get_accounts_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    let stmt = db.prepare("SELECT list_id, name, data, updated_at FROM account_lists WHERE user_id = ?1 ORDER BY list_id");
    let rows = match stmt.bind(&[(claims.uid as i32).into()]) {
        Ok(s) => match s.all().await {
            Ok(r) => match r.results::<AccountListRow>() {
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

    let body: SaveListsRequest = match req.json().await {
        Ok(b) => b,
        Err(_) => return error_response("invalid json format", 400),
    };

    let now = Utc::now().timestamp() as i64;

    let delete_stmt = db.prepare("DELETE FROM account_lists WHERE user_id = ?1");
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

        let stmt = db.prepare("INSERT OR REPLACE INTO account_lists (user_id, list_id, name, data, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)");
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

pub async fn merge_accounts_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

        let email = item
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        let password = item
            .get("password")
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
            "enabled": enabled,
            "email": email,
            "password": password
        }));

        if game_uid.is_empty() || cookie.is_empty() {
            continue;
        }

        let stmt = db.prepare(
            "INSERT OR REPLACE INTO game_accounts (user_id, game_uid, cookie, updated_at, email, password) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        );
        match stmt.bind(&[
            (claims.uid as i32).into(),
            game_uid.into(),
            cookie.into(),
            (cookie_updated_at as f64).into(),
            if email.is_empty() {
                None::<String>
            } else {
                Some(email)
            }
            .into(),
            if password.is_empty() {
                None::<String>
            } else {
                Some(password)
            }
            .into(),
        ]) {
            Ok(s) => {
                if s.run().await.is_err() {
                    return error_response("failed to save game account", 500);
                }
            }
            Err(e) => return error_response(&format!("database bind error: {}", e), 500),
        };
    }

    let insert_stmt = db.prepare(
        "INSERT OR REPLACE INTO user_accounts (user_id, account_data, updated_at) VALUES (?1, ?2, ?3)",
    );
    match insert_stmt.bind(&[
        (claims.uid as i32).into(),
        serde_json::to_string(&sanitized_list)
            .unwrap_or_default()
            .into(),
        now.into(),
    ]) {
        Ok(s) => {
            if s.run().await.is_err() {
                return error_response("failed to save account data", 500);
            }
        }
        Err(e) => return error_response(&format!("database bind error: {}", e), 500),
    };

    json_response(
        &serde_json::json!({
            "ok": true,
            "message": "account data merged and saved",
            "updated_at": now
        }),
        200,
    )
}
