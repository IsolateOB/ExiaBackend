use serde::Serialize;
use worker::*;

pub fn cors_headers() -> Headers {
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

pub fn parse_cookie_digits(cookie: &str, key: &str) -> Option<String> {
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

pub fn parse_game_openid(cookie: &str) -> Option<String> {
    parse_cookie_digits(cookie, "game_openid=")
}

pub fn parse_game_uid(cookie: &str) -> Option<String> {
    parse_cookie_digits(cookie, "game_uid=")
}

pub fn normalize_list_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

pub fn json_response<T: Serialize>(value: &T, status: u16) -> Result<Response> {
    let mut res = Response::from_json(value)?;
    res = res.with_status(status);
    res.headers_mut().set("Content-Type", "application/json")?;
    let cors = cors_headers();
    for (k, v) in cors.entries() {
        res.headers_mut().set(&k, &v)?;
    }
    Ok(res)
}

pub fn error_response(message: &str, status: u16) -> Result<Response> {
    let body = serde_json::json!({"error": message});
    json_response(&body, status)
}

pub fn get_jwt_secret(env: &Env) -> Result<String> {
    Ok(env.secret("JWT_SECRET")?.to_string())
}
