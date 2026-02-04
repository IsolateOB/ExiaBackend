use crate::models::*;
use crate::utils::*;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use worker::*;

pub async fn get_team_template_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

    let mut member_map: HashMap<String, Vec<TeamTemplateMemberRow>> = HashMap::new();
    for row in members.into_iter() {
        member_map
            .entry(row.template_id.clone())
            .or_default()
            .push(row);
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
}

pub async fn save_team_template_handler(
    mut req: Request,
    ctx: RouteContext<()>,
) -> Result<Response> {
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
}
