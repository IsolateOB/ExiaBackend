use crate::models::*;
use crate::utils::*;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use worker::*;

#[derive(Clone)]
struct SlotData {
    step: Option<i64>,
    predicted_damage: Option<f64>,
    predicted_damage_input: String,
    character_ids: Vec<i64>,
}

pub async fn get_raid_plan_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
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
                let mut slot_vec: Vec<serde_json::Value> =
                    vec![serde_json::Value::Null; target_len];
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
}

pub async fn save_raid_plan_handler(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
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

                let (step, predicted_damage, predicted_damage_input, character_ids) =
                    match slot_payload {
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
                        Err(e) => {
                            return error_response(&format!("database bind error: {}", e), 500)
                        }
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
}
