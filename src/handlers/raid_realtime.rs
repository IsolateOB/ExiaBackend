use crate::models::{
    Claims, GameAccountLookupRow, RaidPlanMetaRow, RaidPlanSlotCharRow, RaidPlanSlotRow,
};
use crate::utils::{
    decode_claims_token, error_response, get_jwt_secret, json_response, parse_game_openid,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use worker::*;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RaidPlanRealtimeSlot {
    pub step: Option<i64>,
    #[serde(rename = "predictedDamage")]
    pub predicted_damage: Option<f64>,
    #[serde(default, rename = "characterIds")]
    pub character_ids: Vec<i64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RaidPlanRealtimePlan {
    pub id: String,
    pub name: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    pub data: HashMap<String, Vec<RaidPlanRealtimeSlot>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SlotFieldValue {
    Step(Option<i64>),
    PredictedDamage(Option<f64>),
    CharacterIds(Vec<i64>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SlotUpdateFieldPayload {
    pub plan_id: String,
    pub account_key: String,
    pub slot_index: usize,
    pub field: String,
    pub value: SlotFieldValue,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RaidPlanRealtimePatch {
    SlotUpdateField {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        payload: SlotUpdateFieldPayload,
    },
    PlanRename {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        plan_id: String,
        name: String,
    },
    PlanCreate {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        plan_id: String,
        name: String,
    },
    PlanDelete {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        plan_id: String,
    },
    PlanDuplicate {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        source_plan_id: String,
        new_plan_id: String,
        name: String,
    },
}

fn ensure_slot_len(slots: &mut Vec<RaidPlanRealtimeSlot>, slot_index: usize) {
    while slots.len() <= slot_index {
        slots.push(RaidPlanRealtimeSlot {
            step: None,
            predicted_damage: None,
            character_ids: Vec::new(),
        });
    }
}

pub fn apply_patch_to_snapshot(
    plans: &[RaidPlanRealtimePlan],
    patch: &RaidPlanRealtimePatch,
    updated_at: i64,
) -> Vec<RaidPlanRealtimePlan> {
    let mut next = plans.to_vec();

    match patch {
        RaidPlanRealtimePatch::SlotUpdateField { payload, .. } => {
            if let Some(plan) = next.iter_mut().find(|plan| plan.id == payload.plan_id) {
                let slots = plan
                    .data
                    .entry(payload.account_key.clone())
                    .or_insert_with(Vec::new);
                ensure_slot_len(slots, payload.slot_index);
                let slot = &mut slots[payload.slot_index];

                match &payload.value {
                    SlotFieldValue::Step(value) if payload.field == "step" => {
                        slot.step = *value;
                    }
                    SlotFieldValue::PredictedDamage(value)
                        if payload.field == "predictedDamage" =>
                    {
                        slot.predicted_damage = *value;
                    }
                    SlotFieldValue::CharacterIds(value) if payload.field == "characterIds" => {
                        slot.character_ids = value.clone();
                    }
                    _ => {}
                }

                plan.updated_at = updated_at;
            }
        }
        RaidPlanRealtimePatch::PlanRename { plan_id, name, .. } => {
            if let Some(plan) = next.iter_mut().find(|plan| &plan.id == plan_id) {
                plan.name = name.clone();
                plan.updated_at = updated_at;
            }
        }
        RaidPlanRealtimePatch::PlanCreate { plan_id, name, .. } => {
            if !next.iter().any(|plan| &plan.id == plan_id) {
                next.push(RaidPlanRealtimePlan {
                    id: plan_id.clone(),
                    name: name.clone(),
                    updated_at,
                    data: HashMap::new(),
                });
            }
        }
        RaidPlanRealtimePatch::PlanDelete { plan_id, .. } => {
            next.retain(|plan| &plan.id != plan_id);
        }
        RaidPlanRealtimePatch::PlanDuplicate {
            source_plan_id,
            new_plan_id,
            name,
            ..
        } => {
            if !next.iter().any(|plan| &plan.id == new_plan_id) {
                if let Some(source) = next.iter().find(|plan| &plan.id == source_plan_id).cloned() {
                    next.push(RaidPlanRealtimePlan {
                        id: new_plan_id.clone(),
                        name: name.clone(),
                        updated_at,
                        data: source.data,
                    });
                }
            }
        }
    }

    next
}

#[derive(Deserialize)]
struct DocumentRevisionRow {
    revision: i64,
}

#[derive(Deserialize)]
struct PatchEventRow {
    revision: i64,
    patch_json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum RaidRealtimeClientMessage {
    #[serde(rename = "hello")]
    Hello {
        token: String,
        #[serde(rename = "documentId")]
        document_id: String,
        #[serde(rename = "lastRevision")]
        last_revision: i64,
        #[serde(rename = "sessionId")]
        session_id: String,
    },
    #[serde(rename = "patch")]
    Patch(RaidRealtimePatchMessage),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RaidRealtimePatchMessage {
    #[serde(rename = "clientMutationId")]
    pub client_mutation_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "baseRevision")]
    pub base_revision: i64,
    pub op: String,
    pub payload: Value,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum RaidRealtimeServerMessage<'a> {
    #[serde(rename = "snapshot")]
    Snapshot {
        revision: i64,
        plans: &'a [RaidPlanRealtimePlan],
    },
    #[serde(rename = "patch_replay")]
    PatchReplay {
        revision: i64,
        patches: &'a [RaidRealtimePatchMessage],
    },
    #[serde(rename = "ack")]
    Ack {
        revision: i64,
        #[serde(rename = "clientMutationId")]
        client_mutation_id: &'a str,
        #[serde(rename = "appliedPatch")]
        applied_patch: &'a RaidRealtimePatchMessage,
    },
    #[serde(rename = "patch_broadcast")]
    PatchBroadcast {
        revision: i64,
        patch: &'a RaidRealtimePatchMessage,
        #[serde(rename = "sessionId")]
        session_id: &'a str,
    },
    #[serde(rename = "error")]
    Error { code: &'a str, message: &'a str },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct SocketAttachment {
    user_id: i64,
    session_id: String,
}

#[derive(Deserialize)]
struct PlanIdPayload {
    #[serde(rename = "planId")]
    plan_id: String,
}

#[derive(Deserialize)]
struct PlanRenamePayload {
    #[serde(rename = "planId")]
    plan_id: String,
    name: String,
}

#[derive(Deserialize)]
struct PlanCreatePayload {
    #[serde(rename = "planId")]
    plan_id: String,
    name: String,
}

#[derive(Deserialize)]
struct PlanDuplicatePayload {
    #[serde(rename = "sourcePlanId")]
    source_plan_id: String,
    #[serde(rename = "newPlanId")]
    new_plan_id: String,
    name: String,
}

#[derive(Deserialize)]
struct SlotUpdateFieldPayloadDto {
    #[serde(rename = "planId")]
    plan_id: String,
    #[serde(rename = "accountKey")]
    account_key: String,
    #[serde(rename = "slotIndex")]
    slot_index: usize,
    field: String,
    value: Value,
}

fn validate_token(env: &Env, token: &str) -> Result<Claims> {
    let secret = get_jwt_secret(env)?;
    decode_claims_token(token, &secret, Utc::now().timestamp())
        .map_err(|_| Error::RustError("invalid or expired token".into()))
}

fn parse_patch_message(message: &RaidRealtimePatchMessage) -> Result<RaidPlanRealtimePatch> {
    match message.op.as_str() {
        "slot.updateField" => {
            let payload: SlotUpdateFieldPayloadDto =
                serde_json::from_value(message.payload.clone())
                    .map_err(|_| Error::RustError("invalid slot.updateField payload".into()))?;
            let value = match payload.field.as_str() {
                "step" => SlotFieldValue::Step(payload.value.as_i64()),
                "predictedDamage" => SlotFieldValue::PredictedDamage(payload.value.as_f64()),
                "characterIds" => {
                    let ids = payload
                        .value
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|item| item.as_i64())
                        .collect();
                    SlotFieldValue::CharacterIds(ids)
                }
                _ => return Err(Error::RustError("unsupported slot field".into())),
            };

            Ok(RaidPlanRealtimePatch::SlotUpdateField {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                payload: SlotUpdateFieldPayload {
                    plan_id: payload.plan_id,
                    account_key: payload.account_key,
                    slot_index: payload.slot_index,
                    field: payload.field,
                    value,
                },
            })
        }
        "plan.rename" => {
            let payload: PlanRenamePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid plan.rename payload".into()))?;
            Ok(RaidPlanRealtimePatch::PlanRename {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                plan_id: payload.plan_id,
                name: payload.name,
            })
        }
        "plan.create" => {
            let payload: PlanCreatePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid plan.create payload".into()))?;
            Ok(RaidPlanRealtimePatch::PlanCreate {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                plan_id: payload.plan_id,
                name: payload.name,
            })
        }
        "plan.delete" => {
            let payload: PlanIdPayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid plan.delete payload".into()))?;
            Ok(RaidPlanRealtimePatch::PlanDelete {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                plan_id: payload.plan_id,
            })
        }
        "plan.duplicate" => {
            let payload: PlanDuplicatePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid plan.duplicate payload".into()))?;
            Ok(RaidPlanRealtimePatch::PlanDuplicate {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                source_plan_id: payload.source_plan_id,
                new_plan_id: payload.new_plan_id,
                name: payload.name,
            })
        }
        _ => Err(Error::RustError("unsupported patch op".into())),
    }
}

async fn load_document_revision(env: &Env, user_id: i64) -> Result<i64> {
    let db = env.d1("DB")?;
    let stmt = db.prepare(
        "SELECT revision FROM raid_plan_documents WHERE user_id = ?1 AND document_id = ?2",
    );
    let result = stmt
        .bind(&[(user_id as i32).into(), "raid-plan".into()])?
        .all()
        .await?;
    let rows = result
        .results::<DocumentRevisionRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;
    Ok(rows.first().map(|row| row.revision).unwrap_or(0))
}

async fn load_snapshot(env: &Env, user_id: i64) -> Result<Vec<RaidPlanRealtimePlan>> {
    let db = env.d1("DB")?;
    let plans = db
        .prepare("SELECT plan_id, plan_name, updated_at FROM raid_plans WHERE user_id = ?1 ORDER BY updated_at DESC")
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<RaidPlanMetaRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let slot_rows = db
        .prepare("SELECT plan_id, account_key, slot_index, step, predicted_damage FROM raid_plan_slots WHERE user_id = ?1")
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<RaidPlanSlotRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let char_rows = db
        .prepare("SELECT plan_id, account_key, slot_index, position, character_id FROM raid_plan_slot_characters WHERE user_id = ?1")
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<RaidPlanSlotCharRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let mut slot_map: HashMap<String, HashMap<String, HashMap<i64, RaidPlanRealtimeSlot>>> =
        HashMap::new();

    for row in slot_rows {
        slot_map
            .entry(row.plan_id)
            .or_default()
            .entry(row.account_key)
            .or_default()
            .insert(
                row.slot_index,
                RaidPlanRealtimeSlot {
                    step: if row.step <= 0 { None } else { Some(row.step) },
                    predicted_damage: if row.predicted_damage <= 0.0 {
                        None
                    } else {
                        Some(row.predicted_damage)
                    },
                    character_ids: Vec::new(),
                },
            );
    }

    for row in char_rows {
        let slot = slot_map
            .entry(row.plan_id)
            .or_default()
            .entry(row.account_key)
            .or_default()
            .entry(row.slot_index)
            .or_insert(RaidPlanRealtimeSlot {
                step: None,
                predicted_damage: None,
                character_ids: Vec::new(),
            });
        while slot.character_ids.len() <= row.position as usize {
            slot.character_ids.push(0);
        }
        slot.character_ids[row.position as usize] = row.character_id;
    }

    Ok(plans
        .into_iter()
        .map(|plan| {
            let data = slot_map
                .remove(&plan.plan_id)
                .unwrap_or_default()
                .into_iter()
                .map(|(account_key, slots)| {
                    let max_index = slots.keys().copied().max().unwrap_or(2).max(2) as usize;
                    let mut values = vec![
                        RaidPlanRealtimeSlot {
                            step: None,
                            predicted_damage: None,
                            character_ids: Vec::new(),
                        };
                        max_index + 1
                    ];
                    for (idx, slot) in slots {
                        values[idx as usize] = slot;
                    }
                    (account_key, values)
                })
                .collect();

            RaidPlanRealtimePlan {
                id: plan.plan_id,
                name: plan.plan_name,
                updated_at: plan.updated_at,
                data,
            }
        })
        .collect())
}

async fn load_account_key_map(env: &Env, user_id: i64) -> Result<HashMap<String, String>> {
    let db = env.d1("DB")?;
    let rows = db
        .prepare("SELECT game_uid, cookie FROM game_accounts WHERE user_id = ?1")
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<GameAccountLookupRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let mut account_key_map = HashMap::new();
    for row in rows {
        account_key_map.insert(row.game_uid.clone(), row.game_uid.clone());
        if let Some(cookie) = row.cookie {
            if let Some(openid) = parse_game_openid(&cookie) {
                account_key_map.insert(openid, row.game_uid.clone());
            }
        }
    }

    Ok(account_key_map)
}

async fn persist_snapshot(
    env: &Env,
    user_id: i64,
    revision: i64,
    plans: &[RaidPlanRealtimePlan],
) -> Result<()> {
    let db = env.d1("DB")?;
    let account_key_map = load_account_key_map(env, user_id).await?;
    let now = Utc::now().timestamp();

    for sql in [
        "DELETE FROM raid_plan_slot_characters WHERE user_id = ?1",
        "DELETE FROM raid_plan_slots WHERE user_id = ?1",
        "DELETE FROM raid_plan_accounts WHERE user_id = ?1",
        "DELETE FROM raid_plans WHERE user_id = ?1",
    ] {
        db.prepare(sql)
            .bind(&[(user_id as i32).into()])?
            .run()
            .await?;
    }

    for plan in plans {
        let plan_updated_at = if plan.updated_at > 0 {
            plan.updated_at
        } else {
            now
        };
        db.prepare(
            "INSERT OR REPLACE INTO raid_plans (user_id, plan_id, plan_name, updated_at) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&[
            (user_id as i32).into(),
            plan.id.clone().into(),
            plan.name.clone().into(),
            plan_updated_at.into(),
        ])?
        .run()
        .await?;

        for (account_key, slots) in &plan.data {
            let game_uid = account_key_map
                .get(account_key)
                .cloned()
                .unwrap_or_default();
            db.prepare(
                "INSERT OR REPLACE INTO raid_plan_accounts (user_id, plan_id, account_key, game_uid, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&[
                (user_id as i32).into(),
                plan.id.clone().into(),
                account_key.clone().into(),
                game_uid.into(),
                plan_updated_at.into(),
            ])?
            .run()
            .await?;

            for (slot_index, slot) in slots.iter().enumerate() {
                db.prepare(
                    "INSERT OR REPLACE INTO raid_plan_slots (user_id, plan_id, account_key, slot_index, step, predicted_damage, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .bind(&[
                    (user_id as i32).into(),
                    plan.id.clone().into(),
                    account_key.clone().into(),
                    (slot_index as i32).into(),
                    slot.step.unwrap_or(0).into(),
                    slot.predicted_damage.unwrap_or(0.0).into(),
                    plan_updated_at.into(),
                ])?
                .run()
                .await?;

                for (position, character_id) in slot.character_ids.iter().enumerate() {
                    db.prepare(
                        "INSERT OR REPLACE INTO raid_plan_slot_characters (user_id, plan_id, account_key, slot_index, position, character_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    )
                    .bind(&[
                        (user_id as i32).into(),
                        plan.id.clone().into(),
                        account_key.clone().into(),
                        (slot_index as i32).into(),
                        (position as i32).into(),
                        (*character_id as i32).into(),
                    ])?
                    .run()
                    .await?;
                }
            }
        }
    }

    db.prepare(
        "INSERT OR REPLACE INTO raid_plan_documents (user_id, document_id, revision, updated_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&[
        (user_id as i32).into(),
        "raid-plan".into(),
        revision.into(),
        now.into(),
    ])?
    .run()
    .await?;

    Ok(())
}

async fn find_existing_patch(
    env: &Env,
    user_id: i64,
    client_mutation_id: &str,
) -> Result<Option<(i64, RaidRealtimePatchMessage)>> {
    let db = env.d1("DB")?;
    let rows = db
        .prepare(
            "SELECT revision, session_id, client_mutation_id, patch_json FROM raid_plan_patch_events WHERE user_id = ?1 AND document_id = ?2 AND client_mutation_id = ?3 LIMIT 1",
        )
        .bind(&[
            (user_id as i32).into(),
            "raid-plan".into(),
            client_mutation_id.into(),
        ])?
        .all()
        .await?
        .results::<PatchEventRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };

    let patch: RaidRealtimePatchMessage = serde_json::from_str(&row.patch_json)
        .map_err(|_| Error::RustError("stored patch json is invalid".into()))?;
    Ok(Some((row.revision, patch)))
}

async fn record_patch_event(
    env: &Env,
    user_id: i64,
    revision: i64,
    patch: &RaidRealtimePatchMessage,
) -> Result<()> {
    let db = env.d1("DB")?;
    let patch_json = serde_json::to_string(patch)
        .map_err(|_| Error::RustError("patch serialize failed".into()))?;
    let now = Utc::now().timestamp();

    db.prepare(
        "INSERT OR REPLACE INTO raid_plan_patch_events (user_id, document_id, revision, client_mutation_id, session_id, op, patch_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&[
        (user_id as i32).into(),
        "raid-plan".into(),
        revision.into(),
        patch.client_mutation_id.clone().into(),
        patch.session_id.clone().into(),
        patch.op.clone().into(),
        patch_json.into(),
        now.into(),
    ])?
    .run()
    .await?;

    let prune_before = revision - 200;
    if prune_before > 0 {
        db.prepare(
            "DELETE FROM raid_plan_patch_events WHERE user_id = ?1 AND document_id = ?2 AND revision <= ?3",
        )
        .bind(&[
            (user_id as i32).into(),
            "raid-plan".into(),
            prune_before.into(),
        ])?
        .run()
        .await?;
    }

    Ok(())
}

async fn load_patch_replay(
    env: &Env,
    user_id: i64,
    last_revision: i64,
    current_revision: i64,
) -> Result<Option<Vec<RaidRealtimePatchMessage>>> {
    if last_revision >= current_revision {
        return Ok(Some(Vec::new()));
    }

    let db = env.d1("DB")?;
    let rows = db
        .prepare(
            "SELECT revision, session_id, client_mutation_id, patch_json FROM raid_plan_patch_events WHERE user_id = ?1 AND document_id = ?2 AND revision > ?3 ORDER BY revision ASC",
        )
        .bind(&[
            (user_id as i32).into(),
            "raid-plan".into(),
            last_revision.into(),
        ])?
        .all()
        .await?
        .results::<PatchEventRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    if rows.len() != (current_revision - last_revision) as usize {
        return Ok(None);
    }

    let mut expected_revision = last_revision + 1;
    let mut patches = Vec::with_capacity(rows.len());
    for row in rows {
        if row.revision != expected_revision {
            return Ok(None);
        }
        let patch: RaidRealtimePatchMessage = serde_json::from_str(&row.patch_json)
            .map_err(|_| Error::RustError("stored patch json is invalid".into()))?;
        patches.push(patch);
        expected_revision += 1;
    }

    Ok(Some(patches))
}

fn send_server_message(ws: &WebSocket, message: &RaidRealtimeServerMessage<'_>) -> Result<()> {
    ws.send(message)
}

#[durable_object]
pub struct RaidPlanRoom {
    state: State,
    env: Env,
}

impl RaidPlanRoom {
    async fn handle_hello(
        &self,
        ws: &WebSocket,
        token: String,
        document_id: String,
        last_revision: i64,
        session_id: String,
    ) -> Result<()> {
        if document_id != "raid-plan" {
            return send_server_message(
                ws,
                &RaidRealtimeServerMessage::Error {
                    code: "invalid_document",
                    message: "unsupported document id",
                },
            );
        }

        let claims = validate_token(&self.env, &token)?;
        ws.serialize_attachment(SocketAttachment {
            user_id: claims.uid,
            session_id,
        })?;

        let revision = load_document_revision(&self.env, claims.uid).await?;
        if let Some(patches) =
            load_patch_replay(&self.env, claims.uid, last_revision, revision).await?
        {
            if !patches.is_empty() {
                return send_server_message(
                    ws,
                    &RaidRealtimeServerMessage::PatchReplay {
                        revision,
                        patches: &patches,
                    },
                );
            }
        }

        let plans = load_snapshot(&self.env, claims.uid).await?;
        send_server_message(
            ws,
            &RaidRealtimeServerMessage::Snapshot {
                revision,
                plans: &plans,
            },
        )
    }

    async fn handle_patch(
        &self,
        ws: &WebSocket,
        patch_message: RaidRealtimePatchMessage,
    ) -> Result<()> {
        let attachment = ws
            .deserialize_attachment::<SocketAttachment>()?
            .unwrap_or_default();
        if attachment.user_id <= 0 {
            return send_server_message(
                ws,
                &RaidRealtimeServerMessage::Error {
                    code: "not_initialized",
                    message: "hello must be sent before patch",
                },
            );
        }

        if let Some((revision, stored_patch)) = find_existing_patch(
            &self.env,
            attachment.user_id,
            &patch_message.client_mutation_id,
        )
        .await?
        {
            return send_server_message(
                ws,
                &RaidRealtimeServerMessage::Ack {
                    revision,
                    client_mutation_id: &stored_patch.client_mutation_id,
                    applied_patch: &stored_patch,
                },
            );
        }

        let current_revision = load_document_revision(&self.env, attachment.user_id).await?;
        let plans = load_snapshot(&self.env, attachment.user_id).await?;
        let patch = parse_patch_message(&patch_message)?;
        let updated_at = Utc::now().timestamp();
        let next_plans = apply_patch_to_snapshot(&plans, &patch, updated_at);
        let next_revision = current_revision + 1;

        persist_snapshot(&self.env, attachment.user_id, next_revision, &next_plans).await?;
        record_patch_event(&self.env, attachment.user_id, next_revision, &patch_message).await?;

        send_server_message(
            ws,
            &RaidRealtimeServerMessage::Ack {
                revision: next_revision,
                client_mutation_id: &patch_message.client_mutation_id,
                applied_patch: &patch_message,
            },
        )?;

        for socket in self.state.get_websockets() {
            let socket_attachment = socket
                .deserialize_attachment::<SocketAttachment>()?
                .unwrap_or_default();
            if socket_attachment.session_id == attachment.session_id {
                continue;
            }
            send_server_message(
                &socket,
                &RaidRealtimeServerMessage::PatchBroadcast {
                    revision: next_revision,
                    patch: &patch_message,
                    session_id: &patch_message.session_id,
                },
            )?;
        }

        Ok(())
    }
}

impl DurableObject for RaidPlanRoom {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let is_websocket = req
            .headers()
            .get("Upgrade")?
            .map(|value| value.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false);

        if !is_websocket {
            return json_response(&serde_json::json!({ "ok": true, "realtime": true }), 200);
        }

        let pair = WebSocketPair::new()?;
        pair.server
            .serialize_attachment(SocketAttachment::default())?;
        self.state.accept_web_socket(&pair.server);
        Response::from_websocket(pair.client)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        let text = match message {
            WebSocketIncomingMessage::String(value) => value,
            WebSocketIncomingMessage::Binary(_) => {
                return send_server_message(
                    &ws,
                    &RaidRealtimeServerMessage::Error {
                        code: "unsupported_message",
                        message: "binary websocket messages are not supported",
                    },
                )
            }
        };

        let parsed: RaidRealtimeClientMessage = match serde_json::from_str(&text) {
            Ok(message) => message,
            Err(_) => {
                return send_server_message(
                    &ws,
                    &RaidRealtimeServerMessage::Error {
                        code: "invalid_json",
                        message: "failed to parse websocket message",
                    },
                )
            }
        };

        match parsed {
            RaidRealtimeClientMessage::Hello {
                token,
                document_id,
                last_revision,
                session_id,
            } => {
                self.handle_hello(&ws, token, document_id, last_revision, session_id)
                    .await
            }
            RaidRealtimeClientMessage::Patch(patch) => self.handle_patch(&ws, patch).await,
        }
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, error: Error) -> Result<()> {
        console_error!("raid realtime websocket error: {:?}", error);
        Ok(())
    }
}

pub async fn realtime_proxy_handler(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let url = req.url()?;
    let token = url
        .query_pairs()
        .find(|(key, _)| key == "token" || key == "access_token")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| Error::RustError("missing token".into()));

    let token = match token {
        Ok(token) => token,
        Err(_) => return error_response("missing token", 401),
    };

    let claims = match validate_token(&ctx.env, &token) {
        Ok(claims) => claims,
        Err(_) => return error_response("invalid or expired token", 401),
    };

    let namespace = match ctx.env.durable_object("RAID_PLAN_ROOM") {
        Ok(namespace) => namespace,
        Err(_) => return error_response("durable object binding missing", 500),
    };

    let stub = namespace.get_by_name(&format!("raid-plan:{}", claims.uid))?;
    stub.fetch_with_request(req).await
}

#[cfg(test)]
mod tests {
    use super::{
        apply_patch_to_snapshot, RaidPlanRealtimePatch, RaidPlanRealtimePlan, RaidPlanRealtimeSlot,
        SlotFieldValue, SlotUpdateFieldPayload,
    };
    use std::collections::HashMap;

    fn make_slot(
        step: Option<i64>,
        predicted_damage: Option<f64>,
        character_ids: Vec<i64>,
    ) -> RaidPlanRealtimeSlot {
        RaidPlanRealtimeSlot {
            step,
            predicted_damage,
            character_ids,
        }
    }

    fn make_plan() -> RaidPlanRealtimePlan {
        let mut data = HashMap::new();
        data.insert(
            "alpha".to_string(),
            vec![
                make_slot(Some(1), Some(1000.0), vec![101]),
                make_slot(None, None, vec![]),
                make_slot(None, None, vec![]),
            ],
        );

        RaidPlanRealtimePlan {
            id: "main".to_string(),
            name: "Main".to_string(),
            updated_at: 100,
            data,
        }
    }

    #[test]
    fn slot_update_field_updates_only_the_targeted_field() {
        let plans = vec![make_plan()];
        let patch = RaidPlanRealtimePatch::SlotUpdateField {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            payload: SlotUpdateFieldPayload {
                plan_id: "main".to_string(),
                account_key: "alpha".to_string(),
                slot_index: 0,
                field: "characterIds".to_string(),
                value: SlotFieldValue::CharacterIds(vec![201, 202]),
            },
        };

        let updated = apply_patch_to_snapshot(&plans, &patch, 200);

        assert_eq!(updated[0].data["alpha"][0].step, Some(1));
        assert_eq!(updated[0].data["alpha"][0].predicted_damage, Some(1000.0));
        assert_eq!(updated[0].data["alpha"][0].character_ids, vec![201, 202]);
    }

    #[test]
    fn different_field_updates_merge_when_applied_sequentially() {
        let plans = vec![make_plan()];
        let predicted_damage_patch = RaidPlanRealtimePatch::SlotUpdateField {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            payload: SlotUpdateFieldPayload {
                plan_id: "main".to_string(),
                account_key: "alpha".to_string(),
                slot_index: 0,
                field: "predictedDamage".to_string(),
                value: SlotFieldValue::PredictedDamage(Some(2500.0)),
            },
        };
        let character_patch = RaidPlanRealtimePatch::SlotUpdateField {
            client_mutation_id: "m-2".to_string(),
            session_id: "s-2".to_string(),
            base_revision: 1,
            payload: SlotUpdateFieldPayload {
                plan_id: "main".to_string(),
                account_key: "alpha".to_string(),
                slot_index: 0,
                field: "characterIds".to_string(),
                value: SlotFieldValue::CharacterIds(vec![201, 202]),
            },
        };

        let after_first = apply_patch_to_snapshot(&plans, &predicted_damage_patch, 200);
        let after_second = apply_patch_to_snapshot(&after_first, &character_patch, 300);

        assert_eq!(
            after_second[0].data["alpha"][0].predicted_damage,
            Some(2500.0)
        );
        assert_eq!(
            after_second[0].data["alpha"][0].character_ids,
            vec![201, 202]
        );
    }

    #[test]
    fn later_same_field_write_wins() {
        let plans = vec![make_plan()];
        let first_patch = RaidPlanRealtimePatch::SlotUpdateField {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            payload: SlotUpdateFieldPayload {
                plan_id: "main".to_string(),
                account_key: "alpha".to_string(),
                slot_index: 0,
                field: "predictedDamage".to_string(),
                value: SlotFieldValue::PredictedDamage(Some(2500.0)),
            },
        };
        let second_patch = RaidPlanRealtimePatch::SlotUpdateField {
            client_mutation_id: "m-2".to_string(),
            session_id: "s-2".to_string(),
            base_revision: 1,
            payload: SlotUpdateFieldPayload {
                plan_id: "main".to_string(),
                account_key: "alpha".to_string(),
                slot_index: 0,
                field: "predictedDamage".to_string(),
                value: SlotFieldValue::PredictedDamage(Some(3200.0)),
            },
        };

        let after_first = apply_patch_to_snapshot(&plans, &first_patch, 200);
        let after_second = apply_patch_to_snapshot(&after_first, &second_patch, 300);

        assert_eq!(
            after_second[0].data["alpha"][0].predicted_damage,
            Some(3200.0)
        );
    }
}
