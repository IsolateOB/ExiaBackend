use crate::models::{Claims, TeamTemplateMemberRow, TeamTemplateMetaRow};
use crate::utils::{decode_claims_token, error_response, get_jwt_secret, json_response};
use chrono::Utc;
use futures::lock::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use worker::*;

const TEAM_TEMPLATE_DOCUMENT_ID: &str = "team-template";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TeamTemplateRealtimeMember {
    pub position: i64,
    #[serde(rename = "characterId")]
    pub character_id: Option<String>,
    #[serde(rename = "damageCoefficient")]
    pub damage_coefficient: f64,
    #[serde(default)]
    pub coefficients: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TeamTemplateRealtimeTemplate {
    pub id: String,
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    pub members: Vec<TeamTemplateRealtimeMember>,
    #[serde(rename = "totalDamageCoefficient")]
    pub total_damage_coefficient: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TeamTemplateRealtimePatch {
    TemplateCreate {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        template_id: String,
        name: String,
    },
    TemplateRename {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        template_id: String,
        name: String,
    },
    TemplateDelete {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        template_id: String,
    },
    TemplateDuplicate {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        source_template_id: String,
        new_template_id: String,
        name: String,
    },
    TemplateReplaceMembers {
        client_mutation_id: String,
        session_id: String,
        base_revision: i64,
        template_id: String,
        members: Vec<TeamTemplateRealtimeMember>,
        total_damage_coefficient: f64,
    },
}

pub fn apply_patch_to_snapshot(
    templates: &[TeamTemplateRealtimeTemplate],
    patch: &TeamTemplateRealtimePatch,
    updated_at: i64,
) -> Vec<TeamTemplateRealtimeTemplate> {
    let mut next = templates.to_vec();

    match patch {
        TeamTemplateRealtimePatch::TemplateCreate {
            template_id, name, ..
        } => {
            if !next.iter().any(|template| &template.id == template_id) {
                next.push(TeamTemplateRealtimeTemplate {
                    id: template_id.clone(),
                    name: name.clone(),
                    created_at: updated_at,
                    updated_at,
                    members: Vec::new(),
                    total_damage_coefficient: 0.0,
                });
            }
        }
        TeamTemplateRealtimePatch::TemplateRename {
            template_id, name, ..
        } => {
            if let Some(template) = next.iter_mut().find(|template| &template.id == template_id) {
                template.name = name.clone();
                template.updated_at = updated_at;
            }
        }
        TeamTemplateRealtimePatch::TemplateDelete { template_id, .. } => {
            next.retain(|template| &template.id != template_id);
        }
        TeamTemplateRealtimePatch::TemplateDuplicate {
            source_template_id,
            new_template_id,
            name,
            ..
        } => {
            if !next.iter().any(|template| &template.id == new_template_id) {
                if let Some(source) = next
                    .iter()
                    .find(|template| &template.id == source_template_id)
                    .cloned()
                {
                    next.push(TeamTemplateRealtimeTemplate {
                        id: new_template_id.clone(),
                        name: name.clone(),
                        created_at: updated_at,
                        updated_at,
                        members: source.members,
                        total_damage_coefficient: source.total_damage_coefficient,
                    });
                }
            }
        }
        TeamTemplateRealtimePatch::TemplateReplaceMembers {
            template_id,
            members,
            total_damage_coefficient,
            ..
        } => {
            if let Some(template) = next.iter_mut().find(|template| &template.id == template_id) {
                template.members = members.clone();
                template.total_damage_coefficient = *total_damage_coefficient;
                template.updated_at = updated_at;
            }
        }
    }

    next
}

fn should_persist_snapshot_result(
    current_templates: &[TeamTemplateRealtimeTemplate],
    next_templates: &[TeamTemplateRealtimeTemplate],
    patch: &TeamTemplateRealtimePatch,
) -> bool {
    if current_templates == next_templates {
        return false;
    }

    if current_templates.is_empty() {
        return true;
    }

    if next_templates.is_empty() {
        return matches!(patch, TeamTemplateRealtimePatch::TemplateDelete { .. });
    }

    true
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
enum TeamTemplateRealtimeClientMessage {
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
    Patch(TeamTemplateRealtimePatchMessage),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TeamTemplateRealtimePatchMessage {
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
enum TeamTemplateRealtimeServerMessage<'a> {
    #[serde(rename = "snapshot")]
    Snapshot {
        revision: i64,
        templates: &'a [TeamTemplateRealtimeTemplate],
    },
    #[serde(rename = "patch_replay")]
    PatchReplay {
        revision: i64,
        patches: &'a [TeamTemplateRealtimePatchMessage],
    },
    #[serde(rename = "ack")]
    Ack {
        revision: i64,
        #[serde(rename = "clientMutationId")]
        client_mutation_id: &'a str,
        #[serde(rename = "appliedPatch")]
        applied_patch: &'a TeamTemplateRealtimePatchMessage,
    },
    #[serde(rename = "patch_broadcast")]
    PatchBroadcast {
        revision: i64,
        patch: &'a TeamTemplateRealtimePatchMessage,
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
struct TemplateIdentityPayload {
    #[serde(rename = "templateId")]
    template_id: String,
}

#[derive(Deserialize)]
struct TemplateCreatePayload {
    #[serde(rename = "templateId")]
    template_id: String,
    name: String,
}

#[derive(Deserialize)]
struct TemplateRenamePayload {
    #[serde(rename = "templateId")]
    template_id: String,
    name: String,
}

#[derive(Deserialize)]
struct TemplateDuplicatePayload {
    #[serde(rename = "sourceTemplateId")]
    source_template_id: String,
    #[serde(rename = "newTemplateId")]
    new_template_id: String,
    name: String,
}

#[derive(Deserialize)]
struct TemplateReplaceMembersPayload {
    #[serde(rename = "templateId")]
    template_id: String,
    #[serde(default)]
    members: Vec<TeamTemplateRealtimeMember>,
    #[serde(rename = "totalDamageCoefficient")]
    total_damage_coefficient: f64,
}

#[derive(Deserialize)]
struct TemplateIdRow {
    template_id: String,
}

fn validate_token(env: &Env, token: &str) -> Result<Claims> {
    let secret = get_jwt_secret(env)?;
    decode_claims_token(token, &secret, Utc::now().timestamp())
        .map_err(|_| Error::RustError("invalid or expired token".into()))
}

fn parse_patch_message(message: &TeamTemplateRealtimePatchMessage) -> Result<TeamTemplateRealtimePatch> {
    match message.op.as_str() {
        "template.create" => {
            let payload: TemplateCreatePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid template.create payload".into()))?;
            Ok(TeamTemplateRealtimePatch::TemplateCreate {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                template_id: payload.template_id,
                name: payload.name,
            })
        }
        "template.rename" => {
            let payload: TemplateRenamePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid template.rename payload".into()))?;
            Ok(TeamTemplateRealtimePatch::TemplateRename {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                template_id: payload.template_id,
                name: payload.name,
            })
        }
        "template.delete" => {
            let payload: TemplateIdentityPayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid template.delete payload".into()))?;
            Ok(TeamTemplateRealtimePatch::TemplateDelete {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                template_id: payload.template_id,
            })
        }
        "template.duplicate" => {
            let payload: TemplateDuplicatePayload = serde_json::from_value(message.payload.clone())
                .map_err(|_| Error::RustError("invalid template.duplicate payload".into()))?;
            Ok(TeamTemplateRealtimePatch::TemplateDuplicate {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                source_template_id: payload.source_template_id,
                new_template_id: payload.new_template_id,
                name: payload.name,
            })
        }
        "template.replaceMembers" => {
            let payload: TemplateReplaceMembersPayload =
                serde_json::from_value(message.payload.clone())
                    .map_err(|_| Error::RustError("invalid template.replaceMembers payload".into()))?;
            Ok(TeamTemplateRealtimePatch::TemplateReplaceMembers {
                client_mutation_id: message.client_mutation_id.clone(),
                session_id: message.session_id.clone(),
                base_revision: message.base_revision,
                template_id: payload.template_id,
                members: payload.members,
                total_damage_coefficient: payload.total_damage_coefficient,
            })
        }
        _ => Err(Error::RustError("unsupported template patch op".into())),
    }
}

async fn load_document_revision(env: &Env, user_id: i64) -> Result<i64> {
    let db = env.d1("DB")?;
    let result = db
        .prepare(
            "SELECT revision FROM team_template_documents WHERE user_id = ?1 AND document_id = ?2",
        )
        .bind(&[(user_id as i32).into(), TEAM_TEMPLATE_DOCUMENT_ID.into()])?
        .all()
        .await?;
    let rows = result
        .results::<DocumentRevisionRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;
    Ok(rows.first().map(|row| row.revision).unwrap_or(0))
}

async fn load_snapshot(env: &Env, user_id: i64) -> Result<Vec<TeamTemplateRealtimeTemplate>> {
    let db = env.d1("DB")?;
    let templates = db
        .prepare(
            "SELECT template_id, name, created_at, total_damage_coefficient, updated_at FROM team_templates WHERE user_id = ?1 ORDER BY updated_at DESC",
        )
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<TeamTemplateMetaRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let members = db
        .prepare(
            "SELECT template_id, position, character_id, damage_coefficient, coefficients_json FROM team_template_members WHERE user_id = ?1",
        )
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?
        .results::<TeamTemplateMemberRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;

    let mut member_map: HashMap<String, Vec<TeamTemplateRealtimeMember>> = HashMap::new();
    for member in members {
        let coefficients = if member.coefficients_json.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&member.coefficients_json).unwrap_or(Value::Null)
        };
        member_map
            .entry(member.template_id)
            .or_default()
            .push(TeamTemplateRealtimeMember {
                position: member.position,
                character_id: if member.character_id.trim().is_empty() {
                    None
                } else {
                    Some(member.character_id)
                },
                damage_coefficient: member.damage_coefficient,
                coefficients,
            });
    }

    Ok(templates
        .into_iter()
        .map(|template| {
            let mut members = member_map.remove(&template.template_id).unwrap_or_default();
            members.sort_by_key(|member| member.position);
            TeamTemplateRealtimeTemplate {
                id: template.template_id,
                name: template.name,
                created_at: template.created_at,
                updated_at: template.updated_at,
                members,
                total_damage_coefficient: template.total_damage_coefficient,
            }
        })
        .collect())
}

async fn persist_snapshot(
    env: &Env,
    user_id: i64,
    revision: i64,
    templates: &[TeamTemplateRealtimeTemplate],
) -> Result<()> {
    let db = env.d1("DB")?;
    let now = Utc::now().timestamp();
    let existing = db
        .prepare("SELECT template_id FROM team_templates WHERE user_id = ?1")
        .bind(&[(user_id as i32).into()])?
        .all()
        .await?;
    let existing_ids = existing
        .results::<TemplateIdRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;
    let next_ids: HashSet<String> = templates.iter().map(|template| template.id.clone()).collect();

    for row in existing_ids {
        if next_ids.contains(&row.template_id) {
            continue;
        }

        db.prepare("DELETE FROM team_template_members WHERE user_id = ?1 AND template_id = ?2")
            .bind(&[(user_id as i32).into(), row.template_id.clone().into()])?
            .run()
            .await?;
        db.prepare("DELETE FROM team_templates WHERE user_id = ?1 AND template_id = ?2")
            .bind(&[(user_id as i32).into(), row.template_id.into()])?
            .run()
            .await?;
    }

    for template in templates {
        let created_at = if template.created_at > 0 {
            template.created_at
        } else {
            now
        };
        let updated_at = if template.updated_at > 0 {
            template.updated_at
        } else {
            now
        };

        db.prepare(
            "INSERT OR REPLACE INTO team_templates (user_id, template_id, name, created_at, total_damage_coefficient, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&[
            (user_id as i32).into(),
            template.id.clone().into(),
            template.name.clone().into(),
            to_d1_number(created_at).into(),
            template.total_damage_coefficient.into(),
            to_d1_number(updated_at).into(),
        ])?
        .run()
        .await?;

        db.prepare("DELETE FROM team_template_members WHERE user_id = ?1 AND template_id = ?2")
            .bind(&[(user_id as i32).into(), template.id.clone().into()])?
            .run()
            .await?;

        for member in &template.members {
            let coefficients_json = if member.coefficients.is_null() {
                String::new()
            } else {
                member.coefficients.to_string()
            };
            db.prepare(
                "INSERT OR REPLACE INTO team_template_members (user_id, template_id, position, character_id, damage_coefficient, coefficients_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )
            .bind(&[
                (user_id as i32).into(),
                template.id.clone().into(),
                to_d1_number(member.position).into(),
                member.character_id.clone().unwrap_or_default().into(),
                member.damage_coefficient.into(),
                coefficients_json.into(),
            ])?
            .run()
            .await?;
        }
    }

    db.prepare(
        "INSERT OR REPLACE INTO team_template_documents (user_id, document_id, revision, updated_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&[
        (user_id as i32).into(),
        TEAM_TEMPLATE_DOCUMENT_ID.into(),
        to_d1_number(revision).into(),
        to_d1_number(now).into(),
    ])?
    .run()
    .await?;

    Ok(())
}

async fn find_existing_patch(
    env: &Env,
    user_id: i64,
    client_mutation_id: &str,
) -> Result<Option<(i64, TeamTemplateRealtimePatchMessage)>> {
    let db = env.d1("DB")?;
    let result = match db
        .prepare(
            "SELECT revision, patch_json FROM team_template_patch_events WHERE user_id = ?1 AND document_id = ?2 AND client_mutation_id = ?3 LIMIT 1",
        )
        .bind(&[
            (user_id as i32).into(),
            TEAM_TEMPLATE_DOCUMENT_ID.into(),
            client_mutation_id.into(),
        ])?
        .all()
        .await
    {
        Ok(result) => result,
        Err(error) if is_missing_patch_events_table_error(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let rows = result
        .results::<PatchEventRow>()
        .map_err(|e| Error::RustError(format!("database parse error: {e}")))?;
    let Some(row) = rows.into_iter().next() else {
        return Ok(None);
    };
    let patch = serde_json::from_str(&row.patch_json)
        .map_err(|_| Error::RustError("stored patch json is invalid".into()))?;
    Ok(Some((row.revision, patch)))
}

async fn record_patch_event(
    env: &Env,
    user_id: i64,
    revision: i64,
    patch: &TeamTemplateRealtimePatchMessage,
) -> Result<()> {
    let db = env.d1("DB")?;
    let patch_json = serde_json::to_string(patch)
        .map_err(|_| Error::RustError("patch serialize failed".into()))?;
    let now = Utc::now().timestamp();

    match db.prepare(
        "INSERT OR REPLACE INTO team_template_patch_events (user_id, document_id, revision, client_mutation_id, session_id, op, patch_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&[
        (user_id as i32).into(),
        TEAM_TEMPLATE_DOCUMENT_ID.into(),
        to_d1_number(revision).into(),
        patch.client_mutation_id.clone().into(),
        patch.session_id.clone().into(),
        patch.op.clone().into(),
        patch_json.into(),
        to_d1_number(now).into(),
    ])?
    .run()
    .await
    {
        Ok(_) => {}
        Err(error) if is_missing_patch_events_table_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    }

    let prune_before = revision - 200;
    if prune_before > 0 {
        match db.prepare(
            "DELETE FROM team_template_patch_events WHERE user_id = ?1 AND document_id = ?2 AND revision <= ?3",
        )
        .bind(&[
            (user_id as i32).into(),
            TEAM_TEMPLATE_DOCUMENT_ID.into(),
            to_d1_number(prune_before).into(),
        ])?
        .run()
        .await
        {
            Ok(_) => {}
            Err(error) if is_missing_patch_events_table_error(&error) => return Ok(()),
            Err(error) => return Err(error),
        }
    }

    Ok(())
}

fn to_d1_number(value: i64) -> f64 {
    value as f64
}

fn is_missing_table_error(error: &Error, table_name: &str) -> bool {
    let message = format!("{error:?}").to_ascii_lowercase();
    message.contains("no such table") && message.contains(&table_name.to_ascii_lowercase())
}

fn is_missing_patch_events_table_error(error: &Error) -> bool {
    is_missing_table_error(error, "team_template_patch_events")
}

async fn load_patch_replay(
    env: &Env,
    user_id: i64,
    last_revision: i64,
    current_revision: i64,
) -> Result<Option<Vec<TeamTemplateRealtimePatchMessage>>> {
    if last_revision >= current_revision {
        return Ok(Some(Vec::new()));
    }

    let db = env.d1("DB")?;
    let result = match db
        .prepare(
            "SELECT revision, patch_json FROM team_template_patch_events WHERE user_id = ?1 AND document_id = ?2 AND revision > ?3 ORDER BY revision ASC",
        )
        .bind(&[
            (user_id as i32).into(),
            TEAM_TEMPLATE_DOCUMENT_ID.into(),
            to_d1_number(last_revision).into(),
        ])?
        .all()
        .await
    {
        Ok(result) => result,
        Err(error) if is_missing_patch_events_table_error(&error) => return Ok(None),
        Err(error) => return Err(error),
    };

    let rows = result
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
        let patch = serde_json::from_str(&row.patch_json)
            .map_err(|_| Error::RustError("stored patch json is invalid".into()))?;
        patches.push(patch);
        expected_revision += 1;
    }

    Ok(Some(patches))
}

fn send_server_message(ws: &WebSocket, message: &TeamTemplateRealtimeServerMessage<'_>) -> Result<()> {
    ws.send(message)
}

fn send_runtime_error_message(ws: &WebSocket, code: &str, message: String) -> Result<()> {
    ws.send(&serde_json::json!({
        "type": "error",
        "code": code,
        "message": message,
    }))
}

fn format_runtime_error(error: &Error) -> String {
    let message = format!("{error:?}");
    if message.len() > 400 {
        format!("{}...", &message[..400])
    } else {
        message
    }
}

#[durable_object]
pub struct TeamTemplateRoom {
    state: State,
    env: Env,
    patch_lock: Mutex<()>,
}

impl TeamTemplateRoom {
    async fn handle_hello(
        &self,
        ws: &WebSocket,
        token: String,
        document_id: String,
        last_revision: i64,
        session_id: String,
    ) -> Result<()> {
        if document_id != TEAM_TEMPLATE_DOCUMENT_ID {
            return send_server_message(
                ws,
                &TeamTemplateRealtimeServerMessage::Error {
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
        if last_revision > 0 {
            if let Some(patches) =
                load_patch_replay(&self.env, claims.uid, last_revision, revision).await?
            {
                if !patches.is_empty() {
                    return send_server_message(
                        ws,
                        &TeamTemplateRealtimeServerMessage::PatchReplay {
                            revision,
                            patches: &patches,
                        },
                    );
                }
            }
        }

        let templates = load_snapshot(&self.env, claims.uid).await?;
        send_server_message(
            ws,
            &TeamTemplateRealtimeServerMessage::Snapshot {
                revision,
                templates: &templates,
            },
        )
    }

    async fn handle_patch(
        &self,
        ws: &WebSocket,
        patch_message: TeamTemplateRealtimePatchMessage,
    ) -> Result<()> {
        let _patch_guard = self.patch_lock.lock().await;
        let attachment = ws
            .deserialize_attachment::<SocketAttachment>()?
            .unwrap_or_default();
        if attachment.user_id <= 0 {
            return send_server_message(
                ws,
                &TeamTemplateRealtimeServerMessage::Error {
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
                &TeamTemplateRealtimeServerMessage::Ack {
                    revision,
                    client_mutation_id: &stored_patch.client_mutation_id,
                    applied_patch: &stored_patch,
                },
            );
        }

        let current_revision = load_document_revision(&self.env, attachment.user_id).await?;
        let templates = load_snapshot(&self.env, attachment.user_id).await?;
        let patch = parse_patch_message(&patch_message)?;
        let updated_at = Utc::now().timestamp();
        let next_templates = apply_patch_to_snapshot(&templates, &patch, updated_at);

        if !should_persist_snapshot_result(&templates, &next_templates, &patch) {
            return send_server_message(
                ws,
                &TeamTemplateRealtimeServerMessage::Ack {
                    revision: current_revision,
                    client_mutation_id: &patch_message.client_mutation_id,
                    applied_patch: &patch_message,
                },
            );
        }

        let next_revision = current_revision + 1;
        persist_snapshot(&self.env, attachment.user_id, next_revision, &next_templates).await?;
        record_patch_event(&self.env, attachment.user_id, next_revision, &patch_message).await?;

        send_server_message(
            ws,
            &TeamTemplateRealtimeServerMessage::Ack {
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
                &TeamTemplateRealtimeServerMessage::PatchBroadcast {
                    revision: next_revision,
                    patch: &patch_message,
                    session_id: &patch_message.session_id,
                },
            )?;
        }

        Ok(())
    }
}

impl DurableObject for TeamTemplateRoom {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            patch_lock: Mutex::new(()),
        }
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
                    &TeamTemplateRealtimeServerMessage::Error {
                        code: "unsupported_message",
                        message: "binary websocket messages are not supported",
                    },
                )
            }
        };

        let parsed: TeamTemplateRealtimeClientMessage = match serde_json::from_str(&text) {
            Ok(message) => message,
            Err(_) => {
                return send_server_message(
                    &ws,
                    &TeamTemplateRealtimeServerMessage::Error {
                        code: "invalid_json",
                        message: "failed to parse websocket message",
                    },
                )
            }
        };

        match parsed {
            TeamTemplateRealtimeClientMessage::Hello {
                token,
                document_id,
                last_revision,
                session_id,
            } => {
                self.handle_hello(&ws, token, document_id, last_revision, session_id)
                    .await
            }
            TeamTemplateRealtimeClientMessage::Patch(patch) => {
                if let Err(error) = self.handle_patch(&ws, patch).await {
                    console_error!("team template realtime patch error: {:?}", error);
                    let code = if is_missing_patch_events_table_error(&error) {
                        "missing_patch_events_table"
                    } else if is_missing_table_error(&error, "team_template_documents") {
                        "missing_team_template_documents_table"
                    } else {
                        "patch_failed"
                    };
                    send_runtime_error_message(&ws, code, format_runtime_error(&error))?;
                }
                Ok(())
            }
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
        console_error!("team template realtime websocket error: {:?}", error);
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

    let namespace = match ctx.env.durable_object("TEAM_TEMPLATE_ROOM") {
        Ok(namespace) => namespace,
        Err(_) => return error_response("durable object binding missing", 500),
    };

    let stub = namespace.get_by_name(&format!("team-template:{}", claims.uid))?;
    stub.fetch_with_request(req).await
}

#[cfg(test)]
mod tests {
    use super::{
        apply_patch_to_snapshot, is_missing_patch_events_table_error,
        should_persist_snapshot_result, to_d1_number, TeamTemplateRealtimeMember,
        TeamTemplateRealtimePatch, TeamTemplateRealtimeTemplate,
    };
    use serde_json::json;
    use worker::Error;

    fn make_template(
        id: &str,
        name: &str,
        character_id: &str,
        damage_coefficient: f64,
    ) -> TeamTemplateRealtimeTemplate {
        TeamTemplateRealtimeTemplate {
            id: id.to_string(),
            name: name.to_string(),
            created_at: 100,
            updated_at: 100,
            members: vec![TeamTemplateRealtimeMember {
                position: 1,
                character_id: Some(character_id.to_string()),
                damage_coefficient,
                coefficients: json!({ "axisAttack": 1 }),
            }],
            total_damage_coefficient: damage_coefficient,
        }
    }

    #[test]
    fn apply_template_replace_members_updates_only_one_template() {
        let templates = vec![
            make_template("tpl-1", "模板1", "1001", 1.0),
            make_template("tpl-2", "模板2", "2001", 2.0),
        ];
        let patch = TeamTemplateRealtimePatch::TemplateReplaceMembers {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            template_id: "tpl-2".to_string(),
            members: vec![TeamTemplateRealtimeMember {
                position: 1,
                character_id: Some("3001".to_string()),
                damage_coefficient: 3.0,
                coefficients: json!({ "axisAttack": 2 }),
            }],
            total_damage_coefficient: 3.0,
        };

        let updated = apply_patch_to_snapshot(&templates, &patch, 200);

        assert_eq!(updated[0].members[0].character_id.as_deref(), Some("1001"));
        assert_eq!(updated[1].members[0].character_id.as_deref(), Some("3001"));
        assert_eq!(updated[1].total_damage_coefficient, 3.0);
    }

    #[test]
    fn duplicate_template_creates_a_new_template_with_new_metadata() {
        let templates = vec![make_template("tpl-1", "模板1", "1001", 1.0)];
        let patch = TeamTemplateRealtimePatch::TemplateDuplicate {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            source_template_id: "tpl-1".to_string(),
            new_template_id: "tpl-2".to_string(),
            name: "模板2".to_string(),
        };

        let updated = apply_patch_to_snapshot(&templates, &patch, 300);

        assert_eq!(updated.len(), 2);
        assert_eq!(updated[1].id, "tpl-2");
        assert_eq!(updated[1].name, "模板2");
        assert_eq!(updated[1].created_at, 300);
        assert_eq!(updated[1].updated_at, 300);
        assert_eq!(updated[1].members[0].character_id.as_deref(), Some("1001"));
    }

    #[test]
    fn noop_duplicate_patch_does_not_require_persist() {
        let templates = vec![make_template("tpl-1", "模板1", "1001", 1.0)];
        let patch = TeamTemplateRealtimePatch::TemplateDuplicate {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            source_template_id: "missing".to_string(),
            new_template_id: "tpl-2".to_string(),
            name: "模板2".to_string(),
        };

        let next_templates = apply_patch_to_snapshot(&templates, &patch, 200);

        assert!(!should_persist_snapshot_result(
            &templates,
            &next_templates,
            &patch
        ));
    }

    #[test]
    fn non_delete_patch_cannot_replace_existing_snapshot_with_empty_templates() {
        let templates = vec![make_template("tpl-1", "模板1", "1001", 1.0)];
        let patch = TeamTemplateRealtimePatch::TemplateRename {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            template_id: "tpl-1".to_string(),
            name: "重命名".to_string(),
        };

        assert!(!should_persist_snapshot_result(&templates, &Vec::new(), &patch));
    }

    #[test]
    fn deleting_last_template_is_still_allowed_to_persist() {
        let templates = vec![make_template("tpl-1", "模板1", "1001", 1.0)];
        let patch = TeamTemplateRealtimePatch::TemplateDelete {
            client_mutation_id: "m-1".to_string(),
            session_id: "s-1".to_string(),
            base_revision: 1,
            template_id: "tpl-1".to_string(),
        };

        let next_templates = apply_patch_to_snapshot(&templates, &patch, 200);

        assert!(should_persist_snapshot_result(
            &templates,
            &next_templates,
            &patch
        ));
        assert!(next_templates.is_empty());
    }

    #[test]
    fn recognizes_missing_patch_events_table_errors() {
        let error =
            Error::RustError("D1_ERROR: no such table: team_template_patch_events".to_string());
        assert!(is_missing_patch_events_table_error(&error));
    }

    #[test]
    fn converts_i64_values_to_d1_number_parameters() {
        assert_eq!(to_d1_number(1_772_832_011), 1_772_832_011_f64);
        assert_eq!(to_d1_number(3), 3_f64);
    }
}
