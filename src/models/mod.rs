pub mod requests;
pub use requests::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: i64,
    pub username: String,
    pub avatar_url: Option<String>,
    pub restricted_mode: bool,
}

#[derive(Deserialize)]
pub struct UserAuthRow {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub avatar_url: Option<String>,
}

#[derive(Deserialize)]
pub struct UserProfileRow {
    pub username: String,
    pub avatar_url: Option<String>,
}

#[derive(Deserialize)]
pub struct UserIdRow {
    pub _id: i64,
}

#[derive(Serialize, Deserialize)]
pub struct GameAccountPayload {
    pub game_uid: String,
    pub game_openid: Option<String>,
    pub cookie: Option<String>,
    pub updated_at: i64,
    pub email: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
}

#[derive(Deserialize)]
pub struct RaidPlanMetaRow {
    pub plan_id: String,
    pub plan_name: String,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct RaidPlanSlotRow {
    pub plan_id: String,
    pub account_key: String,
    pub slot_index: i64,
    pub step: i64,
    pub predicted_damage: f64,
    pub predicted_damage_input: String,
}

#[derive(Deserialize)]
pub struct RaidPlanSlotCharRow {
    pub plan_id: String,
    pub account_key: String,
    pub slot_index: i64,
    pub position: i64,
    pub character_id: i64,
}

#[derive(Deserialize)]
pub struct RaidPlanPayload {
    pub id: String,
    pub name: String,
    pub data: serde_json::Value,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct PlanSlotPayload {
    pub step: Option<i64>,
    #[serde(default, rename = "characterIds")]
    pub character_ids: Vec<i64>,
    #[serde(default, rename = "predictedDamage")]
    pub predicted_damage: Option<f64>,
    #[serde(default, rename = "predictedDamageInput")]
    pub predicted_damage_input: Option<String>,
}

#[derive(Deserialize)]
pub struct TeamTemplateMetaRow {
    pub template_id: String,
    pub name: String,
    pub created_at: i64,
    pub total_damage_coefficient: f64,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct TeamTemplateMemberRow {
    pub template_id: String,
    pub position: i64,
    pub character_id: String,
    pub damage_coefficient: f64,
    pub coefficients_json: String,
}

#[derive(Deserialize)]
pub struct TeamTemplatePayload {
    pub id: String,
    pub name: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "totalDamageCoefficient")]
    pub total_damage_coefficient: f64,
    #[serde(default)]
    pub members: Vec<TeamTemplateMemberPayload>,
}

#[derive(Deserialize)]
pub struct TeamTemplateMemberPayload {
    pub position: i64,
    #[serde(rename = "characterId")]
    pub character_id: Option<String>,
    #[serde(rename = "damageCoefficient")]
    pub damage_coefficient: f64,
    #[serde(default)]
    pub coefficients: serde_json::Value,
}

#[derive(Deserialize)]
pub struct ListItemPayload {
    pub id: serde_json::Value,
    pub name: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct CharacterListRow {
    pub list_id: String,
    pub name: String,
    pub data: String,
    pub updated_at: i64,
}

#[derive(Deserialize)]
pub struct GameAccountLookupRow {
    pub game_uid: String,
    pub cookie: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub uid: i64,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
    #[serde(default)]
    pub restricted: bool,
}
