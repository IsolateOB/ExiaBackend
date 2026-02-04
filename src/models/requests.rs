use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct ChangeUsernameRequest {
    pub new_username: String,
}

#[derive(Deserialize)]
pub struct ChangeAvatarRequest {
    pub avatar_url: String,
}

#[derive(Deserialize)]
pub struct SaveRaidPlanRequest {
    pub plan_data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SaveTeamTemplateRequest {
    pub template_data: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SaveListsRequest {
    pub lists: Vec<crate::models::ListItemPayload>,
}
