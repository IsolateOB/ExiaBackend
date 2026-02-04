use worker::*;

mod handlers;
mod models;
mod utils;

use handlers::{auth, data, raid, team, user};
use utils::cors_headers;
use utils::json_response;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .options_async("/*path", |_req, _ctx| async move {
            let mut res = Response::empty()?;
            res = res.with_status(204);
            let cors = cors_headers();
            for (k, v) in cors.entries() {
                res.headers_mut().set(&k, &v)?;
            }
            Ok(res)
        })
        .get_async("/health", |_req, _ctx| async move {
            json_response(&serde_json::json!({"ok": true}), 200)
        })
        .post_async("/login", auth::login_handler)
        .post_async("/register", auth::register_handler)
        .get_async("/me", user::get_user_profile)
        .post_async("/change-password", user::change_password_handler)
        .post_async("/change-username", user::change_username_handler)
        .post_async("/change-avatar", user::change_avatar_handler)
        .delete_async("/account", user::delete_account_handler)
        .get_async("/raid-plan", raid::get_raid_plan_handler)
        .post_async("/raid-plan", raid::save_raid_plan_handler)
        .get_async("/team-template", team::get_team_template_handler)
        .post_async("/team-template", team::save_team_template_handler)
        .get_async("/accounts", data::get_accounts_handler)
        .post_async("/accounts", data::save_accounts_handler)
        .get_async("/characters", data::get_characters_handler)
        .post_async("/characters", data::save_characters_handler)
        .run(req, env)
        .await
}
