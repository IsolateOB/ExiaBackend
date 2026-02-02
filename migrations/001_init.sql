-- Application Schema

-- 1. Users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    avatar_url TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. Raid Plans (Normalized)
CREATE TABLE IF NOT EXISTS raid_plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id TEXT NOT NULL,
    plan_name TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, plan_id)
);
CREATE INDEX IF NOT EXISTS idx_raid_plans_user ON raid_plans(user_id);

CREATE TABLE IF NOT EXISTS raid_plan_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    game_uid TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, plan_id, account_key)
);
CREATE INDEX IF NOT EXISTS idx_raid_plan_accounts_user ON raid_plan_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_raid_plan_accounts_game_uid ON raid_plan_accounts(game_uid);

CREATE TABLE IF NOT EXISTS raid_plan_slots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    slot_index INTEGER NOT NULL,
    step INTEGER,
    predicted_damage REAL,
    predicted_damage_input TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, plan_id, account_key, slot_index)
);
CREATE INDEX IF NOT EXISTS idx_raid_plan_slots_user ON raid_plan_slots(user_id);
CREATE INDEX IF NOT EXISTS idx_raid_plan_slots_plan ON raid_plan_slots(plan_id);

CREATE TABLE IF NOT EXISTS raid_plan_slot_characters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    plan_id TEXT NOT NULL,
    account_key TEXT NOT NULL,
    slot_index INTEGER NOT NULL,
    position INTEGER NOT NULL,
    character_id INTEGER NOT NULL,
    UNIQUE(user_id, plan_id, account_key, slot_index, position)
);
CREATE INDEX IF NOT EXISTS idx_raid_plan_slot_chars_user ON raid_plan_slot_characters(user_id);
CREATE INDEX IF NOT EXISTS idx_raid_plan_slot_chars_char ON raid_plan_slot_characters(character_id);

-- 3. Team Templates (Normalized)
CREATE TABLE IF NOT EXISTS team_templates (
    user_id INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    total_damage_coefficient REAL NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(user_id, template_id)
);
CREATE INDEX IF NOT EXISTS idx_team_templates_user ON team_templates(user_id);

CREATE TABLE IF NOT EXISTS team_template_members (
    user_id INTEGER NOT NULL,
    template_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    character_id TEXT,
    damage_coefficient REAL NOT NULL,
    coefficients_json TEXT,
    PRIMARY KEY(user_id, template_id, position)
);
CREATE INDEX IF NOT EXISTS idx_team_template_members_user ON team_template_members(user_id);
CREATE INDEX IF NOT EXISTS idx_team_template_members_char ON team_template_members(character_id);

-- 4. User Accounts (Game Data)
CREATE TABLE IF NOT EXISTS user_accounts (
    user_id INTEGER PRIMARY KEY,
    account_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 4.1 User Characters (Nikke List)
CREATE TABLE IF NOT EXISTS user_characters (
    user_id INTEGER PRIMARY KEY,
    character_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 4.2 Account Lists (Templates)
CREATE TABLE IF NOT EXISTS account_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    list_id TEXT NOT NULL,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, list_id)
);
CREATE INDEX IF NOT EXISTS idx_account_lists_user ON account_lists(user_id);
CREATE INDEX IF NOT EXISTS idx_account_lists_list_id ON account_lists(list_id);

-- 4.3 Character Lists (Templates)
CREATE TABLE IF NOT EXISTS character_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    list_id TEXT NOT NULL,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, list_id)
);
CREATE INDEX IF NOT EXISTS idx_character_lists_user ON character_lists(user_id);
CREATE INDEX IF NOT EXISTS idx_character_lists_list_id ON character_lists(list_id);

-- 5. Game Accounts (Normalized)
CREATE TABLE IF NOT EXISTS game_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    game_uid TEXT NOT NULL,
    cookie TEXT,
    updated_at INTEGER NOT NULL,
    UNIQUE(user_id, game_uid)
);
CREATE INDEX IF NOT EXISTS idx_game_accounts_user ON game_accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_game_accounts_uid ON game_accounts(game_uid);
