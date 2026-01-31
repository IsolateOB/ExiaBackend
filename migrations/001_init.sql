-- Application Schema

-- 1. Users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- 2. Raid Plans
CREATE TABLE IF NOT EXISTS raid_plans (
    user_id INTEGER PRIMARY KEY,
    plan_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 3. Team Templates
CREATE TABLE IF NOT EXISTS team_templates (
    user_id INTEGER PRIMARY KEY,
    template_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 4. User Accounts (Game Data)
CREATE TABLE IF NOT EXISTS user_accounts (
    user_id INTEGER PRIMARY KEY,
    account_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
