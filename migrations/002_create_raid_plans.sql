-- Create table for storing user raid plans
CREATE TABLE raid_plans (
    user_id INTEGER PRIMARY KEY,
    plan_data TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
