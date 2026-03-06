CREATE TABLE IF NOT EXISTS team_template_documents (
    user_id INTEGER NOT NULL,
    document_id TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, document_id)
);

CREATE INDEX IF NOT EXISTS idx_team_template_documents_user_revision
    ON team_template_documents(user_id, revision);

CREATE TABLE IF NOT EXISTS team_template_patch_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    document_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    client_mutation_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    op TEXT NOT NULL,
    patch_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, document_id, revision),
    UNIQUE(user_id, document_id, client_mutation_id)
);

CREATE INDEX IF NOT EXISTS idx_team_template_patch_events_user_revision
    ON team_template_patch_events(user_id, document_id, revision);
