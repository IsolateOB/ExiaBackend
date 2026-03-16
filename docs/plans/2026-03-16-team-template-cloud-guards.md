# Team Template Cloud Guards Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Prevent local-only team templates from being stored in the backend through both application logic and database constraints.

**Architecture:** Add a shared Rust utility that identifies disallowed template IDs and drives both handler behavior and realtime validation. Then add a D1 migration with triggers that reject any remaining write path which tries to persist those IDs.

**Tech Stack:** Rust, Cloudflare Workers, D1 (SQLite), `worker` crate

---

### Task 1: Shared Validation Utilities

**Files:**
- Create: `D:/cloud/Eixa/ExiaBackend/src/utils/team_templates.rs`
- Modify: `D:/cloud/Eixa/ExiaBackend/src/utils/mod.rs`
- Test: `D:/cloud/Eixa/ExiaBackend/src/utils/team_templates.rs`

**Step 1: Write the failing tests**

Add tests covering:
- `__raid_copy__` is recognized as local-only
- `*-conflict-*` IDs are recognized as local-only
- mixed template lists are split into cloud-safe vs skipped
- local-only-only payloads do not request a destructive replace

**Step 2: Run test to verify it fails**

Run: `cargo test team_templates -- --nocapture`
Expected: FAIL because the helper module does not exist yet.

**Step 3: Write minimal implementation**

Implement shared helpers for:
- detecting disallowed template IDs
- validating a single cloud template ID
- selecting which templates are safe to use for a replace operation

**Step 4: Run test to verify it passes**

Run: `cargo test team_templates -- --nocapture`
Expected: PASS

### Task 2: Application-Layer Guards

**Files:**
- Modify: `D:/cloud/Eixa/ExiaBackend/src/handlers/team.rs`
- Modify: `D:/cloud/Eixa/ExiaBackend/src/handlers/team_realtime.rs`
- Test: `D:/cloud/Eixa/ExiaBackend/src/handlers/team_realtime.rs`

**Step 1: Write the failing tests**

Add realtime tests covering:
- `template.create` rejects `__raid_copy__`
- `template.duplicate` rejects conflict-copy target IDs
- sanitized snapshot reads ignore dirty template IDs

**Step 2: Run test to verify it fails**

Run: `cargo test team_realtime -- --nocapture`
Expected: FAIL because local-only template IDs are currently accepted.

**Step 3: Write minimal implementation**

Implement:
- save handler filtering for local-only templates, with no-op protection when the request only contains skipped templates
- realtime patch validation for local-only IDs
- snapshot/read filtering so dirty rows are not served back to clients
- targeted websocket error code for this case

**Step 4: Run test to verify it passes**

Run: `cargo test team_realtime -- --nocapture`
Expected: PASS

### Task 3: Database Guard Rails

**Files:**
- Create: `D:/cloud/Eixa/ExiaBackend/migrations/005_team_template_cloud_guards.sql`

**Step 1: Write the migration**

Add cleanup and triggers that abort inserts/updates into:
- `team_templates`
- `team_template_members`

when `template_id` is `__raid_copy__` or matches `%-conflict-%`.

**Step 2: Verify migration syntax and integration**

Run: `cargo test`
Expected: PASS

### Task 4: Final Verification

**Files:**
- Modify: `D:/cloud/Eixa/ExiaBackend/src/handlers/team.rs`
- Modify: `D:/cloud/Eixa/ExiaBackend/src/handlers/team_realtime.rs`
- Modify: `D:/cloud/Eixa/ExiaBackend/src/utils/mod.rs`
- Create: `D:/cloud/Eixa/ExiaBackend/src/utils/team_templates.rs`
- Create: `D:/cloud/Eixa/ExiaBackend/migrations/005_team_template_cloud_guards.sql`

**Step 1: Run the full backend verification**

Run: `cargo test`
Expected: PASS

**Step 2: Review behavior**

Confirm:
- plain save no longer writes local-only templates
- realtime sync rejects local-only template mutations before persistence
- D1 rejects direct writes even if an application path regresses
