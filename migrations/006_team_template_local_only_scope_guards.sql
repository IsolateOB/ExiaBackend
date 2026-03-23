DELETE FROM team_template_patch_events
WHERE document_id = 'team-template'
  AND user_id IN (
    SELECT DISTINCT user_id
    FROM team_templates
    WHERE template_id = '__raid_copy__'
       OR template_id = 'default-local'
       OR template_id LIKE 'local-template-%'
       OR template_id LIKE '%-conflict-%'
  );

DELETE FROM team_template_documents
WHERE document_id = 'team-template'
  AND user_id IN (
    SELECT DISTINCT user_id
    FROM team_templates
    WHERE template_id = '__raid_copy__'
       OR template_id = 'default-local'
       OR template_id LIKE 'local-template-%'
       OR template_id LIKE '%-conflict-%'
  );

DELETE FROM team_template_members
WHERE template_id = '__raid_copy__'
   OR template_id = 'default-local'
   OR template_id LIKE 'local-template-%'
   OR template_id LIKE '%-conflict-%';

DELETE FROM team_templates
WHERE template_id = '__raid_copy__'
   OR template_id = 'default-local'
   OR template_id LIKE 'local-template-%'
   OR template_id LIKE '%-conflict-%';

DROP TRIGGER IF EXISTS trg_team_templates_reject_local_only_insert;
DROP TRIGGER IF EXISTS trg_team_templates_reject_local_only_update;
DROP TRIGGER IF EXISTS trg_team_template_members_reject_local_only_insert;
DROP TRIGGER IF EXISTS trg_team_template_members_reject_local_only_update;

CREATE TRIGGER trg_team_templates_reject_local_only_insert
BEFORE INSERT ON team_templates
FOR EACH ROW
WHEN NEW.template_id = '__raid_copy__'
  OR NEW.template_id = 'default-local'
  OR NEW.template_id LIKE 'local-template-%'
  OR NEW.template_id LIKE '%-conflict-%'
BEGIN
    SELECT RAISE(ABORT, 'local-only team templates cannot be stored in cloud');
END;

CREATE TRIGGER trg_team_templates_reject_local_only_update
BEFORE UPDATE ON team_templates
FOR EACH ROW
WHEN NEW.template_id = '__raid_copy__'
  OR NEW.template_id = 'default-local'
  OR NEW.template_id LIKE 'local-template-%'
  OR NEW.template_id LIKE '%-conflict-%'
BEGIN
    SELECT RAISE(ABORT, 'local-only team templates cannot be stored in cloud');
END;

CREATE TRIGGER trg_team_template_members_reject_local_only_insert
BEFORE INSERT ON team_template_members
FOR EACH ROW
WHEN NEW.template_id = '__raid_copy__'
  OR NEW.template_id = 'default-local'
  OR NEW.template_id LIKE 'local-template-%'
  OR NEW.template_id LIKE '%-conflict-%'
BEGIN
    SELECT RAISE(ABORT, 'local-only team templates cannot be stored in cloud');
END;

CREATE TRIGGER trg_team_template_members_reject_local_only_update
BEFORE UPDATE ON team_template_members
FOR EACH ROW
WHEN NEW.template_id = '__raid_copy__'
  OR NEW.template_id = 'default-local'
  OR NEW.template_id LIKE 'local-template-%'
  OR NEW.template_id LIKE '%-conflict-%'
BEGIN
    SELECT RAISE(ABORT, 'local-only team templates cannot be stored in cloud');
END;
