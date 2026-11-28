BEGIN;

CREATE TABLE audit_log (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_id     UUID,
    actor_role   TEXT,
    action       TEXT NOT NULL,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    before       JSONB,
    after        JSONB,
    request_id   TEXT,
    ip           INET
);

CREATE INDEX idx_audit_ts        ON audit_log (ts DESC);
CREATE INDEX idx_audit_object    ON audit_log (object_type, object_id);
CREATE INDEX idx_audit_actor     ON audit_log (actor_id, ts DESC);

CREATE OR REPLACE FUNCTION fn_audit_incidents() RETURNS trigger AS $$
BEGIN
    INSERT INTO audit_log(actor_id, actor_role, action, object_type, object_id, before, after)
    VALUES (
        NULLIF(current_setting('app.user_id', true), '')::uuid,
        NULLIF(current_setting('app.user_role', true), ''),
        TG_OP,
        'incident',
        COALESCE(NEW.id, OLD.id)::text,
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END
    );
    RETURN COALESCE(NEW, OLD);
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_incidents
AFTER INSERT OR UPDATE OR DELETE ON incidents
FOR EACH ROW EXECUTE FUNCTION fn_audit_incidents();

CREATE OR REPLACE FUNCTION fn_audit_verdicts() RETURNS trigger AS $$
BEGIN
    INSERT INTO audit_log(actor_id, actor_role, action, object_type, object_id, before, after)
    VALUES (
        NULLIF(current_setting('app.user_id', true), '')::uuid,
        NULLIF(current_setting('app.user_role', true), ''),
        TG_OP, 'verdict',
        COALESCE(NEW.id, OLD.id)::text,
        CASE WHEN TG_OP <> 'INSERT' THEN to_jsonb(OLD) END,
        CASE WHEN TG_OP <> 'DELETE' THEN to_jsonb(NEW) END
    );
    RETURN COALESCE(NEW, OLD);
END; $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_verdicts
AFTER INSERT OR UPDATE OR DELETE ON verdicts
FOR EACH ROW EXECUTE FUNCTION fn_audit_verdicts();

COMMIT;