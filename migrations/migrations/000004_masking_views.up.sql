BEGIN;

CREATE TABLE pii_vault (
    entity_id  BIGINT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
    ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION mask_value(v TEXT) RETURNS TEXT AS $$
    SELECT CASE
        WHEN v IS NULL THEN NULL
        WHEN v ~ '^[^@]+@[^@]+$' THEN
            left(split_part(v,'@',1),1) || '***@' || split_part(v,'@',2)
        WHEN length(v) <= 2 THEN repeat('*', length(v))
        ELSE left(v,2) || repeat('*', greatest(length(v)-4,0)) || right(v,2)
    END;
$$ LANGUAGE sql IMMUTABLE;

CREATE VIEW v_incidents_masked AS
SELECT
    i.id, i.title, i.status, i.severity,
    i.window_start, i.window_end,
    i.primary_ip::text          AS primary_ip,
    i.primary_domain,
    i.created_at, i.updated_at, i.closed_at,
    (SELECT count(*) FROM entities e WHERE e.incident_id = i.id) AS entities_count,
    (SELECT max(v.created_at) FROM verdicts v WHERE v.incident_id = i.id) AS last_verdict_at
FROM incidents i;

CREATE VIEW v_entities_masked AS
SELECT
    e.id, e.incident_id, e.type,
    CASE e.type
        WHEN 'user' THEN mask_value(e.value)
        ELSE e.value
    END AS value,
    e.first_seen, e.last_seen, e.attrs
FROM entities e;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'analyst') THEN
        CREATE ROLE analyst;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'auditor') THEN
        CREATE ROLE auditor;
    END IF;
END $$;

GRANT SELECT ON v_incidents_masked, v_entities_masked TO analyst, auditor;
GRANT INSERT, UPDATE ON incidents, entities, verdicts TO analyst;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO analyst;
GRANT SELECT ON audit_log TO auditor;

COMMIT;