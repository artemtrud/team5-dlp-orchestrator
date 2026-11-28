BEGIN;

CREATE TYPE incident_status AS ENUM ('open','triaged','closed','false_positive');
CREATE TYPE incident_severity AS ENUM ('low','medium','high','critical');
CREATE TYPE entity_type AS ENUM ('ip','domain','url','hash','user','host');
CREATE TYPE verdict_source AS ENUM ('analyst','rule','ml','external');
CREATE TYPE verdict_label AS ENUM ('malicious','suspicious','benign','unknown');

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT NOT NULL,
    status          incident_status NOT NULL DEFAULT 'open',
    severity        incident_severity NOT NULL DEFAULT 'medium',
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    primary_ip      INET,
    primary_domain  TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at       TIMESTAMPTZ,
    CONSTRAINT window_ok CHECK (window_end > window_start),
    CONSTRAINT window_max_5min CHECK (window_end - window_start <= interval '5 minutes')
);

CREATE TABLE entities (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    type         entity_type NOT NULL,
    value        TEXT NOT NULL,
    value_hash   BYTEA NOT NULL,
    first_seen   TIMESTAMPTZ NOT NULL,
    last_seen    TIMESTAMPTZ NOT NULL,
    attrs        JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (incident_id, type, value_hash)
);

CREATE TABLE verdicts (
    id           BIGSERIAL PRIMARY KEY,
    incident_id  UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    entity_id    BIGINT REFERENCES entities(id) ON DELETE CASCADE,
    source       verdict_source NOT NULL,
    label        verdict_label NOT NULL,
    confidence   NUMERIC(4,3) CHECK (confidence >= 0 AND confidence <= 1),
    reason       TEXT,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;