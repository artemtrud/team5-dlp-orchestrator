BEGIN;

CREATE INDEX idx_incidents_primary_ip     ON incidents (primary_ip);
CREATE INDEX idx_incidents_primary_domain ON incidents (lower(primary_domain));
CREATE INDEX idx_incidents_window         ON incidents (window_start, window_end);
CREATE INDEX idx_incidents_status_sev     ON incidents (status, severity);
CREATE INDEX idx_incidents_created        ON incidents (created_at DESC);

CREATE INDEX idx_entities_hash   ON entities (value_hash);
CREATE INDEX idx_entities_inc    ON entities (incident_id);
CREATE INDEX idx_entities_type   ON entities (type);

CREATE INDEX idx_verdicts_incident ON verdicts (incident_id);
CREATE INDEX idx_verdicts_label    ON verdicts (label);

CREATE INDEX idx_entities_attrs ON entities USING gin (attrs);

COMMIT;