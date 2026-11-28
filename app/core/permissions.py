from app.core.dependencies import require_roles


view_incidents = require_roles(
    "analyst", "admin", "auditor"
)

change_incident = require_roles(
    "analyst", "admin"
)

add_verdict = require_roles(
    "analyst", "admin"
)

manage_users = require_roles("admin")

manage_llm_domains = require_roles("admin")

view_audit_logs = require_roles(
    "admin", "auditor"
)