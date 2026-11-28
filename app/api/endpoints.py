from enum import Enum
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.database import get_db
from app.db.models import Incident, Entity, Verdict

router = APIRouter(prefix="/api/v1", tags=["Frontend API"])

class IncidentStatus(str, Enum):
    NEW = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class IncidentAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    MASK = "MASK"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    BLOCK = "BLOCK"

class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus

def incident_to_dict(incident: Incident):
    verdicts = incident.verdicts

    return {
        "id": str(incident.id),
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
        "client_ip": str(incident.primary_ip) if incident.primary_ip else None,
        "domain": incident.primary_domain,
        "window_start": incident.window_start,
        "window_end": incident.window_end,
        "final_action": verdicts[-1].label if verdicts else None,
        "entities_summary": [
            entity.type for entity in incident.entities
        ],
        "created_at": incident.created_at,
    }

@router.get("/incidents")
async def get_incidents(
    incident_status: IncidentStatus | None = Query(default=None, alias="status"),
    action: IncidentAction | None = None,
    domain: str | None = None,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident).options(
        selectinload(Incident.entities),
        selectinload(Incident.verdicts),
    )

    if incident_status:
        query = query.where(Incident.status == incident_status.value)

    if domain:
        query = query.where(Incident.primary_domain.ilike(f"%{domain}%"))

    if action:
        query = query.where(
            Incident.verdicts.any(Verdict.label == action.value)
        )

    query = query.order_by(Incident.created_at.desc())
    query = query.offset((page - 1) * size).limit(size)

    result = await db.execute(query)
    incidents = result.scalars().all()

    return {
        "page": page,
        "size": size,
        "items": [incident_to_dict(item) for item in incidents],
    }

@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Incident)
        .options(
            selectinload(Incident.entities),
            selectinload(Incident.verdicts),
        )
        .where(Incident.id == incident_id)
    )

    result = await db.execute(query)
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    data = incident_to_dict(incident)
    data["entities"] = [
        {
            "type": entity.type,
            "value": entity.value,
            "first_seen": entity.first_seen,
            "last_seen": entity.last_seen,
        }
        for entity in incident.entities
    ]

    data["verdicts"] = [
        {
            "source": verdict.source,
            "label": verdict.label,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        }
        for verdict in incident.verdicts
    ]

    return data

@router.patch("/incidents/{incident_id}/status")
async def update_incident_status(
    incident_id: UUID,
    body: IncidentStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Incident).where(Incident.id == incident_id)
    )
    incident = result.scalar_one_or_none()

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    incident.status = body.status.value

    await db.commit()
    await db.refresh(incident)

    return {
        "id": str(incident.id),
        "status": incident.status,
        "message": "Incident status updated",
    }