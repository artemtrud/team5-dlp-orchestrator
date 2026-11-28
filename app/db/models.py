import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, Enum, ForeignKey, Float, Text, BigInteger, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, INET
from app.db.database import Base
import enum

class UserRole(str, enum.Enum):
    analyst = "analyst"
    admin = "admin"
    auditor = "auditor"

class IncidentStatus(str, enum.Enum):
    new = "new"
    in_progress = "in_progress"
    resolved = "resolved"

class PolicyAction(str, enum.Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    MASK = "MASK"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    BLOCK = "BLOCK"

class EntityType(str, enum.Enum):
    PERSON = "PERSON"
    PASSPORT = "PASSPORT"
    SNILS = "SNILS"
    INN = "INN"
    PHONE = "PHONE"
    EMAIL = "EMAIL"
    ADDRESS = "ADDRESS"
    BANK_CARD = "BANK_CARD"
    SECRET = "SECRET"
    NDA_MARKER = "NDA_MARKER"
    API_KEY = "API_KEY"

class EventSource(str, enum.Enum):
    DNS = "DNS"
    PROXY = "PROXY"
    DLP = "DLP"

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.analyst, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    audit_logs = relationship("AuditLog", back_populates="actor")

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_ip: Mapped[str] = mapped_column(INET, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(Enum(IncidentStatus), default=IncidentStatus.new)
    final_action: Mapped[PolicyAction] = mapped_column(Enum(PolicyAction), nullable=True)

    raw_events = relationship("RawEvent", back_populates="incident")
    detected_entities = relationship("DetectedEntity", back_populates="incident")
    verdicts = relationship("PolicyVerdict", back_populates="incident")

class RawEvent(Base):
    __tablename__ = "raw_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    source: Mapped[EventSource] = mapped_column(Enum(EventSource), nullable=False)
    client_ip: Mapped[str] = mapped_column(INET, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    event_timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    incident = relationship("Incident", back_populates="raw_events")

class DetectedEntity(Base):
    __tablename__ = "detected_entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    entity_type: Mapped[EntityType] = mapped_column(Enum(EntityType), nullable=False)
    masked_value: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    incident = relationship("Incident", back_populates="detected_entities")

class PolicyVerdict(Base):
    __tablename__ = "policies_verdicts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    policy_name: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[PolicyAction] = mapped_column(Enum(PolicyAction), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=True)

    incident = relationship("Incident", back_populates="verdicts")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    actor = relationship("User", back_populates="audit_logs")
