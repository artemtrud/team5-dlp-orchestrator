from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON, Numeric
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import uuid
import enum
from .database import Base

class UserRole(str, enum.Enum):
    ANALYST = "analyst"
    ADMIN = "admin"
    AUDITOR = "auditor"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(Text, nullable=False)
    status = Column(String, default="open")
    severity = Column(String, default="medium")
    window_start = Column(DateTime(timezone=True), nullable=False)
    window_end = Column(DateTime(timezone=True), nullable=False)
    primary_ip = Column(INET)
    primary_domain = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    entities = relationship("Entity", back_populates="incident")
    verdicts = relationship("Verdict", back_populates="incident")

class Entity(Base):
    __tablename__ = "entities"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"))
    type = Column(String, nullable=False)
    value = Column(Text, nullable=False)
    value_hash = Column(String, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=False)
    last_seen = Column(DateTime(timezone=True), nullable=False)
    attrs = Column(JSON, default={})
    
    incident = relationship("Incident", back_populates="entities")

class Verdict(Base):
    __tablename__ = "verdicts"
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"))
    entity_id = Column(Integer, ForeignKey("entities.id", ondelete="CASCADE"))
    source = Column(String, nullable=False)
    label = Column(String, nullable=False)
    confidence = Column(Numeric(4, 3))
    reason = Column(Text)
    created_by = Column(Integer, ForeignKey("users.id")) # Привязка к юзеру!
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    incident = relationship("Incident", back_populates="verdicts")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    ts = Column(DateTime(timezone=True), server_default=func.now())
    actor_id = Column(Integer, ForeignKey("users.id")) # Привязка к юзеру!
    action = Column(String, nullable=False)
    object_type = Column(String, nullable=False)
    object_id = Column(String, nullable=False)
    before = Column(JSON)
    after = Column(JSON)
    request_id = Column(String)
    ip = Column(INET)
