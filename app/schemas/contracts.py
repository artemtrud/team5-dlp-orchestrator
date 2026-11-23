from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, IPvAnyAddress, field_validator

class EntityType(str, Enum):
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

class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    MASK = "MASK"
    PSEUDONYMIZE = "PSEUDONYMIZE"
    BLOCK = "BLOCK"

class MaskedEntity(BaseModel):
    entity_type: EntityType
    masked_value: str
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator("masked_value")
    @classmethod
    def ensure_masked(cls, v: str) -> str:
        if "*" not in v and "#" not in v and "[MASKED]" not in v:
            raise ValueError("Передано немаскированное значение ПДн! Разрешены только маскированные данные.")
        return v

class DnsEventIn(BaseModel):
    client_ip: IPvAnyAddress
    domain: str
    timestamp: datetime

class ProxyEventIn(BaseModel):
    client_ip: IPvAnyAddress
    domain: str
    timestamp: datetime
    action: PolicyAction
    policy_name: str = "default_policy"
    reason: str | None = None
    entities: list[MaskedEntity] = []
