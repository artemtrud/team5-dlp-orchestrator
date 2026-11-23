import json
import os
from fastapi import FastAPI, Header, HTTPException, status
import redis.asyncio as redis
from app.schemas.contracts import DnsEventIn, ProxyEventIn

app = FastAPI(title="LLM DLP Orchestrator (Team 5)", version="1.0.0")

REDIS_URL = os.getenv("REDIS_URL", "redis://event-bus:6379/0")
DNS_API_KEY = os.getenv("DNS_SERVICE_API_KEY", "dns_secret_token_123")
PROXY_API_KEY = os.getenv("PROXY_SERVICE_API_KEY", "proxy_secret_token_456")

redis_client = redis.from_url(REDIS_URL, decode_responses=True)

@app.get("/health")
async def health():
    return {"status": "ok", "team": "Team 5 Orchestrator"}

@app.post("/api/v1/events/dns", status_code=status.HTTP_202_ACCEPTED)
async def receive_dns_event(
    event: DnsEventIn,
    x_service_api_key: str = Header(..., alias="X-Service-API-Key")
):
    if x_service_api_key != DNS_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid DNS API Key")

    payload = {
        "source": "dns",
        "client_ip": str(event.client_ip),
        "domain": event.domain.lower().strip(),
        "timestamp": event.timestamp.isoformat(),
    }
    await redis_client.xadd("dlp_events_stream", {"data": json.dumps(payload)})
    return {"status": "accepted", "source": "dns"}

@app.post("/api/v1/events/proxy", status_code=status.HTTP_202_ACCEPTED)
async def receive_proxy_event(
    event: ProxyEventIn,
    x_service_api_key: str = Header(..., alias="X-Service-API-Key")
):
    if x_service_api_key != PROXY_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid Proxy API Key")

    payload = {
        "source": "proxy",
        "client_ip": str(event.client_ip),
        "domain": event.domain.lower().strip(),
        "timestamp": event.timestamp.isoformat(),
        "action": event.action.value,
        "policy_name": event.policy_name,
        "reason": event.reason,
        "entities": [e.model_dump() for e in event.entities],
    }
    await redis_client.xadd("dlp_events_stream", {"data": json.dumps(payload)})
    return {"status": "accepted", "source": "proxy"}
