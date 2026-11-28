import asyncio
import json
import os
import uuid
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://event-bus:6379/0")
WINDOW_SECONDS = 300

async def process_events():
    r = redis.from_url(REDIS_URL, decode_responses=True)
    last_id = "$"
    print("[Worker] Запущен воркер корреляции (окно 5 мин)...")
    while True:
        streams = await r.xread({"dlp_events_stream": last_id}, block=5000, count=10)
        for _, messages in streams:
            for msg_id, fields in messages:
                last_id = msg_id
                event = json.loads(fields["data"])
                await correlate_event(r, event)

async def correlate_event(r: redis.Redis, event: dict):
    window_key = f"incident_window:{event['client_ip']}:{event['domain']}"
    incident_id = await r.get(window_key)

    if not incident_id:
        incident_id = str(uuid.uuid4())
        await r.setex(window_key, WINDOW_SECONDS, incident_id)
        event_type = "INCIDENT_CREATED"
    else:
        event_type = "INCIDENT_UPDATED"

    ws_message = {
        "event": event_type,
        "data": {
            "id": incident_id,
            "source_added": event["source"],
            "client_ip": event["client_ip"],
            "domain": event["domain"],
            "timestamp": event["timestamp"],
            "action": event.get("action", "WARN"),
        }
    }
    await r.publish("ws_incidents_channel", json.dumps(ws_message))
    print(f"[{event_type}] ID={incident_id} | {event['source']} -> {event['client_ip']} -> {event['domain']}")

if __name__ == "__main__":
    asyncio.run(process_events())
