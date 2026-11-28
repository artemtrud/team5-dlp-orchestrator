import json

from fastapi import WebSocket
from redis.asyncio import Redis

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)

manager = ConnectionManager()

async def redis_listener(redis_client: Redis):
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("ws_incidents_channel")

    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = json.loads(message["data"])
                await manager.broadcast(data)
    finally:
        await pubsub.unsubscribe("ws_incidents_channel")
        await pubsub.aclose()