from fastapi import WebSocket
from typing import Set
import asyncio

class ConnectionManager:
    def __init__(self):
        self.connections: Set[WebSocket] = set()
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self.lock:
            self.connections.add(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self.lock:
            self.connections.discard(websocket)

    async def broadcast(self, payload: dict):
        async with self.lock:
            clients = list(self.connections)
        stale = []
        for client in clients:
            try:
                await client.send_json(payload)
            except Exception:
                stale.append(client)
        for client in stale:
            await self.disconnect(client)

manager = ConnectionManager()
