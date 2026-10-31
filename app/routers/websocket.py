from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.websocket import manager
from app.utils.security import decode_token
from jose import JWTError

router=APIRouter(tags=["Realtime"])

@router.websocket("/ws/alerts")
async def alerts_socket(websocket:WebSocket,token:str|None=None):
    if not token:
        await websocket.close(code=4401); return
    try:
        payload=decode_token(token)
        if payload.get("type")!="access": raise ValueError()
    except (JWTError,ValueError):
        await websocket.close(code=4401); return
    await manager.connect(websocket)
    try:
        while True:
            # Client ping/pong keeps intermediary connections alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
