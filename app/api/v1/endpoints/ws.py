"""
aegis.app.api.v1.endpoints.ws
----------------------------
实现 WebSocket 实时推送扫描进度。

Author: Python全栈专家
Created: 2026-02-05
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async city_connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@router.websocket("/ws/scans")
async def websocket_endpoint(websocket: WebSocket):
    await manager.city_connect(websocket)
    try:
        while True:
            # 模拟实时进度推送
            # 在实际生产中，这里应该监听 Redis Pub/Sub 或数据库变更
            await asyncio.sleep(5)
            await websocket.send_json({
                "type": "SCAN_UPDATE",
                "data": {
                    "task_id": 1,
                    "progress": 65,
                    "status": "RUNNING"
                }
            })
            # 保持连接
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
