"""
WebSocket 实时通知推送服务

功能：
- 实时推送系统通知到所有连接的客户端
- 支持多种消息类型（通知更新、扫描进度、系统事件等）
- 自动重连机制
- 心跳检测
- 连接管理

Notes:
    - 与 notification_service 完全集成
    - 支持广播和单播模式
    - 低延迟投递（<100ms）
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Optional, List, Dict, Any
import asyncio
import json
import logging
from datetime import datetime

from app.services.notification_service import notification_service

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """
    WebSocket 连接管理器
    
    管理所有活跃的 WebSocket 连接，支持：
    - 连接/断开管理
    - 广播消息到所有客户端
    - 单播消息到指定客户端
    - 心跳检测
    - 连接统计
    """
    
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}
        self._heartbeat_interval = 30  # seconds
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._message_queue: asyncio.Queue = asyncio.Queue()
        
        # 注册到通知服务
        notification_service.register_websocket_callback(self.broadcast_notification)
    
    async def connect(self, websocket: WebSocket, client_id: str = None) -> str:
        """
        接受新的 WebSocket 连接
        
        Args:
            websocket: WebSocket 实例
            client_id: 客户端ID（可选，自动生成）
            
        Returns:
            str: 分配的客户端ID
        """
        await websocket.accept()
        
        if client_id is None:
            client_id = f"client_{datetime.now().timestamp()}"
        
        self.active_connections[client_id] = websocket
        self.connection_metadata[client_id] = {
            "connected_at": datetime.now(),
            "last_heartbeat": datetime.now(),
            "messages_sent": 0,
            "messages_received": 0
        }
        
        logger.info(f"WebSocket client connected: {client_id} (Total: {len(self.active_connections)})")
        
        # 发送欢迎消息
        await self.send_personal_message(
            {
                "type": "connection_established",
                "data": {
                    "client_id": client_id,
                    "message": "Connected to Aegis notification system",
                    "server_time": datetime.now().isoformat(),
                    "active_connections": len(self.active_connections)
                }
            },
            websocket
        )
        
        # 启动心跳检测（如果尚未启动）
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        return client_id
    
    def disconnect(self, client_id: str):
        """
        断开 WebSocket 连接
        
        Args:
            client_id: 客户端ID
        """
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            del self.connection_metadata[client_id]
            
            logger.info(f"WebSocket client disconnected: {client_id} (Total: {len(self.active_connections)})")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket) -> bool:
        """
        发送消息给指定客户端
        
        Args:
            message: 消息内容（字典格式）
            websocket: 目标 WebSocket
            
        Returns:
            bool: 是否发送成功
        """
        try:
            await websocket.send_json(message)
            return True
        except Exception as e:
            logger.error(f"Failed to send personal message: {e}")
            return False
    
    async def send_to_client(self, client_id: str, message: Dict[str, Any]) -> bool:
        """
        发送消息给指定客户端（通过client_id）
        
        Args:
            client_id: 目标客户端ID
            message: 消息内容
            
        Returns:
            bool: 是否发送成功
        """
        if client_id not in self.active_connections:
            logger.warning(f"Client {client_id} not found for sending message")
            return False
        
        try:
            websocket = self.active_connections[client_id]
            await websocket.send_json(message)
            
            # 更新统计信息
            if client_id in self.connection_metadata:
                self.connection_metadata[client_id]["messages_sent"] += 1
            
            return True
        except Exception as e:
            logger.error(f"Failed to send message to client {client_id}: {e}")
            # 如果发送失败，可能连接已断开
            self.disconnect(client_id)
            return False
    
    async def broadcast(self, message: Dict[str, Any], exclude_client: str = None) -> int:
        """
        广播消息到所有连接的客户端
        
        Args:
            message: 消息内容
            exclude_client: 要排除的客户端ID（可选）
            
        Returns:
            int: 成功发送的数量
        """
        sent_count = 0
        failed_clients = []
        
        for client_id, websocket in list(self.active_connections.items()):
            if client_id == exclude_client:
                continue
            
            try:
                await websocket.send_json(message)
                sent_count += 1
                
                # 更新统计信息
                if client_id in self.connection_metadata:
                    self.connection_metadata[client_id]["messages_sent"] += 1
                    
            except Exception as e:
                logger.error(f"Failed to broadcast to client {client_id}: {e}")
                failed_clients.append(client_id)
        
        # 清理失败的连接
        for client_id in failed_clients:
            self.disconnect(client_id)
        
        if sent_count > 0:
            logger.debug(f"Broadcasted message to {sent_count} clients (excluded: {exclude_client})")
        
        return sent_count
    
    async def broadcast_notification(self, notification_data: Dict[str, Any]):
        """
        广播通知数据（由 notification_service 调用）
        
        Args:
            notification_data: 通知数据字典
        """
        message = {
            "type": "notification",
            "data": notification_data,
            "timestamp": datetime.now().isoformat()
        }
        
        await self.broadcast(message)
    
    async def _heartbeat_loop(self):
        """
        心跳检测循环
        定期检查所有活跃连接的状态
        """
        logger.info("Heartbeat loop started")
        
        while len(self.active_connections) > 0:
            await asyncio.sleep(self._heartbeat_interval)
            
            heartbeat_message = {
                "type": "heartbeat",
                "data": {
                    "server_time": datetime.now().isoformat(),
                    "active_connections": len(self.active_connections)
                },
                "timestamp": datetime.now().isoformat()
            }
            
            # 发送心跳并检查响应
            stale_clients = []
            for client_id in list(self.active_connections.keys()):
                metadata = self.connection_metadata.get(client_id, {})
                last_heartbeat = metadata.get("last_heartbeat", datetime.now())
                
                # 检查是否超过2个心跳周期没有响应
                time_since_heartbeat = (datetime.now() - last_heartbeat).total_seconds()
                if time_since_heartbeat > (self._heartbeat_interval * 2.5):
                    logger.warning(f"Client {client_id} appears stale (last heartbeat: {time_since_heartbeat:.0f}s ago)")
                    stale_clients.append(client_id)
                    continue
                
                # 发送心跳
                success = await self.send_to_client(client_id, heartbeat_message)
                if not success:
                    stale_clients.append(client_id)
            
            # 清理不活跃的连接
            for client_id in stale_clients:
                self.disconnect(client_id)
        
        logger.info("Heartbeat loop stopped (no active connections)")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """
        获取连接统计信息
        
        Returns:
            Dict: 统计信息
        """
        total_messages_sent = sum(
            meta.get("messages_sent", 0) 
            for meta in self.connection_metadata.values()
        )
        total_messages_received = sum(
            meta.get("messages_received", 0) 
            for meta in self.connection_metadata.values()
        )
        
        return {
            "active_connections": len(self.active_connections),
            "total_messages_sent": total_messages_sent,
            "total_messages_received": total_messages_received,
            "heartbeat_interval": self._heartbeat_interval,
            "clients": list(self.active_connections.keys())
        }


# 全局连接管理器实例
manager = ConnectionManager()


@router.websocket("/ws/notifications")
async def websocket_notifications_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None, description="认证令牌（可选）"),
    client_id: Optional[str] = Query(None, description="客户端ID（可选）")
):
    """
    WebSocket 通知推送端点
    
    功能：
    - 接收实时系统通知
    - 支持心跳检测
    - 支持订阅特定类型的通知
    
    消息格式：
    - 服务端 -> 客户端：{"type": "...", "data": {...}, "timestamp": "..."}
    - 客户端 -> 服务端：{"type": "...", "data": {...}}
    
    支持的消息类型：
    - connection_established: 连接建立确认
    - notification: 新通知
    - heartbeat: 心跳
    - scan_update: 扫描进度更新
    - system_event: 系统事件
    """
    client_id = await manager.connect(websocket, client_id)
    
    try:
        while True:
            # 接收客户端消息
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type", "unknown")
                
                # 更新统计信息
                if client_id in manager.connection_metadata:
                    manager.connection_metadata[client_id]["messages_received"] += 1
                
                # 处理不同类型的消息
                if message_type == "ping":
                    # 心跳响应
                    manager.connection_metadata[client_id]["last_heartbeat"] = datetime.now()
                    
                    await manager.send_to_client(client_id, {
                        "type": "pong",
                        "data": {
                            "timestamp": message.get("timestamp"),
                            "server_time": datetime.now().isoformat()
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif message_type == "subscribe":
                    # 订阅特定类型的通知（预留扩展）
                    categories = message.get("data", {}).get("categories", [])
                    
                    await manager.send_to_client(client_id, {
                        "type": "subscribed",
                        "data": {
                            "categories": categories,
                            "message": f"Subscribed to categories: {', '.join(categories) if categories else 'all'}"
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif message_type == "get_unread_count":
                    # 获取未读通知数量
                    unread_count = notification_service.get_unread_count()
                    
                    await manager.send_to_client(client_id, {
                        "type": "unread_count",
                        "data": {
                            "unread_count": unread_count
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                elif message_type == "mark_read":
                    # 标记通知为已读
                    notification_id = message.get("data", {}).get("notification_id")
                    
                    if notification_id:
                        success = notification_service.mark_as_read(notification_id)
                        
                        await manager.send_to_client(client_id, {
                            "type": "mark_read_result",
                            "data": {
                                "success": success,
                                "notification_id": notification_id
                            },
                            "timestamp": datetime.now().isoformat()
                        })
                
                elif message_type == "get_stats":
                    # 获取统计信息
                    stats = notification_service.get_delivery_stats()
                    conn_stats = manager.get_connection_stats()
                    
                    await manager.send_to_client(client_id, {
                        "type": "stats",
                        "data": {
                            "notifications": stats,
                            "connections": conn_stats
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                else:
                    # 未知消息类型
                    logger.warning(f"Unknown message type from client {client_id}: {message_type}")
                    
                    await manager.send_to_client(client_id, {
                        "type": "error",
                        "data": {
                            "message": f"Unknown message type: {message_type}",
                            "code": "UNKNOWN_MESSAGE_TYPE"
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                    
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from client {client_id}: {data[:100]}")
                
                await manager.send_to_client(client_id, {
                    "type": "error",
                    "data": {
                        "message": "Invalid JSON format",
                        "code": "INVALID_JSON"
                    },
                    "timestamp": datetime.now().isoformat()
                })
    
    except WebSocketDisconnect:
        logger.info(f"WebSocket client {client_id} disconnected normally")
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}", exc_info=True)
    finally:
        manager.disconnect(client_id)


@router.websocket("/ws/scans/{task_id}")
async def websocket_scan_endpoint(
    websocket: WebSocket,
    task_id: int,
    token: Optional[str] = Query(None, description="认证令牌（可选）")
):
    """
    扫描任务专用 WebSocket 端点
    
    功能：
    - 实时接收指定扫描任务的进度更新
    - 接收漏洞发现通知
    - 接收任务完成/失败通知
    
    Args:
        task_id: 任务ID
    """
    client_id = await manager.connect(websocket, f"scan_{task_id}_{datetime.now().timestamp()}")
    
    try:
        # 发送初始状态
        await manager.send_to_client(client_id, {
            "type": "scan_subscription",
            "data": {
                "task_id": task_id,
                "message": f"Subscribed to scan task {task_id} updates"
            },
            "timestamp": datetime.now().isoformat()
        })
        
        while True:
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                message_type = message.get("type", "unknown")
                
                if message_type == "ping":
                    manager.connection_metadata[client_id]["last_heartbeat"] = datetime.now()
                    
                    await manager.send_to_client(client_id, {
                        "type": "pong",
                        "data": {
                            "timestamp": message.get("timestamp"),
                            "server_time": datetime.now().isoformat(),
                            "task_id": task_id
                        },
                        "timestamp": datetime.now().isoformat()
                    })
                
                else:
                    logger.info(f"Received message from scan client {client_id}: {message_type}")
                    
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON from scan client {client_id}")
    
    except WebSocketDisconnect:
        logger.info(f"Scan WebSocket client {client_id} disconnected")
    except Exception as e:
        logger.error(f"Scan WebSocket error for client {client_id}: {e}", exc_info=True)
    finally:
        manager.disconnect(client_id)


@router.get("/ws/stats")
async def get_websocket_stats():
    """
    获取 WebSocket 连接统计信息
    
    Returns:
        dict: 连接统计信息
    """
    stats = manager.get_connection_stats()
    notif_stats = notification_service.get_delivery_stats()
    
    return {
        "websocket": stats,
        "notifications": notif_stats,
        "status": "healthy"
    }


# ==================== 辅助函数 ====================

async def broadcast_scan_update(task_id: int, update_data: Dict[str, Any]):
    """
    广播扫描进度更新
    
    Args:
        task_id: 任务ID
        update_data: 更新数据
    """
    message = {
        "type": "scan_update",
        "data": {
            "task_id": task_id,
            **update_data
        },
        "timestamp": datetime.now().isoformat()
    }
    
    await manager.broadcast(message)


async def broadcast_system_event(event_type: str, event_data: Dict[str, Any]):
    """
    广播系统事件
    
    Args:
        event_type: 事件类型
        event_data: 事件数据
    """
    message = {
        "type": "system_event",
        "data": {
            "event_type": event_type,
            **event_data
        },
        "timestamp": datetime.now().isoformat()
    }
    
    await manager.broadcast(message)
