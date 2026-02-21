"""
WebSocket消费者
处理实时任务状态更新
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth.models import User
from scans.models import ScanTask
import logging

logger = logging.getLogger(__name__)


class TaskStatusConsumer(AsyncWebsocketConsumer):
    """
    任务状态WebSocket消费者
    实时推送任务状态更新
    """

    async def connect(self):
        """建立WebSocket连接"""
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        self.room_group_name = f'task_{self.task_id}'

        # 验证用户身份和任务权限
        user = self.scope.get('user')
        if not user or not user.is_authenticated:
            await self.close(code=4001)  # 未授权
            return

        # 检查用户是否有权限访问该任务
        has_permission = await self._check_task_permission(user, self.task_id)
        if not has_permission:
            await self.close(code=4003)  # 权限不足
            return

        # 加入房间组
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

        # 发送连接成功消息
        await self.send(text_data=json.dumps({
            'type': 'connection_established',
            'message': 'Connected to task status updates',
            'task_id': self.task_id
        }))

        logger.info(f"WebSocket connection established for task {self.task_id}")

    async def disconnect(self, close_code):
        """断开WebSocket连接"""
        # 离开房间组
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

        logger.info(f"WebSocket connection closed for task {self.task_id}")

    async def receive(self, text_data):
        """接收客户端消息"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'subscribe':
                # 确认订阅
                await self.send(text_data=json.dumps({
                    'type': 'subscribed',
                    'task_id': self.task_id,
                    'message': 'Successfully subscribed to task updates'
                }))

            elif message_type == 'ping':
                # 心跳响应
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {str(e)}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Internal server error'
            }))

    async def task_status_update(self, event):
        """处理任务状态更新事件"""
        # 转发任务状态更新到客户端
        await self.send(text_data=json.dumps(event['data']))

    async def progress_update(self, event):
        """处理进度更新事件"""
        await self.send(text_data=json.dumps(event['data']))

    async def vulnerability_found(self, event):
        """处理发现漏洞事件"""
        await self.send(text_data=json.dumps(event['data']))

    async def task_completed(self, event):
        """处理任务完成事件"""
        await self.send(text_data=json.dumps(event['data']))

    async def task_failed(self, event):
        """处理任务失败事件"""
        await self.send(text_data=json.dumps(event['data']))

    @database_sync_to_async
    def _check_task_permission(self, user, task_id):
        """检查用户是否有权限访问任务"""
        try:
            task = ScanTask.objects.get(task_id=task_id, created_by=user)
            return True
        except ScanTask.DoesNotExist:
            return False


# 广播任务状态更新的工具函数
async def broadcast_task_update(task_id, update_type, data):
    """
    广播任务更新到所有连接的客户端

    Args:
        task_id: 任务ID
        update_type: 更新类型 (status_update, progress_update, vulnerability_found, etc.)
        data: 更新数据
    """
    from channels.layers import get_channel_layer

    channel_layer = get_channel_layer()
    room_group_name = f'task_{task_id}'

    await channel_layer.group_send(
        room_group_name,
        {
            'type': update_type,
            'data': data
        }
    )


async def send_task_status_update(task):
    """发送任务状态更新"""
    from django.utils import timezone

    data = {
        'type': 'status_update',
        'task_id': task.task_id,
        'data': {
            'status': task.status,
            'progress': task.progress,
            'current_phase': _get_current_phase(task),
            'started_at': task.started_at.isoformat() if task.started_at else None,
            'completed_at': task.completed_at.isoformat() if task.completed_at else None,
            'pages_scanned': task.pages_scanned,
            'vulnerabilities_found': task.vulnerabilities_found,
            'timestamp': timezone.now().isoformat()
        }
    }

    await broadcast_task_update(task.task_id, 'task_status_update', data)


async def send_vulnerability_found(task, vulnerability):
    """发送发现漏洞通知"""
    from django.utils import timezone

    data = {
        'type': 'vulnerability_found',
        'task_id': task.task_id,
        'data': {
            'vulnerability_id': vulnerability.vulnerability_id,
            'name': vulnerability.name,
            'type': vulnerability.type,
            'risk_level': vulnerability.risk_level,
            'cvss_score': vulnerability.cvss_score,
            'url': vulnerability.url,
            'timestamp': timezone.now().isoformat()
        }
    }

    await broadcast_task_update(task.task_id, 'vulnerability_found', data)


async def send_task_completed(task):
    """发送任务完成通知"""
    from django.utils import timezone

    data = {
        'type': 'task_completed',
        'task_id': task.task_id,
        'data': {
            'status': 'completed',
            'progress': 100,
            'vulnerabilities_found': task.vulnerabilities_found,
            'duration_seconds': task.duration_seconds(),
            'timestamp': timezone.now().isoformat()
        }
    }

    await broadcast_task_update(task.task_id, 'task_completed', data)


async def send_task_failed(task, error_message=None):
    """发送任务失败通知"""
    from django.utils import timezone

    data = {
        'type': 'task_failed',
        'task_id': task.task_id,
        'data': {
            'status': 'failed',
            'error_message': error_message or 'Task execution failed',
            'timestamp': timezone.now().isoformat()
        }
    }

    await broadcast_task_update(task.task_id, 'task_failed', data)


def _get_current_phase(task):
    """根据任务进度确定当前阶段"""
    if task.status != 'running':
        return 'N/A'

    progress = task.progress
    if progress < 20:
        return 'Initializing'
    elif progress < 40:
        return 'Crawling Website'
    elif progress < 60:
        return 'SQL Injection Testing'
    elif progress < 80:
        return 'XSS Testing'
    elif progress < 100:
        return 'Report Generation'
    else:
        return 'Completed'
