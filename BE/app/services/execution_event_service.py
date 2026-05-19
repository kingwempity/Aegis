"""
扫描执行事件服务：持久化 + WebSocket 广播（供 Worker / ScannerEngine 调用）。
"""

import asyncio
import copy
import logging
import threading
from datetime import datetime
from typing import Any, Callable, Dict, Optional

from sqlalchemy.orm import Session

from app.models.scan_execution_event import ScanExecutionEvent
from app.models.task import ScanTask

logger = logging.getLogger(__name__)

_seq_lock = threading.Lock()
_task_seq: Dict[int, int] = {}


def _next_seq(task_id: int) -> int:
    with _seq_lock:
        current = _task_seq.get(task_id, 0) + 1
        _task_seq[task_id] = current
        return current


def reset_task_seq(task_id: int) -> None:
    with _seq_lock:
        _task_seq.pop(task_id, None)


def _sanitize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not headers:
        return {}
    redacted_keys = {"authorization", "cookie", "set-cookie", "x-api-key", "x-csrf-token"}
    safe = {}
    for key, value in headers.items():
        if key.lower() in redacted_keys:
            safe[key] = "***"
        else:
            safe[key] = value
    return safe


def _truncate_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = copy.deepcopy(payload)
    for section in ("request", "response"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        body = block.get("body") or block.get("body_snippet")
        if isinstance(body, str) and len(body) > 4096:
            block["body_snippet"] = body[:4096]
            block.pop("body", None)
        headers = block.get("headers")
        if isinstance(headers, dict):
            block["headers"] = _sanitize_headers(headers)
    return data


async def _broadcast_scan_execution_event(event_data: Dict[str, Any]) -> None:
    try:
        from app.api.v1.endpoints.ws import manager
        await manager.broadcast({
            "type": "scan_execution_event",
            "data": event_data,
            "timestamp": datetime.now().isoformat(),
        })
    except Exception as e:
        logger.debug(f"WS broadcast scan_execution_event skipped: {e}")


def _schedule_ws_broadcast(event_data: Dict[str, Any]) -> None:
    try:
        from app.services.notification_service import notification_service
        if notification_service._worker_loop is None or notification_service._worker_loop.is_closed():
            return
        if not notification_service._worker_loop_ready.wait(timeout=2.0):
            return
        asyncio.run_coroutine_threadsafe(
            _broadcast_scan_execution_event(event_data),
            notification_service._worker_loop,
        )
    except Exception as e:
        logger.debug(f"Schedule WS broadcast failed: {e}")


class ExecutionEventReporter:
    """ScannerEngine / Worker 使用的进度上报器。"""

    def __init__(self, task_id: int, db: Session, verbose_requests: bool = False):
        self.task_id = task_id
        self.db = db
        self.verbose_requests = verbose_requests
        self._request_count = 0
        self._judgment_count = 0
        self._confirmed_count = 0

    def emit(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        progress: Optional[int] = None,
        current_stage: Optional[str] = None,
    ) -> Optional[ScanExecutionEvent]:
        if event_type == "request_completed" and not self.verbose_requests:
            self._request_count += 1
            if self._request_count % 5 != 0:
                if progress is not None or current_stage:
                    self._update_task_meta(progress, current_stage)
                    self.db.commit()
                return None

        safe_payload = _truncate_payload(payload)
        seq = _next_seq(self.task_id)

        record = ScanExecutionEvent(
            task_id=self.task_id,
            seq=seq,
            event_type=event_type,
            payload=safe_payload,
        )
        self.db.add(record)

        if progress is not None or current_stage:
            self._update_task_meta(progress, current_stage)

        try:
            self.db.commit()
            self.db.refresh(record)
        except Exception as e:
            self.db.rollback()
            logger.warning(f"Failed to persist execution event: {e}")
            return None

        stats_snapshot = {
            "requests": self._request_count,
            "judgments": self._judgment_count,
            "confirmed": self._confirmed_count,
        }
        event_out = {
            "task_id": self.task_id,
            "seq": seq,
            "event_type": event_type,
            "payload": {**safe_payload, "stats": stats_snapshot},
            "progress": progress,
            "current_stage": current_stage,
            "stats": stats_snapshot,
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }
        _schedule_ws_broadcast(event_out)
        return record

    def _update_task_meta(self, progress: Optional[int], current_stage: Optional[str]) -> None:
        task = self.db.query(ScanTask).filter(ScanTask.id == self.task_id).first()
        if not task:
            return
        if progress is not None:
            task.progress = max(0, min(100, int(progress)))
        if current_stage:
            task.current_stage = current_stage[:255]

    def phase_started(self, phase: str, label: str) -> None:
        self.emit("phase_started", {"phase": phase, "label": label}, current_stage=label)

    def request_completed(
        self,
        *,
        plugin_id: str,
        url: str,
        request: Dict[str, Any],
        response: Dict[str, Any],
        duration_ms: float,
        progress: Optional[int] = None,
    ) -> None:
        self._request_count += 1
        self.emit(
            "request_completed",
            {
                "plugin_id": plugin_id,
                "url": url,
                "request": request,
                "response": response,
                "duration_ms": duration_ms,
            },
            progress=progress,
        )

    def stage_recorded(
        self,
        step: Dict[str, Any],
        *,
        progress: Optional[int] = None,
        current_stage: Optional[str] = None,
    ) -> None:
        self.emit("stage_recorded", {"step": step}, progress=progress, current_stage=current_stage)

    def judgment(self, record: Dict[str, Any], *, progress: Optional[int] = None) -> None:
        self._judgment_count += 1
        self.emit("judgment", record, progress=progress)

    def vulnerability_confirmed(self, summary: Dict[str, Any], *, progress: Optional[int] = None) -> None:
        self._confirmed_count += 1
        self.emit("vulnerability_confirmed", summary, progress=progress)

    def scan_progress(self, progress: int, current_stage: str) -> None:
        self.emit("scan_progress", {"progress": progress}, progress=progress, current_stage=current_stage)


def make_progress_callback(reporter: ExecutionEventReporter) -> Callable[[str, Dict[str, Any]], None]:
    """供 ScannerEngine 调用的统一回调。"""

    def callback(event_type: str, payload: Dict[str, Any]) -> None:
        progress = payload.pop("progress", None)
        current_stage = payload.pop("current_stage", None)
        if event_type == "request_completed":
            reporter.request_completed(
                plugin_id=payload.get("plugin_id", ""),
                url=payload.get("url", ""),
                request=payload.get("request", {}),
                response=payload.get("response", {}),
                duration_ms=payload.get("duration_ms", 0),
                progress=progress,
            )
        elif event_type == "stage_recorded":
            reporter.stage_recorded(
                payload.get("step", {}),
                progress=progress,
                current_stage=current_stage,
            )
        elif event_type == "judgment":
            reporter.judgment(payload, progress=progress)
        elif event_type == "vulnerability_confirmed":
            reporter.vulnerability_confirmed(payload, progress=progress)
        elif event_type == "phase_started":
            reporter.phase_started(payload.get("phase", ""), payload.get("label", current_stage or ""))
        elif event_type == "scan_progress":
            reporter.scan_progress(int(progress or 0), current_stage or "扫描中")
        else:
            reporter.emit(event_type, payload, progress=progress, current_stage=current_stage)

    return callback
