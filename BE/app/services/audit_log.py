"""
审计日志服务

功能：
- 登录审计（成功/失败）
- 操作审计（CRUD操作）
- 安全审计（权限拒绝、异常访问）
- 数据审计（敏感数据访问）

Notes:
    - 所有审计日志记录到数据库和文件
    - 支持日志查询和导出
    - 保留周期：90天
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
from enum import Enum
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

logger = logging.getLogger(__name__)

# 数据库模型基类
Base = declarative_base()


class AuditEventType(str, Enum):
    """审计事件类型"""
    # 登录相关
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    LOGIN_CODE_SENT = "LOGIN_CODE_SENT"
    
    # 用户管理
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DELETED = "USER_DELETED"
    USER_STATUS_CHANGED = "USER_STATUS_CHANGED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    
    # 扫描任务
    SCAN_CREATED = "SCAN_CREATED"
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    SCAN_DELETED = "SCAN_DELETED"
    
    # 报告相关
    REPORT_CREATED = "REPORT_CREATED"
    REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
    REPORT_DELETED = "REPORT_DELETED"
    
    # 安全相关
    PERMISSION_DENIED = "PERMISSION_DENIED"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    MFA_REQUIRED = "MFA_REQUIRED"
    
    # 系统操作
    SYSTEM_CONFIG_CHANGED = "SYSTEM_CONFIG_CHANGED"
    DATA_EXPORT = "DATA_EXPORT"


class AuditLogLevel(str, Enum):
    """审计日志级别"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditLog(Base):
    """
    审计日志数据库模型
    
    Attributes:
        id: 主键
        event_type: 事件类型
        level: 日志级别
        user_id: 用户ID
        username: 用户名
        ip_address: 客户端IP
        user_agent: 浏览器信息
        resource_type: 资源类型
        resource_id: 资源ID
        action: 操作动作
        details: 详细信息（JSON）
        status: 状态（success/failed）
        error_message: 错误信息
        created_at: 创建时间
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False, index=True)
    level = Column(String(20), nullable=False, default="INFO")
    
    # 用户信息
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(100), nullable=True)
    
    # 客户端信息
    ip_address = Column(String(50), nullable=True, index=True)
    user_agent = Column(String(500), nullable=True)
    
    # 资源信息
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    
    # 操作信息
    action = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    
    # 状态
    status = Column(String(20), default="success")
    error_message = Column(Text, nullable=True)
    
    # 时间
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


@dataclass
class AuditEvent:
    """
    审计事件数据类
    
    用于创建审计日志的数据结构。
    """
    event_type: AuditEventType
    level: AuditLogLevel = AuditLogLevel.INFO
    user_id: Optional[int] = None
    username: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    status: str = "success"
    error_message: Optional[str] = None


class AuditLogService:
    """
    审计日志服务
    
    提供审计日志的记录、查询功能。
    
    Attributes:
        db_url: 数据库连接URL
        session_maker: SQLAlchemy Session 工厂
    """
    
    def __init__(self, db_url: Optional[str] = None):
        """
        初始化审计日志服务
        
        Args:
            db_url: 数据库连接URL，默认从环境变量读取
        """
        self.db_url = db_url or os.getenv(
            "DATABASE_URL", 
            "sqlite:///./data/audit.db"
        )
        
        # 创建引擎和表
        self.engine = create_engine(self.db_url, echo=False)
        Base.metadata.create_all(self.engine, checkfirst=True)
        
        # 创建 Session 工厂
        self.Session = sessionmaker(bind=self.engine)
        
        logger.info(f"Audit log service initialized with {self.db_url}")
    
    def log(self, event: AuditEvent) -> Optional[int]:
        """
        记录审计日志
        
        Args:
            event: 审计事件
            
        Returns:
            Optional[int]: 日志ID，失败返回 None
        """
        session = self.Session()
        try:
            log_entry = AuditLog(
                event_type=event.event_type.value,
                level=event.level.value,
                user_id=event.user_id,
                username=event.username,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                action=event.action,
                details=event.details,
                status=event.status,
                error_message=event.error_message,
                created_at=datetime.utcnow()
            )
            
            session.add(log_entry)
            session.commit()
            
            # 同时输出到日志文件
            self._log_to_file(event)
            
            return log_entry.id
            
        except Exception as e:
            logger.error(f"Failed to save audit log: {e}")
            session.rollback()
            return None
        finally:
            session.close()
    
    def _log_to_file(self, event: AuditEvent):
        """
        输出日志到文件
        
        Args:
            event: 审计事件
        """
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event.event_type.value,
            "level": event.level.value,
            "user_id": event.user_id,
            "username": event.username,
            "ip_address": event.ip_address,
            "action": event.action,
            "status": event.status,
            "details": event.details
        }
        
        log_message = json.dumps(log_data, ensure_ascii=False)
        
        if event.level == AuditLogLevel.CRITICAL:
            logger.critical(log_message)
        elif event.level == AuditLogLevel.ERROR:
            logger.error(log_message)
        elif event.level == AuditLogLevel.WARNING:
            logger.warning(log_message)
        else:
            logger.info(log_message)
    
    def log_login_success(
        self, 
        user_id: int, 
        username: str, 
        ip_address: str,
        user_agent: Optional[str] = None,
        login_method: str = "password"
    ):
        """
        记录登录成功事件
        
        Args:
            user_id: 用户ID
            username: 用户名
            ip_address: 客户端IP
            user_agent: 浏览器信息
            login_method: 登录方式（password/email_code）
        """
        self.log(AuditEvent(
            event_type=AuditEventType.LOGIN_SUCCESS,
            level=AuditLogLevel.INFO,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action="登录成功",
            details={"login_method": login_method},
            status="success"
        ))
    
    def log_login_failed(
        self, 
        username: Optional[str],
        ip_address: str,
        reason: str,
        user_agent: Optional[str] = None
    ):
        """
        记录登录失败事件
        
        Args:
            username: 尝试的用户名
            ip_address: 客户端IP
            reason: 失败原因
            user_agent: 浏览器信息
        """
        self.log(AuditEvent(
            event_type=AuditEventType.LOGIN_FAILED,
            level=AuditLogLevel.WARNING,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            action="登录失败",
            details={"reason": reason},
            status="failed",
            error_message=reason
        ))
    
    def log_logout(
        self, 
        user_id: int, 
        username: str, 
        ip_address: str
    ):
        """
        记录登出事件
        
        Args:
            user_id: 用户ID
            username: 用户名
            ip_address: 客户端IP
        """
        self.log(AuditEvent(
            event_type=AuditEventType.LOGOUT,
            level=AuditLogLevel.INFO,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            action="登出",
            status="success"
        ))
    
    def log_user_operation(
        self,
        event_type: AuditEventType,
        operator_id: int,
        operator_name: str,
        target_user_id: int,
        target_username: str,
        ip_address: str,
        changes: Optional[Dict[str, Any]] = None
    ):
        """
        记录用户操作事件
        
        Args:
            event_type: 事件类型
            operator_id: 操作者ID
            operator_name: 操作者用户名
            target_user_id: 目标用户ID
            target_username: 目标用户名
            ip_address: 客户端IP
            changes: 变更内容
        """
        self.log(AuditEvent(
            event_type=event_type,
            level=AuditLogLevel.INFO,
            user_id=operator_id,
            username=operator_name,
            ip_address=ip_address,
            resource_type="user",
            resource_id=str(target_user_id),
            action=event_type.value.replace("_", " ").lower(),
            details={"target_username": target_username, "changes": changes},
            status="success"
        ))
    
    def log_scan_operation(
        self,
        event_type: AuditEventType,
        user_id: int,
        username: str,
        ip_address: str,
        task_id: int,
        target: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        记录扫描任务操作
        
        Args:
            event_type: 事件类型
            user_id: 用户ID
            username: 用户名
            ip_address: 客户端IP
            task_id: 任务ID
            target: 扫描目标
            details: 详细信息
        """
        self.log(AuditEvent(
            event_type=event_type,
            level=AuditLogLevel.INFO,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource_type="scan_task",
            resource_id=str(task_id),
            action=event_type.value.replace("_", " ").lower(),
            details={"target": target, **(details or {})},
            status="success"
        ))
    
    def log_permission_denied(
        self,
        user_id: Optional[int],
        username: Optional[str],
        ip_address: str,
        resource: str,
        action: str,
        reason: str
    ):
        """
        记录权限拒绝事件
        
        Args:
            user_id: 用户ID
            username: 用户名
            ip_address: 客户端IP
            resource: 资源
            action: 尝试的操作
            reason: 拒绝原因
        """
        self.log(AuditEvent(
            event_type=AuditEventType.PERMISSION_DENIED,
            level=AuditLogLevel.WARNING,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource_type=resource,
            action=action,
            details={"reason": reason},
            status="failed",
            error_message=reason
        ))
    
    def log_report_operation(
        self,
        event_type: AuditEventType,
        user_id: int,
        username: str,
        ip_address: str,
        report_id: int,
        report_name: Optional[str] = None
    ):
        """
        记录报告操作
        
        Args:
            event_type: 事件类型
            user_id: 用户ID
            username: 用户名
            ip_address: 客户端IP
            report_id: 报告ID
            report_name: 报告名称
        """
        self.log(AuditEvent(
            event_type=event_type,
            level=AuditLogLevel.INFO,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            resource_type="report",
            resource_id=str(report_id),
            action=event_type.value.replace("_", " ").lower(),
            details={"report_name": report_name},
            status="success"
        ))
    
    def query_logs(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        status: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        查询审计日志
        
        Args:
            event_type: 事件类型
            user_id: 用户ID
            ip_address: IP地址
            status: 状态
            start_time: 开始时间
            end_time: 结束时间
            limit: 返回数量限制
            offset: 偏移量
            
        Returns:
            List[Dict[str, Any]]: 日志列表
        """
        session = self.Session()
        try:
            query = session.query(AuditLog)
            
            if event_type:
                query = query.filter(AuditLog.event_type == event_type)
            if user_id:
                query = query.filter(AuditLog.user_id == user_id)
            if ip_address:
                query = query.filter(AuditLog.ip_address == ip_address)
            if status:
                query = query.filter(AuditLog.status == status)
            if start_time:
                query = query.filter(AuditLog.created_at >= start_time)
            if end_time:
                query = query.filter(AuditLog.created_at <= end_time)
            
            query = query.order_by(AuditLog.created_at.desc())
            query = query.limit(limit).offset(offset)
            
            logs = query.all()
            
            return [
                {
                    "id": log.id,
                    "event_type": log.event_type,
                    "level": log.level,
                    "user_id": log.user_id,
                    "username": log.username,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "action": log.action,
                    "details": log.details,
                    "status": log.status,
                    "error_message": log.error_message,
                    "created_at": log.created_at.isoformat() if log.created_at else None
                }
                for log in logs
            ]
            
        except Exception as e:
            logger.error(f"Failed to query audit logs: {e}")
            return []
        finally:
            session.close()


# 全局单例实例
_audit_log_service: Optional[AuditLogService] = None


def get_audit_log_service() -> AuditLogService:
    """
    获取审计日志服务单例
    
    Returns:
        AuditLogService: 审计日志服务实例
    """
    global _audit_log_service
    
    if _audit_log_service is None:
        # 使用MySQL数据库
        db_url = os.getenv(
            "DATABASE_URL",
            f"mysql+pymysql://{os.getenv('DB_USER', 'root')}:{os.getenv('DB_PASSWORD', 'aegis_password')}@{os.getenv('DB_HOST', 'aegis-db')}:3306/{os.getenv('DB_NAME', 'aegis')}"
        )
        _audit_log_service = AuditLogService(db_url=db_url)
    
    return _audit_log_service