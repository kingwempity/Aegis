from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean
from app.db.database import Base
from datetime import datetime

class DiscoveryResult(Base):
    """
    DiscoveryResult 数据库模型，用于存储网络扫描发现的设备信息。

    Attributes:
        id (int): 主键，自增ID。
        ip_address (str): 设备的 IP 地址。
        hostname (str): 设备的主机名。
        mac_address (str): 设备的 MAC 地址。
        open_ports (str): 开放端口，以逗号分隔的字符串形式存储。
        os_info (str): 操作系统信息。
        services (str): 运行的服务，以逗号分隔的字符串形式存储。
        network_range (str): 进行扫描的网络范围。
        status (str): 设备状态（例如：active）。
        last_seen (datetime): 最后一次发现设备的时间。
        created_at (datetime): 记录创建时间。
        updated_at (datetime): 记录最后更新时间。
    """
    __tablename__ = "discovery_results"
    
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), index=True, nullable=False)
    hostname = Column(String(255))
    mac_address = Column(String(17))
    open_ports = Column(Text) # 存储逗号分隔的端口
    os_info = Column(String(255))
    services = Column(Text) # 存储逗号分隔的服务
    network_range = Column(String(255), index=True)
    status = Column(String(50), default="active")
    last_seen = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
