import asyncio
import socket
import ipaddress
from typing import List, Dict
import nmap
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor

class NetworkScanner:
    """
    网络扫描服务类，用于执行网络设备发现和端口扫描。

    Attributes:
        nm (nmap.PortScanner): nmap 端口扫描器实例。
        executor (ThreadPoolExecutor): 用于执行阻塞式 nmap 扫描的线程池。
    """

    def __init__(self):
        """初始化 NetworkScanner 实例。"""
        self.nm = nmap.PortScanner()
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    async def scan_network(self, network_range: str) -> List[Dict]:
        """
        扫描指定网络范围内的设备，并收集其信息。

        Args:
            network_range (str): 要扫描的网络范围，例如 "192.168.1.0/24"。

        Returns:
            List[Dict]: 扫描结果列表，每个字典包含设备的 IP、主机名、MAC 地址、开放端口、操作系统和服务信息。
        """
        results = []
        
        try:
            # 使用 nmap 进行网络扫描
            loop = asyncio.get_event_loop()
            scan_result = await loop.run_in_executor(
                self.executor,
                self._nmap_scan,
                network_range
            )
            
            for host in scan_result.all_hosts():
                if scan_result[host][\'status\'][\'state\'] == \'up\':
                    host_info = {
                        \'ip\': host,
                        \'hostname\': self._get_hostname(host),
                        \'mac\': self._get_mac_address(scan_result, host),
                        \'ports\': self._get_open_ports(scan_result, host),
                        \'os\': self._get_os_info(scan_result, host),
                        \'services\': self._get_services(scan_result, host)
                    }
                    results.append(host_info)
        
        except Exception as e:
            print(f"扫描错误: {e}")
            # 如果 nmap 失败，使用基础扫描
            results = await self._basic_scan(network_range)
        
        return results
    
    def _nmap_scan(self, network_range: str):
        """
        执行 nmap 扫描的同步方法。

        Args:
            network_range (str): 要扫描的网络范围。

        Returns:
            nmap.PortScanner: 包含 nmap 扫描结果的 PortScanner 对象。
        """
        self.nm.scan(hosts=network_range, arguments=\'-sS -sV -O -F\')
        return self.nm
    
    def _get_hostname(self, ip: str) -> str:
        """
        通过 IP 地址获取主机名。

        Args:
            ip (str): 设备的 IP 地址。

        Returns:
            str: 设备的主机名，如果无法获取则返回空字符串。
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except:
            return \'\'
    
    def _get_mac_address(self, scan_result, host: str) -> str:
        """
        从 nmap 扫描结果中获取 MAC 地址。

        Args:
            scan_result: nmap 扫描结果对象。
            host (str): 主机 IP 地址。

        Returns:
            str: 设备的 MAC 地址，如果无法获取则返回空字符串。
        """
        try:
            return scan_result[host][\'addresses\'].get(\'mac\', \'\')
        except:
            return \'\'
    
    def _get_open_ports(self, scan_result, host: str) -> List[int]:
        """
        从 nmap 扫描结果中获取开放端口列表。

        Args:
            scan_result: nmap 扫描结果对象。
            host (str): 主机 IP 地址。

        Returns:
            List[int]: 开放端口的列表。
        """
        ports = []
        try:
            if \'tcp\' in scan_result[host]:
                for port in scan_result[host][\'tcp\']:
                    if scan_result[host][\'tcp\'][port][\'state\'] == \'open\':
                        ports.append(port)
        except:
            pass
        return ports
    
    def _get_os_info(self, scan_result, host: str) -> str:
        """
        从 nmap 扫描结果中获取操作系统信息。

        Args:
            scan_result: nmap 扫描结果对象。
            host (str): 主机 IP 地址。

        Returns:
            str: 设备的操作系统信息，如果无法获取则返回 "Unknown"。
        """
        try:
            if \'osmatch\' in scan_result[host]:
                if scan_result[host][\'osmatch\']:
                    return scan_result[host][\'osmatch\'][0][\'name\']
        except:
            pass
        return \'Unknown\'
    
    def _get_services(self, scan_result, host: str) -> List[str]:
        """
        从 nmap 扫描结果中获取服务信息。

        Args:
            scan_result: nmap 扫描结果对象。
            host (str): 主机 IP 地址。

        Returns:
            List[str]: 服务信息列表，格式为 "服务名:端口"。
        """
        services = []
        try:
            if \'tcp\' in scan_result[host]:
                for port in scan_result[host][\'tcp\']:
                    service = scan_result[host][\'tcp\'][port].get(\'name\', \'\')
                    if service:
                        services.append(f"{service}:{port}")
        except:
            pass
        return services
    
    async def _basic_scan(self, network_range: str) -> List[Dict]:
        """
        执行基础网络扫描（不依赖 nmap），作为 nmap 失败时的备用方案。

        Args:
            network_range (str): 要扫描的网络范围。

        Returns:
            List[Dict]: 扫描结果列表，每个字典包含设备的 IP、主机名、开放端口等信息。
        """
        results = []
        network = ipaddress.ip_network(network_range, strict=False)
        
        # 使用 ping 扫描
        tasks = []
        for ip in network.hosts():
            tasks.append(self._ping_host(str(ip)))
        
        ping_results = await asyncio.gather(*tasks)
        
        for ip, is_alive in ping_results:
            if is_alive:
                results.append({
                    \'ip\': ip,
                    \'hostname\': self._get_hostname(ip),
                    \'mac\': \'\',
                    \'ports\': await self._scan_common_ports(ip),
                    \'os\': \'Unknown\',
                    \'services\': []
                })
        
        return results
    
    async def _ping_host(self, ip: str) -> tuple:
        """
        Ping 主机以检查其是否在线。

        Args:
            ip (str): 要 ping 的 IP 地址。

        Returns:
            tuple: 包含 IP 地址和主机是否在线的布尔值的元组。
        """
        try:
            param = \'-n\' if platform.system().lower() == \'windows\' else \'-c\'
            command = [\'ping\', param, \'1\', \'-W\', \'1\', ip]
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await asyncio.wait_for(process.wait(), timeout=2)
            return (ip, process.returncode == 0)
        except:
            return (ip, False)
    
    async def _scan_common_ports(self, ip: str) -> List[int]:
        """
        扫描主机的常见端口。

        Args:
            ip (str): 要扫描的 IP 地址。

        Returns:
            List[int]: 开放的常见端口列表。
        """
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            if await self._is_port_open(ip, port):
                open_ports.append(port)
        
        return open_ports
    
    async def _is_port_open(self, ip: str, port: int) -> bool:
        """
        检查指定 IP 地址的端口是否开放。

        Args:
            ip (str): 目标 IP 地址。
            port (int): 要检查的端口号。

        Returns:
            bool: 如果端口开放则为 True，否则为 False。
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
