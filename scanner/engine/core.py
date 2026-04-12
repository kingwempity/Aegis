"""
scanner.engine.core
-------------------
核心扫描逻辑：遍历插件 -> 生成攻击脚本 -> 路径优先调度 -> 发送请求 -> 匹配漏洞。

集成优化功能：
1. 智能Payload生成与编码
2. 多维度路径优先级探索
3. 上下文感知攻击策略
4. 动态路径发现与学习

"""

import os
import asyncio
import time
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
import logging

import httpx

from scanner.engine.attack import (
    AttackScriptGenerator,
    AttackPathExplorer,
    ContextAwareEngine,
    PayloadVariant,
    PathCandidate,
    AttackContext,
    PayloadType,
    EncodingType,
)

# 配置日志
logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """
    扫描结果实体。
    
    Attributes:
        vuln_name: 漏洞名称
        severity: 严重程度
        url: 发现漏洞的URL
        payload: 使用的payload
        evidence: 证据信息
        plugin_id: 插件ID
        scan_time: 扫描时间戳
        request: 请求详情
        response: 响应摘要
        context: 攻击上下文信息
    """
    vuln_name: str
    severity: str
    url: str
    payload: str
    evidence: Dict[str, Any]
    plugin_id: str
    scan_time: float = field(default_factory=time.time)
    request: Dict[str, Any] = field(default_factory=dict)
    response: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanStatistics:
    """
    扫描统计信息。
    
    Attributes:
        total_requests: 总请求数
        successful_requests: 成功请求数
        failed_requests: 失败请求数
        vulnerabilities_found: 发现的漏洞数
        paths_visited: 访问的路径数
        paths_discovered: 发现的新路径数
        start_time: 开始时间
        end_time: 结束时间
    """
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    vulnerabilities_found: int = 0
    paths_visited: int = 0
    paths_discovered: int = 0
    start_time: float = 0.0
    end_time: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "vulnerabilities_found": self.vulnerabilities_found,
            "paths_visited": self.paths_visited,
            "paths_discovered": self.paths_discovered,
            "duration": self.end_time - self.start_time if self.end_time > 0 else 0,
        }


class ScannerEngineBuilder:
    """
    扫描引擎构建器。
    """
    def __init__(self, target: str):
        self.target = target
        self.strategy = "default"
        self.enable_learning = True
        self.enable_discovery = True
        self.max_concurrent = 10
        self.timeout = 10.0
        self.max_depth = 3
        
    def with_strategy(self, strategy: str):
        self.strategy = strategy
        return self
        
    def build(self):
        return ScannerEngine(
            target=self.target,
            strategy=self.strategy,
            enable_learning=self.enable_learning,
            enable_discovery=self.enable_discovery,
            max_concurrent=self.max_concurrent,
            timeout=self.timeout,
            max_depth=self.max_depth
        )

def create_default_engine(target: str):
    return ScannerEngineBuilder(target).build()

def create_aggressive_engine(target: str):
    return ScannerEngineBuilder(target).with_strategy("aggressive").build()

def create_stealthy_engine(target: str):
    return ScannerEngineBuilder(target).with_strategy("stealthy").build()

class ScannerEngine:
    """
    高级漏洞扫描引擎。
    
    功能特性：
    1. 智能Payload生成：根据目标技术栈动态选择payload
    2. 多维度路径探索：综合风险、新颖度、历史成功率评分
    3. 上下文感知：基于响应动态调整攻击策略
    4. 自适应学习：记录扫描结果优化后续扫描
    5. 动态路径发现：从响应中提取新路径进行递归扫描
    
    使用示例：
        engine = ScannerEngine(
            target="http://example.com",
            strategy="default",
            enable_learning=True,
            enable_discovery=True
        )
        vulnerabilities = await engine.run()
    """
    
    def __init__(
        self,
        target: str,
        strategy: str = "default",
        plugin_dir: str = "/app/scanner/plugins",
        enable_learning: bool = True,
        enable_discovery: bool = True,
        max_concurrent: int = 10,
        timeout: float = 10.0,
        max_depth: int = 3,
    ):
        """
        初始化扫描引擎。
        
        Args:
            target: 目标URL
            strategy: 扫描策略（default, aggressive, stealthy）
            plugin_dir: 插件目录路径
            enable_learning: 是否启用自适应学习
            enable_discovery: 是否启用动态路径发现
            max_concurrent: 最大并发请求数
            timeout: 请求超时时间（秒）
            max_depth: 最大递归深度
        """
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.enable_learning = enable_learning
        self.enable_discovery = enable_discovery
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_depth = max_depth
        
        # 解析插件目录
        resolved_plugin_dir = plugin_dir
        if not os.path.exists(resolved_plugin_dir):
            resolved_plugin_dir = os.path.join(os.getcwd(), "scanner", "plugins")
        
        logger.info(f"📂 插件目录: {resolved_plugin_dir}")
        
        # 延迟导入避免循环依赖
        from scanner.engine.parser import TemplateParser
        self.plugins = TemplateParser.load_plugins(resolved_plugin_dir)
        
        plugin_ids = [p.get('id', 'unknown') for p in self.plugins]
        logger.info(f"📋 已加载 {len(self.plugins)} 个插件: {plugin_ids}")
        
        # 初始化组件
        self.script_generator = AttackScriptGenerator(strategy=strategy)
        self.path_explorer = AttackPathExplorer(learning_enabled=enable_learning)
        
        # 目标URL解析
        self._target_origin = urlparse(self.target)
        
        # 扫描上下文
        self._context: Optional[AttackContext] = None
        
        # 统计信息
        self._stats = ScanStatistics()
        
        # 已发现漏洞
        self._vulnerabilities: List[ScanResult] = []
        
        # 并发控制
        self._semaphore: Optional[asyncio.Semaphore] = None
    
    async def run(self) -> List[Dict[str, Any]]:
        """
        执行扫描并返回发现的漏洞列表。
        
        Returns:
            漏洞信息列表，每个元素包含漏洞详情
        """
        self._stats.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        logger.info(f"🚀 开始扫描目标: {self.target}")
        logger.info(f"📋 加载插件数量: {len(self.plugins)}")
        logger.info(f"⚙️ 扫描策略: {self.strategy}")
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(
                connect=10.0,
                read=30.0,
                write=10.0,
                pool=10.0
            ),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=self.max_concurrent * 2, max_keepalive_connections=20),
            headers={
                "User-Agent": "Aegis-Security-Scanner/2.0",
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"
            }
        ) as client:
            # 阶段1: 初始探测，获取上下文
            await self._initial_probe(client)
            
            # 阶段2: 执行插件扫描
            await self._execute_plugins(client)
            
            # 阶段3: 动态路径发现扫描（如果启用）
            if self.enable_discovery and self._stats.paths_discovered > 0:
                await self._discovery_scan(client)
        
        self._stats.end_time = time.time()
        
        # 记录统计信息
        logger.info(f"✅ 扫描完成")
        logger.info(f"📊 统计: {self._stats.to_dict()}")
        
        return [self._result_to_dict(r) for r in self._vulnerabilities]
    
    async def _initial_probe(self, client: httpx.AsyncClient) -> None:
        """
        初始探测，获取目标上下文信息。
        
        Args:
            client: HTTP客户端
        """
        logger.info(f"🔍 执行初始探测: {self.target}")
        
        try:
            resp = await self._request_in_scope(client, "GET", self.target)
            logger.info(f"📡 初始探测成功 - 状态码: {resp.status_code}, 内容长度: {len(resp.text)}")
            
            self._context = ContextAwareEngine.build_context(
                target_url=self.target,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text,
            )
            
            # 更新脚本生成器的上下文
            self.script_generator.set_context(self._context)
            
            # 发现新路径
            if self.enable_discovery:
                discovered = self.path_explorer.discover_paths(resp.text, self.target)
                self._stats.paths_discovered += len(discovered)
                logger.info(f"📂 发现 {len(discovered)} 个新路径")
            
            detected_tech = ', '.join(self._context.detected_tech) or '未知'
            logger.info(f"🔬 检测到技术栈: {detected_tech}")
            
        except httpx.ConnectError as e:
            logger.error(f"❌ 无法连接到目标 {self.target}: {e}")
            raise
        except httpx.TimeoutException as e:
            logger.error(f"⏱️ 连接目标超时 {self.target}: {e}")
            raise
        except Exception as e:
            logger.warning(f"⚠️ 初始探测失败: {type(e).__name__}: {e}")
            self._context = AttackContext(target_url=self.target)
    
    async def _execute_plugins(self, client: httpx.AsyncClient) -> None:
        """
        执行所有插件的扫描任务。
        
        Args:
            client: HTTP客户端
        """
        tasks = []
        
        logger.info(f"🔧 开始执行插件扫描 - 共 {len(self.plugins)} 个插件")
        
        success_count = 0
        error_count = 0
        scheduled = 0
        
        async def _gather_pending() -> None:
            nonlocal tasks, success_count, error_count
            if not tasks:
                return
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    error_count += 1
                    logger.error(f"❌ 扫描任务 {i} 异常: {type(result).__name__}: {result}")
                else:
                    success_count += 1
            tasks = []
        
        for plugin in self.plugins:
            plugin_id = plugin.get("id", "unknown")
            plugin_name = plugin.get("info", {}).get("name", "unknown")
            requests_list = plugin.get("requests", [])
            sequential = bool(plugin.get("sequential_requests"))
            
            logger.info(f"  📦 插件: {plugin_id} ({plugin_name}) - {len(requests_list)} 个请求")
            
            if sequential:
                await _gather_pending()
                logger.info(f"     ⏳ 顺序执行模式 (sequential_requests)")
            
            for req_idx, req in enumerate(requests_list):
                if not self._check_preconditions(req):
                    logger.debug(f"    ⏭️ 跳过请求 {req_idx}: 不满足前置条件")
                    continue
                
                if sequential:
                    scheduled += 1
                    try:
                        await self._scan_with_plugin(client, plugin, req)
                    except Exception as e:
                        logger.error(f"❌ 顺序扫描任务失败: {e}")
                else:
                    tasks.append(self._scan_with_plugin(client, plugin, req))
                    scheduled += 1
                    
                    if len(tasks) >= self.max_concurrent:
                        await _gather_pending()
        
        await _gather_pending()
        logger.info(f"✅ 插件扫描完成: 成功 {success_count}, 失败 {error_count}, 总计调度 {scheduled}")

    async def _scan_with_plugin(self, client: httpx.AsyncClient, plugin: Dict[str, Any], req_def: Dict[str, Any]) -> None:
        """
        执行单个插件请求扫描。
        """
        async with self._semaphore:
            method = req_def.get("method", "GET").upper()
            paths = req_def.get("path", [])
            headers = req_def.get("headers", {})
            body = req_def.get("body")
            matchers = req_def.get("matchers", [])
            matchers_condition = req_def.get("matchers-condition", "or")
            
            for path in paths:
                # 变量替换
                url = self._resolve_variables(path)
                
                self._stats.total_requests += 1
                try:
                    resp = await self._request_in_scope(client, method, url, headers, body)
                    self._stats.successful_requests += 1
                    
                    if self._check_matchers(resp, matchers, matchers_condition):
                        result = ScanResult(
                            vuln_name=plugin.get("info", {}).get("name", "Unknown Vulnerability"),
                            severity=plugin.get("info", {}).get("severity", "Medium"),
                            url=url,
                            payload=body if body else url,
                            evidence={
                                "matchers": matchers,
                                "matchers_condition": matchers_condition,
                            },
                            plugin_id=plugin.get("id", "unknown"),
                            request={"method": method, "url": url, "headers": headers, "body": body},
                            response={"status": resp.status_code, "body_snippet": resp.text[:1000]}
                        )
                        self._vulnerabilities.append(result)
                        self._stats.vulnerabilities_found += 1
                        logger.info(f"🔴 发现漏洞: {result.vuln_name} @ {url}")
                except Exception as e:
                    self._stats.failed_requests += 1
                    logger.debug(f"⚠️ 请求失败 {url}: {e}")

    def _resolve_variables(self, template: str) -> str:
        """替换模板变量"""
        import datetime
        now = datetime.datetime.now()
        vars = {
            "BaseURL": self.target,
            "Year": now.strftime("%Y"),
            "Month": now.strftime("%m"),
            "Day": now.strftime("%d"),
        }
        result = template
        for k, v in vars.items():
            result = result.replace("{{" + k + "}}", v)
        return result

    async def _discovery_scan(self, client: httpx.AsyncClient) -> None:
        """
        对发现的路径进行扫描。
        """
        logger.info(f" 开始发现路径扫描...")
        discovered_paths = self.path_explorer._discovered_paths
        prioritized = self.path_explorer.get_prioritized_paths(discovered_paths, self.target)
        max_discovery_scan = min(len(prioritized), 50)
        
        for path in prioritized[:max_discovery_scan]:
            if path.url in self.path_explorer._visited:
                continue
            self._stats.total_requests += 1
            try:
                resp = await self._request_in_scope(client, "GET", path.url)
                self.path_explorer.mark_visited(path.url)
                self._stats.paths_visited += 1
                self._stats.successful_requests += 1
                self._check_sensitive_disclosure(path.url, resp)
            except Exception as e:
                self._stats.failed_requests += 1
                logger.debug(f" 发现路径请求失败 {path.url}: {e}")
    
    def _check_sensitive_disclosure(self, url: str, response: httpx.Response) -> None:
        """检查敏感信息泄露"""
        sensitive_patterns = {
            "api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})',
            "password": r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{8,})',
            "secret": r'(?i)(secret|token|auth)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{16,})',
            "aws_key": r'(?i)(AKIA[0-9A-Z]{16})',
            "private_key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
        }
        import re
        for pattern_name, pattern in sensitive_patterns.items():
            if re.search(pattern, response.text):
                result = ScanResult(
                    vuln_name=f"Sensitive Information Disclosure ({pattern_name})",
                    severity="Medium",
                    url=url,
                    payload="N/A",
                    plugin_id="discovery-sensitive",
                    evidence={"matchers": [{"type": "regex", "pattern": pattern_name}]},
                    request={"method": "GET", "url": url},
                    response={"status": response.status_code, "body_snippet": response.text[:500]},
                )
                self._vulnerabilities.append(result)
                self._stats.vulnerabilities_found += 1
                logger.info(f" 发现敏感信息泄露: {pattern_name} @ {url}")
    
    async def _request_in_scope(self, client: httpx.AsyncClient, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None, max_redirects: int = 5) -> httpx.Response:
        """发送请求并仅跟随同源重定向"""
        current_url = url
        current_headers = headers or {}
        for _ in range(max_redirects + 1):
            resp = await client.request(method, current_url, headers=current_headers, content=body)
            location = resp.headers.get("location")
            if not location or not (300 <= resp.status_code < 400):
                return resp
            next_url = urljoin(current_url, location)
            if not self._is_in_scope(next_url):
                return resp
            current_url = next_url
        return resp
    
    def _is_in_scope(self, url: str) -> bool:
        """检查URL是否在扫描范围内"""
        parsed = urlparse(url)
        return (
            parsed.scheme.lower() == self._target_origin.scheme.lower()
            and parsed.hostname == self._target_origin.hostname
            and (parsed.port or self._default_port(parsed.scheme))
            == (self._target_origin.port or self._default_port(self._target_origin.scheme))
        )
    
    @staticmethod
    def _default_port(scheme: str) -> int:
        return 443 if scheme.lower() == "https" else 80
    
    def _check_preconditions(self, req: Dict[str, Any]) -> bool:
        """模板前置条件校验"""
        pre = req.get("preconditions")
        if not pre:
            return True
        if isinstance(pre, dict):
            allowed_methods = pre.get("methods")
            if allowed_methods:
                method = req.get("method", "GET").upper()
                if method not in {m.upper() for m in allowed_methods}:
                    return False
            required_tech = pre.get("requires_tech")
            if required_tech and self._context:
                # 优化逻辑：如果没有检测到任何技术栈，为了召回率允许扫描
                # 如果检测到了技术栈但不在要求列表中，为了防误报跳过扫描
                if self._context.detected_tech:
                    if not any(tech in self._context.detected_tech for tech in required_tech):
                        return False
        return True
    
    def _check_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]], matchers_condition: str = "or") -> bool:
        """检查响应是否命中规则"""
        if not matchers:
            return False
        for m in matchers:
            if not isinstance(m, dict):
                continue
            mtype = m.get("type")
            hit = False
            if mtype == "word":
                words = m.get("words", [])
                part = m.get("part", "body")
                condition = m.get("condition", "and")
                content = resp.text if part == "body" else str(resp.headers)
                if condition == "and":
                    hit = all(w in content for w in words)
                else:
                    hit = any(w in content for w in words)
            elif mtype == "status":
                statuses = m.get("status", [])
                hit = resp.status_code in statuses
            elif mtype == "regex":
                import re
                patterns = m.get("regex", [])
                part = m.get("part", "body")
                content = resp.text if part == "body" else str(resp.headers)
                try:
                    hit = all(re.search(p, content) for p in patterns)
                except re.error:
                    hit = False
            elif mtype == "size":
                sizes = m.get("size", [])
                hit = len(resp.content) in sizes
            elif mtype == "binary":
                binary_patterns = m.get("binary", [])
                for pattern in binary_patterns:
                    try:
                        if bytes.fromhex(pattern) in resp.content:
                            hit = True
                            break
                    except ValueError:
                        pass
            if matchers_condition == "or" and hit:
                return True
            elif matchers_condition == "and" and not hit:
                return False
        return matchers_condition == "and"
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """将扫描结果转换为字典格式"""
        vuln_type = self._extract_vuln_type(result.plugin_id, result.vuln_name)
        parameter = self._extract_parameter(result.url, result.request)
        return {
            "vuln_name": result.vuln_name,
            "vuln_type": vuln_type,
            "severity": result.severity,
            "url": result.url,
            "payload": result.payload,
            "parameter": parameter,
            "method": result.request.get("method", "GET") if result.request else "GET",
            "evidence": result.evidence,
            "request": result.request,
            "response": result.response,
            "scan_time": result.scan_time,
        }

    def _extract_vuln_type(self, plugin_id: str, vuln_name: str) -> str:
        if "sqli" in plugin_id or "SQL Injection" in vuln_name: return "SQL Injection"
        if "xss" in plugin_id or "XSS" in vuln_name: return "Cross-Site Scripting"
        if "file-upload" in plugin_id: return "Unrestricted File Upload"
        return "Other"

    def _extract_parameter(self, url: str, request: Dict[str, Any]) -> str:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params: return list(params.keys())[0]
        return "N/A"
