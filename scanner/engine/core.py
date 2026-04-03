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
            timeout=self.timeout,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=self.max_concurrent * 2),
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
        logger.debug("🔍 执行初始探测...")
        
        try:
            resp = await self._request_in_scope(client, "GET", self.target)
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
                logger.debug(f"📂 发现 {len(discovered)} 个新路径")
            
            logger.info(f"🔬 检测到技术栈: {', '.join(self._context.detected_tech) or '未知'}")
            
        except Exception as e:
            logger.warning(f"⚠️ 初始探测失败: {e}")
            self._context = AttackContext(target_url=self.target)
    
    async def _execute_plugins(self, client: httpx.AsyncClient) -> None:
        """
        执行所有插件的扫描任务。
        
        Args:
            client: HTTP客户端
        """
        tasks = []
        
        for plugin in self.plugins:
            for req in plugin.get("requests", []):
                if not self._check_preconditions(req):
                    continue
                
                # 创建扫描任务
                task = self._scan_with_plugin(client, plugin, req)
                tasks.append(task)
        
        # 并发执行所有任务
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            # 检查并记录异常
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"❌ 扫描任务 {i} 异常: {type(result).__name__}: {result}")
    
    async def _scan_with_plugin(
        self,
        client: httpx.AsyncClient,
        plugin: Dict[str, Any],
        request_def: Dict[str, Any],
    ) -> None:
        """
        使用单个插件执行扫描。
        
        Args:
            client: HTTP客户端
            plugin: 插件配置
            request_def: 请求定义
        """
        async with self._semaphore:
            # 生成payload变体
            payload_variants = self.script_generator.build_payloads(plugin, request_def)
            
            # 路径优先级排序
            ranked_paths = self.path_explorer.rank(
                plugin, request_def, self.target, self._context
            )
            
            for path in ranked_paths:
                for payload_variant in payload_variants:
                    await self._try_attack(
                        client, plugin, request_def, path, payload_variant
                    )
    
    async def _try_attack(
        self,
        client: httpx.AsyncClient,
        plugin: Dict[str, Any],
        request_def: Dict[str, Any],
        path: PathCandidate,
        payload_variant: PayloadVariant,
    ) -> bool:
        """
        尝试单个攻击请求。
        
        Args:
            client: HTTP客户端
            plugin: 插件配置
            request_def: 请求定义
            path: 路径候选
            payload_variant: payload变体
            
        Returns:
            是否发现漏洞
        """
        # 构建请求
        url = self.script_generator.render_path(path.url, self.target, payload_variant.encoded)
        method = request_def.get("method", "GET").upper()
        
        logger.debug(f"🔍 发送请求: {method} {url}")
        
        # 构建请求头和请求体
        headers = dict(request_def.get("headers", {}))
        body = None
        
        if "body" in request_def:
            body = self.script_generator.render_body(request_def["body"], payload_variant.encoded)
        
        # 添加CSRF令牌
        if self._context and self._context.csrf_token:
            headers["X-CSRF-Token"] = self._context.csrf_token
        
        self._stats.total_requests += 1
        
        try:
            resp = await self._request_in_scope(client, method, url, headers, body)
            self.path_explorer.mark_visited(path.url)
            self._stats.paths_visited += 1
            
            # 记录结果用于学习
            matchers = request_def.get("matchers", [])
            matchers_condition = request_def.get("matchers-condition", "or")
            is_vulnerable = self._check_matchers(resp, matchers, matchers_condition)
            
            logger.debug(f"📊 响应状态: {resp.status_code}, 匹配结果: {is_vulnerable}")
            if resp.status_code != 200:
                logger.debug(f"📄 响应内容片段: {resp.text[:500]}")
            
            self.path_explorer.record_result(path.url, is_vulnerable)
            
            if is_vulnerable:
                self._stats.vulnerabilities_found += 1
                vuln_info = plugin.get("info", {})
                
                result = ScanResult(
                    vuln_name=vuln_info.get("name", plugin.get("id", "unknown")),
                    severity=vuln_info.get("severity", "Info"),
                    url=url,
                    payload=payload_variant.encoded,
                    plugin_id=plugin.get("id", "unknown"),
                    evidence={
                        "matchers": matchers,
                        "encoding_used": payload_variant.encoding_type.value,
                        "mutation_type": payload_variant.mutation_type,
                    },
                    request={
                        "method": method,
                        "url": url,
                        "headers": headers,
                        "body": body,
                        "payload_original": payload_variant.original,
                    },
                    response={
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                        "body_snippet": resp.text[:500],
                    },
                    context={
                        "detected_tech": self._context.detected_tech if self._context else [],
                        "context_score": payload_variant.context_score,
                    },
                )
                
                self._vulnerabilities.append(result)
                logger.info(f" 发现漏洞: {result.vuln_name} @ {url}")
                
                return True
            
            # 从响应中发现新路径
            if self.enable_discovery:
                discovered = self.path_explorer.discover_paths(resp.text, self.target)
                self._stats.paths_discovered += len(discovered)
            
            self._stats.successful_requests += 1
            
        except httpx.TimeoutException:
            self._stats.failed_requests += 1
            logger.warning(f"⏱️ 请求超时: {url}")
            
        except Exception as e:
            self._stats.failed_requests += 1
            logger.warning(f"❌ 请求失败 {url}: {type(e).__name__}: {e}")
        
        return False
    
    async def _discovery_scan(self, client: httpx.AsyncClient) -> None:
        """
        对发现的路径进行扫描。
        
        Args:
            client: HTTP客户端
        """
        logger.info(f" 开始发现路径扫描...")
        
        # 获取优先级排序的发现路径
        discovered_paths = self.path_explorer._discovered_paths
        prioritized = self.path_explorer.get_prioritized_paths(discovered_paths, self.target)
        
        # 只扫描前N个高优先级路径
        max_discovery_scan = min(len(prioritized), 50)
        
        for path in prioritized[:max_discovery_scan]:
            # 检查是否已访问
            if path.url in self.path_explorer._visited:
                continue
            
            self._stats.total_requests += 1
            
            try:
                resp = await self._request_in_scope(client, "GET", path.url)
                self.path_explorer.mark_visited(path.url)
                self._stats.paths_visited += 1
                self._stats.successful_requests += 1
                
                # 检查敏感信息泄露
                self._check_sensitive_disclosure(path.url, resp)
                
            except Exception as e:
                self._stats.failed_requests += 1
                logger.debug(f" 发现路径请求失败 {path.url}: {e}")
    
    def _check_sensitive_disclosure(self, url: str, response: httpx.Response) -> None:
        """
        检查敏感信息泄露。
        
        Args:
            url: 请求URL
            response: HTTP响应
        """
        # 敏感信息模式
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
                    evidence={
                        "matchers": [{"type": "regex", "pattern": pattern_name}],
                        "discovered_in": "discovery_scan",
                    },
                    request={"method": "GET", "url": url},
                    response={
                        "status": response.status_code,
                        "body_snippet": response.text[:500],
                    },
                )
                
                self._vulnerabilities.append(result)
                self._stats.vulnerabilities_found += 1
                logger.info(f" 发现敏感信息泄露: {pattern_name} @ {url}")
    
    async def _request_in_scope(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        max_redirects: int = 5,
    ) -> httpx.Response:
        """
        发送请求并仅跟随同源重定向，避免向目标域外发包。
        
        Args:
            client: HTTP客户端
            method: HTTP方法
            url: 请求URL
            headers: 请求头
            body: 请求体
            max_redirects: 最大重定向次数
            
        Returns:
            HTTP响应
        """
        current_url = url
        current_headers = headers or {}
        
        for _ in range(max_redirects + 1):
            resp = await client.request(
                method, current_url, headers=current_headers, content=body
            )
            
            location = resp.headers.get("location")
            
            if not location or not (300 <= resp.status_code < 400):
                return resp
            
            next_url = urljoin(current_url, location)
            
            if not self._is_in_scope(next_url):
                return resp
            
            current_url = next_url
        
        return resp
    
    def _is_in_scope(self, url: str) -> bool:
        """
        检查URL是否在扫描范围内。
        
        Args:
            url: 待检查的URL
            
        Returns:
            是否在范围内
        """
        parsed = urlparse(url)
        return (
            parsed.scheme.lower() == self._target_origin.scheme.lower()
            and parsed.hostname == self._target_origin.hostname
            and (parsed.port or self._default_port(parsed.scheme))
            == (self._target_origin.port or self._default_port(self._target_origin.scheme))
        )
    
    @staticmethod
    def _default_port(scheme: str) -> int:
        """获取协议默认端口"""
        return 443 if scheme.lower() == "https" else 80
    
    def _check_preconditions(self, req: Dict[str, Any]) -> bool:
        """
        模板前置条件校验。
        
        Args:
            req: 请求定义
            
        Returns:
            是否满足前置条件
        """
        pre = req.get("preconditions")
        if not pre:
            return True
        
        # 检查方法限制
        if isinstance(pre, dict):
            allowed_methods = pre.get("methods")
            if allowed_methods:
                method = req.get("method", "GET").upper()
                if method not in {m.upper() for m in allowed_methods}:
                    return False
            
            # 检查技术栈条件
            required_tech = pre.get("requires_tech")
            if required_tech and self._context:
                if not any(tech in self._context.detected_tech for tech in required_tech):
                    return False
        
        return True
    
    def _check_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]], matchers_condition: str = "or") -> bool:
        """
        检查响应是否命中规则。
        
        支持的匹配器类型：
        - word: 关键词匹配
        - status: 状态码匹配
        - regex: 正则表达式匹配
        - size: 响应大小匹配
        - binary: 二进制内容匹配
        
        Args:
            resp: HTTP响应
            matchers: 匹配器列表
            matchers_condition: 匹配器条件（and/or），默认or
            
        Returns:
            是否命中
        """
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
                content_length = len(resp.content)
                hit = content_length in sizes
            
            elif mtype == "binary":
                binary_patterns = m.get("binary", [])
                for pattern in binary_patterns:
                    try:
                        if bytes.fromhex(pattern) in resp.content:
                            hit = True
                            break
                    except ValueError:
                        pass
            
            # 根据条件处理
            if matchers_condition == "or" and hit:
                return True
            elif matchers_condition == "and" and not hit:
                return False
        
        return matchers_condition == "and"
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """
        将扫描结果转换为字典格式。
        
        包含完整的攻击路径和载荷信息，用于报告生成。
        
        Args:
            result: 扫描结果
            
        Returns:
            字典格式的结果
        """
        # 构建攻击路径信息
        attack_path = {
            "steps": [
                {
                    "step": 1,
                    "method": result.request.get("method", "GET") if result.request else "GET",
                    "url": result.url,
                    "description": self._get_attack_description(result)
                }
            ],
            "request": result.request,
            "response_summary": {
                "status": result.response.get("status") if result.response else None,
                "body_snippet": result.response.get("body_snippet", "")[:500] if result.response else None
            } if result.response else None
        }
        
        # 提取漏洞类型
        vuln_type = self._extract_vuln_type(result.plugin_id, result.vuln_name)
        
        # 提取参数名
        parameter = self._extract_parameter(result.url, result.request)
        
        return {
            "vuln_name": result.vuln_name,
            "vuln_type": vuln_type,
            "severity": result.severity,
            "url": result.url,
            "payload": result.payload,
            "parameter": parameter,
            "method": result.request.get("method", "GET") if result.request else "GET",
            "plugin_id": result.plugin_id,
            "scan_time": result.scan_time,
            "evidence": result.evidence,
            "attack_path": attack_path,
            "request": result.request,
            "response": result.response,
            "context": result.context,
        }
    
    def _get_attack_description(self, result: ScanResult) -> str:
        """
        根据漏洞信息生成攻击描述。
        
        Args:
            result: 扫描结果
            
        Returns:
            攻击描述文本
        """
        vuln_name = result.vuln_name.lower() if result.vuln_name else ""
        
        if "xss" in vuln_name or "cross-site" in vuln_name:
            return "向目标注入恶意JavaScript代码，验证XSS漏洞存在"
        elif "sql" in vuln_name or "sqli" in vuln_name:
            return "向目标发送SQL注入载荷，验证数据库注入漏洞存在"
        elif "lfi" in vuln_name or "local file" in vuln_name:
            return "尝试读取本地敏感文件，验证LFI漏洞存在"
        elif "rfi" in vuln_name or "remote file" in vuln_name:
            return "尝试包含远程文件，验证RFI漏洞存在"
        elif "ssrf" in vuln_name or "server-side" in vuln_name:
            return "构造服务端请求，验证SSRF漏洞存在"
        elif "traversal" in vuln_name or "path" in vuln_name:
            return "使用路径穿越序列访问敏感文件"
        elif "xxe" in vuln_name or "xml" in vuln_name:
            return "注入恶意XML实体，验证XXE漏洞存在"
        elif "cmd" in vuln_name or "rce" in vuln_name or "command" in vuln_name:
            return "注入系统命令，验证命令执行漏洞存在"
        elif "redirect" in vuln_name:
            return "构造恶意重定向URL，验证开放重定向漏洞存在"
        elif "sensitive" in vuln_name or "disclosure" in vuln_name:
            return "访问敏感资源，验证信息泄露漏洞存在"
        else:
            return "向目标发送恶意请求，验证漏洞存在"
    
    def _extract_vuln_type(self, plugin_id: str, vuln_name: str) -> str:
        """
        从插件ID和漏洞名称提取漏洞类型。
        
        Args:
            plugin_id: 插件ID
            vuln_name: 漏洞名称
            
        Returns:
            漏洞类型字符串
        """
        combined = f"{plugin_id} {vuln_name}".lower()
        
        if "xss" in combined or "cross-site" in combined:
            return "XSS"
        elif "sql" in combined or "sqli" in combined:
            return "SQL注入"
        elif "lfi" in combined or "local file" in combined:
            return "LFI"
        elif "rfi" in combined or "remote file" in combined:
            return "RFI"
        elif "ssrf" in combined or "server-side" in combined:
            return "SSRF"
        elif "traversal" in combined or "path" in combined:
            return "路径穿越"
        elif "xxe" in combined or "xml" in combined:
            return "XXE"
        elif "cmd" in combined or "rce" in combined or "command" in combined:
            return "命令注入"
        elif "redirect" in combined:
            return "开放重定向"
        elif "sensitive" in combined or "disclosure" in combined:
            return "信息泄露"
        else:
            return "其他"
    
    def _extract_parameter(self, url: str, request: Optional[Dict[str, Any]]) -> str:
        """
        从URL或请求中提取参数名。
        
        Args:
            url: 请求URL
            request: 请求详情
            
        Returns:
            参数名字符串
        """
        import re
        from urllib.parse import urlparse, parse_qs
        
        # 从URL查询参数提取
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = list(parse_qs(parsed.query).keys())
                if params:
                    return params[0]
        except Exception:
            pass
        
        # 从路径参数提取
        path_params = re.findall(r'\{(\w+)\}|\[(\w+)\]', url)
        if path_params:
            return path_params[0][0] or path_params[0][1]
        
        # 从请求体提取
        if request and request.get("body"):
            body = request["body"]
            # 表单数据
            if "=" in body:
                match = re.match(r'(\w+)=', body)
                if match:
                    return match.group(1)
        
        return "unknown"
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        获取扫描统计信息。
        
        Returns:
            统计信息字典
        """
        stats = self._stats.to_dict()
        stats["explorer_stats"] = self.path_explorer.get_statistics()
        return stats


class ScannerEngineBuilder:
    """
    扫描引擎构建器。
    
    提供流式API构建扫描引擎实例。
    
    使用示例：
        engine = (
            ScannerEngineBuilder()
            .target("http://example.com")
            .with_strategy("aggressive")
            .enable_learning(True)
            .enable_discovery(True)
            .with_timeout(15.0)
            .build()
        )
    """
    
    def __init__(self):
        """初始化构建器"""
        self._target: Optional[str] = None
        self._strategy: str = "default"
        self._plugin_dir: str = "/app/scanner/plugins"
        self._enable_learning: bool = True
        self._enable_discovery: bool = True
        self._max_concurrent: int = 10
        self._timeout: float = 10.0
        self._max_depth: int = 3
    
    def target(self, url: str) -> "ScannerEngineBuilder":
        """设置目标URL"""
        self._target = url
        return self
    
    def with_strategy(self, strategy: str) -> "ScannerEngineBuilder":
        """设置扫描策略"""
        self._strategy = strategy
        return self
    
    def with_plugin_dir(self, plugin_dir: str) -> "ScannerEngineBuilder":
        """设置插件目录"""
        self._plugin_dir = plugin_dir
        return self
    
    def enable_learning(self, enabled: bool) -> "ScannerEngineBuilder":
        """设置是否启用学习"""
        self._enable_learning = enabled
        return self
    
    def enable_discovery(self, enabled: bool) -> "ScannerEngineBuilder":
        """设置是否启用路径发现"""
        self._enable_discovery = enabled
        return self
    
    def with_max_concurrent(self, max_concurrent: int) -> "ScannerEngineBuilder":
        """设置最大并发数"""
        self._max_concurrent = max_concurrent
        return self
    
    def with_timeout(self, timeout: float) -> "ScannerEngineBuilder":
        """设置超时时间"""
        self._timeout = timeout
        return self
    
    def with_max_depth(self, max_depth: int) -> "ScannerEngineBuilder":
        """设置最大深度"""
        self._max_depth = max_depth
        return self
    
    def build(self) -> ScannerEngine:
        """构建扫描引擎实例"""
        if not self._target:
            raise ValueError("Target URL is required")
        
        return ScannerEngine(
            target=self._target,
            strategy=self._strategy,
            plugin_dir=self._plugin_dir,
            enable_learning=self._enable_learning,
            enable_discovery=self._enable_discovery,
            max_concurrent=self._max_concurrent,
            timeout=self._timeout,
            max_depth=self._max_depth,
        )


# 便捷函数
def create_default_engine(target: str) -> ScannerEngine:
    """创建默认配置的扫描引擎"""
    return ScannerEngine(target=target)


def create_aggressive_engine(target: str) -> ScannerEngine:
    """创建激进模式的扫描引擎"""
    return ScannerEngine(
        target=target,
        strategy="aggressive",
        enable_learning=True,
        enable_discovery=True,
        max_concurrent=20,
    )


def create_stealthy_engine(target: str) -> ScannerEngine:
    """创建隐蔽模式的扫描引擎"""
    return ScannerEngine(
        target=target,
        strategy="stealthy",
        enable_learning=False,
        enable_discovery=False,
        max_concurrent=3,
        timeout=30.0,
    )