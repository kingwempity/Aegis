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
import datetime
import random
import string
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
        """
        self._stats.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        logger.info(f"🚀 开始扫描目标: {self.target}")
        
        async with httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=self.max_concurrent * 2, max_keepalive_connections=20),
            headers={
                "User-Agent": "Aegis-Security-Scanner/2.0",
                "Accept": "*/*",
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
        return [self._result_to_dict(r) for r in self._vulnerabilities]
    
    async def _initial_probe(self, client: httpx.AsyncClient) -> None:
        """初始探测，获取目标上下文信息"""
        try:
            resp = await self._request_in_scope(client, "GET", self.target)
            self._context = ContextAwareEngine.build_context(
                target_url=self.target,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text,
            )
            self.script_generator.set_context(self._context)
            if self.enable_discovery:
                discovered = self.path_explorer.discover_paths(resp.text, self.target)
                self._stats.paths_discovered += len(discovered)
        except Exception as e:
            logger.warning(f"⚠️ 初始探测失败: {e}")
            self._context = AttackContext(target_url=self.target)
    
    async def _execute_plugins(self, client: httpx.AsyncClient) -> None:
        """执行所有插件的扫描任务"""
        tasks = []
        async def _gather_pending():
            nonlocal tasks
            if not tasks: return
            await asyncio.gather(*tasks, return_exceptions=True)
            tasks = []
        
        for plugin in self.plugins:
            requests_list = plugin.get("requests", [])
            # 兼容 sequential_requests (top-level)
            sequential = bool(plugin.get("sequential_requests"))
            
            if sequential:
                await _gather_pending()
                # 顺序模式下，如果某一步失败（未命中 matchers），则停止该插件后续请求
                for req in requests_list:
                    if not self._check_preconditions(req): continue
                    success = await self._scan_with_plugin(client, plugin, req)
                    if not success:
                        logger.info(f"🛑 插件 {plugin.get('id')} 步骤未命中 matchers，中断后续请求")
                        break
            else:
                for req in requests_list:
                    if not self._check_preconditions(req): continue
                    tasks.append(self._scan_with_plugin(client, plugin, req))
                    if len(tasks) >= self.max_concurrent: await _gather_pending()
        
        await _gather_pending()

    async def _scan_with_plugin(self, client: httpx.AsyncClient, plugin: Dict[str, Any], req_def: Dict[str, Any]) -> bool:
        """执行单个插件请求扫描，支持动态Payload和置信度评估"""
        async with self._semaphore:
            method = req_def.get("method", "GET").upper()
            paths = req_def.get("path", [])
            headers = req_def.get("headers", {})
            base_body = req_def.get("body")
            matchers = req_def.get("matchers", [])
            matchers_condition = req_def.get("matchers-condition", "or")
            
            # 置信度阈值 (低于此值的结果将被过滤或标记为低置信度)
            confidence_threshold = 0.15  # 放宽阈值以提高检出率
            
            # 生成Payload变体
            payload_variants = self.script_generator.build_payloads(plugin, req_def)
            if not payload_variants:
                payload_variants = [None]
            
            any_success = False
            for path_template in paths:
                for variant in payload_variants:
                    payload_str = variant.encoded if variant else ""
                    
                    # 使用当前选择的变量进行解析
                    url = self._resolve_variables(path_template, payload_str, plugin)
                    
                    # 准备请求头 (处理 multipart)
                    current_headers = dict(headers)
                    current_body = self._resolve_variables(base_body, payload_str, plugin) if base_body else None
                    
                    # 自动注入 CSRF 令牌（如果已获取）
                    if self._context and self._context.csrf_token:
                        current_headers["X-CSRF-Token"] = self._context.csrf_token
                    
                    if current_headers.get("Content-Type") == "multipart/form-data":
                        if "------WebKitFormBoundary" in (current_body or ""):
                            boundary = "----AegisBoundary" + ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                            current_headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
                            current_body = current_body.replace("------WebKitFormBoundary", "--" + boundary)
                    
                    self._stats.total_requests += 1
                    try:
                        resp = await self._request_in_scope(client, method, url, current_headers, current_body)
                        self._stats.successful_requests += 1
                        
                        # 动态提取变量 (支持从响应中提取路径等)
                        self._extract_dynamic_variables(resp, plugin)
                        
                        # 基础匹配检查
                        if self._check_matchers(resp, matchers, matchers_condition):
                            any_success = True
                            # 计算置信度
                            confidence = self._calculate_confidence(resp, matchers)
                            
                            # 放宽条件: 即使置信度较低也记录 (可通过阈值调整)
                            if confidence >= confidence_threshold:
                                result = ScanResult(
                                    vuln_name=plugin.get("info", {}).get("name", "Unknown Vulnerability"),
                                    severity=plugin.get("info", {}).get("severity", "Medium"),
                                    url=url,
                                    payload=payload_str or "N/A",
                                    evidence={
                                        "matchers": matchers,
                                        "matchers_condition": matchers_condition,
                                        "confidence": round(confidence, 3),
                                        "response_status": resp.status_code,
                                    },
                                    plugin_id=plugin.get("id", "unknown"),
                                    request={"method": method, "url": url, "headers": current_headers, "body": current_body},
                                    response={
                                        "status": resp.status_code,
                                        "body_snippet": resp.text[:1000],
                                        "content_length": len(resp.content),
                                    },
                                )
                                self._vulnerabilities.append(result)
                                self._stats.vulnerabilities_found += 1
                                
                                level = "🔴" if confidence > 0.6 else "🟡" if confidence > 0.3 else "🔵"
                                logger.info(f"{level} 发现漏洞 [{confidence:.1%}]: {result.vuln_name} @ {url}")
                    except Exception as e:
                        self._stats.failed_requests += 1
            
            return any_success

    def _resolve_variables(self, template: str, payload: str = "", plugin: Optional[Dict[str, Any]] = None) -> str:
        """
        替换模板变量，支持:
        - {{BaseURL}}, {{payload}}
        - {{Year}}, {{Month}}, {{Day}}
        - {{filename}} (在同一插件生命周期内保持一致)
        - {{RandomInt}}, {{RandomString}}
        - {{ExtractedPath}} (从前序响应中动态提取的路径)
        """
        if not template: return ""
        now = datetime.datetime.now()
        
        # 在 ScannerEngine 实例级别缓存当前插件的变量
        plugin_id = plugin.get("id") if plugin else "default"
        if not hasattr(self, "_plugin_vars_cache"):
            self._plugin_vars_cache = {}
            
        if plugin_id not in self._plugin_vars_cache:
            filename = "test.gif"
            if plugin:
                fn_variants = plugin.get("filename_variants", [])
                if fn_variants:
                    filename = random.choice(fn_variants)
            self._plugin_vars_cache[plugin_id] = {
                "filename": filename,
                "ExtractedPath": "" # 初始为空
            }
        
        cached_vars = self._plugin_vars_cache[plugin_id]
        
        vars = {
            "BaseURL": self.target,
            "Year": now.strftime("%Y"),
            "Month": now.strftime("%m"),
            "Day": now.strftime("%d"),
            "payload": payload,
            "filename": cached_vars["filename"],
            "ExtractedPath": cached_vars.get("ExtractedPath", ""),
            "RandomInt": str(random.randint(1000, 9999)),
            "RandomString": ''.join(random.choices(string.ascii_lowercase, k=8)),
        }
        
        result = template
        for k, v in vars.items():
            result = result.replace("{{" + k + "}}", v)
        return result

    def _extract_dynamic_variables(self, resp: httpx.Response, plugin: Optional[Dict[str, Any]]) -> None:
        """从响应中提取动态变量，如文件上传后的真实路径"""
        if not plugin: return
        plugin_id = plugin.get("id")
        if not plugin_id: return
        
        if not hasattr(self, "_plugin_vars_cache"):
            self._plugin_vars_cache = {}
        
        if plugin_id not in self._plugin_vars_cache:
            self._plugin_vars_cache[plugin_id] = {}
            
        # 尝试提取路径 (常见于 Drupal 上传后的 JSON 响应或重定向)
        import re
        content = resp.text
        
        # 1. 尝试提取 Drupal 典型的 sites/default/files/... 路径
        path_match = re.search(r'sites/default/files/[^"\'>\s]+', content)
        if path_match:
            extracted_path = path_match.group(0)
            self._plugin_vars_cache[plugin_id]["ExtractedPath"] = extracted_path
            logger.info(f"✨ 从响应中提取到动态路径: {extracted_path}")
            
        # 2. 尝试提取 CSRF Token (如果响应包含)
        csrf_match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', content)
        if csrf_match:
            token = csrf_match.group(1)
            if self._context:
                self._context.csrf_token = token
                logger.info(f"🔑 提取到 CSRF Token: {token}")

    async def _discovery_scan(self, client: httpx.AsyncClient) -> None:
        """对发现的路径进行扫描"""
        discovered_paths = self.path_explorer._discovered_paths
        prioritized = self.path_explorer.get_prioritized_paths(discovered_paths, self.target)
        for path in prioritized[:50]:
            if path.url in self.path_explorer._visited: continue
            self._stats.total_requests += 1
            try:
                resp = await self._request_in_scope(client, "GET", path.url)
                self.path_explorer.mark_visited(path.url)
                self._stats.successful_requests += 1
                self._check_sensitive_disclosure(path.url, resp)
            except: self._stats.failed_requests += 1
    
    def _check_sensitive_disclosure(self, url: str, response: httpx.Response) -> None:
        """检查敏感信息泄露"""
        sensitive_patterns = {"api_key": r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})'}
        import re
        for pattern_name, pattern in sensitive_patterns.items():
            if re.search(pattern, response.text):
                result = ScanResult(
                    vuln_name=f"Sensitive Information Disclosure ({pattern_name})",
                    severity="Medium",
                    url=url, payload="N/A", plugin_id="discovery-sensitive",
                    evidence={"matchers": [{"type": "regex", "pattern": pattern_name}]},
                    request={"method": "GET", "url": url},
                    response={"status": response.status_code, "body_snippet": response.text[:500]},
                )
                self._vulnerabilities.append(result)
                self._stats.vulnerabilities_found += 1
    
    async def _request_in_scope(self, client: httpx.AsyncClient, method: str, url: str, headers: Optional[Dict[str, str]] = None, body: Optional[str] = None, max_redirects: int = 5) -> httpx.Response:
        """发送请求并仅跟随同源重定向"""
        current_url = url
        current_headers = headers or {}
        for _ in range(max_redirects + 1):
            resp = await client.request(method, current_url, headers=current_headers, content=body)
            location = resp.headers.get("location")
            if not location or not (300 <= resp.status_code < 400): return resp
            next_url = urljoin(current_url, location)
            if not self._is_in_scope(next_url): return resp
            current_url = next_url
        return resp
    
    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        return (parsed.scheme.lower() == self._target_origin.scheme.lower() and parsed.hostname == self._target_origin.hostname)
    
    def _check_preconditions(self, req: Dict[str, Any]) -> bool:
        """模板前置条件校验"""
        pre = req.get("preconditions")
        if not pre: return True
        if isinstance(pre, dict):
            required_tech = pre.get("requires_tech")
            if required_tech and self._context:
                if self._context.detected_tech:
                    if not any(tech in self._context.detected_tech for tech in required_tech): return False
        return True
    
    def _check_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]], matchers_condition: str = "or") -> bool:
        """
        检查响应是否命中规则 (增强版)
        
        优化点:
        1. 支持大小写不敏感匹配 (case_insensitive)
        2. 支持负向匹配 (negative)
        3. 增强正则匹配性能
        4. 支持响应长度差异检测
        5. 置信度评分辅助判定
        """
        if not matchers:
            return False
        
        hit_count = 0
        total_matchers = len(matchers)
        
        for m in matchers:
            if not isinstance(m, dict):
                continue
            
            mtype = m.get("type")
            hit = False
            case_insensitive = m.get("case_insensitive", True)  # 默认大小写不敏感
            negative = m.get("negative", False)  # 负向匹配
            
            if mtype == "word":
                words = m.get("words", [])
                part = m.get("part", "body")
                content = resp.text if part == "body" else str(resp.headers)
                
                # 大小写处理
                if case_insensitive:
                    content_lower = content.lower()
                    words_to_check = [w.lower() for w in words]
                    condition = m.get("condition", "and")
                    
                    if condition == "and":
                        hit = all(w in content_lower for w in words_to_check)
                    else:
                        hit = any(w in content_lower for w in words_to_check)
                else:
                    condition = m.get("condition", "and")
                    if condition == "and":
                        hit = all(w in content for w in words)
                    else:
                        hit = any(w in content for w in words)
            
            elif mtype == "status":
                hit = resp.status_code in m.get("status", [])
            
            elif mtype == "regex":
                import re
                content = resp.text if m.get("part", "body") == "body" else str(resp.headers)
                flags = re.IGNORECASE if case_insensitive else 0
                
                try:
                    patterns = m.get("regex", [])
                    hit = all(re.search(p, content, flags=flags) for p in patterns)
                except re.error:
                    hit = False
            
            elif mtype == "size":
                # 响应长度差异检测 (用于盲注场景)
                expected_size = m.get("size", 0)
                tolerance = m.get("tolerance", 100)  # 允许的字节误差范围
                actual_size = len(resp.content)
                hit = abs(actual_size - expected_size) <= tolerance
            
            elif mtype == "binary":
                # 二进制/编码内容检测
                binary_patterns = m.get("binary", [])
                import base64
                try:
                    decoded = base64.b64decode(resp.text + "==") if resp.text else b""
                    hit = any(p.encode() in decoded for p in binary_patterns)
                except Exception:
                    hit = False
            
            # 处理负向匹配
            if negative:
                hit = not hit
            
            if hit:
                hit_count += 1
            
            # 快速返回优化
            if matchers_condition == "or" and hit:
                return True
            elif matchers_condition == "and" and not hit:
                return False
        
        # AND条件需要所有都命中
        if matchers_condition == "and":
            return hit_count == total_matchers
        
        # OR条件：至少一个命中
        return hit_count > 0
    
    def _calculate_confidence(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> float:
        """
        计算漏洞判定的置信度 (0.0 - 1.0)
        
        综合考虑以下因素:
        - 命中的匹配规则数量和权重
        - 特征关键词的唯一性
        - 响应状态码异常程度
        - 响应体特征强度
        """
        confidence = 0.0
        weight_total = 0.0
        
        # 高置信度特征词 (唯一性强)
        high_confidence_keywords = [
            "XPATH syntax error",
            "extractvalue()",
            "updatexml()",
            "SQLSTATE[42",
            "SQLSTATE[HY000]",
            "Think\\Db\\Exception",
        ]
        
        # 中置信度特征词
        medium_confidence_keywords = [
            "SQLSTATE",
            "SQL syntax",
            "mysql_",
            "Database Error",
            "PDO::prepare()",
        ]
        
        content_lower = resp.text.lower()
        
        # 检查高置信度特征
        high_hits = sum(1 for kw in high_confidence_keywords if kw.lower() in content_lower)
        confidence += min(high_hits * 0.3, 0.6)  # 最多贡献0.6
        
        # 检查中置信度特征
        medium_hits = sum(1 for kw in medium_confidence_keywords if kw.lower() in content_lower)
        confidence += min(medium_hits * 0.1, 0.3)  # 最多贡献0.3
        
        # 状态码异常加分
        if resp.status_code >= 500:
            confidence += 0.05
        elif resp.status_code >= 400:
            confidence += 0.02
        
        # 响应体包含典型错误模式
        error_indicators = ["error", "exception", "fatal", "warning"]
        error_hits = sum(1 for ind in error_indicators if ind in content_lower)
        confidence += min(error_hits * 0.02, 0.1)
        
        return min(confidence, 1.0)
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        return {
            "vuln_name": result.vuln_name,
            "severity": result.severity,
            "url": result.url,
            "payload": result.payload,
            "method": result.request.get("method", "GET"),
            "evidence": result.evidence,
            "request": result.request,
            "response": result.response,
            "scan_time": result.scan_time,
        }
