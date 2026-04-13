"""
scanner.engine.core
-------------------
核心扫描逻辑：遍历插件 -> 生成攻击脚本 -> 路径优先调度 -> 发送请求 -> 匹配漏洞。

集成优化功能：
1. 智能Payload生成与编码
2. 多维度路径优先级探索
3. 上下文感知攻击策略
4. 动态路径发现与学习
5. 规则引擎驱动的多重验证判定
6. 跨框架误报防护
7. 详细扫描日志记录

"""

import os
import asyncio
import time
import datetime
import random
import re
import string
import json
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
from scanner.engine.rules import (
    RuleEngine,
    FrameworkType,
    ValidationLevel,
)

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
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
    validation_log: Dict[str, Any] = field(default_factory=dict)


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
    高级漏洞扫描引擎（集成规则引擎与多重验证）。
    """
    
    def __init__(
        self,
        target: str,
        strategy: str = "default",
        plugin_dir: str = "scanner/plugins",
        enable_learning: bool = True,
        enable_discovery: bool = True,
        max_concurrent: int = 10,
        timeout: float = 10.0,
        max_depth: int = 3,
        rules_config_path: Optional[str] = None,
    ):
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.enable_learning = enable_learning
        self.enable_discovery = enable_discovery
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_depth = max_depth
        
        # 优化插件路径解析：支持绝对路径和项目根目录相对路径
        if os.path.isabs(plugin_dir):
            resolved_plugin_dir = plugin_dir
        else:
            # 尝试相对于当前工作目录
            base_path = os.getcwd()
            resolved_plugin_dir = os.path.join(base_path, plugin_dir)
            
            # 如果不存在，尝试寻找 Aegis 根目录下的 scanner/plugins
            if not os.path.exists(resolved_plugin_dir):
                # 方案1: 如果在 BE 目录下运行 (Aegis/BE)
                parent_path = os.path.dirname(base_path)
                resolved_plugin_dir = os.path.join(parent_path, plugin_dir)
                
            # 方案2: 尝试脚本所在位置 (Aegis/scanner/engine/core.py)
            if not os.path.exists(resolved_plugin_dir):
                script_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                resolved_plugin_dir = os.path.join(script_dir, plugin_dir)

        if not os.path.exists(resolved_plugin_dir):
            # 方案3: 最后的兜底方案，使用常见部署路径
            fallbacks = [
                "/home/ubuntu/Aegis/scanner/plugins",
                "/app/scanner/plugins",
                "./scanner/plugins"
            ]
            for fb in fallbacks:
                if os.path.exists(fb):
                    resolved_plugin_dir = fb
                    break
            else:
                logger.error(f"❌ 插件目录无法定位: {plugin_dir}")
        
        logger.info(f"📂 插件目录: {resolved_plugin_dir}")
        
        from scanner.engine.parser import TemplateParser
        self.plugins = TemplateParser.load_plugins(resolved_plugin_dir)
        
        plugin_ids = [p.get('id', 'unknown') for p in self.plugins]
        logger.info(f"📋 已加载 {len(self.plugins)} 个插件: {plugin_ids}")
        
        self.script_generator = AttackScriptGenerator(strategy=strategy)
        self.path_explorer = AttackPathExplorer(learning_enabled=enable_learning)
        
        self._target_origin = urlparse(self.target)
        
        self._context: Optional[AttackContext] = None
        self._stats = ScanStatistics()
        self._vulnerabilities: List[ScanResult] = []
        self._semaphore: Optional[asyncio.Semaphore] = None
        
        self._rule_engine = RuleEngine(config_path=rules_config_path)
        logger.info("🛡️ 规则引擎已初始化（跨框架误报防护已启用）")
        
        self._detected_frameworks: List[FrameworkType] = []
        self._framework_confidence: Dict[FrameworkType, float] = {}
        self._framework_versions: Dict[FrameworkType, Optional[str]] = {}
        
        self._judgment_log: List[Dict[str, Any]] = []
    
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
        """初始探测，获取目标上下文信息（集成规则引擎框架检测）"""
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
            
            self._detected_frameworks, self._framework_confidence = (
                self._rule_engine.detect_framework(
                    response_body=resp.text,
                    response_headers=dict(resp.headers),
                    request_url=self.target,
                )
            )
            
            # 同步 RuleEngine 检测结果到 AttackContext.detected_tech
            if self._context:
                self._context.detected_tech = [fw.value for fw in self._detected_frameworks if fw != FrameworkType.UNKNOWN]
            
            for fw in self._detected_frameworks:
                version = self._rule_engine.detect_version(
                    fw, resp.text, dict(resp.headers)
                )
                self._framework_versions[fw] = version
            
            fw_info = ", ".join(
                f"{fw.value}(v{self._framework_versions.get(fw, 'unknown')}, "
                f"conf={self._framework_confidence.get(fw, 0):.2f})"
                for fw in self._detected_frameworks
            )
            logger.info(f"🔍 框架检测结果: [{fw_info}]" if fw_info else "🔍 框架检测结果: 未识别已知框架")
            
            self._log_judgment(
                phase="initial_probe",
                plugin_id="N/A",
                action="framework_detection",
                details={
                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                    "framework_confidence": {fw.value: round(conf, 3) for fw, conf in self._framework_confidence.items()},
                    "framework_versions": {fw.value: v for fw, v in self._framework_versions.items()},
                },
                result="success",
            )
        except Exception as e:
            logger.warning(f"⚠️ 初始探测失败: {e}")
            self._context = AttackContext(target_url=self.target)
            self._log_judgment(
                phase="initial_probe", plugin_id="N/A",
                action="framework_detection", details={"error": str(e)}, result="failed",
            )
    
    async def _execute_plugins(self, client: httpx.AsyncClient) -> None:
        """执行所有插件的扫描任务"""
        tasks = []
        async def _gather_pending():
            nonlocal tasks
            if not tasks: return
            await asyncio.gather(*tasks, return_exceptions=True)
            tasks = []
        
        for plugin in self.plugins:
            plugin_id = plugin.get("id", "unknown")
            requests_list = plugin.get("requests", [])
            # 兼容 sequential_requests (top-level)
            sequential = bool(plugin.get("sequential_requests"))
            flattened_paths = [
                path_item
                for req in requests_list
                for path_item in req.get("path", [])
                if isinstance(path_item, str)
            ]
            can_execute, execute_reason = self._rule_engine.should_execute_plugin(
                plugin_id=plugin_id,
                detected_frameworks=self._detected_frameworks,
                request_paths=flattened_paths,
            )
            self._log_judgment(
                phase="plugin_gate",
                plugin_id=plugin_id,
                action="framework_scope_check",
                details={
                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                    "request_paths": flattened_paths[:10],
                    "reason": execute_reason,
                },
                result="allow" if can_execute else "skip",
            )
            if not can_execute:
                logger.info(f"⏭️ 跳过插件 {plugin_id}: {execute_reason}")
                continue
            
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
        """执行单个插件请求扫描（集成多重验证与跨框架误报防护）"""
        async with self._semaphore:
            method = req_def.get("method", "GET").upper()
            paths = req_def.get("path", [])
            headers = req_def.get("headers", {})
            base_body = req_def.get("body")
            matchers = req_def.get("matchers", [])
            matchers_condition = req_def.get("matchers-condition", "or")
            should_report = req_def.get("report", True)
            
            plugin_id = plugin.get("id", "unknown")
            
            rule_min_confidence = self._rule_engine.get_min_confidence(plugin_id)
            rule_required_evidence = self._rule_engine.get_required_evidence_count(plugin_id)
            
            payload_variants = self.script_generator.build_payloads(plugin, req_def)
            if not payload_variants:
                payload_variants = [None]
            
            any_success = False
            for path_template in paths:
                for variant in payload_variants:
                    payload_str = variant.encoded if variant else ""

                    cached_vars = getattr(self, "_plugin_vars_cache", {}).get(plugin_id, {})
                    if "{{ExtractedPath}}" in path_template and not cached_vars.get("ExtractedPath"):
                        continue
                    if "{{UploadedFilename}}" in path_template and not cached_vars.get("UploadedFilename"):
                        continue
                    
                    url = self._resolve_variables(path_template, payload_str, plugin)
                    
                    current_headers = dict(headers)
                    current_body = self._resolve_variables(base_body, payload_str, plugin) if base_body else None
                    
                    if self._context and self._context.csrf_token:
                        current_headers["X-CSRF-Token"] = self._context.csrf_token
                    
                    content_type = current_headers.get("Content-Type", "")
                    if content_type.startswith("multipart/form-data"):
                        boundary = self._infer_multipart_boundary(current_body or "")
                        if not boundary:
                            boundary = "----AegisBoundary" + ''.join(
                                random.choices(string.ascii_letters + string.digits, k=16)
                            )
                        if boundary and "boundary=" not in content_type:
                            current_headers["Content-Type"] = f"{content_type}; boundary={boundary}"
                    
                    self._stats.total_requests += 1
                    try:
                        resp = await self._request_in_scope(client, method, url, current_headers, current_body)
                        self._stats.successful_requests += 1
                        
                        self._extract_dynamic_variables(resp, plugin)
                        
                        if self._check_matchers(resp, matchers, matchers_condition):
                            any_success = True
                            
                            if should_report:
                                matched_keywords = self._extract_matched_keywords(resp, matchers)
                                
                                is_valid, validation_reason = self._rule_engine.validate_vulnerability(
                                    plugin_id=plugin_id,
                                    detected_frameworks=self._detected_frameworks,
                                    response_body=resp.text,
                                    response_headers=dict(resp.headers),
                                    request_url=url,
                                    matched_keywords=matched_keywords,
                                    framework_versions=self._framework_versions,
                                )
                                
                                base_confidence = self._calculate_confidence(resp, matchers, plugin)
                                
                                adjusted_confidence, adjustment_details = self._rule_engine.adjust_confidence(
                                    plugin_id=plugin_id,
                                    base_confidence=base_confidence,
                                    detected_frameworks=self._detected_frameworks,
                                    response_body=resp.text,
                                    response_headers=dict(resp.headers),
                                    request_url=url,
                                    matched_keywords=matched_keywords,
                                )
                                
                                evidence_count = self._count_evidence(resp, matchers)
                                
                                judgment_record = {
                                    "phase": "vulnerability_judgment",
                                    "plugin_id": plugin_id,
                                    "url": url,
                                    "payload": payload_str[:200] if payload_str else "N/A",
                                    "base_confidence": round(base_confidence, 4),
                                    "adjusted_confidence": round(adjusted_confidence, 4),
                                    "adjustment_details": adjustment_details,
                                    "is_valid": is_valid,
                                    "validation_reason": validation_reason,
                                    "evidence_count": evidence_count,
                                    "required_evidence": rule_required_evidence,
                                    "matched_keywords": matched_keywords[:10],
                                    "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                                    "framework_confidence": {
                                        fw.value: round(self._framework_confidence.get(fw, 0), 3)
                                        for fw in self._detected_frameworks
                                    },
                                    "request_path_validated": True,
                                    "framework_versions": {
                                        fw.value: v for fw, v in self._framework_versions.items()
                                    },
                                    "response_status": resp.status_code,
                                    "response_length": len(resp.content),
                                }
                                
                                final_report = False
                                final_reason = ""
                                
                                if not is_valid:
                                    final_report = False
                                    final_reason = f"验证未通过: {validation_reason}"
                                    logger.info(
                                        f"🛡️ 跨框架误报拦截: [{plugin_id}] @ {url} - {validation_reason}"
                                    )
                                elif adjusted_confidence < rule_min_confidence:
                                    final_report = False
                                    final_reason = (
                                        f"置信度不足: {adjusted_confidence:.3f} < {rule_min_confidence:.3f}"
                                    )
                                    logger.info(
                                        f"🔵 低置信度过滤: [{plugin_id}] conf={adjusted_confidence:.3f} @ {url}"
                                    )
                                elif evidence_count < rule_required_evidence:
                                    final_report = False
                                    final_reason = (
                                        f"证据不足: {evidence_count} < {rule_required_evidence}"
                                    )
                                    logger.info(
                                        f"🔵 证据不足过滤: [{plugin_id}] evidence={evidence_count} @ {url}"
                                    )
                                else:
                                    final_report = True
                                    final_reason = "验证通过"
                                
                                judgment_record["final_decision"] = "report" if final_report else "suppress"
                                judgment_record["final_reason"] = final_reason
                                self._judgment_log.append(judgment_record)
                                
                                if final_report:
                                    result = ScanResult(
                                        vuln_name=plugin.get("info", {}).get("name", "Unknown Vulnerability"),
                                        severity=plugin.get("info", {}).get("severity", "Medium"),
                                        url=url,
                                        payload=payload_str or "N/A",
                                        evidence={
                                            "matchers": matchers,
                                            "matchers_condition": matchers_condition,
                                            "confidence": round(adjusted_confidence, 3),
                                            "base_confidence": round(base_confidence, 3),
                                            "evidence_count": evidence_count,
                                            "matched_keywords": matched_keywords[:10],
                                            "response_status": resp.status_code,
                                            "framework_validation": {
                                                "is_valid": is_valid,
                                                "reason": validation_reason,
                                            },
                                            "confidence_adjustments": [
                                                a for a in adjustment_details if a.get("triggered")
                                            ],
                                        },
                                        plugin_id=plugin_id,
                                        request={"method": method, "url": url, "headers": current_headers, "body": current_body},
                                        response={
                                            "status": resp.status_code,
                                            "body_snippet": resp.text[:1000],
                                            "content_length": len(resp.content),
                                        },
                                        validation_log={
                                            "detected_frameworks": [fw.value for fw in self._detected_frameworks],
                                            "framework_versions": {
                                                fw.value: v for fw, v in self._framework_versions.items()
                                            },
                                            "judgment_reason": final_reason,
                                        },
                                    )
                                    self._vulnerabilities.append(result)
                                    self._stats.vulnerabilities_found += 1
                                    
                                    level = "🔴" if adjusted_confidence > 0.6 else "🟡" if adjusted_confidence > 0.3 else "🔵"
                                    logger.info(
                                        f"{level} 确认漏洞 [{adjusted_confidence:.1%}]: "
                                        f"{result.vuln_name} @ {url} (证据={evidence_count})"
                                    )
                    except Exception as e:
                        self._stats.failed_requests += 1
                        self._log_judgment(
                            phase="scan_request", plugin_id=plugin_id,
                            action="request_failed", details={"url": url, "error": str(e)}, result="failed",
                        )
            
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
                "ExtractedPath": "",
                "FormBuildId": "",
                "FormToken": "",
                "UploadedFilename": "",
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
            "FormBuildId": cached_vars.get("FormBuildId", ""),
            "FormToken": cached_vars.get("FormToken", ""),
            "UploadedFilename": cached_vars.get("UploadedFilename", ""),
            "RandomInt": str(random.randint(1000, 9999)),
            "RandomString": ''.join(random.choices(string.ascii_lowercase, k=8)),
        }
        
        result = template
        for k, v in vars.items():
            result = result.replace("{{" + k + "}}", v)
        return result

    def _infer_multipart_boundary(self, body: str) -> str:
        if not body:
            return ""

        for raw_line in body.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("--") and len(line) > 4:
                candidate = line[2:]
                if candidate.endswith("--"):
                    candidate = candidate[:-2]
                if candidate:
                    return candidate
        return ""

    def _extract_dynamic_variables(self, resp: httpx.Response, plugin: Optional[Dict[str, Any]]) -> None:
        """从响应中提取动态变量，如文件上传后的真实路径"""
        if not plugin: return
        plugin_id = plugin.get("id")
        if not plugin_id: return
        
        if not hasattr(self, "_plugin_vars_cache"):
            self._plugin_vars_cache = {}
        
        if plugin_id not in self._plugin_vars_cache:
            self._plugin_vars_cache[plugin_id] = {}
            
        content = resp.text
        normalized_content = (
            content
            .replace("\\/", "/")
            .replace("\\u002F", "/")
            .replace("\\u002f", "/")
        )
        
        # 1. 尝试提取 Drupal form_build_id (用于表单提交)
        # 支持 HTML 和 AJAX JSON 响应
        form_build_match = re.search(r'name="form_build_id"\s+value="([^"]+)"', normalized_content)
        if not form_build_match:
            form_build_match = re.search(r'"form_build_id"\s*:\s*"([^"]+)"', normalized_content)
            
        if form_build_match:
            form_build_id = form_build_match.group(1)
            self._plugin_vars_cache[plugin_id]["FormBuildId"] = form_build_id
            logger.info(f"📋 提取到 form_build_id: {form_build_id}")
        
        # 2. 尝试提取 Drupal form_token
        form_token_match = re.search(r'name="form_token"\s+value="([^"]+)"', normalized_content)
        if not form_token_match:
            form_token_match = re.search(r'"form_token"\s*:\s*"([^"]+)"', normalized_content)
            
        if form_token_match:
            form_token = form_token_match.group(1)
            self._plugin_vars_cache[plugin_id]["FormToken"] = form_token
            logger.info(f"🔐 提取到 form_token: {form_token}")
        
        # 3. 尝试提取 Drupal 典型的 sites/default/files/... 路径
        extracted_path = self._extract_upload_path(normalized_content)
        if extracted_path:
            self._plugin_vars_cache[plugin_id]["ExtractedPath"] = extracted_path
            logger.info(f"✨ 从响应中提取到动态路径: {extracted_path}")
        
        # 4. 尝试提取上传后的文件名 (Drupal AJAX 响应)
        filename_match = re.search(r'"filename"\s*:\s*"([^"]+)"', normalized_content)
        if filename_match:
            uploaded_filename = filename_match.group(1)
            self._plugin_vars_cache[plugin_id]["UploadedFilename"] = uploaded_filename
            logger.info(f"📎 提取到上传文件名: {uploaded_filename}")
        elif extracted_path:
            uploaded_filename = extracted_path.rsplit("/", 1)[-1]
            self._plugin_vars_cache[plugin_id]["UploadedFilename"] = uploaded_filename
        
        # 5. 尝试提取 CSRF Token (如果响应包含)
        csrf_match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', normalized_content)
        if csrf_match:
            token = csrf_match.group(1)
            if self._context:
                self._context.csrf_token = token
                logger.info(f"🔑 提取到 CSRF Token: {token}")

        # 6. 尝试提取 Django IntegrityError 信息
        if "IntegrityError" in normalized_content or "UNIQUE constraint failed" in normalized_content:
            logger.info("🎯 检测到 Django 数据库错误，可能触发 CVE-2017-12794")

    def _extract_upload_path(self, content: str) -> str:
        if not content:
            return ""
        candidates: List[str] = []

        absolute_or_relative_paths = re.findall(
            r'(https?://[^\s"\']+|/?sites/default/files/[^\s"\'>,]+)',
            content,
            flags=re.IGNORECASE,
        )
        for raw_match in absolute_or_relative_paths:
            parsed = urlparse(raw_match)
            candidate = parsed.path if parsed.scheme else raw_match
            candidate = candidate.lstrip("/")
            if candidate.lower().startswith("sites/default/files/") and self._is_probable_upload_path(candidate):
                candidates.append(candidate)

        public_uri_matches = re.findall(r'public://([^\s"\'>,]+)', content, flags=re.IGNORECASE)
        for match in public_uri_matches:
            candidate = f"sites/default/files/{match.lstrip('/')}"
            if self._is_probable_upload_path(candidate):
                candidates.append(candidate)

        if candidates:
            candidates.sort(key=len)
            return candidates[0]

        return ""

    def _is_probable_upload_path(self, candidate: str) -> bool:
        normalized = candidate.split("?", 1)[0].lower()
        if not normalized.startswith("sites/default/files/"):
            return False

        # 排除静态资源目录和文件
        non_upload_markers = [
            "/css/",
            "/js/",
            "/styles/",
            "/translations/",
            "/advagg_css/",
            "/advagg_js/",
            ".css",
            ".js",
            ".map",
            ".json",
        ]
        if any(marker in normalized for marker in non_upload_markers):
            return False

        # 必须包含典型的上传目录或文件扩展名
        upload_markers = [
            "/pictures/",
            "/inline-images/",
            "/uploads/",
            "/files/",
            ".gif",
            ".jpg",
            ".jpeg",
            ".png",
            ".svg",
            ".html",
            ".htm",
            ".txt",
            ".pdf",
        ]
        
        # 排除掉只有目录名的情况
        if normalized.endswith("/"):
            return False
            
        return any(marker in normalized for marker in upload_markers)

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
    
    def _match_single_matcher(self, resp: httpx.Response, matcher: Dict[str, Any]) -> bool:
        if not isinstance(matcher, dict):
            return False

        mtype = matcher.get("type")
        hit = False
        case_insensitive = matcher.get("case_insensitive", True)
        negative = matcher.get("negative", False)

        if mtype == "word":
            words = matcher.get("words", [])
            part = matcher.get("part", "body")
            content = resp.text if part == "body" else str(resp.headers)

            if case_insensitive:
                content_lower = content.lower()
                words_to_check = [w.lower() for w in words]
                condition = matcher.get("condition", "and")

                if condition == "and":
                    hit = all(w in content_lower for w in words_to_check)
                else:
                    hit = any(w in content_lower for w in words_to_check)
            else:
                condition = matcher.get("condition", "and")
                if condition == "and":
                    hit = all(w in content for w in words)
                else:
                    hit = any(w in content for w in words)

        elif mtype == "status":
            hit = resp.status_code in matcher.get("status", [])

        elif mtype == "regex":
            content = resp.text if matcher.get("part", "body") == "body" else str(resp.headers)
            flags = re.IGNORECASE if case_insensitive else 0

            try:
                patterns = matcher.get("regex", [])
                hit = all(re.search(p, content, flags=flags) for p in patterns)
            except re.error:
                hit = False

        elif mtype == "size":
            expected_size = matcher.get("size", 0)
            tolerance = matcher.get("tolerance", 100)
            actual_size = len(resp.content)
            hit = abs(actual_size - expected_size) <= tolerance

        elif mtype == "binary":
            binary_patterns = matcher.get("binary", [])
            import base64
            try:
                decoded = base64.b64decode(resp.text + "==") if resp.text else b""
                hit = any(p.encode() in decoded for p in binary_patterns)
            except Exception:
                hit = False

        if negative:
            hit = not hit

        return hit

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
            hit = self._match_single_matcher(resp, m)
            
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
    
    def _calculate_confidence(self, resp: httpx.Response, matchers: List[Dict[str, Any]], plugin: Optional[Dict[str, Any]] = None) -> float:
        """
        计算漏洞判定的置信度 (0.0 - 1.0)
        
        综合考虑以下因素:
        - 命中的匹配规则数量和权重
        - 特征关键词的唯一性
        - 响应状态码异常程度
        - 响应体特征强度
        """
        confidence = 0.0
        matched_count = 0

        for matcher in matchers:
            if not self._match_single_matcher(resp, matcher):
                continue

            matched_count += 1
            mtype = matcher.get("type")
            part = matcher.get("part", "body")

            if mtype == "regex":
                confidence += 0.28
            elif mtype == "word":
                confidence += 0.18 if part == "header" else 0.24
            elif mtype == "status":
                if resp.status_code >= 500:
                    confidence += 0.12
                elif resp.status_code >= 400:
                    confidence += 0.08
                else:
                    confidence += 0.03
            elif mtype == "size":
                confidence += 0.08
            else:
                confidence += 0.06

        if matched_count > 1:
            confidence += min((matched_count - 1) * 0.07, 0.21)
        
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
        header_lower = str(resp.headers).lower()
        plugin_info = plugin.get("info", {}) if plugin else {}
        tags = {str(tag).lower() for tag in plugin_info.get("tags", [])}
        plugin_fingerprint = " ".join(
            [
                str(plugin.get("id", "") if plugin else ""),
                str(plugin_info.get("name", "")),
                " ".join(tags),
            ]
        ).lower()
        
        # 检查高置信度特征
        if any(token in plugin_fingerprint for token in ["sql", "sqli", "injection"]):
            high_hits = sum(1 for kw in high_confidence_keywords if kw.lower() in content_lower)
            confidence += min(high_hits * 0.3, 0.6)
        
        # 检查中置信度特征
        if any(token in plugin_fingerprint for token in ["sql", "sqli", "injection"]):
            medium_hits = sum(1 for kw in medium_confidence_keywords if kw.lower() in content_lower)
            confidence += min(medium_hits * 0.1, 0.3)

        if "xss" in tags or "cross-site scripting" in plugin_fingerprint:
            xss_indicators = [
                "<script",
                "<svg",
                "onload=",
                "onerror=",
                "javascript:",
                "alert(",
                "document.cookie",
                "document.domain",
            ]
            xss_hits = sum(1 for kw in xss_indicators if kw in content_lower)
            confidence += min(xss_hits * 0.08, 0.24)
            if "text/html" in header_lower:
                confidence += 0.08
        
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
            "validation_log": result.validation_log,
            "plugin_id": result.plugin_id,
        }
    
    def _extract_matched_keywords(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> List[str]:
        """提取实际命中的关键词列表，用于置信度调整和日志记录"""
        matched = []
        for matcher in matchers:
            if not isinstance(matcher, dict):
                continue
            mtype = matcher.get("type")
            if mtype == "word":
                words = matcher.get("words", [])
                part = matcher.get("part", "body")
                content = resp.text if part == "body" else str(resp.headers)
                case_insensitive = matcher.get("case_insensitive", True)
                check_content = content.lower() if case_insensitive else content
                for w in words:
                    check_w = w.lower() if case_insensitive else w
                    if check_w in check_content:
                        matched.append(w)
            elif mtype == "status":
                if resp.status_code in matcher.get("status", []):
                    matched.append(f"status:{resp.status_code}")
            elif mtype == "regex":
                patterns = matcher.get("regex", [])
                content = resp.text if matcher.get("part", "body") == "body" else str(resp.headers)
                flags = re.IGNORECASE if matcher.get("case_insensitive", True) else 0
                for p in patterns:
                    try:
                        if re.search(p, content, flags=flags):
                            matched.append(f"regex:{p[:50]}")
                    except re.error:
                        pass
        return matched
    
    def _count_evidence(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> int:
        """计算命中的证据数量（匹配器数量 + 关键词特异性加权）"""
        evidence = 0
        for matcher in matchers:
            if self._match_single_matcher(resp, matcher):
                evidence += 1
                mtype = matcher.get("type")
                if mtype == "word":
                    words = matcher.get("words", [])
                    part = matcher.get("part", "body")
                    content = resp.text if part == "body" else str(resp.headers)
                    case_insensitive = matcher.get("case_insensitive", True)
                    check_content = content.lower() if case_insensitive else content
                    from scanner.engine.rules import HIGH_SPECIFICITY_SQLI_KEYWORDS, THINKPHP_EXCLUSIVE_SQLI_KEYWORDS
                    for w in words:
                        check_w = w.lower() if case_insensitive else w
                        if check_w in check_content:
                            if any(hkw.lower() == check_w for hkw in HIGH_SPECIFICITY_SQLI_KEYWORDS):
                                evidence += 1
                            if any(ekw.lower() == check_w for ekw in THINKPHP_EXCLUSIVE_SQLI_KEYWORDS):
                                evidence += 1
                elif mtype == "regex":
                    evidence += 1
        return evidence
    
    def _log_judgment(
        self,
        phase: str,
        plugin_id: str,
        action: str,
        details: Dict[str, Any],
        result: str,
    ) -> None:
        """记录判定日志，便于问题追踪和审计"""
        record = {
            "timestamp": time.time(),
            "phase": phase,
            "plugin_id": plugin_id,
            "action": action,
            "details": details,
            "result": result,
        }
        self._judgment_log.append(record)
        logger.debug(
            f"📝 判定日志 [{phase}] {plugin_id}/{action}: {result} - "
            f"{json.dumps(details, ensure_ascii=False)[:200]}"
        )
    
    def get_judgment_log(self) -> List[Dict[str, Any]]:
        """获取完整的判定日志"""
        return list(self._judgment_log)
    
    def get_framework_detection_result(self) -> Dict[str, Any]:
        """获取框架检测结果"""
        return {
            "detected_frameworks": [fw.value for fw in self._detected_frameworks],
            "framework_confidence": {
                fw.value: round(self._framework_confidence.get(fw, 0), 3)
                for fw in self._detected_frameworks
            },
            "framework_versions": {
                fw.value: v for fw, v in self._framework_versions.items()
            },
        }
