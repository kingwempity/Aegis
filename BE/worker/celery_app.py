import os
import asyncio
import logging
import traceback
import time
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
from celery import Celery
import httpx
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.hybrid_engine import HybridScannerEngine

AUTO_GENERATE_LAB_SCENARIOS = os.getenv("AUTO_GENERATE_LAB_SCENARIOS", "true").lower() == "true"
LAB_SCENARIO_MIN_SEVERITY = os.getenv("LAB_SCENARIO_MIN_SEVERITY", "medium").lower()
LAB_SCENARIO_MAX_PER_SCAN = int(os.getenv("LAB_SCENARIO_MAX_PER_SCAN", "3"))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
# 通知回调地址：FastAPI 后端服务地址
# 默认值 'http://localhost:8000' 适用于开发环境，生产环境请通过 FASTAPI_URL 环境变量配置
_FASTAPI_ENV = os.getenv("FASTAPI_URL", "").rstrip("/")
if not _FASTAPI_ENV:
    logger.warning("FASTAPI_URL 未配置，使用默认值 'http://localhost:8000'（仅适用于开发环境）")
FASTAPI_URL = _FASTAPI_ENV if _FASTAPI_ENV else "http://localhost:8000"
NOTIFICATION_API_URL = f"{FASTAPI_URL}/api/v1/notifications/events/emit"
# 同进程模式下直接导入通知服务（用于 _run_scan_in_background 场景）
# 如果导入失败（独立 Celery Worker 进程），则回退到 HTTP 回调
try:
    from app.services.notification_service import notification_service as _notif_service
    _IN_PROCESS_NOTIFICATION = True
except Exception:
    _IN_PROCESS_NOTIFICATION = False
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)


def _emit_notification(event_type: str, data: Dict[str, Any], source: str = "scanner_worker"):
    """
    智能通知发射：优先通过 HTTP 回调通知 FastAPI，失败时回退到同进程内存调用。
    
    Args:
        event_type: 事件类型
        data: 事件数据
        source: 事件源标识
    """
    # 策略1：HTTP 回调到 FastAPI（适用于 Celery Worker 和 _run_scan_in_background）
    if NOTIFICATION_API_URL:
        try:
            response = httpx.post(
                NOTIFICATION_API_URL,
                json={
                    "event_type": event_type,
                    "data": data,
                    "source": source
                },
                timeout=5.0,
            )
            if response.status_code == 200:
                logger.info(f" [Notification] HTTP callback success: {event_type}")
                return
            else:
                logger.warning(f" [Notification] HTTP callback failed ({response.status_code}): {event_type}")
        except Exception as e:
            logger.warning(f"[Notification] HTTP callback not available ({e}), trying direct emit...")
    
    # 策略2：同进程直接调用（回退方案）
    try:
        from app.services.notification_service import notification_service
        notification_service.emit_event_from_thread(
            event_type=event_type,
            data=data,
            source=source
        )
        logger.info(f" [Notification] Direct emit success: {event_type}")
        return
    except Exception as e:
        logger.warning(f"[Notification] Direct emit failed: {e}")
    
    # 所有策略均失败
    logger.error(f" [Notification] ALL methods failed for event: {event_type}")


def get_risk_level(severity_str: str) -> str:
    """
    将严重级别字符串转换为标准小写风险级别。

    Args:
        severity_str: 严重级别字符串（如 "HIGH", "critical", "Medium"）

    Returns:
        标准风险级别: "critical" | "high" | "medium" | "low" | "info"
    """
    severity = severity_str.upper() if severity_str else ""
    if severity == "CRITICAL":
        return "critical"
    elif severity == "HIGH":
        return "high"
    elif severity == "MEDIUM":
        return "medium"
    elif severity == "LOW":
        return "low"
    else:
        return "info"


def infer_vulnerability_type(vuln_data: Dict[str, Any]) -> str:
    """
    根据漏洞特征推断漏洞类型，生成更具体的漏洞名称
    
    Args:
        vuln_data: 漏洞数据字典，包含 url, payload, evidence, llm_analysis 等
        
    Returns:
        漏洞类型名称
    """
    url = vuln_data.get("url", "").lower()
    payload = vuln_data.get("payload", "").lower() if vuln_data.get("payload") else ""
    
    # evidence 可能是字典或字符串，需要安全转换
    evidence_raw = vuln_data.get("evidence", "")
    if isinstance(evidence_raw, dict):
        evidence = str(evidence_raw).lower()
    elif evidence_raw:
        evidence = evidence_raw.lower()
    else:
        evidence = ""
    
    llm_analysis = vuln_data.get("llm_analysis", "").lower() if vuln_data.get("llm_analysis") else ""
    
    # 合并所有文本用于分析
    full_text = f"{url} {payload} {evidence} {llm_analysis}"
    
    # SQL 注入特征
    sqli_patterns = [
        r"sql\s*(injection|inject)", r"sqli", r"sql\s*error", r"database\s*error",
        r"mysql", r"postgres", r"oracle", r"mssql", r"sqlite",
        r"union\s+select", r"or\s+1\s*=\s*1", r"and\s+1\s*=\s*1",
        r"xp_cmdshell", r"waitfor\s+delay", r"benchmark\s*\(",
        r"sleep\s*\(", r"extractvalue", r"updatexml",
        r"thinkphp.*sql", r"pdo.*exception", r"integrityerror",
    ]
    
    # XSS 特征
    xss_patterns = [
        r"xss", r"cross.*site.*script",
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"alert\s*\(", r"document\.cookie", r"document\.domain",
        r"<svg", r"<iframe", r"<img.*src\s*=\s*x",
    ]
    
    # 命令注入特征（移除 /etc/passwd，避免与文件读取混淆）
    cmd_injection_patterns = [
        r"command\s*injection", r"rce", r"remote\s*code\s*execution",
        r"cmd\s*=", r"exec\s*\(", r"system\s*\(", r"shell_exec",
        r"passthru", r"proc_open", r"\|\s*(cat|ls|dir|whoami|id)",
        r"`.*`", r"\$\(.*\)", r"/bin/(ba)?sh",
    ]
    
    # 文件包含/遍历特征
    lfi_patterns = [
        r"file\s*inclusion", r"lfi", r"rfi", r"path\s*traversal",
        r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
        r"win\.ini", r"boot\.ini", r"php://filter", r"php://input",
        r"expect://", r"data://", r"file://",
    ]
    
    # CVE-2025-32395 特定特征
    cve_2025_32395_patterns = [
        r"cve.*2025.*32395", r"vite.*hash", r"vite.*bypass",
        r"/@fs/", r"server\.fs\.deny", r"vite.*file.*read",
    ]
    
    # SSRF 特征
    ssrf_patterns = [
        r"ssrf", r"server.*side.*request",
        r"169\.254\.", r"127\.0\.0\.1", r"localhost",
        r"metadata", r"ami-id", r"instance-id",
        r"internal.*resource", r"aws.*metadata",
    ]
    
    # 信息泄露特征
    info_disclosure_patterns = [
        r"info.*disclosure", r"information\s+leak",
        r"git.*config", r"\[core\]", r"repositoryformatversion",
        r"api[_-]?key", r"secret[_-]?key", r"password\s*=",
        r"credentials", r"token\s*=", r"private[_-]?key",
    ]
    
    # 文件上传特征
    file_upload_patterns = [
        r"file\s*upload", r"upload\s*vulnerability",
        r"public://", r"sites/default/files",
        r'"fid"', r'"uuid"', r'"uri"',
    ]
    
    # 框架特定漏洞
    framework_patterns = {
        "ThinkPHP SQL Injection": [r"thinkphp.*sql", r"think\\db\\exception"],
        "Django Debug Page Disclosure": [r"django.*debug", r"django_settings_module"],
        "Drupal File Upload (CVE-2018-7600)": [r"drupal.*upload", r"cve.*2018.*7600"],
        "Django IntegrityError (CVE-2017-12794)": [r"django.*integrity", r"cve.*2017.*12794"],
        "CVE-2025-32395 Vite Hash Bypass": cve_2025_32395_patterns,
    }
    
    # 检查框架特定漏洞（包括 CVE-2025-32395）
    for vuln_name, patterns in framework_patterns.items():
        if any(re.search(p, full_text) for p in patterns):
            return f"{vuln_name} (Simulation-Confirmed)"
    
    # 检查通用漏洞类型
    vulnerability_checks = [
        ("SQL Injection", sqli_patterns),
        ("Cross-Site Scripting (XSS)", xss_patterns),
        ("Command Injection", cmd_injection_patterns),
        ("Local File Inclusion", lfi_patterns),
        ("Server-Side Request Forgery (SSRF)", ssrf_patterns),
        ("Information Disclosure", info_disclosure_patterns),
        ("Arbitrary File Upload", file_upload_patterns),
    ]
    
    for vuln_name, patterns in vulnerability_checks:
        if any(re.search(p, full_text) for p in patterns):
            return f"{vuln_name} (Simulation-Confirmed)"
    
    # 默认返回
    return "Simulation-Confirmed Vulnerability"


def execute_scan_task(
    task_id: int,
    target_url: str,
    scan_strategy: str = "attack_validation",
    target_paths: Optional[List[str]] = None,
    target_vuln_types: Optional[List[str]] = None,
    target_parameters: Optional[List[str]] = None,
):
    """
    执行模拟攻击扫描任务 (LLM 增强版)
    """
    db = SessionLocal()
    start_time = time.time()
    
    logger.info("=" * 60)
    logger.info(f" [Worker] 启动模拟攻击引擎 (模式: {scan_strategy})")
    logger.info(f"   任务 ID: {task_id}")
    logger.info(f"   目标 URL: {target_url}")
    logger.info(f"   策略：{scan_strategy}")
    if target_paths:
        logger.info(f"   定向路径: {target_paths}")
    if target_vuln_types:
        logger.info(f"   定向漏洞类型: {target_vuln_types}")
    if target_parameters:
        logger.info(f"   定向参数: {target_parameters}")
    logger.info("=" * 60)
    
    task = None
    
    try:
        # 更新状态 -> RUNNING
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            logger.error(f" [Worker] 任务不存在：{task_id}")
            return
        
        task.status = "RUNNING"
        db.commit()
        
        # 发射扫描启动通知
        _emit_notification(
            event_type="scan.started",
            data={
                "task_id": task_id,
                "display_id": task.display_id,
                "target_url": target_url,
                "scan_strategy": scan_strategy,
                "scan_range": {
                    "paths": target_paths or [],
                    "vuln_types": target_vuln_types or [],
                    "parameters": target_parameters or [],
                },
                "started_at": datetime.now().isoformat(),
            },
        )

        # === 使用混合扫描引擎 ===
        logger.info(" [Worker] 初始化 HybridScannerEngine...")
        engine = HybridScannerEngine(
            target=target_url,
            strategy=scan_strategy,
            target_paths=target_paths,
            target_vuln_types=target_vuln_types,
            target_parameters=target_parameters,
        )
        
        # 执行混合扫描
        logger.info(" [Worker] 开始执行混合扫描...")
        # 兼容 Python 3.6
        if hasattr(asyncio, 'run'):
            found_vulns = asyncio.run(engine.run())
        else:
            loop = asyncio.get_event_loop()
            found_vulns = loop.run_until_complete(engine.run())
        
        execution_time = time.time() - start_time
        
        # 保存漏洞结果
        vuln_count = len(found_vulns)
        if vuln_count > 0:
            logger.info(f" [Worker] 发现 {vuln_count} 个确认漏洞:")
            
            for idx, v in enumerate(found_vulns, 1):
                # 智能推断漏洞类型
                vuln_name = infer_vulnerability_type(v)
                
                # 提取 Payload - 优先使用原始 payload，如果没有则从 URL 中提取攻击路径
                payload = v.get("payload", "N/A")
                if not payload or payload == "N/A" or payload == "aegis_probe":
                    # 从 URL 中提取攻击路径（特别是对于 CVE-2025-32395 等文件读取漏洞）
                    url = v.get("url", "")
                    if "/@fs/" in url:
                        # 提取 /@fs/ 及其后面的部分作为 Payload
                        payload_start = url.find("/@fs/")
                        payload = url[payload_start:] if payload_start >= 0 else url
                
                # 提取攻击路径信息（来自 ScannerEngine 的 ScanResult）
                attack_path = v.get("attack_path")
                
                # 提取漏洞类型和参数
                vuln_type = None
                parameter = None
                
                # 尝试从 validation_log 中提取
                validation_log = v.get("validation_log")
                if validation_log and isinstance(validation_log, dict):
                    vuln_type = validation_log.get("vuln_type")
                    parameter = validation_log.get("parameter")
                
                # 尝试从 evidence 中提取
                evidence_data = v.get("evidence")
                if evidence_data and isinstance(evidence_data, dict):
                    if not vuln_type:
                        vuln_type = evidence_data.get("vuln_type")
                    if not parameter:
                        parameter = evidence_data.get("parameter")
                
                # 尝试从 attack_path 中提取
                if attack_path and isinstance(attack_path, dict):
                    if not parameter:
                        request_info = attack_path.get("request", {})
                        if isinstance(request_info, dict):
                            url_str = request_info.get("url", "")
                            if "?" in url_str:
                                query = url_str.split("?", 1)[1]
                                for part in query.split("&"):
                                    if "=" in part:
                                        parameter = part.split("=", 1)[0]
                                        break
                
                # 推断漏洞类型（如果还没有的话）
                if not vuln_type:
                    vuln_type = vuln_name.split(" (Simulation-Confirmed)")[0] if " (Simulation-Confirmed)" in vuln_name else None
                
                # 构建证据数据 - 保留完整的结构化证据
                evidence_dict = {
                    "evidence": v.get("evidence"),
                    "llm_analysis": v.get("llm_analysis"),
                }
                
                # 如果 evidence 本身就是结构化数据（来自 ScannerEngine），合并它
                if evidence_data and isinstance(evidence_data, dict):
                    evidence_dict.update({
                        "matchers": evidence_data.get("matchers"),
                        "matchers_condition": evidence_data.get("matchers_condition"),
                        "confidence": evidence_data.get("confidence"),
                        "base_confidence": evidence_data.get("base_confidence"),
                        "evidence_count": evidence_data.get("evidence_count"),
                        "matched_keywords": evidence_data.get("matched_keywords"),
                        "response_status": evidence_data.get("response_status"),
                        "response_time_ms": evidence_data.get("response_time_ms"),
                        "framework_validation": evidence_data.get("framework_validation"),
                        "confidence_adjustments": evidence_data.get("confidence_adjustments"),
                        "attack_stage_count": evidence_data.get("attack_stage_count"),
                        "attack_artifacts": evidence_data.get("attack_artifacts"),
                        "encoding_used": evidence_data.get("encoding_used"),
                        "mutation_type": evidence_data.get("mutation_type"),
                    })
                
                vuln_record = Vulnerability(
                    task_id=task_id,
                    vuln_name=vuln_name,
                    severity="HIGH",
                    url=v["url"],
                    payload=payload,
                    evidence=evidence_dict,
                    attack_path=attack_path,
                    vuln_type=vuln_type,
                    parameter=parameter,
                )
                db.add(vuln_record)
                
                logger.info(f"  [{idx}] {vuln_name} @ {v['url']}")
                logger.info(f"      Payload: {payload[:100]}")
                logger.info(f"      分析：{v.get('llm_analysis')}")
        else:
            logger.info("ℹ  [Worker] 未发现漏洞")
        
        # 自动生成 Vuln Lab 场景
        if AUTO_GENERATE_LAB_SCENARIOS and found_vulns:
            try:
                logger.info(" 开始自动生成 Vuln Lab 场景...")
                from scanner.engine.lab_generator import LabScenarioGenerator, SEVERITY_ORDER
                from app.models.lab import LabScenario
                
                generator = LabScenarioGenerator()
                min_severity_level = SEVERITY_ORDER.get(LAB_SCENARIO_MIN_SEVERITY, 2)
                generated_count = 0
                
                for vuln_data in found_vulns:
                    if generated_count >= LAB_SCENARIO_MAX_PER_SCAN:
                        logger.info(f" 已达到本次扫描场景生成上限 ({LAB_SCENARIO_MAX_PER_SCAN})")
                        break
                    
                    vuln_severity = get_risk_level(vuln_data.get("severity", "HIGH"))
                    vuln_severity_level = SEVERITY_ORDER.get(vuln_severity, 4)
                    
                    if vuln_severity_level > min_severity_level:
                        logger.info(f" 跳过场景生成: {vuln_data.get('url')} (严重级别 {vuln_severity} 低于阈值 {LAB_SCENARIO_MIN_SEVERITY})")
                        continue
                    
                    try:
                        scenario_data = generator.generate_from_vuln_sync(vuln_data, scan_task_id=task_id)
                        
                        if scenario_data:
                            lab_scenario = LabScenario(
                                name=scenario_data["name"],
                                vuln_type=scenario_data["vuln_type"],
                                difficulty=scenario_data["difficulty"],
                                description=scenario_data.get("description", ""),
                                attack_steps=scenario_data.get("attack_steps", []),
                                remediation=scenario_data.get("remediation", []),
                                learning=scenario_data.get("learning", {}),
                                tags=scenario_data.get("tags", []),
                                is_active=scenario_data.get("is_active", False),
                                is_auto_generated=True,
                                source_scan_task_id=task_id,
                            )
                            db.add(lab_scenario)
                            generated_count += 1
                            logger.info(f" 生成 Vuln Lab 场景: {scenario_data['name']}")
                        else:
                            logger.warning(f" 场景生成返回空数据: {vuln_data.get('url')}")
                    except Exception as e:
                        logger.warning(f" 生成单个场景失败: {e}")
                
                if generated_count > 0:
                    logger.info(f" Vuln Lab 场景生成完成: {generated_count} 个场景")
            except Exception as e:
                logger.warning(f"自动生成 Vuln Lab 场景失败: {e}")
        
        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        task.vulnerabilities_found = vuln_count
        db.commit()
        
        # 按严重级别统计漏洞
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        top_vulns = []
        for v in found_vulns:
            sev = get_risk_level(v.get("severity", "HIGH"))
            severity_counts[sev] += 1
            top_vulns.append({
                "name": v.get("vuln_name", v.get("name", "未知")),
                "severity": sev,
                "url": v.get("url", ""),
            })
        
        # 发射扫描完成通知
        _emit_notification(
            event_type="scan.completed",
            data={
                "task_id": task_id,
                "display_id": task.display_id,
                "target_url": target_url,
                "vulnerabilities_found": vuln_count,
                "duration_seconds": execution_time,
                "completed_at": datetime.now().isoformat(),
                "severity_summary": severity_counts,
            },
        )
        
        # 发射漏洞汇总通知（HTTP回调到FastAPI）
        if vuln_count > 0:
            _emit_notification(
                event_type="vulnerability.summary",
                data={
                    "task_id": task_id,
                    "display_id": task.display_id,
                    "target_url": target_url,
                    "total_count": vuln_count,
                    "severity_counts": severity_counts,
                    "top_vulnerabilities": top_vulns[:5],
                    "scan_duration": execution_time,
                    "scan_range": {
                        "paths": target_paths or [],
                        "vuln_types": target_vuln_types or [],
                        "parameters": target_parameters or [],
                    },
                },
            )
        
        logger.info("=" * 60)
        logger.info(f" [Worker] 模拟攻击任务完成")
        logger.info(f"   耗时：{execution_time:.2f} 秒")
        logger.info("=" * 60)

    except Exception as e:
        error_msg = f" [Worker] 引擎异常：{e}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        if task:
            task.status = "FAILED"
            db.commit()
            
            # 发射扫描失败通知
            _emit_notification(
                event_type="scan.failed",
                data={
                    "task_id": task_id,
                    "display_id": task.display_id if hasattr(task, 'display_id') else task_id,
                    "error_message": str(e),
                    "failed_at": datetime.now().isoformat(),
                },
            )
    finally:
        db.close()

@celery_app.task(bind=True)
def run_scan_task(
    self,
    task_id: int,
    target_url: str,
    scan_strategy: str = "attack_validation",
    target_paths: Optional[List[str]] = None,
    target_vuln_types: Optional[List[str]] = None,
    target_parameters: Optional[List[str]] = None,
):
    execute_scan_task(
        task_id, target_url, scan_strategy,
        target_paths, target_vuln_types, target_parameters,
    )
