import os
import asyncio
import logging
import traceback
import time
import json
import re
from typing import Dict, Any
from celery import Celery
import httpx
from app.database import SessionLocal
from app.models.task import ScanTask, Vulnerability
from scanner.engine.hybrid_engine import HybridScannerEngine

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "redis://aegis-redis:6379/0")
celery_app = Celery("aegis_worker", broker=REDIS_URL, backend=REDIS_URL)


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
    
    # 命令注入特征
    cmd_injection_patterns = [
        r"command\s*injection", r"rce", r"remote\s*code\s*execution",
        r"cmd\s*=", r"exec\s*\(", r"system\s*\(", r"shell_exec",
        r"passthru", r"proc_open", r"\|\s*(cat|ls|dir|whoami|id)",
        r"`.*`", r"\$\(.*\)", r"/bin/(ba)?sh", r"/etc/passwd",
    ]
    
    # 文件包含/遍历特征
    lfi_patterns = [
        r"file\s*inclusion", r"lfi", r"rfi", r"path\s*traversal",
        r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
        r"win\.ini", r"boot\.ini", r"php://filter", r"php://input",
        r"expect://", r"data://", r"file://",
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
    }
    
    # 检查框架特定漏洞
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


def execute_scan_task(task_id: int, target_url: str, scan_strategy: str = "intelligent"):
    """
    执行模拟攻击扫描任务 (LLM 增强版)
    """
    db = SessionLocal()
    start_time = time.time()
    
    logger.info("=" * 60)
    logger.info(f"🚀 [Worker] 启动模拟攻击引擎 (Simulation Mode)")
    logger.info(f"   任务 ID: {task_id}")
    logger.info(f"   目标 URL: {target_url}")
    logger.info(f"   策略：{scan_strategy}")
    logger.info("=" * 60)
    
    task = None
    
    try:
        # 更新状态 -> RUNNING
        task = db.query(ScanTask).filter(ScanTask.id == task_id).first()
        if not task:
            logger.error(f"❌ [Worker] 任务不存在：{task_id}")
            return
        
        task.status = "RUNNING"
        db.commit()

        # === 使用混合扫描引擎 ===
        logger.info("🔧 [Worker] 初始化 HybridScannerEngine...")
        engine = HybridScannerEngine(
            target=target_url,
            strategy="hybrid",
            max_concurrent=5,
            timeout=15.0,
            max_depth=2
        )
        
        # 执行混合扫描
        logger.info("🎯 [Worker] 开始执行混合扫描...")
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
            logger.info(f"🔴 [Worker] 发现 {vuln_count} 个确认漏洞:")
            
            for idx, v in enumerate(found_vulns, 1):
                # 智能推断漏洞类型
                vuln_name = infer_vulnerability_type(v)
                
                vuln_record = Vulnerability(
                    task_id=task_id,
                    vuln_name=vuln_name,
                    severity="HIGH", # 模拟攻击确认的通常是高危
                    url=v["url"],
                    payload=v.get("payload"),
                    evidence=json.dumps({
                        "evidence": v["evidence"],
                        "llm_analysis": v.get("llm_analysis")
                    }, ensure_ascii=False)
                )
                db.add(vuln_record)
                
                logger.info(f"  [{idx}] {vuln_name} @ {v['url']}")
                logger.info(f"      Payload: {v.get('payload', 'N/A')[:100]}")
                logger.info(f"      分析：{v.get('llm_analysis')}")
        else:
            logger.info("ℹ️  [Worker] 未发现漏洞")
        
        # 更新状态 -> COMPLETED
        task.status = "COMPLETED"
        task.vulnerabilities_found = vuln_count
        db.commit()
        
        logger.info("=" * 60)
        logger.info(f"✅ [Worker] 模拟攻击任务完成")
        logger.info(f"   耗时：{execution_time:.2f} 秒")
        logger.info("=" * 60)

    except Exception as e:
        error_msg = f"❌ [Worker] 引擎异常：{e}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        if task:
            task.status = "FAILED"
            db.commit()
    finally:
        db.close()

@celery_app.task(bind=True)
def run_scan_task(self, task_id: int, target_url: str, scan_strategy: str = "intelligent"):
    execute_scan_task(task_id, target_url, scan_strategy)
