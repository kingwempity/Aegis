"""
混合扫描引擎: 结合 ScannerEngine (插件驱动) 和 AttackSimulator (LLM 驱动)
实现两阶段扫描,提高漏洞检测命中率
"""

import logging
from typing import List, Dict, Any, Optional
from scanner.engine.core import ScannerEngine
from scanner.engine.simulator import AttackSimulator
from scanner.engine.scan_mode_config import get_scan_mode_config, ScanModeConfig

logger = logging.getLogger(__name__)


class HybridScannerEngine:
    """
    混合扫描引擎
    
    工作流程:
    1. 阶段1: ScannerEngine 快速扫描 (确定性,高可靠性)
    2. 阶段2: AttackSimulator 智能探索 (利用阶段1信息,LLM 自主学习)
    3. 合并并去重结果
    """
    
    def __init__(
        self,
        target: str,
        strategy: str = "attack_validation",
        target_paths: Optional[List[str]] = None,
        target_vuln_types: Optional[List[str]] = None,
        target_parameters: Optional[List[str]] = None,
        **kwargs
    ):
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.target_paths = target_paths or []
        self.target_vuln_types = target_vuln_types or []
        self.target_parameters = target_parameters or []
        self.mode_config = get_scan_mode_config(strategy)
        self.kwargs = kwargs
        
    async def run(self) -> List[Dict[str, Any]]:
        """执行混合扫描"""
        logger.info(f"🚀 启动混合扫描引擎: {self.target} (模式: {self.strategy})")
        
        scanner_strategy = self.kwargs.get('scanner_strategy', self.mode_config.scanner_strategy)
        max_concurrent = self.kwargs.get('max_concurrent', self.mode_config.max_concurrent)
        timeout = self.kwargs.get('timeout', self.mode_config.timeout)
        max_depth = self.kwargs.get('max_depth', self.mode_config.max_depth)
        
        logger.info(
            f"   策略={scanner_strategy}, 并发={max_concurrent}, "
            f"超时={timeout}s, 深度={max_depth}"
        )
        
        if self.target_paths:
            logger.info(f"   定向路径: {self.target_paths}")
        if self.target_vuln_types:
            logger.info(f"   定向漏洞类型: {self.target_vuln_types}")
        if self.target_parameters:
            logger.info(f"   定向参数: {self.target_parameters}")
        
        # === 阶段1: ScannerEngine 扫描 ===
        logger.info("=" * 60)
        logger.info("📡 阶段1: ScannerEngine 扫描...")
        logger.info("=" * 60)
        
        scanner = ScannerEngine(
            target=self.target,
            strategy=scanner_strategy,
            max_concurrent=max_concurrent,
            timeout=timeout,
            max_depth=max_depth,
            target_paths=self.target_paths if self.target_paths else None,
            target_vuln_types=self.target_vuln_types if self.target_vuln_types else None,
            target_parameters=self.target_parameters if self.target_parameters else None,
            enable_discovery_scan=self.mode_config.enable_discovery_scan,
            payload_set=self.mode_config.payload_set,
        )
        
        fast_vulns = await scanner.run()
        recon_info = scanner.get_framework_detection_result()
        
        logger.info(f"✅ 阶段1完成: 发现 {len(fast_vulns)} 个漏洞")
        logger.info(f"📦 框架检测: {recon_info.get('detected_frameworks', [])}")
        
        # === 阶段2: AttackSimulator 智能探索 (仅配置启用时) ===
        smart_vulns = []
        if self.mode_config.enable_llm_phase:
            detected_frameworks = recon_info.get('detected_frameworks', [])
            
            if detected_frameworks:
                logger.info("=" * 60)
                logger.info(f"🤖 阶段2: AttackSimulator 智能探索 (策略: {self.mode_config.simulator_strategy})...")
                logger.info("=" * 60)
                
                simulator = AttackSimulator(
                    target=self.target,
                    strategy=self.mode_config.simulator_strategy,
                    max_rounds=self.mode_config.max_llm_rounds,
                    enable_vulhub_scan=self.mode_config.enable_vulhub_scan,
                )
                
                simulator.set_recon_context({
                    'detected_frameworks': detected_frameworks,
                    'framework_versions': recon_info.get('framework_versions', {}),
                    'entry_points': recon_info.get('entry_points', []),
                    'already_found_vulns': fast_vulns,
                    'technologies': recon_info.get('technologies', []),
                    'target_vuln_types': self.target_vuln_types,
                    'target_parameters': self.target_parameters,
                })
                
                try:
                    smart_result = await simulator.run_simulation()
                    smart_vulns = smart_result.get('vulnerabilities', [])
                    logger.info(f"✅ 阶段2完成: 发现 {len(smart_vulns)} 个漏洞")
                except Exception as e:
                    logger.warning(f"⚠️ 阶段2失败: {e}")
                    smart_vulns = []
            else:
                logger.info("⏭️ 跳过阶段2: 无框架检测结果")
        else:
            logger.info("⏭️ 跳过阶段2: 定向模式不需要LLM探索")
        
        # === 合并并去重结果 ===
        merged_vulns = self._merge_and_deduplicate(fast_vulns, smart_vulns)
        
        logger.info("=" * 60)
        logger.info(f"🎯 混合扫描完成: 共发现 {len(merged_vulns)} 个漏洞")
        logger.info(f"   - 阶段1 (ScannerEngine): {len(fast_vulns)} 个")
        logger.info(f"   - 阶段2 (AttackSimulator): {len(smart_vulns)} 个")
        logger.info(f"   - 合并后 (去重): {len(merged_vulns)} 个")
        logger.info("=" * 60)
        
        return merged_vulns
    
    def _merge_and_deduplicate(self, fast_vulns: List[Dict], smart_vulns: List[Dict]) -> List[Dict]:
        """合并并去重漏洞结果"""
        seen = set()
        merged = []
        
        for vuln in fast_vulns:
            key = (vuln.get('url', ''), vuln.get('vuln_name', ''))
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
        
        for vuln in smart_vulns:
            key = (vuln.get('url', ''), vuln.get('vuln_name', ''))
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
        
        return merged
