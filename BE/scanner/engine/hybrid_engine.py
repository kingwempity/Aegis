"""
混合扫描引擎: 结合 ScannerEngine (插件驱动) 和 AttackSimulator (LLM 驱动)
实现两阶段扫描,提高漏洞检测命中率
"""

import logging
from typing import List, Dict, Any
from scanner.engine.core import ScannerEngine
from scanner.engine.simulator import AttackSimulator

logger = logging.getLogger(__name__)


class HybridScannerEngine:
    """
    混合扫描引擎
    
    工作流程:
    1. 阶段1: ScannerEngine 快速扫描 (确定性,高可靠性)
    2. 阶段2: AttackSimulator 智能探索 (利用阶段1信息,LLM 自主学习)
    3. 合并并去重结果
    """
    
    def __init__(self, target: str, strategy: str = "hybrid", **kwargs):
        self.target = target.rstrip("/")
        self.strategy = strategy
        self.kwargs = kwargs
        
    async def run(self) -> List[Dict[str, Any]]:
        """执行混合扫描"""
        logger.info(f"🚀 启动混合扫描引擎: {self.target}")
        
        # === 阶段1: 快速扫描 ===
        logger.info("=" * 60)
        logger.info("📡 阶段1: ScannerEngine 快速扫描...")
        logger.info("=" * 60)
        
        scanner = ScannerEngine(
            target=self.target,
            strategy="aggressive",
            max_concurrent=self.kwargs.get('max_concurrent', 5),
            timeout=self.kwargs.get('timeout', 15.0),
            max_depth=self.kwargs.get('max_depth', 2)
        )
        
        fast_vulns = await scanner.run()
        recon_info = scanner.get_framework_detection_result()
        
        logger.info(f"✅ 阶段1完成: 发现 {len(fast_vulns)} 个漏洞")
        logger.info(f"📦 框架检测: {recon_info.get('detected_frameworks', [])}")
        
        # === 阶段2: 智能探索 (仅当有侦察信息时) ===
        detected_frameworks = recon_info.get('detected_frameworks', [])
        
        if detected_frameworks:
            logger.info("=" * 60)
            logger.info("🤖 阶段2: AttackSimulator 智能探索...")
            logger.info("=" * 60)
            
            simulator = AttackSimulator(
                target=self.target,
                strategy="intelligent"
            )
            
            # 传递阶段1结果作为上下文
            simulator.set_recon_context({
                'detected_frameworks': detected_frameworks,
                'framework_versions': recon_info.get('framework_versions', {}),
                'entry_points': recon_info.get('entry_points', []),
                'already_found_vulns': fast_vulns,
                'technologies': recon_info.get('technologies', [])
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
            smart_vulns = []
        
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
        
        # 优先保留 ScannerEngine 的结果 (更可靠)
        for vuln in fast_vulns:
            key = (vuln.get('url', ''), vuln.get('vuln_name', ''))
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
        
        # 添加 AttackSimulator 的独特结果
        for vuln in smart_vulns:
            key = (vuln.get('url', ''), vuln.get('vuln_name', ''))
            if key not in seen:
                seen.add(key)
                merged.append(vuln)
        
        return merged
