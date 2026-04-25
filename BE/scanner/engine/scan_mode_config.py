"""
scanner.engine.scan_mode_config
-------------------------------
扫描模式配置: 定义三种验证模式的差异化扫描参数
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List


@dataclass
class ScanModeConfig:
    """单个扫描模式的配置"""
    scanner_strategy: str = "aggressive"
    simulator_strategy: str = "intelligent"
    max_concurrent: int = 5
    timeout: float = 15.0
    max_depth: int = 2
    enable_llm_phase: bool = True
    enable_vulhub_scan: bool = True
    max_llm_rounds: int = 10
    target_paths: Optional[List[str]] = None
    target_vuln_types: Optional[List[str]] = None
    target_parameters: Optional[List[str]] = None
    enable_discovery_scan: bool = True
    payload_set: str = "standard"


SCAN_MODE_CONFIGS: Dict[str, ScanModeConfig] = {
    "attack_validation": ScanModeConfig(
        scanner_strategy="aggressive",
        simulator_strategy="intelligent",
        max_concurrent=5,
        timeout=15.0,
        max_depth=2,
        enable_llm_phase=True,
        enable_vulhub_scan=True,
        max_llm_rounds=10,
        enable_discovery_scan=True,
        payload_set="standard",
    ),
    "full_audit": ScanModeConfig(
        scanner_strategy="aggressive",
        simulator_strategy="intelligent",
        max_concurrent=10,
        timeout=30.0,
        max_depth=4,
        enable_llm_phase=True,
        enable_vulhub_scan=True,
        max_llm_rounds=20,
        enable_discovery_scan=True,
        payload_set="full",
    ),
    "focused_probe": ScanModeConfig(
        scanner_strategy="stealthy",
        simulator_strategy="focused",
        max_concurrent=3,
        timeout=10.0,
        max_depth=1,
        enable_llm_phase=False,
        enable_vulhub_scan=False,
        max_llm_rounds=3,
        enable_discovery_scan=False,
        payload_set="minimal",
    ),
}

DEFAULT_CONFIG = ScanModeConfig()


def get_scan_mode_config(mode: Optional[str] = None) -> ScanModeConfig:
    if not mode or mode not in SCAN_MODE_CONFIGS:
        return DEFAULT_CONFIG
    return SCAN_MODE_CONFIGS[mode]
