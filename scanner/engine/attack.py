"""scanner.engine.attack
-----------------------
模拟攻击引擎扩展：
1) 攻击脚本生成 (AttackScriptGenerator)
2) 攻击路径探索 (AttackPathExplorer)

保持无害化扫描：仅生成验证型 payload，不执行破坏性命令。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any


DEFAULT_SAFE_PAYLOADS: Dict[str, List[str]] = {
    "generic": ["aegis_probe"],
    "sqli": ["' OR '1'='1", "1' AND '1'='1"],
    "xss": ["<svg onload=alert(1)>", "\"'><script>alert(1)</script>"],
    "path_traversal": ["../etc/passwd", "..%2f..%2fetc%2fpasswd"],
}


@dataclass
class PathCandidate:
    """路径候选实体。"""

    url: str
    method: str
    score: float
    source_plugin: str


class AttackScriptGenerator:
    """根据模板和上下文生成最终请求脚本。"""

    def __init__(self, strategy: str = "default"):
        self.strategy = strategy

    def build_payloads(self, plugin: Dict[str, Any], request_def: Dict[str, Any]) -> List[str]:
        """根据插件声明生成 payload 列表。"""
        payload_sets = request_def.get("payload_sets") or plugin.get("payload_sets")
        if isinstance(payload_sets, dict):
            if self.strategy in payload_sets:
                payloads = payload_sets[self.strategy]
            else:
                payloads = payload_sets.get("default", [])
            if payloads:
                return [str(x) for x in payloads]

        # 自动依据 vuln type 提供保底 payload
        vuln_type = str(plugin.get("id", "generic")).lower()
        for key, candidates in DEFAULT_SAFE_PAYLOADS.items():
            if key in vuln_type:
                return candidates
        return DEFAULT_SAFE_PAYLOADS["generic"]

    def render_path(self, raw_path: str, base_url: str, payload: str) -> str:
        """渲染模板变量。"""
        return (
            raw_path.replace("{{BaseURL}}", base_url.rstrip("/"))
            .replace("{{payload}}", payload)
        )


class AttackPathExplorer:
    """路径优先级探索：综合新颖度、风险、成本进行简单打分。"""

    def __init__(self):
        self._visited: set[str] = set()

    @staticmethod
    def _risk_score(path: str, method: str) -> float:
        score = 0.0
        p = path.lower()
        if any(k in p for k in ["admin", "config", "upload", ".git", "debug"]):
            score += 0.8
        if "{{payload}}" in path:
            score += 0.5
        if method.upper() in {"POST", "PUT", "PATCH"}:
            score += 0.2
        return score

    def rank(self, plugin: Dict[str, Any], request_def: Dict[str, Any], base_url: str) -> List[PathCandidate]:
        method = request_def.get("method", "GET").upper()
        candidates: List[PathCandidate] = []
        for raw_path in request_def.get("path", []):
            url = raw_path.replace("{{BaseURL}}", base_url.rstrip("/"))
            novelty = 1.0 if url not in self._visited else 0.2
            risk = self._risk_score(raw_path, method)
            cost = 0.2 if method == "GET" else 0.4
            score = 0.5 * novelty + 0.4 * risk - 0.2 * cost
            candidates.append(
                PathCandidate(
                    url=url,
                    method=method,
                    score=score,
                    source_plugin=plugin.get("id", "unknown"),
                )
            )

        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def mark_visited(self, url: str):
        self._visited.add(url)
