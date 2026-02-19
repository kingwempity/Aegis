"""
scanner.engine.core
-------------------
核心扫描逻辑：遍历插件 -> 生成攻击脚本 -> 路径优先调度 -> 发送请求 -> 匹配漏洞。
"""

import os
import httpx
from typing import List, Dict, Any

from scanner.engine.attack import AttackScriptGenerator, AttackPathExplorer
from scanner.engine.parser import TemplateParser


class ScannerEngine:
    def __init__(self, target: str, strategy: str = "default", plugin_dir: str = "/app/scanner/plugins"):
        self.target = target.rstrip("/")
        self.strategy = strategy
        resolved_plugin_dir = plugin_dir
        if not os.path.exists(resolved_plugin_dir):
            resolved_plugin_dir = os.path.join(os.getcwd(), "scanner", "plugins")
        self.plugins = TemplateParser.load_plugins(resolved_plugin_dir)
        self.script_generator = AttackScriptGenerator(strategy=strategy)
        self.path_explorer = AttackPathExplorer()

    async def run(self) -> List[dict]:
        """执行扫描并返回发现的漏洞列表"""
        vulns: List[dict] = []
        # Keep redirects disabled so scans stay on the requested endpoint/scope
        # and matcher evaluation uses the original response.
        async with httpx.AsyncClient(verify=False, timeout=10.0, follow_redirects=False) as client:
            for plugin in self.plugins:
                for req in plugin.get("requests", []):
                    if not self._check_preconditions(req):
                        continue

                    payloads = self.script_generator.build_payloads(plugin, req)
                    ranked_paths = self.path_explorer.rank(plugin, req, self.target)

                    for path in ranked_paths:
                        for payload in payloads:
                            url = self.script_generator.render_path(path.url, self.target, payload)
                            method = req.get("method", "GET")

                            try:
                                resp = await client.request(method, url)
                                self.path_explorer.mark_visited(path.url)

                                matchers = req.get("matchers", [])
                                if self._check_matchers(resp, matchers):
                                    vuln_info = plugin.get("info", {})
                                    vulns.append(
                                        {
                                            "vuln_name": vuln_info.get("name", plugin.get("id", "unknown")),
                                            "severity": vuln_info.get("severity", "Info"),
                                            "url": url,
                                            "payload": payload,
                                            "evidence": {
                                                "request": {
                                                    "method": method.upper(),
                                                    "url": url,
                                                    "payload": payload,
                                                },
                                                "response": {
                                                    "status": resp.status_code,
                                                    "headers": dict(resp.headers),
                                                    "body_snippet": resp.text[:500],
                                                },
                                                "matchers": matchers,
                                            },
                                        }
                                    )
                            except Exception as e:
                                print(f"⚠️ 请求失败 {url}: {e}")
        return vulns

    def _check_preconditions(self, req: Dict[str, Any]) -> bool:
        """模板前置条件校验（基础实现，可扩展）"""
        pre = req.get("preconditions")
        if not pre:
            return True

        allowed_methods = pre.get("methods") if isinstance(pre, dict) else None
        if allowed_methods and req.get("method", "GET").upper() not in {m.upper() for m in allowed_methods}:
            return False
        return True

    def _check_matchers(self, resp: httpx.Response, matchers: List[Dict[str, Any]]) -> bool:
        """检查响应是否命中规则。支持 word/status/regex。"""
        if not matchers:
            return False

        for m in matchers:
            mtype = m.get("type")
            if mtype == "word":
                words = m.get("words", [])
                content = resp.text if m.get("part", "body") == "body" else str(resp.headers)
                if all(w in content for w in words):
                    return True

            elif mtype == "status":
                statuses = m.get("status", [])
                if resp.status_code in statuses:
                    return True

            elif mtype == "regex":
                import re

                patterns = m.get("regex", [])
                content = resp.text if m.get("part", "body") == "body" else str(resp.headers)
                if all(re.search(p, content) for p in patterns):
                    return True

        return False
