"""
scanner.engine.core
-------------------
核心扫描逻辑：遍历插件 -> 发送请求 -> 匹配漏洞。
"""
import httpx
import asyncio
from typing import Dict, List
from app.models.task import Vulnerability
from scanner.engine.parser import TemplateParser

class ScannerEngine:
    def __init__(self, target: str):
        self.target = target.rstrip("/")
        # 加载插件
        self.plugins = TemplateParser.load_plugins("/app/scanner/plugins")

    async def run(self) -> List[dict]:
        """执行扫描并返回发现的漏洞列表"""
        vulns = []
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            for plugin in self.plugins:
                for req in plugin.get("requests", []):
                    # 1. 替换变量
                    paths = req.get("path", [])
                    for p in paths:
                        url = p.replace("{{BaseURL}}", self.target)
                        method = req.get("method", "GET")
                        
                        try:
                            # 2. 发送请求
                            resp = await client.request(method, url)
                            
                            # 3. 匹配漏洞 (简单实现: 关键词匹配)
                            matchers = req.get("matchers", [])
                            if self._check_matchers(resp, matchers):
                                print(f"🚨 发现漏洞: {plugin['info']['name']} at {url}")
                                vulns.append({
                                    "vuln_name": plugin['info']['name'],
                                    "severity": plugin['info']['severity'],
                                    "url": url,
                                    "evidence": {
                                        "status": resp.status_code,
                                        "body_snippet": resp.text[:200]
                                    }
                                })
                        except Exception as e:
                            print(f"⚠️ 请求失败 {url}: {e}")
        return vulns

    def _check_matchers(self, resp, matchers) -> bool:
        """检查响应是否命中规则"""
        for m in matchers:
            if m.get("type") == "word":
                words = m.get("words", [])
                # 必须包含所有关键词
                content = resp.text if m.get("part") == "body" else str(resp.headers)
                if all(w in content for w in words):
                    return True
        return False
