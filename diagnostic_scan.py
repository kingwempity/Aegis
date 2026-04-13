"""
诊断脚本：检查漏洞扫描判定逻辑
运行方式：python diagnostic_scan.py
"""

import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def diagnose():
    print("=" * 70)
    print("Aegis 漏洞扫描判定逻辑诊断报告")
    print("=" * 70)
    
    print("\n[1] 检查规则引擎配置")
    print("-" * 50)
    try:
        from scanner.engine.rules import RuleEngine, DETECTION_RULES, FrameworkType
        
        engine = RuleEngine()
        
        test_plugins = ["thinkphp-sqli", "drupal-cve-2019-6341", "xss-reflected", "sqli-probe", "git-config-leak"]
        
        for plugin_id in test_plugins:
            min_conf = engine.get_min_confidence(plugin_id)
            req_evidence = engine.get_required_evidence_count(plugin_id)
            is_valid, reason = engine.validate_vulnerability(
                plugin_id=plugin_id,
                detected_frameworks=[],
                response_body="test",
                response_headers={},
                request_url="http://test.com",
            )
            print(f"  {plugin_id}:")
            print(f"    - 最低置信度: {min_conf}")
            print(f"    - 所需证据数: {req_evidence}")
            print(f"    - 默认验证: {is_valid} ({reason})")
        
        print("\n  ✓ 规则引擎加载成功")
    except Exception as e:
        print(f"  ✗ 规则引擎加载失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[2] 检查Payload生成")
    print("-" * 50)
    try:
        from scanner.engine.attack import AttackScriptGenerator
        
        generator = AttackScriptGenerator(strategy="default")
        
        test_cases = [
            {"id": "xss-reflected", "info": {"tags": ["xss"]}, "requests": [{"payload_sets": {"default": ["<script>alert(1)</script>"]}}]},
            {"id": "sqli-probe", "info": {"tags": ["sqli"]}, "requests": [{"payload_sets": {"default": ["' OR '1'='1"]}}]},
            {"id": "git-config-leak", "info": {"tags": ["disclosure"]}},
        ]
        
        for plugin in test_cases:
            plugin_id = plugin.get("id")
            request_def = plugin.get("requests", [{}])[0] if "requests" in plugin else {}
            if "payload_sets" in plugin:
                request_def["payload_sets"] = plugin["payload_sets"]
            
            payloads = generator.build_payloads(plugin, request_def)
            print(f"  {plugin_id}:")
            print(f"    - 生成Payload数量: {len(payloads)}")
            if payloads:
                for i, p in enumerate(payloads[:2]):
                    print(f"    - Payload {i+1}: {p.encoded[:50]}...")
        
        print("\n  ✓ Payload生成正常")
    except Exception as e:
        print(f"  ✗ Payload生成失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[3] 检查插件加载")
    print("-" * 50)
    try:
        from scanner.engine.parser import TemplateParser
        
        plugin_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner", "plugins")
        if not os.path.exists(plugin_dir):
            plugin_dir = "/app/scanner/plugins"
        
        plugins = TemplateParser.load_plugins(plugin_dir)
        print(f"  加载的插件数量: {len(plugins)}")
        for p in plugins:
            plugin_id = p.get("id", "unknown")
            requests = p.get("requests", [])
            print(f"    - {plugin_id}: {len(requests)} 个请求定义")
        
        print("\n  ✓ 插件加载正常")
    except Exception as e:
        print(f"  ✗ 插件加载失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[4] 检查置信度计算")
    print("-" * 50)
    try:
        from scanner.engine.rules import RuleEngine, FrameworkType
        
        engine = RuleEngine()
        
        test_cases = [
            {
                "name": "XSS响应 (未知插件)",
                "plugin_id": "xss-reflected",
                "body": "<html><body><script>alert(1)</script></body></html>",
                "headers": {"Content-Type": "text/html"},
                "frameworks": [],
            },
            {
                "name": "SQL错误响应 (未知插件)",
                "plugin_id": "sqli-probe",
                "body": "SQLSTATE[42000]: Syntax error",
                "headers": {},
                "frameworks": [],
            },
            {
                "name": "ThinkPHP SQL注入 (ThinkPHP站点)",
                "plugin_id": "thinkphp-sqli",
                "body": "XPATH syntax error: root@localhost",
                "headers": {"X-Powered-By": "ThinkPHP/5.0"},
                "frameworks": [FrameworkType.THINKPHP],
            },
            {
                "name": "ThinkPHP SQL注入 (Drupal站点)",
                "plugin_id": "thinkphp-sqli",
                "body": "SQLSTATE[42000] Drupal.settings",
                "headers": {"X-Generator": "Drupal 8"},
                "frameworks": [FrameworkType.DRUPAL],
            },
        ]
        
        for case in test_cases:
            adjusted, details = engine.adjust_confidence(
                plugin_id=case["plugin_id"],
                base_confidence=0.3,
                detected_frameworks=case["frameworks"],
                response_body=case["body"],
                response_headers=case["headers"],
            )
            is_valid, reason = engine.validate_vulnerability(
                plugin_id=case["plugin_id"],
                detected_frameworks=case["frameworks"],
                response_body=case["body"],
                response_headers=case["headers"],
                request_url="http://test.com",
            )
            min_conf = engine.get_min_confidence(case["plugin_id"])
            
            print(f"  {case['name']}:")
            print(f"    - 基础置信度: 0.3")
            print(f"    - 调整后置信度: {adjusted:.3f}")
            print(f"    - 最低置信度要求: {min_conf}")
            print(f"    - 验证结果: {'通过' if is_valid else '拒绝'} ({reason})")
            print(f"    - 最终判定: {'报告' if is_valid and adjusted >= min_conf else '过滤'}")
        
        print("\n  ✓ 置信度计算正常")
    except Exception as e:
        print(f"  ✗ 置信度计算失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n[5] 检查核心扫描引擎")
    print("-" * 50)
    try:
        from scanner.engine.core import ScannerEngine
        
        print("  ScannerEngine 类加载成功")
        
        required_methods = [
            "_scan_with_plugin",
            "_check_matchers",
            "_calculate_confidence",
            "_count_evidence",
            "_extract_matched_keywords",
            "_log_judgment",
            "get_judgment_log",
            "get_framework_detection_result",
        ]
        
        for method in required_methods:
            if hasattr(ScannerEngine, method):
                print(f"    ✓ {method}")
            else:
                print(f"    ✗ {method} 缺失")
        
        print("\n  ✓ 核心扫描引擎正常")
    except Exception as e:
        print(f"  ✗ 核心扫描引擎加载失败: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 70)
    print("诊断完成")
    print("=" * 70)


if __name__ == "__main__":
    diagnose()
