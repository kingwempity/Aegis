#!/usr/bin/env python3
"""
VULHUB 靶场快速测试脚本
用法: python3 quick_test_vulhub.py
"""

import asyncio
import sys
import os
import logging

# 设置项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('vulhub_scan.log', encoding='utf-8')
    ]
)

async def main():
    target = "http://47.114.88.90:8080"
    
    print("\n" + "="*60)
    print("🎯 VULHUB ThinkPHP SQL 注入漏洞扫描测试")
    print(f"📡 目标: {target}")
    print("="*60 + "\n")
    
    from scanner.engine.core import ScannerEngine
    
    engine = ScannerEngine(
        target=target,
        strategy="aggressive",
        max_concurrent=5,
        timeout=15.0
    )
    
    print("🚀 开始扫描...\n")
    results = await engine.run()
    
    print("\n" + "="*60)
    print("📊 扫描结果")
    print("="*60)
    
    if results:
        print(f"\n✅ 发现 {len(results)} 个漏洞:\n")
        for idx, vuln in enumerate(results, 1):
            print(f"🔴 漏洞 {idx}:")
            print(f"   名称: {vuln.get('vuln_name', 'Unknown')}")
            print(f"   严重: {vuln.get('severity', 'Unknown')}")
            print(f"   URL: {vuln.get('url', 'N/A')}")
            print(f"   Payload: {vuln.get('payload', 'N/A')[:80]}")
            print()
    else:
        print("\n❌ 未发现任何漏洞")
        print("\n可能原因:")
        print("  1. 靶场未启动")
        print("  2. 框架识别失败")
        print("  3. 验证规则过滤")
        
        fw = engine.get_framework_detection_result()
        print(f"\n📋 框架检测: {fw.get('detected_frameworks', [])}")
        print(f"📋 置信度: {fw.get('framework_confidence', {})}")
    
    print("="*60)
    print(f"📄 详细日志: vulhub_scan.log")
    print("="*60 + "\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断")
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
