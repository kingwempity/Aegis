"""
独立测试脚本 - 验证ThinkPHP SQL注入检测
运行方式: python test_scan.py
"""

import asyncio
import sys
import os

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.engine.core import ScannerEngine

async def test_scan():
    target = "http://47.114.88.90:8080/"
    
    print("=" * 60)
    print(f"🧪 测试扫描目标: {target}")
    print("=" * 60)
    
    engine = ScannerEngine(
        target=target,
        strategy="default",
        timeout=30.0,
        max_concurrent=5
    )
    
    print(f"\n📋 加载插件数量: {len(engine.plugins)}")
    print(f"📋 插件列表: {[p.get('id', 'unknown') for p in engine.plugins]}")
    
    if len(engine.plugins) == 0:
        print("\n❌ 未加载任何插件！请检查插件目录。")
        return
    
    # 检查thinkphp-sqli插件是否存在
    thinkphp_plugin = None
    for p in engine.plugins:
        if p.get('id') == 'thinkphp-sqli':
            thinkphp_plugin = p
            break
    
    if thinkphp_plugin:
        print(f"\n✅ 找到 thinkphp-sqli 插件")
        print(f"   请求定义数量: {len(thinkphp_plugin.get('requests', []))}")
    else:
        print("\n⚠️ 未找到 thinkphp-sqli 插件")
    
    print("\n🚀 开始执行扫描...")
    print("-" * 60)
    
    try:
        results = await engine.run()
        
        print("\n" + "=" * 60)
        print(f"📊 扫描完成")
        print(f"   发现漏洞数量: {len(results)}")
        print("=" * 60)
        
        for i, vuln in enumerate(results, 1):
            print(f"\n🔴 漏洞 {i}:")
            print(f"   名称: {vuln.get('vuln_name')}")
            print(f"   严重程度: {vuln.get('severity')}")
            print(f"   URL: {vuln.get('url')}")
            print(f"   Payload: {vuln.get('payload')}")
            
    except Exception as e:
        print(f"\n❌ 扫描异常: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_scan())
