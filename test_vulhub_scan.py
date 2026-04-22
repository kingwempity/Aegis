#!/usr/bin/env python3
"""
Vulhub靶场扫描测试脚本
用于Aegis系统扫描宝塔部署的Vulhub真实漏洞环境

使用方法：
1. 确保Vulhub靶场已启动并在aegis-shared-net网络中
2. 在Docker容器内运行：
   docker exec -it aegis-api python /app/test_vulhub_scan.py <靶场URL>

示例：
# Vulhub ThinkPHP 5.x SQL注入
docker exec -it aegis-api python /app/test_vulhub_scan.py http://thinkphp:8080

# Vulhub Drupal CVE-2019-6341
docker exec -it aegis-api python /app/test_vulhub_scan.py http://drupal:8080
"""
import sys
import os
import asyncio
import json
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'BE'))

from scanner.engine.core import ScannerEngine


def print_vulhub_banner(target_url):
    """打印Vulhub扫描横幅"""
    print("\n" + "=" * 70)
    print("🎯 Aegis x Vulhub - 真实漏洞环境扫描测试")
    print("=" * 70)
    print(f"⏰ 测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🎯 靶场地址: {target_url}")
    print(f"🌐 靶场类型: Vulhub (真实漏洞环境)")
    print()


async def scan_vulhub_target(target_url):
    """扫描Vulhub目标"""
    print("📋 开始初始化扫描引擎...")
    print("-" * 70)
    
    # 使用默认策略（适合真实漏洞环境）
    engine = ScannerEngine(
        target=target_url,
        strategy="default",
        enable_learning=False,
        enable_discovery=True,
        max_concurrent=8,
        timeout=15.0,
        max_depth=3
    )
    
    # 显示插件信息
    plugin_ids = [p.get('id', 'unknown') for p in engine.plugins]
    print(f"\n📦 已加载 {len(engine.plugins)} 个漏洞检测插件:")
    
    # 分类显示插件
    sqli_plugins = [p for p in plugin_ids if 'sqli' in p.lower()]
    xss_plugins = [p for p in plugin_ids if 'xss' in p.lower()]
    other_plugins = [p for p in plugin_ids if p not in sqli_plugins and p not in xss_plugins]
    
    if sqli_plugins:
        print(f"\n   🔴 SQL注入类 ({len(sqli_plugins)}个):")
        for p in sqli_plugins:
            print(f"      • {p}")
    
    if xss_plugins:
        print(f"\n   🟠 XSS跨站脚本 ({len(xss_plugins)}个):")
        for p in xss_plugins:
            print(f"      • {p}")
    
    if other_plugins:
        print(f"\n   🟡 其他漏洞 ({len(other_plugins)}个):")
        for p in other_plugins:
            print(f"      • {p}")
    
    print()
    print("=" * 70)
    print("⏳ 开始扫描Vulhub靶场...")
    print("(真实漏洞环境可能需要15-60秒，请耐心等待)")
    print()
    
    try:
        results = await engine.run()
        
        # 输出详细结果
        print("\n" + "=" * 70)
        print("📊 扫描结果报告")
        print("=" * 70)
        
        stats = engine._stats.to_dict()
        
        print(f"\n📈 扫描统计:")
        print(f"   • 总请求数: {stats['total_requests']}")
        print(f"   • 成功请求: {stats['successful_requests']}")
        print(f"   • 失败请求: {stats['failed_requests']}")
        print(f"   • 发现路径: {stats['paths_discovered']}")
        print(f"   • 扫描耗时: {stats['duration']:.2f}秒")
        
        print(f"\n🔍 框架识别:")
        fw_result = engine.get_framework_detection_result()
        frameworks = fw_result.get('detected_frameworks', ['unknown'])
        confidences = fw_result.get('framework_confidence', {})
        versions = fw_result.get('framework_versions', {})
        
        if frameworks and frameworks != ['unknown']:
            print(f"   ✅ 检测到框架: {', '.join(frameworks)}")
            for fw in frameworks:
                if fw != 'unknown':
                    ver = versions.get(fw, 'unknown')
                    conf = confidences.get(fw, 0)
                    print(f"      └─ {fw}: 版本={ver}, 置信度={conf:.1%}")
        else:
            print(f"   ⚠️  未识别出特定框架（将使用通用检测）")
        
        print(f"\n{'═' * 70}")
        print(f"🎯 漏洞发现结果")
        print(f"{'═' * 70}\n")
        
        if results:
            print(f"🎉 成功发现 {len(results)} 个漏洞！\n")
            
            for i, vuln in enumerate(results, 1):
                print(f"{'─' * 70}")
                print(f"📌 漏洞 #{i}: {vuln.get('vuln_name', 'Unknown Vulnerability')}")
                
                severity = vuln.get('severity', 'Medium')
                severity_icon = {'Critical': '☢️', 'High': '🔴', 'Medium': '🟠', 'Low': '🔵', 'Info': '⚪'}
                print(f"   严重程度: {severity_icon.get(severity, '⚪')} {severity}")
                
                print(f"   目标URL:   {vuln.get('url', 'N/A')}")
                print(f"   请求方法:  {vuln.get('request', {}).get('method', 'GET')}")
                
                payload = vuln.get('payload', 'N/A')
                if len(payload) > 80:
                    payload = payload[:80] + "..."
                print(f"   Payload:   {payload}")
                
                evidence = vuln.get('evidence', {})
                confidence = evidence.get('confidence', 0)
                
                confidence_bar = '█' * int(confidence * 20) + '░' * (20 - int(confidence * 20))
                print(f"   置信度:    [{confidence_bar}] {confidence:.1%}")
                
                matched_keywords = evidence.get('matched_keywords', [])
                if matched_keywords:
                    keywords_str = ', '.join(matched_keywords[:6])
                    if len(matched_keywords) > 6:
                        keywords_str += f" (+{len(matched_keywords)-6}更多)"
                    print(f"   匹配特征:  {keywords_str}")
                
                response = vuln.get('response', {})
                status_code = response.get('status', 'N/A')
                resp_time = response.get('response_time_ms', 0)
                print(f"   响应状态:  HTTP {status_code}")
                print(f"   响应时间:  {resp_time:.0f}ms")
                
                validation_log = vuln.get('validation_log', {})
                attack_status = validation_log.get('attack_status', 'N/A')
                print(f"   攻击状态:  {attack_status}")
                
                attack_path = vuln.get('attack_path', {})
                steps = attack_path.get('steps', [])
                if steps:
                    print(f"   攻击链:    包含 {len(steps)} 个步骤")
                
                print()
            
            print(f"{'═' * 70}")
            print("✅ 扫描完成！成功检测到真实漏洞。")
            print("\n💡 分析结论:")
            print("   • 靶场存在可利用的安全漏洞")
            print("   • Aegis系统正常工作，能够识别真实漏洞特征")
            print("   • 建议查看上述漏洞详情并验证利用可行性")
            
            return True
            
        else:
            print("❌ 未发现任何漏洞\n")
            print("可能的原因分析:\n")
            
            print("1️⃣  靶场类型不匹配")
            print("   当前插件主要支持: ThinkPHP/Drupal/Django/通用SQL注入/XSS等")
            print("   如果是其他类型漏洞（如Struts2、Spring等），需要添加对应插件\n")
            
            print("2️⃣  漏洞未被触发")
            print("   • 确认靶场的漏洞点是否正确（如特定的URL路径或参数）")
            print("   • 某些CVE需要特定的前提条件才能触发\n")
            
            print("3️⃣  网络或配置问题")
            print("   • 确认容器间网络连通性")
            print("   • 检查防火墙规则是否阻止了请求\n")
            
            # 显示调试信息
            judgment_log = engine.get_judgment_log()
            if judgment_log:
                print("📝 最近判定日志 (帮助调试):\n")
                recent_logs = judgment_log[-10:] if len(judgment_log) > 10 else judgment_log
                
                skipped_count = 0
                executed_count = 0
                
                for log in recent_logs:
                    phase = log.get('phase', '')
                    plugin_id = log.get('plugin_id', '')
                    action = log.get('action', '')
                    result_status = log.get('result', '')
                    
                    if result_status == 'skip':
                        skipped_count += 1
                        details = log.get('details', {})
                        reason = details.get('reason', '')
                        print(f"   ⏭️  跳过 [{plugin_id}]: {reason}")
                    else:
                        executed_count += 1
                        if result_status == 'report':
                            print(f"   ✅ 发现 [{plugin_id}]")
                        elif result_status == 'suppress':
                            details = log.get('details', {})
                            reason = details.get('final_reason', details.get('suppressed_reason', ''))
                            print(f"   🚫 过滤 [{plugin_id}]: {reason}")
                
                print(f"\n   统计: 执行{executed_count}次, 跳过{skipped_count}次")
            
            return False
            
    except Exception as e:
        print(f"\n❌ 扫描过程出错: {e}")
        print("\n调试建议:")
        print("1. 检查靶场URL是否正确且可从容器内部访问")
        print("2. 确认Vulhub容器正在运行: docker ps | grep vulhub")
        print("3. 测试网络连通性: docker exec aegis-api curl <target_url>")
        print("4. 查看完整错误堆栈信息:")
        import traceback
        traceback.print_exc()
        return False


def print_vulhub_summary(success, target_url):
    """打印总结"""
    print("\n" + "=" * 70)
    print("📋 Vulhub扫描总结")
    print("=" * 70)
    
    print(f"\n🎯 目标: {target_url}")
    print(f"✅ 结果: {'成功检测到漏洞' if success else '未发现漏洞'}")
    
    if success:
        print("\n🎊 好消息！")
        print("• Aegis系统能够检测Vulhub真实漏洞环境中的安全漏洞")
        print("• 规则引擎工作正常，能够识别真实的漏洞特征")
        print("• LLM辅助模块可用于进一步分析和决策优化")
        print("\n下一步建议:")
        print("1. 通过前端界面创建正式扫描任务")
        print("2. 尝试不同的扫描策略（aggressive/stealthy）")
        print("3. 生成详细的漏洞报告（PDF/HTML）")
        print("4. 尝试更多Vulhub漏洞场景进行测试")
    else:
        print("\n⚠️  需要进一步排查:")
        print("1. 确认使用的Vulhub场景类型")
        print("2. 检查靶场是否完全启动并可用")
        print("3. 手动确认漏洞点的URL和参数")
        print("4. 查看上方的判定日志了解详情")
        print("\n常见Vulhub场景与对应插件:")
        print("• thinkphp/tcplist → thinkphp-sqli.yaml ✅")
        print("• drupal/CVE-2019-6341 → drupal-cve-2019-6341.yaml ✅")
        print("• django/CVE-2017-12794 → django-cve-2017-12794.yaml ✅")
        print("• 通用SQL注入场景 → sqli-probe.yaml ✅")
        print("• XSS漏洞场景 → xss-reflected.yaml ✅")
    
    print("\n" + "=" * 70 + "\n")


def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("❌ 错误：未指定靶场URL")
        print("\n使用方法:")
        print("  python test_vulhub_scan.py <靶场URL>")
        print("\n示例:")
        print("  docker exec -it aegis-api python /app/test_vulhub_scan.py http://thinkphp:8080")
        print("  docker exec -it aegis-api python /app/test_vulhub_scan.py http://192.168.1.100:8080")
        print("\n支持的Vulhub场景:")
        print("  • ThinkPHP 5.x SQL注入")
        print("  • Drupal CVE-2019-6341 远程代码执行")
        print("  • Django CVE-2017-12794 调试页面泄露")
        print("  • 通用SQL注入/XSS/路径遍历等")
        sys.exit(1)
    
    target_url = sys.argv[1]
    
    print_vulhub_banner(target_url)
    
    success = asyncio.run(scan_vulhub_target(target_url))
    
    print_vulhub_summary(success, target_url)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  用户中断扫描")
        sys.exit(130)
