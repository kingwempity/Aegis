"""
Django CVE-2017-12794 检测修复验证脚本
运行方式: python test_django_cve_fix.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_django_plugin_execution():
    """测试 Django CVE 插件是否能通过框架门控"""
    print("=" * 70)
    print("🔍 Django CVE-2017-12794 插件执行权限测试")
    print("=" * 70)

    try:
        from scanner.engine.rules import RuleEngine, FrameworkType, DETECTION_RULES

        engine = RuleEngine()

        # 测试场景1：未知框架（最常见情况）
        print("\n[场景1] 目标框架为 UNKNOWN（初始探测未识别）")
        print("-" * 50)
        can_exec, reason = engine.should_execute_plugin(
            plugin_id="django-cve-2017-12794",
            detected_frameworks=[FrameworkType.UNKNOWN],
            request_paths=[
                "{{BaseURL}}/create_user/?username=%3Cscript%3Eaegis_cve_12794%3C%2Fscript%3E",
                "{{BaseURL}}/create_user/?username=%3Cscript%3Eaegis_cve_12794%3C%2Fscript%3E",
            ],
        )
        print(f"  执行结果: {'✅ 允许' if can_exec else '❌ 拒绝'}")
        print(f"  原因: {reason}")
        assert can_exec, f"❌ 测试失败：未知框架时应该允许执行，但实际拒绝了: {reason}"

        # 测试场景2：检测到 ThinkPHP（框架不匹配）
        print("\n[场景2] 目标框架为 THINKPHP（框架不匹配但路径匹配）")
        print("-" * 50)
        can_exec, reason = engine.should_execute_plugin(
            plugin_id="django-cve-2017-12794",
            detected_frameworks=[FrameworkType.THINKPHP],
            request_paths=[
                "{{BaseURL}}/create_user/?username=test",
            ],
        )
        print(f"  执行结果: {'✅ 允许' if can_exec else '❌ 拒绝'}")
        print(f"  原因: {reason}")
        assert can_exec, f"❌ 测试失败：路径匹配时应允许执行，但实际拒绝了: {reason}"

        # 测试场景3：检测到 Django（完美匹配）
        print("\n[场景3] 目标框架为 DJANGO（完美匹配）")
        print("-" * 50)
        can_exec, reason = engine.should_execute_plugin(
            plugin_id="django-cve-2017-12794",
            detected_frameworks=[FrameworkType.DJANGO],
            request_paths=["{{BaseURL}}/create_user/"],
        )
        print(f"  执行结果: {'✅ 允许' if can_exec else '❌ 拒绝'}")
        print(f"  原因: {reason}")
        assert can_exec, f"❌ 测试失败：框架匹配时应允许执行，但实际拒绝了: {reason}"

        # 测试场景4：检测到 Drupal（框架和路径都不匹配）
        print("\n[场景4] 目标框架为 DRUPAL 且路径不匹配（应拒绝）")
        print("-" * 50)
        can_exec, reason = engine.should_execute_plugin(
            plugin_id="django-cve-2017-12794",
            detected_frameworks=[FrameworkType.DRUPAL],
            request_paths=["{{BaseURL}}/node/add"],
        )
        print(f"  执行结果: {'❌ 拒绝' if not can_exec else '✅ 允许'}")
        print(f"  原因: {reason}")
        assert not can_exec, "⚠️ 注意：此场景应拒绝（正常行为）"

        print("\n[场景5] 验证规则配置参数")
        print("-" * 50)
        rule = DETECTION_RULES.get("django-cve-2017-12794")
        if rule:
            print(f"  validation_level: {rule.validation_level.name} (期望: MODERATE)")
            print(f"  min_confidence: {rule.min_confidence} (期望: 0.30)")
            print(f"  required_evidence_count: {rule.required_evidence_count} (期望: 2)")
            print(f"  allow_when_framework_unknown: {rule.allow_when_framework_unknown} (期望: True)")
            print(f"  required_path_patterns: {rule.required_path_patterns}")
            assert rule.validation_level.name == "MODERATE", "❌ validation_level 应为 MODERATE"
            assert rule.min_confidence == 0.30, "❌ min_confidence 应为 0.30"
            assert rule.required_evidence_count == 2, "❌ required_evidence_count 应为 2"

        print("\n✅ 所有测试通过！Django CVE-2017-12794 插件现在应该能正确执行。")

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True


def test_django_framework_detection():
    """测试 Django 框架特征是否已添加"""
    print("\n\n" + "=" * 70)
    print("🔍 Django 框架特征签名测试")
    print("=" * 70)

    try:
        from scanner.engine.rules import FRAMEWORK_SIGNATURES, FrameworkType

        django_sig = FRAMEWORK_SIGNATURES.get(FrameworkType.DJANGO)

        if not django_sig:
            print("❌ 未找到 DJANGO 框架签名！")
            return False

        print(f"\n  ✅ Django 框架签名已添加")
        print(f"  - body_patterns 数量: {len(django_sig.body_patterns)}")
        print(f"  - url_patterns 数量: {len(django_sig.url_patterns)}")
        print(f"  - exclusive_signatures 数量: {len(django_sig.exclusive_signatures)}")

        # 测试关键特征是否包含
        critical_patterns = [
            r"csrfmiddlewaretoken",
            r"Exception Type",
            r"Traceback \(most recent call last\)",
            r"DEBUG = True",
        ]

        print(f"\n  关键特征检查:")
        for pattern in critical_patterns:
            found = pattern in django_sig.body_patterns or pattern in django_sig.exclusive_signatures
            status = "✅" if found else "❌"
            print(f"    {status} {pattern}")

        return True

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_drupal_plugin_execution():
    """测试 Drupal CVE 插件执行权限（附带验证）"""
    print("\n\n" + "=" * 70)
    print("🔍 Drupal CVE-2019-6341 插件执行权限测试")
    print("=" * 70)

    try:
        from scanner.engine.rules import RuleEngine, FrameworkType, DETECTION_RULES

        engine = RuleEngine()

        # 测试：未知框架 + 路径匹配
        print("\n[场景] 未知框架 + 路径包含 /user/register")
        print("-" * 50)
        can_exec, reason = engine.should_execute_plugin(
            plugin_id="drupal-cve-2019-6341",
            detected_frameworks=[FrameworkType.UNKNOWN],
            request_paths=[
                "{{BaseURL}}/user/register",
                "{{BaseURL}}/?q=user/register",
                "{{BaseURL}}/",
            ],
        )
        print(f"  执行结果: {'✅ 允许' if can_exec else '❌ 拒绝'}")
        print(f"  原因: {reason}")

        # 验证规则配置
        rule = DETECTION_RULES.get("drupal-cve-2019-6341")
        if rule:
            print(f"\n  规则配置:")
            print(f"    validation_level: {rule.validation_level.name}")
            print(f"    min_confidence: {rule.min_confidence}")
            print(f"    required_evidence_count: {rule.required_evidence_count}")
            print(f"    required_path_patterns: {rule.required_path_patterns}")

        return True

    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n" + "🚀" * 35)
    print("Aegis Django/Drupal CVE 检测修复验证工具")
    print("🚀" * 35)

    results = []

    results.append(("Django插件执行权限", test_django_plugin_execution()))
    results.append(("Django框架特征签名", test_django_framework_detection()))
    results.append(("Drupal插件执行权限", test_drupal_plugin_execution()))

    print("\n\n" + "=" * 70)
    print("📊 测试结果汇总")
    print("=" * 70)

    all_passed = True
    for name, passed in results:
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"  {status}: {name}")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n🎉 所有测试通过！现在可以重新扫描 vulhub 靶场了。")
        print("\n建议操作:")
        print("  1. 重启 Aegis 扫描器")
        print("  2. 指向 Django/CVE-2017-12794 靶场")
        print("  3. 观察日志中是否出现:")
        print("     - '✅ 允许: ... 探测模式'")
        print("     - 'GET /create_user/?username=...'")
        print("     - '确认漏洞 [xxx%]: Django DEBUG 页面 XSS'")
        sys.exit(0)
    else:
        print("\n❌ 部分测试失败，请检查上方错误信息。")
        sys.exit(1)
