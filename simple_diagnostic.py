"""
简化诊断脚本：不依赖模块导入，直接检查配置文件
运行方式：python simple_diagnostic.py
"""

import os
import sys
import re

def check_yaml_plugins():
    print("\n[1] 检查YAML插件文件")
    print("-" * 50)
    
    plugin_dir = "scanner/plugins/vulnerabilities"
    if not os.path.exists(plugin_dir):
        print(f"  ✗ 插件目录不存在: {plugin_dir}")
        return
    
    yaml_files = [f for f in os.listdir(plugin_dir) if f.endswith('.yaml')]
    print(f"  找到 {len(yaml_files)} 个插件文件:")
    
    for yaml_file in yaml_files:
        filepath = os.path.join(plugin_dir, yaml_file)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        plugin_id = re.search(r'^id:\s*(.+)$', content, re.MULTILINE)
        plugin_name = re.search(r'^\s+name:\s*(.+)$', content, re.MULTILINE)
        requires_tech = re.search(r'requires_tech:\s*\[(.+?)\]', content)
        has_negative = 'negative: true' in content
        matchers_condition = re.search(r'matchers-condition:\s*(\w+)', content)
        
        print(f"\n  {yaml_file}:")
        print(f"    - ID: {plugin_id.group(1) if plugin_id else 'N/A'}")
        print(f"    - 名称: {plugin_name.group(1) if plugin_name else 'N/A'}")
        print(f"    - requires_tech: {requires_tech.group(1) if requires_tech else '无'}")
        print(f"    - 包含负向匹配: {'是' if has_negative else '否'}")
        print(f"    - matchers-condition: {matchers_condition.group(1) if matchers_condition else '默认(or)'}")


def check_rules_config():
    print("\n[2] 检查规则引擎配置")
    print("-" * 50)
    
    rules_file = "scanner/engine/rules.py"
    if not os.path.exists(rules_file):
        print(f"  ✗ 规则文件不存在: {rules_file}")
        return
    
    with open(rules_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    min_conf_pattern = r'"([^"]+)":\s*DetectionRule\([^)]*min_confidence=([0-9.]+)'
    matches = re.findall(min_conf_pattern, content, re.DOTALL)
    
    print("  插件最低置信度配置:")
    for plugin_id, min_conf in matches:
        print(f"    - {plugin_id}: {min_conf}")
    
    req_evidence_pattern = r'"([^"]+)":\s*DetectionRule\([^)]*required_evidence_count=(\d+)'
    matches = re.findall(req_evidence_pattern, content, re.DOTALL)
    
    print("\n  插件所需证据数配置:")
    for plugin_id, count in matches:
        print(f"    - {plugin_id}: {count}")
    
    exclusion_pattern = r'"([^"]+)":\s*ExclusionRule\('
    matches = re.findall(exclusion_pattern, content)
    
    print(f"\n  跨框架排除规则: {len(matches)} 个")
    for rule_id in matches:
        print(f"    - {rule_id}")


def check_core_judgment_logic():
    print("\n[3] 检查核心判定逻辑")
    print("-" * 50)
    
    core_file = "scanner/engine/core.py"
    if not os.path.exists(core_file):
        print(f"  ✗ 核心文件不存在: {core_file}")
        return
    
    with open(core_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ("rule_min_confidence", "最低置信度检查"),
        ("rule_required_evidence", "证据数检查"),
        ("validate_vulnerability", "漏洞验证"),
        ("should_exclude", "跨框架排除"),
        ("adjust_confidence", "置信度调整"),
        ("_count_evidence", "证据计数"),
        ("_extract_matched_keywords", "关键词提取"),
    ]
    
    for keyword, desc in checks:
        if keyword in content:
            print(f"  ✓ {desc} ({keyword})")
        else:
            print(f"  ✗ {desc} ({keyword}) 缺失")
    
    if "final_report = False" in content:
        print("\n  ✓ 包含最终判定逻辑")
    else:
        print("\n  ✗ 缺少最终判定逻辑")
    
    if "cross_framework_exclusion" in content.lower():
        print("  ✓ 包含跨框架排除逻辑")
    else:
        print("  ✗ 缺少跨框架排除逻辑")


def analyze_thinkphp_plugin():
    print("\n[4] 分析ThinkPHP插件配置")
    print("-" * 50)
    
    thinkphp_file = "scanner/plugins/vulnerabilities/thinkphp-sqli.yaml"
    if not os.path.exists(thinkphp_file):
        print(f"  ✗ 文件不存在: {thinkphp_file}")
        return
    
    with open(thinkphp_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print("  关键配置分析:")
    
    if 'negative: true' in content:
        print("  ✓ 包含负向匹配 (排除Drupal特征)")
        negative_count = content.count('negative: true')
        print(f"    - 负向匹配数量: {negative_count}")
    else:
        print("  ✗ 缺少负向匹配")
    
    if 'matchers-condition: and' in content:
        print("  ✓ 使用 AND 条件 (更严格)")
    else:
        print("  ⚠ 使用 OR 条件 (可能过于宽松)")
    
    drupal_keywords = ['Drupal.settings', 'form_build_id', 'X-Generator: Drupal']
    found = [kw for kw in drupal_keywords if kw in content]
    if found:
        print(f"  ✓ 包含Drupal排除关键词: {found}")
    else:
        print("  ✗ 缺少Drupal排除关键词")


def analyze_other_plugins():
    print("\n[5] 分析其他插件配置")
    print("-" * 50)
    
    plugins = [
        ("scanner/plugins/vulnerabilities/xss-reflected.yaml", "XSS反射型"),
        ("scanner/plugins/vulnerabilities/sqli-probe.yaml", "SQL注入探测"),
        ("scanner/plugins/vulnerabilities/git-config.yaml", "Git配置泄露"),
        ("scanner/plugins/vulnerabilities/drupal-cve-2019-6341.yaml", "Drupal XSS"),
    ]
    
    for filepath, name in plugins:
        if not os.path.exists(filepath):
            print(f"  ✗ {name}: 文件不存在")
            continue
        
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        has_matchers = 'matchers:' in content
        has_payload = 'payload_sets:' in content or 'payload:' in content
        requires_tech = re.search(r'requires_tech:\s*\[(.+?)\]', content)
        
        status = "✓" if has_matchers else "✗"
        print(f"  {status} {name}:")
        print(f"      - 匹配器: {'有' if has_matchers else '无'}")
        print(f"      - Payload: {'有' if has_payload else '无'}")
        print(f"      - requires_tech: {requires_tech.group(1) if requires_tech else '无'}")


def check_potential_issues():
    print("\n[6] 潜在问题分析")
    print("-" * 50)
    
    issues = []
    
    rules_file = "scanner/engine/rules.py"
    if os.path.exists(rules_file):
        with open(rules_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '"xss-reflected"' not in content:
            issues.append("xss-reflected 插件未在规则引擎中配置，将使用默认阈值 0.15")
        
        if '"sqli-probe"' not in content:
            issues.append("sqli-probe 插件未在规则引擎中配置，将使用默认阈值 0.15")
        
        if '"git-config-leak"' not in content and '"git-config"' not in content:
            issues.append("git-config 插件未在规则引擎中配置，将使用默认阈值 0.15")
    
    core_file = "scanner/engine/core.py"
    if os.path.exists(core_file):
        with open(core_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if "rule_required_evidence" in content and "> 1" in content:
            issues.append("证据数要求 > 1 可能导致部分插件无法报告漏洞")
    
    if issues:
        for issue in issues:
            print(f"  ⚠ {issue}")
    else:
        print("  ✓ 未发现明显问题")


def main():
    print("=" * 70)
    print("Aegis 漏洞扫描判定逻辑诊断报告 (简化版)")
    print("=" * 70)
    
    check_yaml_plugins()
    check_rules_config()
    check_core_judgment_logic()
    analyze_thinkphp_plugin()
    analyze_other_plugins()
    check_potential_issues()
    
    print("\n" + "=" * 70)
    print("诊断完成")
    print("=" * 70)
    
    print("\n建议:")
    print("1. 确保所有插件都在规则引擎中有配置")
    print("2. 检查证据数要求是否过高")
    print("3. 确认置信度阈值是否合理")


if __name__ == "__main__":
    main()
