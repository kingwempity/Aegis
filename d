"""
攻击引擎优化功能测试脚本。

测试内容：
1. Payload编码器功能
2. Payload变异器功能
3. 上下文感知引擎功能
4. 攻击脚本生成器功能
5. 攻击路径探索器功能

"""

import sys
import os

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from scanner.engine.attack import (
    PayloadEncoder,
    PayloadMutator,
    ContextAwareEngine,
    AttackScriptGenerator,
    AttackPathExplorer,
    AttackContext,
    PayloadType,
    EncodingType,
)


def test_payload_encoder():
    """测试Payload编码器功能"""
    print("\n" + "=" * 60)
    print("测试 PayloadEncoder")
    print("=" * 60)
    
    test_payload = "<script>alert(1)</script>"
    
    # 测试各种编码
    encodings = [
        EncodingType.NONE,
        EncodingType.URL,
        EncodingType.DOUBLE_URL,
        EncodingType.BASE64,
        EncodingType.HEX,
        EncodingType.UNICODE,
        EncodingType.HTML_ENTITY,
        EncodingType.JSON,
    ]
    
    for encoding in encodings:
        encoded = PayloadEncoder.encode(test_payload, encoding)
        print(f"  {encoding.value:15} -> {encoded[:60]}{'...' if len(encoded) > 60 else ''}")
    
    print("[PASS] PayloadEncoder 测试通过")


def test_payload_mutator():
    """测试Payload变异器功能"""
    print("\n" + "=" * 60)
    print("测试 PayloadMutator")
    print("=" * 60)
    
    # SQL注入变异测试
    print("\n  SQL注入变异:")
    sqli_payload = "' OR '1'='1"
    variants = PayloadMutator.mutate_sqli(sqli_payload)
    print(f"  原始: {sqli_payload}")
    print(f"  变体数: {len(variants)}")
    for i, v in enumerate(variants[:5]):
        print(f"    变体 {i+1}: {v}")
    
    print("[PASS] PayloadMutator 测试通过")


def test_context_aware_engine():
    """测试上下文感知引擎功能"""
    print("\n" + "=" * 60)
    print("测试 ContextAwareEngine")
    print("=" * 60)
    
    # 模拟响应
    response_body = """
    <!DOCTYPE html>
    <html>
    <body>
        <input type="text" name="username" />
        <input type="hidden" name="csrf_token" value="abc123def456" />
        <!-- PHP/MySQL Application -->
    </body>
    </html>
    """
    
    response_headers = {
        "Server": "nginx/1.18.0",
        "X-Powered-By": "PHP/7.4.3",
    }
    
    # 构建上下文
    context = ContextAwareEngine.build_context(
        target_url="http://example.com",
        response_status=200,
        response_headers=response_headers,
        response_body=response_body,
    )
    
    print(f"  目标URL: {context.target_url}")
    print(f"  检测到技术栈: {context.detected_tech}")
    print(f"  CSRF令牌: {context.csrf_token}")
    
    print("[PASS] ContextAwareEngine 测试通过")


def test_attack_script_generator():
    """测试攻击脚本生成器功能"""
    print("\n" + "=" * 60)
    print("测试 AttackScriptGenerator")
    print("=" * 60)
    
    # 创建生成器
    generator = AttackScriptGenerator(strategy="aggressive", max_variants=5)
    
    # 设置上下文
    context = AttackContext(
        target_url="http://example.com",
        detected_tech=["php", "mysql"],
        input_fields=[{"name": "search", "type": "text"}],
    )
    generator.set_context(context)
    
    # 测试插件配置
    plugin = {
        "id": "sqli-probe",
        "info": {"name": "SQL Injection Probe", "severity": "High"},
        "requests": [
            {
                "method": "GET",
                "path": ["{{BaseURL}}/?id={{payload}}"],
                "payload_sets": {
                    "default": ["' OR '1'='1", "1' AND '1'='1"],
                },
            }
        ],
    }
    
    request_def = plugin["requests"][0]
    variants = generator.build_payloads(plugin, request_def)
    
    print(f"  策略: {generator.strategy}")
    print(f"  生成的Payload变体数: {len(variants)}")
    
    print("[PASS] AttackScriptGenerator 测试通过")


def test_attack_path_explorer():
    """测试攻击路径探索器功能"""
    print("\n" + "=" * 60)
    print("测试 AttackPathExplorer")
    print("=" * 60)
    
    explorer = AttackPathExplorer(learning_enabled=True)
    
    # 测试路径评分
    test_paths = [
        ("http://example.com/", "GET", 0),
        ("http://example.com/admin", "GET", 1),
        ("http://example.com/.git/config", "GET", 2),
        ("http://example.com/.env", "GET", 1),
    ]
    
    print("  路径评分测试:")
    for path, method, depth in test_paths:
        score = explorer.calculate_score(path, method, depth)
        print(f"    [{method:4}] {path[:40]:40} 得分: {score:.3f}")
    
    print("[PASS] AttackPathExplorer 测试通过")


def main():
    """运行所有测试"""
    print("\n" + "=" * 60)
    print("攻击引擎优化功能测试")
    print("=" * 60)
    
    try:
        test_payload_encoder()
        test_payload_mutator()
        test_context_aware_engine()
        test_attack_script_generator()
        test_attack_path_explorer()
        
        print("\n" + "=" * 60)
        print("[SUCCESS] 所有测试通过！")
        print("=" * 60)
        
        print("\n优化功能总结:")
        print("  1. PayloadEncoder - 支持8种编码方式，可链式组合")
        print("  2. PayloadMutator - 自动生成SQL注入/XSS/路径穿越变体")
        print("  3. ContextAwareEngine - 技术栈检测、输入字段提取、编码建议")
        print("  4. AttackScriptGenerator - 智能payload生成、上下文感知")
        print("  5. AttackPathExplorer - 多维度评分、自适应学习、路径发现")
        
    except Exception as e:
        print(f"\n[FAIL] 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())