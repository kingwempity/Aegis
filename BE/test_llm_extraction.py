"""
测试 LLM Provider 的自然语言 JSON 提取功能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.engine.llm_provider import LLMProvider

def test_extraction():
    """测试从自然语言中提取 JSON 的能力"""
    
    provider = LLMProvider()
    
    test_cases = [
        {
            "name": "标准 JSON",
            "input": '{"action":"continue","reason":"测试","next_target_path":"/admin","confidence":0.8}',
            "expected_action": "continue",
            "expected_path": "/admin"
        },
        {
            "name": "自然语言 - Continue",
            "input": "Alright, I think we should continue testing. The target path should be /admin to check for vulnerabilities.",
            "expected_action": "continue",
            "expected_path": "/admin"
        },
        {
            "name": "自然语言 - Change Vector",
            "input": "Let me try a different approach. I want to switch to a new attack vector and target /api/users endpoint.",
            "expected_action": "change_vector",
            "expected_path": "/api/users"
        },
        {
            "name": "自然语言 - Terminate",
            "input": "I think we should stop now. The testing is complete and we've covered all paths.",
            "expected_action": "terminate",
            "expected_path": ""
        },
        {
            "name": "带推理过程",
            "input": "Looking at the history, they tried 'test' three times with 200 status. I recommend to move to /admin path to check for more vulnerabilities because the admin panel might expose sensitive functions.",
            "expected_action": "continue",
            "expected_path": "/admin"
        }
    ]
    
    print("=" * 80)
    print("🧪 测试 LLM Provider 自然语言 JSON 提取功能")
    print("=" * 80)
    
    for i, case in enumerate(test_cases, 1):
        print(f"\n[测试 {i}/{len(test_cases)}] {case['name']}")
        print(f"输入：{case['input'][:100]}...")
        
        result = provider._extract_json_from_natural_language(case['input'])
        
        if result:
            print(f"✅ 提取成功:")
            print(f"   - Action: {result['action']} (期望：{case['expected_action']})")
            print(f"   - Path: {result['next_target_path']} (期望：{case['expected_path']})")
            print(f"   - Reason: {result['reason'][:50]}...")
            
            action_match = result['action'] == case['expected_action']
            path_match = result['next_target_path'] == case['expected_path']
            
            if action_match and (path_match or not case['expected_path']):
                print(f"   ✅ 结果正确")
            else:
                print(f"   ⚠️  结果部分正确")
        else:
            print(f"❌ 提取失败")
    
    print("\n" + "=" * 80)
    print("✅ 测试完成")
    print("=" * 80)

if __name__ == "__main__":
    test_extraction()
