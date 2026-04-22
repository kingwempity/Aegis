"""
快速测试自然语言提取功能
"""
import re
from typing import Dict, Any, Optional

def _extract_json_from_natural_language(text: str) -> Optional[Dict[str, Any]]:
    """简化版提取函数用于测试"""
    text_lower = text.lower()
    
    result = {
        "action": "continue",
        "reason": "",
        "payload_mutation": "test",
        "next_target_path": "",
        "confidence": 0.5
    }
    
    # 测试 action 提取
    action_keywords = {
        "continue": ["continue", "keep going", "proceed", "next", "move on"],
        "retry": ["retry", "try again", "attempt again", "retest"],
        "change_vector": ["change", "switch", "different", "alternative", "new vector"],
        "terminate": ["terminate", "stop", "finish", "done", "complete"]
    }
    
    print(f"📝 分析文本：{text[:100]}...")
    print(f"📝 小写后：{text_lower[:100]}...")
    
    for action, keywords in action_keywords.items():
        if any(kw in text_lower for kw in keywords):
            result["action"] = action
            print(f"✅ 匹配到 action: {action} (关键词：{[kw for kw in keywords if kw in text_lower]})")
            break
    
    # 测试 path 提取
    path_patterns = [
        r'(?:path|url|target|endpoint|route)[s]?\s*(?:is|:|=|to)\s*[/\?][a-zA-Z0-9_\-./?=&%]+',
        r'/(?:admin|api|user|login|upload|config|debug|test|manager|console)',
        r'\?[a-zA-Z0-9_\-./?=&%]+',
    ]
    
    for pattern in path_patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            result["next_target_path"] = match.group(0).strip()
            print(f"✅ 匹配到 path: {match.group(0)} (模式：{pattern[:50]})")
            break
    
    # 测试 reason 提取
    reason_match = re.search(r'(?:reason|because|therefore|so)[s]?\s*(?:is|:|=)?\s*([^.\n]+)', text, re.IGNORECASE)
    if reason_match:
        result["reason"] = reason_match.group(1).strip()[:200]
        print(f"✅ 匹配到 reason: {result['reason']}")
    
    if not result["reason"]:
        result["reason"] = text[:100].strip()
    
    return result


# 测试用例 - 来自实际日志
test_text = """Alright, so I'm trying to figure out what the next action should be in this penetration testing scenario. The target is `http://vulhub-thinkphp-web,`  and it's using PHP and Apache. We're in the exploitation phase. 

Looking at the history, the user tried the payload "test" seven times. All those attempts returned 200 status. I should move to a different path. Let me try /index.php?s=/admin since this is a ThinkPHP vulnerability scenario."""

print("=" * 80)
print("🧪 测试自然语言提取")
print("=" * 80)

result = _extract_json_from_natural_language(test_text)

print("\n" + "=" * 80)
print("📊 提取结果:")
print("=" * 80)
print(f"Action: {result['action']}")
print(f"Path: {result['next_target_path']}")
print(f"Reason: {result['reason']}")
print(f"Payload: {result['payload_mutation']}")
print(f"Confidence: {result['confidence']}")
print("=" * 80)
