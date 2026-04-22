#!/bin/bash
# Vulhub靶场连通性测试脚本
# 在服务器上运行此脚本，快速验证Aegis能否访问所有Vulhub靶场

echo "================================================================"
echo "🔍 Aegis → Vulhub 网络连通性测试"
echo "================================================================"
echo ""

TARGETS=(
    "vulhub-thinkphp-web:80:ThinkPHP SQL注入"
    "cve-2017-12794-web-1:8000:Django CVE-2017-12794"
    "cve-2019-6341-web-1:80:Drupal CVE-2019-6341"
)

PASS=0
FAIL=0

for target_info in "${TARGETS[@]}"; do
    IFS=':' read -r target port name <<< "$target_info"
    
    echo "📍 测试: $name"
    echo "   目标: $target:$port"
    
    # 尝试使用curl测试
    result=$(docker exec -it aegis-api curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$target:$port" 2>/dev/null)
    
    if [ "$result" = "000" ]; then
        # curl失败，尝试python
        result=$(docker exec -it aegis-api python -c "
import urllib.request
try:
    resp = urllib.request.urlopen('http://$target:$port', timeout=5)
    print(resp.status)
except Exception as e:
    print('000')
" 2>/dev/null)
    fi
    
    if [ "$result" != "000" ] && [ -n "$result" ]; then
        echo "   ✅ 连接成功! HTTP状态码: $result"
        PASS=$((PASS + 1))
    else
        echo "   ❌ 连接失败!"
        
        # 提供调试建议
        echo ""
        echo "   🔧 排查建议:"
        echo "      1. 确认容器正在运行: docker ps | grep $target"
        echo "      2. 检查网络配置: docker inspect $target | grep IPAddress"
        echo "      3. 手动连接网络: docker network connect <net> $target"
        FAIL=$((FAIL + 1))
    fi
    
    echo ""
done

echo "================================================================"
echo "📊 测试结果汇总"
echo "================================================================"
echo "✅ 成功: $PASS 个靶场"
echo "❌ 失败: $FAIL 个靶场"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "🎉 所有靶场均可访问！可以开始扫描了！"
    echo ""
    echo "🚀 执行扫描命令:"
    echo "   # ThinkPHP SQL注入"
    echo "   docker exec -it aegis-api python /app/test_vulhub_scan.py http://vulhub-thinkphp-web:80"
    echo ""
    echo "   # Django CVE-2017-12794"
    echo "   docker exec -it aegis-api python /app/test_vulhub_scan.py http://cve-2017-12794-web-1:8000"
    echo ""
    echo "   # Drupal CVE-2019-6341"
    echo "   docker exec -it aegis-api python /app/test_vulhub_scan.py http://cve-2019-6341-web-1:80"
else
    echo "⚠️  部分靶场无法访问，请按照上述建议排查"
fi

echo "================================================================"
