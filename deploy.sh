#!/bin/bash
# Aegis 漏洞扫描系统部署脚本
# 用于更新Docker容器中的代码

set -e

echo "=================================================="
echo "Aegis 漏洞扫描系统 - 代码更新部署"
echo "=================================================="

# 检查是否在项目根目录
if [ ! -f "docker-compose.yml" ] && [ ! -f "docker-compose.yaml" ]; then
    echo "错误: 请在项目根目录运行此脚本"
    exit 1
fi

echo ""
echo "[1/5] 检查修改的文件..."
MODIFIED_FILES=(
    "scanner/engine/rules.py"
    "scanner/engine/core.py"
    "scanner/engine/attack.py"
    "scanner/plugins/vulnerabilities/thinkphp-sqli.yaml"
    "scanner/plugins/vulnerabilities/drupal-cve-2019-6341.yaml"
)

for file in "${MODIFIED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file 存在"
    else
        echo "  ✗ $file 不存在"
    fi
done

echo ""
echo "[2/5] 停止当前容器..."
docker-compose stop aegis-worker aegis-api 2>/dev/null || docker compose stop aegis-worker aegis-api 2>/dev/null || true

echo ""
echo "[3/5] 重新构建镜像..."
docker-compose build --no-cache aegis-worker aegis-api 2>/dev/null || docker compose build --no-cache aegis-worker aegis-api 2>/dev/null

echo ""
echo "[4/5] 启动容器..."
docker-compose up -d aegis-worker aegis-api 2>/dev/null || docker compose up -d aegis-worker aegis-api

echo ""
echo "[5/5] 等待服务启动..."
sleep 5

echo ""
echo "检查容器状态..."
docker-compose ps 2>/dev/null || docker compose ps

echo ""
echo "=================================================="
echo "部署完成!"
echo "=================================================="
echo ""
echo "查看日志命令:"
echo "  docker-compose logs -f aegis-worker"
echo "  docker-compose logs -f aegis-api"
echo ""
echo "运行诊断命令:"
echo "  docker exec -it aegis-worker python simple_diagnostic.py"
