#!/bin/bash
# Aegis 分步依赖安装脚本
# 适用于 Python 3.6 环境，避免版本冲突

set -e

echo "🚀 开始分步安装 Aegis 依赖..."

# 检查Python版本
python3 --version

# 步骤1: 升级pip
echo "📦 步骤1: 升级pip..."
python3 -m pip install --upgrade pip

# 步骤2: 安装核心依赖（排除playwright）
echo "📦 步骤2: 安装核心依赖..."
python3 -m pip install -r requirements-core.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 步骤3: 单独安装playwright（尝试不同版本）
echo "🎭 步骤3: 安装 Playwright..."
# 尝试安装已知可用的版本
python3 -m pip install playwright==1.17.2 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install playwright==1.16.3 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install playwright==1.15.4 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
echo "⚠️  Playwright安装失败，跳过此步骤"

# 步骤4: 安装playwright浏览器（如果playwright安装成功）
echo "🌐 步骤4: 安装 Playwright 浏览器..."
playwright install chromium || echo "⚠️  浏览器安装失败，跳过此步骤"

echo "✅ 依赖安装完成！"

echo "🧪 运行兼容性测试..."
python3 test_python36_compatibility.py

echo "🎉 安装成功！"