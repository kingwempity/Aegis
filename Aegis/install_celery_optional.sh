#!/bin/bash
# 可选安装Celery和Redis相关包
# 用于任务队列功能

set -e

echo "🔄 可选安装: Celery和Redis..."

# 尝试安装Redis
echo "📦 安装Redis..."
python3 -m pip install redis==4.3.6 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install redis==4.2.2 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install redis==4.1.4 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
echo "⚠️  Redis安装失败"

# 尝试安装Celery
echo "📦 安装Celery..."
python3 -m pip install celery==5.2.0b3 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install celery==5.1.2 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install celery==5.0.6 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
python3 -m pip install celery==4.4.7 -i https://pypi.tuna.tsinghua.edu.cn/simple || \
echo "⚠️  Celery安装失败"

# 测试导入
echo "🧪 测试导入..."
python3 -c "import redis; print('Redis version:', redis.__version__)" || echo "Redis导入失败"
python3 -c "import celery; print('Celery version:', celery.__version__)" || echo "Celery导入失败"

echo "✅ 可选包安装完成！"