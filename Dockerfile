# 第一阶段：前端构建
FROM node:22-slim AS frontend-builder
WORKDIR /AFE

# 配置 npm/pnpm 使用国内镜像源加速
RUN npm config set registry https://registry.npmmirror.com && \
    npm install -g pnpm && \
    pnpm config set registry https://registry.npmmirror.com

COPY AFE/package*json ./
RUN pnpm install
COPY AFE/ ./
RUN pnpm run build

# 第二阶段：后端运行环境
FROM python:3.10-slim-bookworm

# 设置 Debian 清华源
RUN rm -rf /etc/apt/sources.list.d/* && \
    echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list && \
    echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    nmap \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxext6 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libpangoft2-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    libopenjp2-7 fonts-wqy-microhei \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

# 安装 Playwright 浏览器（使用淘宝镜像加速）
ENV PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright
RUN playwright install chromium

# 复制后端代码（BE 目录包含所有后端模块）
COPY BE/ ./BE/

# 从第一阶段复制前端构建产物到后端静态文件目录
RUN mkdir -p /app/static
COPY --from=frontend-builder /AFE/dist /app/static

# 暴露端口
EXPOSE 8000

# 启动命令 - 低配服务器优化：单 worker 减少内存占用
# PYTHONPATH 包含 /app/BE，使得 from app.xxx 等导入正常工作
ENV PYTHONPATH=/app/BE:/app
CMD ["gunicorn", "app.main:app", "-w", "1", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000", "--timeout", "120", "--threads", "2"]
