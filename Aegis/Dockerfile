# 关键修改：显式指定 bookworm 版本，防止漂移到测试版
FROM python:3.10-slim-bookworm

# 关键修改：
# 1. 删除系统默认的所有源文件，防止干扰
# 2. 写入清华源 (HTTP 协议，防止 SSL 证书问题)
RUN rm -rf /etc/apt/sources.list.d/* &&     echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm main contrib non-free non-free-firmware" > /etc/apt/sources.list &&     echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian/ bookworm-updates main contrib non-free non-free-firmware" >> /etc/apt/sources.list &&     echo "deb http://mirrors.tuna.tsinghua.edu.cn/debian-security bookworm-security main contrib non-free non-free-firmware" >> /etc/apt/sources.list

# 安装依赖
# 增加 ca-certificates 以防后续 HTTPS 请求报错
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

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

RUN playwright install chromium

COPY . .

CMD ["gunicorn", "app.main:app", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000", "--timeout", "120"]
