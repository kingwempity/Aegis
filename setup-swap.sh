#!/bin/bash
# 2G 内存服务器 Swap 配置脚本
# 适用于低配服务器，防止内存不足导致进程被杀

echo "=== 配置 Swap 分区 ==="

# 检查是否已有 swap
if swapon --show | grep -q "swap"; then
    echo "Swap 已存在："
    swapon --show
    exit 0
fi

# 创建 2G swap 文件
echo "创建 2G swap 文件..."
sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048 status=progress

# 设置权限
echo "设置权限..."
sudo chmod 600 /swapfile

# 格式化为 swap
echo "格式化 swap..."
sudo mkswap /swapfile

# 启用 swap
echo "启用 swap..."
sudo swapon /swapfile

# 添加到 fstab 实现开机自动挂载
if ! grep -q "/swapfile" /etc/fstab; then
    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
fi

# 优化 swappiness（值越低越少使用 swap，建议 10-20）
echo "设置 swappiness..."
sudo sysctl vm.swappiness=10
if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
    echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
fi

echo "=== Swap 配置完成 ==="
echo "当前内存状态："
free -h
echo ""
echo "Swap 状态："
swapon --show