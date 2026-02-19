# Aegis 服务器部署指南

本文给出在 Linux 服务器（Ubuntu/CentOS）上通过 Docker Compose 部署 Aegis 的推荐流程。

## 1. 前置条件

- 一台可联网 Linux 服务器（建议 2C4G 起步）
- 已安装：Docker、Docker Compose v2、Git
- 防火墙放行端口：
  - `8000/tcp`（Aegis API）
  - `3307/tcp`（MySQL，**仅在需要外部连接时开放**）

## 2. 拉取代码

```bash
git clone <你的仓库地址> Aegis
cd Aegis
```

## 3. 启动服务

```bash
docker compose up -d --build
```

等待容器健康后检查：

```bash
docker compose ps
docker compose logs --tail=100 aegis-api
```

## 4. 验证部署

```bash
curl http://127.0.0.1:8000/
```

预期返回：

```json
{"status":"online"}
```

## 5. 常用运维命令

### 查看日志

```bash
docker compose logs -f aegis-api
docker compose logs -f aegis-worker
```

### 重启服务

```bash
docker compose restart aegis-api aegis-worker
```

### 停止并保留数据

```bash
docker compose down
```

### 停止并删除数据（危险）

```bash
docker compose down -v
```

## 6. 生产环境建议

1. **修改默认密码**：将 `docker-compose.yml` 中的 `MYSQL_ROOT_PASSWORD` 改为强口令。
2. **反向代理**：使用 Nginx/Caddy 暴露 80/443，把外网流量转发到 `127.0.0.1:8000`。
3. **TLS 证书**：务必开启 HTTPS。
4. **最小化开放端口**：若不需要外部直连数据库，关闭 `3307` 对公网开放。
5. **定期备份**：备份 `data/mysql` 与 `data/reports`。

## 7. 升级流程

```bash
git pull
docker compose up -d --build
```

升级后建议检查：

```bash
docker compose ps
docker compose logs --tail=100 aegis-api
```
