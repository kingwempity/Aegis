# 基于模拟攻击的Web应用程序漏洞检测系统 API接口文档

---

**版本信息** | **V1.1**
---|---
**编写日期** | 2025年12月18日
**API版本** | v1
**基础URL（开发环境）** | `http://127.0.0.1:8000/api/v1`
**基础URL（生产示例）** | `https://api.vuln-scanner.example.com/api/v1`
**协议** | HTTP / HTTPS（推荐HTTPS）
**数据格式** | JSON

## 文档说明

本文档描述了基于模拟攻击的Web应用程序漏洞检测系统的RESTful API接口规范。所有API遵循RESTful设计原则，使用JSON格式进行数据交换。

本接口文档与《基于模拟攻击的Web应用程序漏洞检测系统功能需求分析文档（V1.1）》保持一致，从接口角度覆盖以下核心功能需求：

- **FR1 模拟攻击路径与漏洞验证**：通过漏洞详情、攻击证据与WebSocket实时消息（见第3章与第6章）体现攻击过程、攻击步骤与证据。
- **FR2 漏洞检测模块**：通过任务创建参数 `scan_profile`、`custom_modules` 以及漏洞模块管理接口（第4章）对应多维度检测与业务逻辑漏洞扩展。
- **FR3 检测文档生成与导出**：通过扫描报告与导出接口（第3章），提供结构化JSON报告及PDF/HTML/Excel等导出能力，支撑后续报告模板与多格式生成。
- **FR4 任务管理与典型工作流程**：通过任务管理接口（第2章）实现任务创建、状态查询、排队与并发管理。
- **FR5 可扩展漏洞库与模块化设计**：通过模块列表、更新、详情接口（第4章）支撑漏洞库扩展与模块化插件架构。
- **FR6 系统管理与用户管理**：通过认证接口（第1章）和统计接口（第5章）实现基础用户认证、角色字段暴露及系统运行概况查询，为后续RBAC、审计与系统配置接口预留扩展空间。

### 认证方式

系统采用JWT (JSON Web Token) 进行身份认证。除登录和注册接口外，所有API请求都需要在请求头中携带有效的JWT Token：

```
Authorization: Bearer <JWT_TOKEN>
Content-Type: application/json
```

### 统一响应格式

所有API响应遵循以下统一格式：

```json
{
  "code": 200,
  "message": "Success",
  "data": {}
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| code | integer | HTTP状态码，200表示成功 |
| message | string | 响应消息描述 |
| data | object/array | 响应数据，具体结构见各接口说明 |

### 错误码说明

| HTTP状态码 | 说明 | 处理建议 |
|-----------|------|----------|
| 200 | 请求成功 | - |
| 400 | 请求参数错误 | 检查请求参数格式和必填项 |
| 401 | 未授权 | 检查Token是否有效或已过期 |
| 403 | 权限不足 | 确认用户是否有权限执行该操作 |
| 404 | 资源不存在 | 检查资源ID是否正确 |
| 422 | 业务逻辑错误 | 检查业务规则是否满足 |
| 429 | 请求频率过高 | 降低请求频率 |
| 500 | 服务器内部错误 | 联系技术支持 |

### 任务状态说明

| 状态值 | 说明 |
|--------|------|
| queued | 任务已创建，等待执行 |
| running | 任务正在执行中 |
| paused | 任务已暂停 |
| completed | 任务已完成 |
| failed | 任务执行失败 |
| cancelled | 任务已取消 |

### 风险等级说明

| 等级 | CVSS评分范围 | 说明 |
|------|-------------|------|
| critical | 9.0 - 10.0 | 危急，需要立即修复 |
| high | 7.0 - 8.9 | 高危，建议尽快修复 |
| medium | 4.0 - 6.9 | 中危，建议修复 |
| low | 0.1 - 3.9 | 低危，可选择性修复 |
| info | 0.0 | 信息性提示 |

---

## 目录

- [1. 认证相关接口](#1-认证相关接口)
  - [1.1 用户注册](#11-用户注册)
  - [1.2 用户登录](#12-用户登录)
  - [1.3 刷新Token](#13-刷新token)
  - [1.4 用户登出](#14-用户登出)
  - [1.5 获取当前用户信息](#15-获取当前用户信息)
- [2. 任务管理接口](#2-任务管理接口)
  - [2.1 创建扫描任务](#21-创建扫描任务)
  - [2.2 查询任务状态](#22-查询任务状态)
  - [2.3 列出用户所有任务](#23-列出用户所有任务)
  - [2.4 取消扫描任务](#24-取消扫描任务)
  - [2.5 获取任务详情](#25-获取任务详情)
- [3. 检测结果接口](#3-检测结果接口)
  - [3.1 获取扫描报告](#31-获取扫描报告)
  - [3.2 获取漏洞详情](#32-获取漏洞详情)
  - [3.3 获取攻击证据](#33-获取攻击证据)
  - [3.4 导出报告](#34-导出报告)
- [4. 漏洞库管理接口](#4-漏洞库管理接口)
  - [4.1 获取系统支持的漏洞模块列表](#41-获取系统支持的漏洞模块列表)
  - [4.2 更新漏洞库](#42-更新漏洞库)
  - [4.3 获取漏洞模块详情](#43-获取漏洞模块详情)
- [5. 统计与监控接口](#5-统计与监控接口)
  - [5.1 获取系统统计信息](#51-获取系统统计信息)
  - [5.2 获取漏洞统计图表数据](#52-获取漏洞统计图表数据)
- [6. WebSocket实时更新](#6-websocket实时更新)

---

## 1. 认证相关接口

### 1.1 用户注册

### 接口名称  
用户注册新账户

### 请求URL  
`/api/v1/auth/register`

### 请求方式  
`POST`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| username | string | 是 | 用户名，3-20个字符，只能包含字母、数字和下划线 |
| email | string | 是 | 邮箱地址，需符合邮箱格式 |
| password | string | 是 | 密码，至少8个字符，需包含大小写字母和数字 |
| full_name | string | 否 | 用户全名 |

### 返回数据示例

```json
{
  "code": 200,
  "message": "User registered successfully",
  "data": {
    "user_id": "user_20251205_xyz789",
    "username": "testuser",
    "email": "test@example.com",
    "created_at": "2025-12-05T22:50:00Z"
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 400 | Invalid email format | 邮箱格式不正确 |
| 400 | Username already exists | 用户名已存在 |
| 400 | Email already registered | 邮箱已被注册 |
| 400 | Password too weak | 密码强度不足 |
| 422 | Validation failed | 参数验证失败 |

---

### 1.2 用户登录

### 接口名称  
用户登录获取访问令牌

### 请求URL  
`/api/v1/auth/login`

### 请求方式  
`POST`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| username | string | 是 | 用户名或邮箱 |
| password | string | 是 | 密码 |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Login successful",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {
      "user_id": "user_20251205_xyz789",
      "username": "testuser",
      "email": "test@example.com",
      "role": "user"
    }
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 401 | Invalid credentials | 用户名或密码错误 |
| 429 | Too many login attempts | 登录尝试次数过多，请稍后再试 |

---

### 1.3 刷新Token

### 接口名称  
使用刷新令牌获取新的访问令牌

### 请求URL  
`/api/v1/auth/refresh`

### 请求方式  
`POST`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| refresh_token | string | 是 | 刷新令牌 |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Token refreshed",
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 3600
  }
}
```

---

### 1.4 用户登出

### 接口名称  
用户登出，使Token失效

### 请求URL  
`/api/v1/auth/logout`

### 请求方式  
`POST`

### 请求参数
无（需要在Header中携带Authorization Token）

### 返回数据示例

```json
{
  "code": 200,
  "message": "Logout successful",
  "data": {}
}
```

---

### 1.5 获取当前用户信息

### 接口名称  
获取当前登录用户的详细信息

### 请求URL  
`/api/v1/auth/me`

### 请求方式  
`GET`

### 请求参数
无（需要在Header中携带Authorization Token）

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "user_id": "user_20251205_xyz789",
    "username": "testuser",
    "email": "test@example.com",
    "full_name": "Test User",
    "role": "user",
    "created_at": "2025-12-05T22:50:00Z",
    "total_tasks": 15,
    "total_scans": 42
  }
}
```

---

## 2. 任务管理接口

### 2.1 创建扫描任务

### 接口名称  
创建新的Web应用漏洞扫描任务  

### 请求URL  
`/api/v1/tasks/create`  

### 请求方式  
`POST`  

### 请求参数  

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| target_url | string | 是 | 目标Web应用的完整URL（如 `https://example.com`） |
| task_name | string | 否 | 任务名称，用于标识任务，默认为自动生成 |
| scan_profile | string | 否 | 扫描配置模板，可选值：`quick`, `full`, `custom`，默认为 `full` |
| custom_modules | array | 否 | 当 `scan_profile=custom` 时必填，指定要启用的检测模块（如 `["sql_injection", "xss", "csrf"]`） |
| auth_token | string | 否 | 用于认证目标站点的会话Token（如有登录态） |
| auth_cookies | string | 否 | 用于认证目标站点的Cookie字符串 |
| max_depth | integer | 否 | 爬虫最大深度，默认5，范围1-10 |
| max_pages | integer | 否 | 最大扫描页面数，默认100，范围10-1000 |
| timeout | integer | 否 | 请求超时时间（秒），默认30，范围10-300 |
| user_agent | string | 否 | 自定义User-Agent，默认为系统默认值 |
| headers | object | 否 | 自定义HTTP请求头，JSON对象格式 |
| exclude_patterns | array | 否 | 排除的URL模式（正则表达式数组） |

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Task created successfully",
  "data": {
    "task_id": "task_20251205_abc123",
    "status": "queued",
    "created_at": "2025-12-05T22:55:00Z"
  }
}
```

### 错误码及错误信息说明  

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 400 | Invalid target URL | 提供的URL格式不合法 |
| 400 | Missing required parameter: target_url | 缺少必要参数 |
| 401 | Unauthorized | 用户未登录或无权限 |
| 422 | Unsupported scan module | 自定义模块中包含不支持的检测类型 |
| 500 | Internal server error | 服务端内部错误 |

---

### 2.2 查询任务状态

### 接口名称  
获取指定扫描任务的当前状态与进度  

### 请求URL  
`/api/v1/tasks/{task_id}/status`  

### 请求方式  
`GET`  

### 请求参数  

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "task_id": "task_20251205_abc123",
    "status": "running",
    "progress": 65,
    "current_phase": "SQL Injection Testing",
    "started_at": "2025-12-05T22:56:00Z",
    "estimated_completion": "2025-12-05T23:30:00Z"
  }
}
```

### 错误码及错误信息说明  

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 404 | Task not found | 任务ID不存在 |
| 401 | Unauthorized | 用户无权访问该任务 |
| 500 | Internal server error | 服务端内部错误 |

---

### 2.3 列出用户所有任务

### 接口名称  
获取当前用户创建的所有扫描任务列表

### 请求URL  
`/api/v1/tasks/list`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| page | integer | 否 | 页码，从1开始，默认为1 |
| page_size | integer | 否 | 每页数量，默认10，最大50 |
| status_filter | string | 否 | 状态过滤器，可选值：`all`, `queued`, `running`, `completed`, `failed`, `cancelled` |
| sort_by | string | 否 | 排序字段，可选值：`created_at`, `completed_at`, `status`，默认为 `created_at` |
| order | string | 否 | 排序方向，可选值：`asc`, `desc`，默认为 `desc` |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "total": 5,
    "page": 1,
    "page_size": 10,
    "tasks": [
      {
        "task_id": "task_20251205_abc123",
        "task_name": "Prod Scan - Dec 5",
        "target_url": "https://example.com",
        "status": "completed",
        "progress": 100,
        "vulnerabilities_found": 3,
        "created_at": "2025-12-05T22:55:00Z",
        "completed_at": "2025-12-05T23:40:00Z"
      }
    ]
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 401 | Unauthorized | 用户未登录 |
| 400 | Invalid page size | page_size 超出范围 |
| 500 | Internal server error | 服务端内部错误 |

---

### 2.4 取消扫描任务

### 接口名称  
取消正在排队或运行中的扫描任务  

### 请求URL  
`/api/v1/tasks/{task_id}/cancel`  

### 请求方式  
`POST`  

### 请求参数  

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Task cancelled successfully",
  "data": {
    "task_id": "task_20251205_abc123",
    "status": "cancelled"
  }
}
```

### 错误码及错误信息说明  

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 404 | Task not found | 任务ID不存在 |
| 400 | Task already completed | 任务已完成，无法取消 |
| 401 | Unauthorized | 用户无权操作该任务 |
| 500 | Failed to cancel task | 任务取消失败（如进程僵死） |

---

### 2.5 获取任务详情

### 接口名称  
获取指定任务的完整详细信息

### 请求URL  
`/api/v1/tasks/{task_id}`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "task_id": "task_20251205_abc123",
    "task_name": "Prod Scan - Dec 5",
    "target_url": "https://example.com",
    "status": "completed",
    "progress": 100,
    "scan_profile": "full",
    "modules_enabled": ["sql_injection", "xss", "csrf", "file_upload", "path_traversal"],
    "created_at": "2025-12-05T22:55:00Z",
    "started_at": "2025-12-05T22:56:00Z",
    "completed_at": "2025-12-05T23:40:00Z",
    "duration_seconds": 2640,
    "pages_scanned": 45,
    "vulnerabilities_found": 3,
    "created_by": {
      "user_id": "user_20251205_xyz789",
      "username": "testuser"
    }
  }
}
```

---

## 3. 检测结果接口

### 3.1 获取扫描报告

### 接口名称  
获取已完成任务的详细安全报告

### 请求URL  
`/api/v1/tasks/{task_id}/report`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |
| format | string | 否 | 报告格式，可选值：`json`, `pdf`，默认为 `json` |

> 注：若 `format=pdf`，则返回二进制PDF文件流（Content-Type: application/pdf）

### 返回数据格式  
`JSON`（当 format=json 时）

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Report generated",
  "data": {
    "task_id": "task_20251205_abc123",
    "target_url": "https://example.com",
    "scan_time": "2025-12-05T23:40:00Z",
    "scan_duration": 2640,
    "summary": {
      "total_vulnerabilities": 3,
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "pages_scanned": 45,
      "modules_executed": 5
    },
    "vulnerabilities": [
      {
        "id": "vuln_sql_001",
        "name": "SQL Injection",
        "type": "sql_injection",
        "url": "https://example.com/login",
        "method": "POST",
        "parameter": "username",
        "payload": "' OR '1'='1",
        "evidence": "Database error message exposed: You have an error in your SQL syntax",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "risk_level": "critical",
        "remediation": "Use parameterized queries or ORM to prevent SQL injection attacks.",
        "references": [
          "https://owasp.org/www-community/attacks/SQL_Injection"
        ],
        "detected_at": "2025-12-05T23:15:30Z"
      }
    ],
    "technology_stack": {
      "server": "Apache/2.4.41",
      "language": "PHP 7.4",
      "framework": "Laravel 8.x",
      "database": "MySQL 8.0"
    }
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 404 | Task not found | 任务ID不存在 |
| 400 | Task not completed yet | 任务尚未完成，无法生成报告 |
| 401 | Unauthorized | 用户无权访问该报告 |
| 500 | Report generation failed | 报告生成异常 |

---

### 3.2 获取漏洞详情

### 接口名称  
获取指定漏洞的详细信息，包括攻击过程和证据

### 请求URL  
`/api/v1/vulnerabilities/{vulnerability_id}`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| vulnerability_id | string | 是 | 漏洞唯一ID（路径参数） |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "id": "vuln_sql_001",
    "task_id": "task_20251205_abc123",
    "name": "SQL Injection",
    "type": "sql_injection",
    "url": "https://example.com/login",
    "method": "POST",
    "parameter": "username",
    "payload": "' OR '1'='1",
    "evidence": "Database error message exposed",
    "cvss_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "risk_level": "critical",
    "description": "The application is vulnerable to SQL injection attacks in the login form.",
    "remediation": "Use parameterized queries or ORM to prevent SQL injection attacks.",
    "references": [
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ],
    "attack_steps": [
      {
        "step": 1,
        "action": "Sent payload: ' OR '1'='1",
        "response_code": 200,
        "response_time_ms": 150
      },
      {
        "step": 2,
        "action": "Detected database error in response",
        "response_code": 200,
        "response_time_ms": 145
      }
    ],
    "screenshots": [
      {
        "url": "/api/v1/vulnerabilities/vuln_sql_001/screenshots/1",
        "description": "Initial request with payload"
      }
    ],
    "detected_at": "2025-12-05T23:15:30Z"
  }
}
```

---

### 3.3 获取攻击证据

### 接口名称  
获取漏洞攻击过程中的详细证据，包括请求/响应数据

### 请求URL  
`/api/v1/vulnerabilities/{vulnerability_id}/evidence`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| vulnerability_id | string | 是 | 漏洞唯一ID（路径参数） |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "vulnerability_id": "vuln_sql_001",
    "request": {
      "method": "POST",
      "url": "https://example.com/login",
      "headers": {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0..."
      },
      "body": "username=' OR '1'='1&password=test",
      "timestamp": "2025-12-05T23:15:30Z"
    },
    "response": {
      "status_code": 200,
      "headers": {
        "Content-Type": "text/html; charset=utf-8"
      },
      "body": "<html>...You have an error in your SQL syntax...</html>",
      "response_time_ms": 150,
      "timestamp": "2025-12-05T23:15:30.150Z"
    },
    "exploitation_result": {
      "successful": true,
      "data_extracted": "Database name: example_db",
      "tables_discovered": ["users", "products", "orders"]
    }
  }
}
```

---

### 3.4 导出报告

### 接口名称  
导出扫描报告为PDF、Excel或HTML格式

### 请求URL  
`/api/v1/tasks/{task_id}/report/export`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |
| format | string | 是 | 导出格式，可选值：`pdf`, `excel`, `html` |
| include_evidence | boolean | 否 | 是否包含攻击证据，默认false |
| include_screenshots | boolean | 否 | 是否包含截图，默认true |

### 返回数据格式
当format=pdf时，返回PDF文件流（Content-Type: application/pdf）
当format=excel时，返回Excel文件流（Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet）
当format=html时，返回HTML文件流（Content-Type: text/html）

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 404 | Task not found | 任务ID不存在 |
| 400 | Task not completed yet | 任务尚未完成，无法导出报告 |
| 400 | Unsupported export format | 不支持的导出格式 |
| 401 | Unauthorized | 用户无权访问该报告 |

---

## 4. 漏洞库管理接口

### 4.1 获取系统支持的漏洞模块列表

### 接口名称  
获取系统当前支持的所有漏洞检测模块清单

### 请求URL  
`/api/v1/modules/list`

### 请求方式  
`GET`

### 请求参数  
无

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "modules": [
      {
        "id": "sql_injection",
        "name": "SQL Injection",
        "category": "Injection",
        "description": "Detects and exploits SQL injection vulnerabilities",
        "enabled": true,
        "version": "1.2.0"
      },
      {
        "id": "xss",
        "name": "Cross-Site Scripting (XSS)",
        "category": "Client-Side",
        "description": "Tests for reflected, stored, and DOM-based XSS",
        "enabled": true,
        "version": "1.1.5"
      },
      {
        "id": "idor",
        "name": "Insecure Direct Object Reference (IDOR)",
        "category": "Business Logic",
        "description": "Checks for unauthorized access to other users' resources",
        "enabled": true,
        "version": "1.0.3"
      }
    ]
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 500 | Module list unavailable | 漏洞库加载失败 |

---

### 4.2 更新漏洞库

### 接口名称  
手动触发漏洞库更新，同步最新的漏洞特征和攻击脚本  

### 请求URL  
`/api/v1/modules/update`  

### 请求方式  
`POST`  

### 请求参数  
无

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Vulnerability database update initiated",
  "data": {
    "update_job_id": "job_update_20251205_def456",
    "status": "in_progress",
    "last_updated": "2025-12-05T23:50:00Z",
    "new_vulnerabilities_added": 12
  }
}
```

### 错误码及错误信息说明  

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 403 | Permission denied | 用户无权限执行此操作（通常是管理员） |
| 500 | Update process failed | 漏洞库更新过程异常 |

---

### 4.3 获取漏洞模块详情

### 接口名称  
获取指定漏洞检测模块的详细信息

### 请求URL  
`/api/v1/modules/{module_id}`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| module_id | string | 是 | 模块唯一ID（路径参数） |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "id": "sql_injection",
    "name": "SQL Injection",
    "category": "Injection",
    "description": "Detects and exploits SQL injection vulnerabilities",
    "version": "1.2.0",
    "enabled": true,
    "author": "Security Team",
    "last_updated": "2025-12-01T10:00:00Z",
    "supported_databases": ["MySQL", "PostgreSQL", "MSSQL", "Oracle"],
    "attack_vectors": [
      "Boolean-based blind",
      "Time-based blind",
      "Union-based",
      "Error-based"
    ],
    "configurable_options": {
      "max_payloads": 100,
      "timeout_seconds": 30,
      "enable_union_attack": true
    }
  }
}
```

---

## 5. 统计与监控接口

### 5.1 获取系统统计信息

### 接口名称  
获取系统整体的运行统计和扫描概况  

### 请求URL  
`/api/v1/stats/overview`  

### 请求方式  
`GET`  

### 请求参数  
无

### 返回数据格式  
`JSON`

### 返回数据示例  

```json
{
  "code": 200,
  "message": "Statistics retrieved",
  "data": {
    "total_scans": 1250,
    "vulnerabilities_found": 420,
    "critical_vulnerabilities": 15,
    "active_tasks": 8,
    "system_uptime_hours": 48
  }
}
```

### 错误码及错误信息说明  

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 401 | Unauthorized | 用户未登录 |
| 500 | Statistics retrieval failed | 统计数据获取失败 |

---

### 5.2 获取漏洞统计图表数据

### 接口名称  
获取用于生成ECharts图表的漏洞统计数据

### 请求URL  
`/api/v1/stats/charts`

### 请求方式  
`GET`

### 请求参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| chart_type | string | 是 | 图表类型，可选值：`risk_distribution`, `vulnerability_trend`, `module_statistics`, `top_vulnerabilities` |
| time_range | string | 否 | 时间范围，可选值：`7d`, `30d`, `90d`, `1y`，默认为 `30d` |
| task_id | string | 否 | 任务ID，如果指定则只统计该任务的漏洞 |

### 返回数据示例

```json
{
  "code": 200,
  "message": "Success",
  "data": {
    "chart_type": "risk_distribution",
    "data": {
      "labels": ["Critical", "High", "Medium", "Low"],
      "values": [5, 12, 28, 8],
      "colors": ["#ff4d4f", "#ff7a45", "#faad14", "#52c41a"]
    },
    "time_range": "30d"
  }
}
```

### 错误码及错误信息说明

| 错误码 | 错误信息 | 说明 |
|--------|----------|------|
| 400 | Invalid chart type | 不支持的图表类型 |
| 401 | Unauthorized | 用户未登录 |
| 500 | Statistics retrieval failed | 统计数据获取失败 |

---

## 6. WebSocket实时更新

### 6.1 任务状态实时推送

### 接口名称  
通过WebSocket连接实时接收任务状态更新

### 连接URL  
`wss://api.vuln-scanner.example.com/ws/tasks/{task_id}`

### 协议  
WebSocket

### 连接参数

| 参数名 | 类型 | 是否必填 | 说明 |
|--------|------|----------|------|
| task_id | string | 是 | 任务唯一ID（路径参数） |
| token | string | 是 | JWT Token（查询参数） |

### 连接示例

```javascript
const ws = new WebSocket('wss://api.vuln-scanner.example.com/ws/tasks/task_20251205_abc123?token=YOUR_JWT_TOKEN');
```

### 消息格式

#### 客户端发送消息

```json
{
  "action": "subscribe",
  "task_id": "task_20251205_abc123"
}
```

#### 服务端推送消息

```json
{
  "type": "status_update",
  "task_id": "task_20251205_abc123",
  "data": {
    "status": "running",
    "progress": 65,
    "current_phase": "SQL Injection Testing",
    "vulnerabilities_found": 2,
    "timestamp": "2025-12-05T23:20:00Z"
  }
}
```

### 消息类型说明

| 消息类型 | 说明 |
|---------|------|
| status_update | 任务状态更新 |
| progress_update | 进度更新 |
| vulnerability_found | 发现新漏洞 |
| task_completed | 任务完成 |
| task_failed | 任务失败 |
| error | 错误信息 |

### 错误处理

```json
{
  "type": "error",
  "code": 401,
  "message": "Unauthorized",
  "timestamp": "2025-12-05T23:20:00Z"
}
```

---

## 附录

### A. 请求示例

#### cURL示例

```bash
# 创建扫描任务
curl -X POST https://api.vuln-scanner.example.com/api/v1/tasks/create \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "task_name": "Production Scan",
    "scan_profile": "full"
  }'

# 查询任务状态
curl -X GET https://api.vuln-scanner.example.com/api/v1/tasks/task_20251205_abc123/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Python示例

```python
import requests

# 设置认证头
headers = {
    "Authorization": "Bearer YOUR_JWT_TOKEN",
    "Content-Type": "application/json"
}

# 创建扫描任务
response = requests.post(
    "https://api.vuln-scanner.example.com/api/v1/tasks/create",
    headers=headers,
    json={
        "target_url": "https://example.com",
        "task_name": "Production Scan",
        "scan_profile": "full"
    }
)

task_data = response.json()
task_id = task_data["data"]["task_id"]

# 查询任务状态
status_response = requests.get(
    f"https://api.vuln-scanner.example.com/api/v1/tasks/{task_id}/status",
    headers=headers
)
```

### B. 速率限制

| 接口类型 | 限制 |
|---------|------|
| 认证接口 | 10次/分钟 |
| 任务创建 | 5次/分钟 |
| 其他接口 | 100次/分钟 |

超过限制时返回429状态码，响应头中包含：
- `X-RateLimit-Limit`: 限制数量
- `X-RateLimit-Remaining`: 剩余请求数
- `X-RateLimit-Reset`: 重置时间（Unix时间戳）

### C. 数据模型

#### 任务对象 (Task)

```json
{
  "task_id": "string",
  "task_name": "string",
  "target_url": "string",
  "status": "queued|running|completed|failed|cancelled",
  "progress": "integer (0-100)",
  "scan_profile": "quick|full|custom",
  "modules_enabled": ["string"],
  "created_at": "ISO 8601 datetime",
  "started_at": "ISO 8601 datetime",
  "completed_at": "ISO 8601 datetime",
  "created_by": {
    "user_id": "string",
    "username": "string"
  }
}
```

#### 漏洞对象 (Vulnerability)

```json
{
  "id": "string",
  "task_id": "string",
  "name": "string",
  "type": "string",
  "url": "string",
  "method": "GET|POST|PUT|DELETE",
  "parameter": "string",
  "payload": "string",
  "evidence": "string",
  "cvss_score": "float (0.0-10.0)",
  "cvss_vector": "string",
  "risk_level": "critical|high|medium|low|info",
  "description": "string",
  "remediation": "string",
  "references": ["string"],
  "detected_at": "ISO 8601 datetime"
}
```

---

> **说明**：所有API请求需在请求头（Header）中携带有效的身份认证信息，例如：
> ```
> Authorization: Bearer <JWT_TOKEN>
> Content-Type: application/json
> ```