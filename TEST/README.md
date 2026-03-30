# SQL注入漏洞测试页面

## ⚠️ 重要警告

**此页面故意包含SQL注入漏洞，仅用于安全测试和教育目的！**

请勿在生产环境中使用此类代码，SQL注入是Web应用中最严重的安全漏洞之一。

## 📋 功能说明

这是一个故意设计成存在SQL注入漏洞的登录页面，用于：
- 演示SQL注入攻击原理
- 测试漏洞扫描工具的检测能力
- 安全教育和培训

## 🚀 快速开始

### 1. 环境要求
- PHP 7.0 或更高版本
- 支持SQLite的PHP环境

### 2. 启动服务器
双击运行 `start_server.bat` 文件，或在命令行中执行：
```bash
php -S localhost:8080
```

### 3. 访问测试页面
打开浏览器访问：http://localhost:8080

## 🔍 SQL注入漏洞原理

### 漏洞代码分析
在 `login.php` 中，存在以下危险代码：

```php
// ⚠️ 严重的安全漏洞：直接拼接SQL查询！
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

这段代码直接将用户输入拼接到SQL查询中，没有进行任何过滤或转义。

### 攻击向量

#### 1. 绕过认证
输入用户名：`' OR '1'='1`
密码：任意值

生成的SQL查询：
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '任意值'
```

#### 2. 提取数据库信息
输入用户名：`admin' UNION SELECT database(), user(), version() -- `
密码：任意值

#### 3. 查看所有表
输入用户名：`admin' UNION SELECT table_name, NULL FROM information_schema.tables -- `
密码：任意值

#### 4. 查看用户数据
输入用户名：`admin' UNION SELECT username, password FROM users -- `
密码：任意值

#### 5. 删除表（破坏性攻击）
输入用户名：`admin'; DROP TABLE users; -- `
密码：任意值

## 🛡️ 安全修复建议

### 1. 使用预编译语句（推荐）
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```

### 2. 输入过滤和转义
```php
$username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_STRING);
$password = filter_input(INPUT_POST, 'password', FILTER_SANITIZE_STRING);
```

### 3. 使用ORM框架
如 Laravel Eloquent、Doctrine 等。

### 4. 最小权限原则
数据库用户只授予必要权限。

## 📁 文件结构

```
TEST/
├── index.html          # 前端登录页面
├── login.php           # 后端处理（含漏洞）
├── start_server.bat   # Windows启动脚本
├── README.md           # 说明文档
└── test.db            # SQLite数据库（自动生成）
```

## 🧪 测试数据

系统预置了以下测试用户：

| 用户名 | 密码     | 角色   |
|--------|----------|--------|
| admin  | admin123 | admin  |
| user1  | password1| user   |
| user2  | password2| user   |
| test   | test123  | user   |

## 🔧 故障排除

### 1. PHP未找到
- 下载PHP：https://windows.php.net/download
- 添加PHP到系统PATH

### 2. 端口被占用
修改 `start_server.bat` 中的端口号：
```bash
php -S localhost:8081
```

### 3. 数据库错误
删除 `test.db` 文件，刷新页面重新创建数据库。

## 📚 学习资源

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PHP PDO 安全使用指南](https://www.php.net/manual/en/book.pdo.php)
- [Web安全基础](https://websec.fr/)

---

**记住：安全无小事，开发时请始终保持安全意识！** 🛡️
