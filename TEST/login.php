<?php
// SQL注入漏洞测试页面 - 后端处理
// ⚠️ 警告：此代码故意包含SQL注入漏洞，仅用于教育和测试目的！
// 使用模拟数据库（数组）来避免依赖外部数据库驱动

header('Content-Type: text/html; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// 模拟数据库 - 用户数据存储在数组中
$users_db = [
    ['id' => 1, 'username' => 'admin', 'password' => 'admin123', 'email' => 'admin@test.com', 'role' => 'admin'],
    ['id' => 2, 'username' => 'user1', 'password' => 'password1', 'email' => 'user1@test.com', 'role' => 'user'],
    ['id' => 3, 'username' => 'user2', 'password' => 'password2', 'email' => 'user2@test.com', 'role' => 'user'],
    ['id' => 4, 'username' => 'test', 'password' => 'test123', 'email' => 'test@test.com', 'role' => 'user'],
    ['id' => 5, 'username' => 'john', 'password' => 'john123', 'email' => 'john@example.com', 'role' => 'user'],
    ['id' => 6, 'username' => 'alice', 'password' => 'alice123', 'email' => 'alice@example.com', 'role' => 'user']
];

// 模拟SQL注入检查函数
function simulate_sql_injection($username, $password, $users_db) {
    // ⚠️ 严重的安全漏洞：模拟SQL注入逻辑
    // 在实际数据库中，这段代码会被直接拼接到SQL查询中
    // 这里我们用字符串操作模拟SQL注入的行为

    // 构造模拟的SQL查询字符串（实际应用中会被发送到数据库）
    $sql_query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";

    // 显示执行的查询（教育目的）
    echo "<p><strong>模拟执行的SQL查询:</strong></p>";
    echo "<code style='background: #f0f0f0; padding: 10px; display: block; margin: 10px 0;'>$sql_query</code>";

    // 模拟SQL注入逻辑
    // 1. 检查是否存在SQL注入payload
    $injected_query = strtolower($sql_query);

    // 如果包含 ' OR '1'='1 这样的注入
    if (strpos($injected_query, "' or '1'='1") !== false ||
        strpos($injected_query, "' or 1=1") !== false ||
        strpos($injected_query, "' or '1' = '1") !== false) {
        // SQL注入成功 - 返回第一个用户（模拟绕过认证）
        return $users_db[0]; // 返回admin用户
    }

    // 如果包含UNION注入
    if (strpos($injected_query, "union select") !== false) {
        // 模拟UNION注入 - 返回特殊数据
        if (strpos($injected_query, "database()") !== false) {
            return ['id' => 999, 'username' => 'test_db', 'password' => 'db_user', 'email' => '5.7.0', 'role' => 'injected'];
        }
        if (strpos($injected_query, "table_name") !== false) {
            return ['id' => 999, 'username' => 'users', 'password' => 'NULL', 'email' => 'NULL', 'role' => 'injected'];
        }
        if (strpos($injected_query, "from users") !== false) {
            return ['id' => 999, 'username' => 'admin', 'password' => 'admin123', 'email' => 'NULL', 'role' => 'injected'];
        }
        return ['id' => 999, 'username' => 'INJECTED_DATA', 'password' => 'INJECTED_PASS', 'email' => 'injected@test.com', 'role' => 'hacker'];
    }

    // 如果包含注释注入
    if (strpos($injected_query, "' --") !== false ||
        strpos($injected_query, "'#") !== false ||
        strpos($injected_query, "'; --") !== false) {
        // 模拟注释注入 - 忽略密码检查
        $clean_username = trim($username);
        // 移除注释部分
        $comment_pos = strpos($clean_username, "' --");
        if ($comment_pos !== false) {
            $clean_username = substr($clean_username, 0, $comment_pos);
        }
        $comment_pos = strpos($clean_username, "'#");
        if ($comment_pos !== false) {
            $clean_username = substr($clean_username, 0, $comment_pos);
        }
        $comment_pos = strpos($clean_username, "'; --");
        if ($comment_pos !== false) {
            $clean_username = substr($clean_username, 0, $comment_pos + 1);
        }

        $clean_username = trim($clean_username, "'");

        foreach ($users_db as $user) {
            if ($user['username'] === $clean_username) {
                return $user;
            }
        }
    }

    // 如果包含DROP TABLE
    if (strpos($injected_query, "drop table") !== false) {
        // 模拟破坏性攻击
        return ['id' => 999, 'username' => 'TABLE_DROPPED', 'password' => 'SYSTEM_COMPROMISED', 'email' => 'hacked@test.com', 'role' => 'destroyed'];
    }

    // 正常的用户认证逻辑
    foreach ($users_db as $user) {
        if ($user['username'] === $username && $user['password'] === $password) {
            return $user;
        }
    }

    return false; // 认证失败
}

// 处理登录请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // 模拟SQL注入检查
    $user = simulate_sql_injection($username, $password, $users_db);

    if ($user) {
        // 登录成功
        echo "<h3 style='color: green;'>✅ 登录成功！</h3>";
        echo "<p><strong>欢迎回来，{$user['username']}！</strong></p>";
        echo "<p>角色: {$user['role']}</p>";
        echo "<p>邮箱: {$user['email']}</p>";

        if ($user['id'] === 999) {
            echo "<p style='color: red; font-weight: bold;'>⚠️ 检测到SQL注入攻击！</p>";
        }
    } else {
        // 登录失败
        echo "<h3 style='color: red;'>❌ 登录失败！</h3>";
        echo "<p>用户名或密码错误</p>";
    }
} else {
    echo "<h3 style='color: orange;'>⚠️ 请使用POST方法提交登录请求</h3>";
}

// 显示当前"数据库"中的用户（仅用于测试）
echo "<hr>";
echo "<h4>当前数据库中的用户（测试用）：</h4>";
echo "<table border='1' style='border-collapse: collapse; width: 100%;'>";
echo "<tr><th>用户名</th><th>密码</th><th>邮箱</th><th>角色</th></tr>";
foreach ($users_db as $user) {
    echo "<tr>";
    echo "<td>" . htmlspecialchars($user['username']) . "</td>";
    echo "<td>" . htmlspecialchars($user['password']) . "</td>";
    echo "<td>" . htmlspecialchars($user['email']) . "</td>";
    echo "<td>" . htmlspecialchars($user['role']) . "</td>";
    echo "</tr>";
}
echo "</table>";
?>
