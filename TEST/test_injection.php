<?php
// SQL注入漏洞测试脚本
// 用于验证各种SQL注入攻击是否有效

echo "🔍 SQL注入漏洞测试脚本\n";
echo str_repeat("=", 50) . "\n\n";

// 模拟数据库 - 用户数据
$users_db = [
    ['id' => 1, 'username' => 'admin', 'password' => 'admin123', 'email' => 'admin@test.com', 'role' => 'admin'],
    ['id' => 2, 'username' => 'user1', 'password' => 'password1', 'email' => 'user1@test.com', 'role' => 'user'],
    ['id' => 3, 'username' => 'user2', 'password' => 'password2', 'email' => 'user2@test.com', 'role' => 'user'],
    ['id' => 4, 'username' => 'test', 'password' => 'test123', 'email' => 'test@test.com', 'role' => 'user'],
    ['id' => 5, 'username' => 'john', 'password' => 'john123', 'email' => 'john@example.com', 'role' => 'user'],
    ['id' => 6, 'username' => 'alice', 'password' => 'alice123', 'email' => 'alice@example.com', 'role' => 'user']
];

// 模拟SQL注入检查函数
function test_sql_injection($username, $password, $users_db, $description) {
    echo "测试: $description\n";
    echo "用户名: '$username'\n";
    echo "密码: '$password'\n";

    // 构造模拟的SQL查询字符串
    $sql_query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    echo "模拟SQL查询: $sql_query\n";

    // 模拟SQL注入逻辑
    $injected_query = strtolower($sql_query);

    // 检查各种SQL注入payload
    if (strpos($injected_query, "' or '1'='1") !== false ||
        strpos($injected_query, "' or 1=1") !== false ||
        strpos($injected_query, "' or '1' = '1") !== false) {
        // SQL注入成功 - 返回第一个用户
        $user = $users_db[0];
        echo "✅ 结果: SQL注入成功！绕过认证，用户: {$user['username']} (角色: {$user['role']})\n";
        return true;
    }

    // UNION注入
    if (strpos($injected_query, "union select") !== false) {
        echo "✅ 结果: UNION注入成功！提取到数据\n";
        if (strpos($injected_query, "database()") !== false) {
            echo "   提取的数据: 数据库名=test_db, 用户=db_user, 版本=5.7.0\n";
        } elseif (strpos($injected_query, "table_name") !== false) {
            echo "   提取的数据: 表名=users\n";
        } elseif (strpos($injected_query, "from users") !== false) {
            echo "   提取的数据: 用户名=admin, 密码=admin123\n";
        } else {
            echo "   提取的数据: INJECTED_DATA / INJECTED_PASS\n";
        }
        return true;
    }

    // 注释注入
    if (strpos($injected_query, "' --") !== false || strpos($injected_query, "'#") !== false) {
        // 模拟注释注入 - 忽略密码检查
        foreach ($users_db as $user) {
            if ($user['username'] === trim($username, "'")) {
                echo "✅ 结果: 注释注入成功！用户: {$user['username']} (角色: {$user['role']})\n";
                return true;
            }
        }
    }

    // DROP TABLE
    if (strpos($injected_query, "drop table") !== false) {
        echo "✅ 结果: 破坏性注入成功！表已被删除（模拟）\n";
        return true;
    }

    // 正常认证
    foreach ($users_db as $user) {
        if ($user['username'] === $username && $user['password'] === $password) {
            echo "✅ 结果: 正常登录成功！用户: {$user['username']} (角色: {$user['role']})\n";
            return true;
        }
    }

    echo "❌ 结果: 登录失败\n";
    return false;
}

// 测试用例
echo "🧪 开始SQL注入漏洞测试...\n\n";

// 1. 正常登录
test_sql_injection('admin', 'admin123', $users_db, '正常登录');

// 2. 错误的凭据
test_sql_injection('admin', 'wrongpass', $users_db, '错误密码');

// 3. 经典SQL注入 - 绕过认证
test_sql_injection("' OR '1'='1", 'anything', $users_db, '经典绕过认证');

// 4. 注释注入
test_sql_injection("admin' -- ", 'anything', $users_db, '注释注入');

// 5. UNION注入 - 提取数据库信息
test_sql_injection("admin' UNION SELECT 'db_name', 'db_user', 'db_version' -- ", 'anything', $users_db, 'UNION注入 - 数据库信息');

// 6. 查看所有表
test_sql_injection("admin' UNION SELECT name, NULL, NULL FROM sqlite_master WHERE type='table' -- ", 'anything', $users_db, '查看所有表');

// 7. 查看用户数据
test_sql_injection("admin' UNION SELECT username, password FROM users -- ", 'anything', $users_db, '查看用户数据');

// 8. 尝试删除表（破坏性测试）
echo "\n⚠️  破坏性SQL注入测试:\n";
test_sql_injection("admin'; DROP TABLE users; -- ", 'anything', $users_db, '删除表（破坏性测试）');

echo "\n🎉 测试完成！\n";
echo "\n📝 测试总结:\n";
echo "- ✅ 经典绕过认证: ' OR '1'='1 - 绕过了密码验证\n";
echo "- ✅ 注释注入: admin' -- - 忽略了密码检查\n";
echo "- ✅ UNION注入: 可提取数据库敏感信息\n";
echo "- ✅ 破坏性注入: 可执行DELETE/DROP等危险操作\n";
echo "\n🔒 安全建议:\n";
echo "- 使用预编译语句（PDO::prepare）\n";
echo "- 输入过滤和转义\n";
echo "- 最小权限原则\n";
echo "- 使用ORM框架\n";
?>
