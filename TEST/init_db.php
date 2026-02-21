<?php
// 数据库初始化脚本
// 显示测试用户数据（现在使用模拟数据库）

echo "🔧 SQL注入漏洞测试环境初始化\n";
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

echo "✅ 使用模拟数据库（无需外部依赖）\n";
echo "✅ 加载 " . count($users_db) . " 个测试用户成功\n\n";

// 显示所有用户
echo "📋 当前数据库中的用户：\n";
echo str_repeat("-", 60) . "\n";
echo sprintf("%-15s %-15s %-20s %-10s\n", "用户名", "密码", "邮箱", "角色");
echo str_repeat("-", 60) . "\n";

foreach ($users_db as $user) {
    echo sprintf("%-15s %-15s %-20s %-10s\n",
        $user['username'],
        $user['password'],
        $user['email'] ?: 'N/A',
        $user['role']
    );
}

echo "\n🎉 数据库初始化完成！\n";
echo "现在可以访问 http://localhost:8080 来测试SQL注入漏洞\n";
echo "\n📝 测试提示:\n";
echo "- 正常登录: admin / admin123\n";
echo "- SQL注入绕过: ' OR '1'='1 (密码任意)\n";
echo "- 更多测试用例请查看README.md\n";
?>
