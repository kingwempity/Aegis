#!/usr/bin/env python
"""
重置管理员账户和初始化系统数据
"""
import os
import sys
import django

# 添加项目路径到系统路径
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')

# 初始化Django
django.setup()

from django.contrib.auth.models import User
from django.core.management import execute_from_command_line
from scans.models import ScanTask, Vulnerability
from stats.models import Statistics


def reset_admin():
    """重置管理员账户"""
    print("重置管理员账户...")

    # 删除现有管理员
    User.objects.filter(is_superuser=True).delete()

    # 创建新的管理员账户
    admin_user = User.objects.create_superuser(
        username='admin',
        email='admin@example.com',
        password='admin123',
        is_active=True
    )

    print(f"管理员账户已重置: {admin_user.username}")

    return admin_user


def create_test_users():
    """创建测试用户"""
    print("创建或更新测试用户...")

    # 获取或创建测试用户
    test_user, created = User.objects.get_or_create(
        username='demo',
        defaults={
            'email': 'demo@example.com',
            'is_active': True
        }
    )

    # 设置密码
    test_user.set_password('Demo123456')
    test_user.save()

    if created:
        print(f"测试用户已创建: {test_user.username}")
    else:
        print(f"测试用户已更新: {test_user.username}")

    return test_user


def init_statistics():
    """初始化统计数据"""
    print("初始化统计数据...")

    # 删除现有统计数据
    Statistics.objects.all().delete()

    # 计算实际统计数据
    total_scans = ScanTask.objects.count()
    vulnerabilities_found = Vulnerability.objects.count()
    critical_vulnerabilities = Vulnerability.objects.filter(risk_level='critical').count()
    active_tasks = ScanTask.objects.filter(status__in=['queued', 'running']).count()

    # 创建统计记录
    stats = Statistics.objects.create(
        total_scans=total_scans,
        vulnerabilities_found=vulnerabilities_found,
        critical_vulnerabilities=critical_vulnerabilities,
        active_tasks=active_tasks,
        system_uptime_hours=0.0
    )

    print(f"统计数据已初始化: 扫描{total_scans}次, 漏洞{vulnerabilities_found}个")

    return stats


def main():
    """主函数"""
    try:
        print("开始重置系统数据...")

        # 重置管理员
        admin_user = reset_admin()

        # 创建测试用户
        test_user = create_test_users()

        # 初始化统计数据
        stats = init_statistics()

        print("\n系统重置完成!")
        print(f"管理员账户: {admin_user.username} / admin123")
        print(f"测试账户: {test_user.username} / Demo123456")

    except Exception as e:
        print(f"重置过程中出现错误: {e}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())