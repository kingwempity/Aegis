#!/usr/bin/env python
"""
检查所有URL模式
"""
import os
import sys
import django

# 添加项目路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 配置Django环境
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vuln_scanner.settings')
django.setup()

from django.urls import get_resolver

def show_all_urls():
    """显示所有URL模式"""
    resolver = get_resolver()
    
    def print_urls(urlpatterns, prefix=''):
        for pattern in urlpatterns:
            if hasattr(pattern, 'url_patterns'):
                print_urls(pattern.url_patterns, prefix + str(pattern.pattern))
            else:
                print(f"{prefix}{pattern.pattern} -> {pattern.callback}")

    print_urls(resolver.url_patterns)

if __name__ == '__main__':
    show_all_urls()