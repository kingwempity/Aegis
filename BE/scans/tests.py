"""
扫描任务管理模块测试
"""
from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from .models import ScanTask, Vulnerability


class ScanTaskAPITestCase(APITestCase):
    """扫描任务API测试"""

    def setUp(self):
        """测试前准备"""
        # 创建测试用户
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # 创建测试任务
        self.task = ScanTask.objects.create(
            task_name='Test Scan',
            target_url='https://example.com',
            created_by=self.user
        )

    def test_create_scan_task(self):
        """测试创建扫描任务"""
        self.client.force_authenticate(user=self.user)

        url = reverse('scans:create')
        data = {
            'target_url': 'https://httpbin.org',
            'task_name': 'API Test Scan',
            'scan_profile': 'quick'
        }

        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('task_id', response.data['data'])

    def test_get_task_list(self):
        """测试获取任务列表"""
        self.client.force_authenticate(user=self.user)

        url = reverse('scans:list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('tasks', response.data['data'])
        self.assertGreaterEqual(len(response.data['data']['tasks']), 1)

    def test_get_task_detail(self):
        """测试获取任务详情"""
        self.client.force_authenticate(user=self.user)

        url = reverse('scans:detail', kwargs={'task_id': self.task.task_id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['data']['task_id'], self.task.task_id)

    def test_cancel_task(self):
        """测试取消任务"""
        self.client.force_authenticate(user=self.user)

        url = reverse('scans:cancel', kwargs={'task_id': self.task.task_id})
        response = self.client.post(url)

        # 任务应该是可以取消的（queued状态）
        if self.task.can_cancel():
            self.assertEqual(response.status_code, status.HTTP_200_OK)
        else:
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)