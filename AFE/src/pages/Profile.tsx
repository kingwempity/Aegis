import React, { useEffect, useMemo, useState } from 'react';
import { Card, Avatar, Tag, List, Space, Button, Skeleton, message, Descriptions, Row, Col, Statistic } from 'antd';
import { UserOutlined, ReloadOutlined, MailOutlined, CrownOutlined, CalendarOutlined, SafetyOutlined } from '@ant-design/icons';
import { useAuth } from '../hooks/useAuth';
import { apiService } from '../services/api';
import { User } from '../types';

interface ProfileData extends User {
  total_vulnerabilities?: number;
  recent_scans?: Array<{
    task_id: string;
    task_name: string;
    status: string;
    created_at: string;
    vulnerabilities_found?: number;
  }>;
}

const Profile: React.FC = () => {
  const { user } = useAuth();
  const [profile, setProfile] = useState<ProfileData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const fetchProfile = async () => {
    setLoading(true);
    try {
      const data = await apiService.getCurrentUser();
      setProfile(data as ProfileData);
    } catch (error) {
      console.error('获取个人资料失败', error);
      message.error('加载个人资料失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  const displayUser = profile || user;

  const stats = useMemo(
    () => [
      { title: '创建任务数', value: displayUser?.total_tasks ?? 0 },
      { title: '扫描总数', value: displayUser?.total_scans ?? 0 },
      { title: '发现漏洞数', value: profile?.total_vulnerabilities ?? 0 },
      { title: '角色', value: displayUser?.role === 'admin' ? '管理员' : '普通用户' },
    ],
    [displayUser, profile]
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">个人资料</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">查看账户信息和近期扫描记录</p>
        </div>
        <Button icon={<ReloadOutlined />} onClick={fetchProfile} loading={loading}>
          刷新
        </Button>
      </div>

      <Card className="card-retro">
        <Skeleton loading={loading} active avatar paragraph={{ rows: 2 }}>
          <div className="flex items-center space-x-4">
            <Avatar size={72} icon={<UserOutlined />} className="bg-brand-primary" />
            <div>
              <div className="flex items-center space-x-3">
                <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">{displayUser?.username}</h2>
                <Tag color={displayUser?.role === 'admin' ? 'gold' : 'blue'}>
                  {displayUser?.role === 'admin' ? '管理员' : '普通用户'}
                </Tag>
              </div>
              <Space size="middle" className="text-sm text-gray-600 dark:text-gray-400">
                <span>
                  <MailOutlined className="mr-1" />
                  {displayUser?.email || '未填写邮箱'}
                </span>
                <span>
                  <CalendarOutlined className="mr-1" />
                  加入时间：{displayUser?.created_at ? new Date(displayUser.created_at).toLocaleString() : '未知'}
                </span>
              </Space>
            </div>
          </div>
        </Skeleton>
      </Card>

      <Row gutter={[16, 16]}>
        {stats.map((item) => (
          <Col xs={24} sm={12} md={6} key={item.title}>
            <Card className="card-retro">
              <Statistic title={item.title} value={item.value} valueStyle={{ fontWeight: 600 }} />
            </Card>
          </Col>
        ))}
      </Row>

      <Card title="账户详情" className="card-retro">
        <Skeleton loading={loading} active paragraph={{ rows: 4 }}>
          <Descriptions column={1} colon>
            <Descriptions.Item label="用户名">{displayUser?.username}</Descriptions.Item>
            <Descriptions.Item label="邮箱">{displayUser?.email || '未填写'}</Descriptions.Item>
            <Descriptions.Item label="角色">
              <Space>
                <CrownOutlined />
                {displayUser?.role === 'admin' ? '管理员' : '普通用户'}
              </Space>
            </Descriptions.Item>
            <Descriptions.Item label="账户创建时间">
              {displayUser?.created_at ? new Date(displayUser.created_at).toLocaleString() : '未知'}
            </Descriptions.Item>
          </Descriptions>
        </Skeleton>
      </Card>

      <Card title="近期扫描任务" className="card-retro">
        <Skeleton loading={loading} active paragraph={{ rows: 4 }}>
          <List
            dataSource={profile?.recent_scans || []}
            locale={{ emptyText: '暂无近期任务' }}
            renderItem={(item) => (
              <List.Item>
                <List.Item.Meta
                  title={
                    <Space>
                      <SafetyOutlined className="text-brand-primary" />
                      <span>{item.task_name || item.task_id}</span>
                      <Tag color="blue">{item.status}</Tag>
                    </Space>
                  }
                  description={
                    <Space size="middle">
                      <span>任务ID：{item.task_id}</span>
                      <span>创建时间：{new Date(item.created_at).toLocaleString()}</span>
                      <span>发现漏洞：{item.vulnerabilities_found ?? 0}</span>
                    </Space>
                  }
                />
              </List.Item>
            )}
          />
        </Skeleton>
      </Card>
    </div>
  );
};

export default Profile;

