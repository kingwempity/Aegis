import React, { useMemo, useState } from 'react';
import { Layout, Avatar, Dropdown, Button, Space, Badge, Drawer, List, Tag, Typography, Empty } from 'antd';
import {
  MenuUnfoldOutlined,
  MenuFoldOutlined,
  UserOutlined,
  LogoutOutlined,
  SettingOutlined,
  MoonOutlined,
  SunOutlined,
  BellOutlined
} from '@ant-design/icons';
import { useAuth } from '../../hooks/useAuth';
import { useTheme } from '../../contexts/ThemeContext';
import { useNavigate } from 'react-router-dom';

const { Header: AntHeader } = Layout;
const { Text } = Typography;

interface HeaderProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

const Header: React.FC<HeaderProps> = ({ collapsed, setCollapsed }) => {
  const { user, logout } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [notifications, setNotifications] = useState(
    [
      { id: 'n1', title: '任务完成', content: '扫描任务 #20250110 已完成，请查看报告。', type: 'task', read: false, time: '刚刚' },
      { id: 'n2', title: '系统更新', content: '漏洞库已更新，包含最新注入与XSS规则。', type: 'system', read: false, time: '10 分钟前' },
      { id: 'n3', title: '安全提醒', content: '检测到异常登录尝试，如非本人操作请尽快修改密码。', type: 'security', read: true, time: '1 小时前' }
    ]
  );

  const unreadCount = useMemo(() => notifications.filter(n => !n.read).length, [notifications]);

  const handleMenuClick = ({ key }: { key: string }) => {
    switch (key) {
      case 'profile':
        navigate('/profile');
        break;
      case 'settings':
        navigate('/settings');
        break;
      case 'logout':
        logout();
        break;
      default:
        break;
    }
  };

  const handleOpenNotifications = () => {
    setNotificationOpen(true);
    // 打开时将未读标记为已读
    if (unreadCount > 0) {
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
    }
  };

  const handleMarkAllRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  const renderTag = (type: string) => {
    switch (type) {
      case 'task':
        return <Tag color="blue">任务</Tag>;
      case 'system':
        return <Tag color="green">系统</Tag>;
      case 'security':
        return <Tag color="red">安全</Tag>;
      default:
        return <Tag>通知</Tag>;
    }
  };

  const userMenuItems = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: '个人资料',
    },
    {
      key: 'settings',
      icon: <SettingOutlined />,
      label: '设置',
    },
    {
      type: 'divider' as const,
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      danger: true,
    },
  ];

  return (
    <AntHeader className="bg-white dark:bg-elegant-800 border-b border-elegant-200 dark:border-elegant-700 px-8 flex items-center justify-between shadow-elegant">
      {/* 左侧：折叠按钮和标题 */}
      <div className="flex items-center">
        <Button
          type="text"
          icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
          onClick={() => setCollapsed(!collapsed)}
          className="text-elegant-600 dark:text-elegant-300 hover:bg-elegant-100 dark:hover:bg-elegant-700 rounded-xl transition-all duration-300"
        />
        <div className="ml-6">
          <h1 className="text-2xl font-bold text-accent-primary dark:text-accent-light tracking-tight">
            🔍 漏洞检测系统
          </h1>
          <p className="text-sm text-elegant-500 dark:text-elegant-400 mt-1 tracking-wide">
            基于模拟攻击的安全检测平台
          </p>
        </div>
      </div>

      {/* 右侧：功能按钮和用户信息 */}
      <div className="flex items-center space-x-3">
        {/* 通知按钮 */}
        <Badge count={unreadCount} size="small">
          <Button
            type="text"
            icon={<BellOutlined />}
            className="text-elegant-600 dark:text-elegant-300 hover:bg-elegant-100 dark:hover:bg-elegant-700 rounded-xl transition-all duration-300"
            onClick={handleOpenNotifications}
          />
        </Badge>

        {/* 主题切换按钮 */}
        <Button
          type="text"
          icon={isDark ? <SunOutlined /> : <MoonOutlined />}
          onClick={toggleTheme}
          className="text-elegant-600 dark:text-elegant-300 hover:bg-elegant-100 dark:hover:bg-elegant-700 rounded-xl transition-all duration-300"
          title={isDark ? '切换到亮色模式' : '切换到暗色模式'}
        />

        {/* 用户菜单 */}
        <Dropdown
          menu={{ items: userMenuItems, onClick: handleMenuClick }}
          placement="bottomRight"
          trigger={['click']}
        >
          <div className="flex items-center cursor-pointer hover:bg-elegant-100 dark:hover:bg-elegant-700 px-4 py-3 rounded-xl transition-all duration-300 hover:shadow-elegant">
            <Avatar
              icon={<UserOutlined />}
              className="bg-accent-primary mr-4"
              size="small"
            />
            <div className="hidden sm:block">
              <div className="text-sm font-medium text-elegant-900 dark:text-elegant-100 tracking-tight">
                {user?.username || '用户'}
              </div>
              <div className="text-xs text-elegant-500 dark:text-elegant-400 mt-0.5">
                {user?.role === 'admin' ? '管理员' : '普通用户'}
              </div>
            </div>
          </div>
        </Dropdown>
      </div>

      <Drawer
        title="消息通知"
        placement="right"
        width={360}
        onClose={() => setNotificationOpen(false)}
        open={notificationOpen}
        extra={
          <Button type="link" size="small" onClick={handleMarkAllRead}>
            全部已读
          </Button>
        }
      >
        {notifications.length === 0 ? (
          <Empty description="暂无通知" />
        ) : (
          <List
            itemLayout="vertical"
            dataSource={notifications}
            renderItem={(item) => (
              <List.Item>
                <List.Item.Meta
                  title={
                    <Space>
                      {renderTag(item.type)}
                      <Text strong>{item.title}</Text>
                    </Space>
                  }
                  description={<Text type="secondary">{item.time}</Text>}
                />
                <Text>{item.content}</Text>
              </List.Item>
            )}
          />
        )}
      </Drawer>
    </AntHeader>
  );
};

export default Header;
