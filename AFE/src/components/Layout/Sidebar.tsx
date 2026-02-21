import React from 'react';
import { Layout, Menu, Avatar } from 'antd';
import {
  DashboardOutlined,
  FileSearchOutlined,
  BarChartOutlined,
  SettingOutlined,
  ExperimentOutlined,
  FileTextOutlined,
  CrownOutlined,
  ThunderboltOutlined
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

const { Sider } = Layout;

interface SidebarProps {
  collapsed: boolean;
  setCollapsed: (collapsed: boolean) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ collapsed, setCollapsed }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();

  const menuItems = [
    {
      key: '/dashboard',
      icon: <DashboardOutlined />,
      label: '仪表板',
    },
    {
      key: '/attack-engine',
      icon: <ThunderboltOutlined />,
      label: '攻击引擎',
    },
    {
      key: '/tasks',
      icon: <FileSearchOutlined />,
      label: '扫描任务',
    },
    {
      key: '/reports',
      icon: <FileTextOutlined />,
      label: '检测报告',
    },
    {
      key: '/statistics',
      icon: <BarChartOutlined />,
      label: '统计分析',
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: '系统设置',
    },
  ];

  // 管理员专用菜单项
  if (user?.role === 'admin') {
    menuItems.splice(1, 0, {
      key: '/admin',
      icon: <CrownOutlined />,
      label: '管理面板',
    });
    menuItems.splice(7, 0, {
      key: '/modules',
      icon: <ExperimentOutlined />,
      label: '漏洞库管理',
    });
  }

  const handleMenuClick = ({ key }: { key: string }) => {
    navigate(key);
  };

  return (
    <Sider
      collapsible
      collapsed={collapsed}
      onCollapse={setCollapsed}
      className="bg-white dark:bg-elegant-800 border-r border-elegant-200 dark:border-elegant-700 shadow-elegant"
      width={260}
      theme="light"
    >
      {/* Logo区域 */}
      <div className="flex items-center justify-center py-8 px-6 border-b border-elegant-200 dark:border-elegant-700">
        <div className="flex items-center space-x-4">
          <div className="w-10 h-10 bg-accent-primary rounded-xl flex items-center justify-center shadow-elegant-lg">
            <span className="text-white text-xl">🔍</span>
          </div>
          {!collapsed && (
            <div className="slide-in-elegant">
              <div className="text-xl font-bold text-accent-primary dark:text-accent-light tracking-tight">
                VulnScanner
              </div>
              <div className="text-sm text-elegant-500 dark:text-elegant-400 mt-1 tracking-wide">
                专业安全检测
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 导航菜单 */}
      <Menu
        mode="inline"
        selectedKeys={[location.pathname]}
        items={menuItems.map(item => ({
          ...item,
          className: location.pathname === item.key ? 'nav-item active' : 'nav-item'
        }))}
        onClick={handleMenuClick}
        className="border-none bg-transparent"
        style={{
          background: 'transparent',
        }}
      />

      {/* 底部用户信息 */}
      {!collapsed && (
        <div className="absolute bottom-0 left-0 right-0 p-6 border-t border-elegant-200 dark:border-elegant-700 bg-elegant-50 dark:bg-elegant-900">
          <div className="flex items-center space-x-4">
            <Avatar
              size="small"
              className="bg-accent-primary shadow-elegant"
              icon={<span className="text-xs text-white">👤</span>}
            />
            <div className="flex-1 min-w-0">
              <div className="text-sm font-medium text-elegant-900 dark:text-elegant-100 truncate tracking-tight">
                {user?.username}
              </div>
              <div className="text-xs text-elegant-500 dark:text-elegant-400 mt-0.5">
                {user?.total_tasks || 0} 个任务
              </div>
            </div>
          </div>
        </div>
      )}
    </Sider>
  );
};

export default Sidebar;
