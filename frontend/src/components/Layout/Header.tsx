/**
 * 顶部导航栏组件
 * 简约风格，包含面包屑、搜索和用户信息
 */
import React from 'react';
import { Layout, Breadcrumb, Input, Avatar, Dropdown, Space } from 'antd';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  UserOutlined,
  LogoutOutlined,
  SettingOutlined,
  SearchOutlined,
} from '@ant-design/icons';
import type { MenuProps } from 'antd';

const { Header: AntHeader } = Layout;
const { Search } = Input;

interface HeaderProps {
  collapsed: boolean;
}

const Header: React.FC<HeaderProps> = ({ collapsed }) => {
  const location = useLocation();
  const navigate = useNavigate();

  // 根据路径生成面包屑
  const getBreadcrumbItems = () => {
    const pathSnippets = location.pathname.split('/').filter((i) => i);
    const breadcrumbNameMap: Record<string, string> = {
      dashboard: '仪表盘',
      tasks: '任务管理',
      vulnerabilities: '漏洞审计',
      reports: '报告中心',
      settings: '设置',
    };

    const items = [{ title: '首页' }];
    pathSnippets.forEach((_, index) => {
      const url = `/${pathSnippets.slice(0, index + 1).join('/')}`;
      const title = breadcrumbNameMap[pathSnippets[index]] || pathSnippets[index];
      items.push({ title, href: url });
    });

    return items;
  };

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'profile',
      icon: <UserOutlined />,
      label: '个人中心',
    },
    {
      key: 'settings',
      icon: <SettingOutlined />,
      label: '设置',
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      danger: true,
    },
  ];

  const handleUserMenuClick: MenuProps['onClick'] = ({ key }) => {
    if (key === 'logout') {
      // 处理退出登录
      console.log('退出登录');
    } else if (key === 'settings') {
      navigate('/settings');
    }
  };

  return (
    <AntHeader
      style={{
        padding: '0 24px',
        background: '#ffffff',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: '1px solid #e8e8e8',
        position: 'fixed',
        top: 0,
        left: collapsed ? 80 : 200,
        right: 0,
        zIndex: 1000,
        height: 64,
      }}
    >
      <Breadcrumb
        items={getBreadcrumbItems()}
        style={{ fontSize: 14 }}
      />
      <Space size="middle">
        <Search
          placeholder="搜索任务、漏洞..."
          allowClear
          style={{ width: 300 }}
          prefix={<SearchOutlined />}
          onSearch={(value) => {
            console.log('搜索:', value);
          }}
        />
        <Dropdown
          menu={{ items: userMenuItems, onClick: handleUserMenuClick }}
          placement="bottomRight"
        >
          <Space style={{ cursor: 'pointer' }}>
            <Avatar
              style={{ backgroundColor: '#1677ff' }}
              icon={<UserOutlined />}
            />
            <span style={{ color: '#262626' }}>Admin User</span>
          </Space>
        </Dropdown>
      </Space>
    </AntHeader>
  );
};

export default Header;
