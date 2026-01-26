/**
 * 主应用组件
 * 配置路由和整体布局
 */
import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import Sidebar from './components/Layout/Sidebar';
import Header from './components/Layout/Header';
import Dashboard from './pages/Dashboard';
import TaskList from './pages/TaskList';
import TaskDetail from './pages/TaskDetail';
import VulnAudit from './pages/VulnAudit';
import './App.css';

const App: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);

  return (
    <ConfigProvider
      locale={zhCN}
      theme={{
        token: {
          colorPrimary: '#1677ff',
          borderRadius: 4,
          colorBgContainer: '#ffffff',
          colorText: '#262626',
          colorTextSecondary: '#595959',
          colorBorder: '#d9d9d9',
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
        },
        algorithm: theme.defaultAlgorithm,
      }}
    >
      <BrowserRouter>
        <div style={{ display: 'flex', minHeight: '100vh' }}>
          <Sidebar collapsed={collapsed} onCollapse={setCollapsed} />
          <div
            style={{
              marginLeft: collapsed ? 80 : 200,
              width: '100%',
              transition: 'margin-left 0.2s',
            }}
          >
            <Header collapsed={collapsed} />
            <div style={{ marginTop: 64 }}>
              <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/tasks" element={<TaskList />} />
                <Route path="/tasks/:id" element={<TaskDetail />} />
                <Route path="/vulnerabilities" element={<VulnAudit />} />
                <Route path="/vulnerabilities/:id" element={<VulnAudit />} />
                <Route path="/reports" element={<div style={{ padding: 24 }}>报告中心（待实现）</div>} />
                <Route path="/settings" element={<div style={{ padding: 24 }}>设置（待实现）</div>} />
              </Routes>
            </div>
          </div>
        </div>
      </BrowserRouter>
    </ConfigProvider>
  );
};

export default App;
