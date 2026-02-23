/**
 * Aegis 主应用组件
 * 
 * 管理应用的整体布局和认证状态。
 */

import React, { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Login from './components/Login';
import AppShell from './components/AppShell';
import Dashboard from './components/Dashboard';
import TaskList from './components/TaskList';
import VulnerabilityList from './components/VulnerabilityList';
import TargetList from './components/TargetList';
import Discovery from './components/Discovery';
import Reports from './components/Reports';
import Users from './components/Users';
import ScanProfiles from './components/ScanProfiles';
import NewScanModal from './components/NewScanModal';

/**
 * 主应用内容组件（在 AuthProvider 内部）
 */
const AppContent: React.FC = () => {
  const { isAuthenticated, isLoading } = useAuth();
  const [currentPage, setCurrentPage] = useState<'overview' | 'discovery' | 'targets' | 'scans' | 'vulnerabilities' | 'reports' | 'users' | 'settings'>('overview');
  const [isNewScanModalOpen, setIsNewScanModalOpen] = useState(false);

  // 加载中状态
  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#1a1d2e] flex items-center justify-center">
        <div className="text-center">
          <div className="w-12 h-12 border-4 border-[#ff6b00]/30 border-t-[#ff6b00] rounded-full animate-spin mx-auto mb-4"></div>
          <p className="text-gray-400">加载中...</p>
        </div>
      </div>
    );
  }

  // 未登录状态，显示登录页面
  if (!isAuthenticated) {
    return <Login onLoginSuccess={() => {}} />;
  }

  // 已登录状态，显示主应用
  const navItems = [
    {
      icon: 'overview',
      label: 'Overview',
      active: currentPage === 'overview',
      onClick: () => setCurrentPage('overview'),
    },
    {
      icon: 'discovery',
      label: 'Discovery',
      active: currentPage === 'discovery',
      onClick: () => setCurrentPage('discovery'),
    },
    {
      icon: 'targets',
      label: 'Targets',
      active: currentPage === 'targets',
      onClick: () => setCurrentPage('targets'),
    },
    {
      icon: 'scans',
      label: 'Scans',
      active: currentPage === 'scans',
      onClick: () => setCurrentPage('scans'),
    },
    {
      icon: 'vulnerabilities',
      label: 'Vulnerabilities',
      active: currentPage === 'vulnerabilities',
      onClick: () => setCurrentPage('vulnerabilities'),
    },
    {
      icon: 'reports',
      label: 'Reports',
      active: currentPage === 'reports',
      onClick: () => setCurrentPage('reports'),
    },
    
    // SETTINGS 分组
    {
      label: 'SETTINGS',
      variant: 'section-header' as const,
    },
    {
      icon: 'users',
      label: 'Users',
      active: currentPage === 'users',
      onClick: () => setCurrentPage('users'),
    },
    {
      icon: 'settings',
      label: 'Scan Profiles',
      active: currentPage === 'settings',
      onClick: () => setCurrentPage('settings'),
    },
  ];

  const handleNewScanSuccess = () => {
    setCurrentPage('scans');
  };

  const handleViewReport = (taskId: number) => {
    console.log(`Navigating to report for task ${taskId}`);
    setCurrentPage('reports');
  };

  const renderContent = () => {
    switch (currentPage) {
      case 'overview':
        return <Dashboard />;
      case 'discovery':
        return <Discovery />;
      case 'targets':
        return <TargetList />;
      case 'scans':
        return (
          <TaskList
            onCreateTask={() => setIsNewScanModalOpen(true)}
            onViewReport={handleViewReport}
          />
        );
      case 'vulnerabilities':
        return <VulnerabilityList />;
      case 'reports':
        return <Reports />;
      case 'users':
        return <Users />;
      case 'settings':
        return <ScanProfiles />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <>
      <AppShell
        navItems={navItems}
        onNewScan={() => setIsNewScanModalOpen(true)}
      >
        {renderContent()}
      </AppShell>

      <NewScanModal 
        isOpen={isNewScanModalOpen} 
        onClose={() => setIsNewScanModalOpen(false)}
        onSuccess={handleNewScanSuccess}
      />
    </>
  );
};

/**
 * App 根组件
 * 
 * 包裹 AuthProvider 提供认证上下文
 */
const App: React.FC = () => {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
};

export default App;