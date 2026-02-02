import React, { useState } from 'react';
import AppShell from './components/AppShell';
import Dashboard from './components/Dashboard';
import TaskList from './components/TaskList';

/**
 * App 主应用组件
 * 
 * 管理整个 Aegis DAST 平台的页面路由和状态。
 * 提供 AWVS 风格的导航菜单和页面切换功能。
 */
const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<'dashboard' | 'discovery' | 'targets' | 'scans' | 'vulnerabilities' | 'reports' | 'settings'>('dashboard');

  /**
   * 构建导航菜单项
   * 包括分组标题和各个菜单项
   */
  const navItems = [
    // 主菜单
    {
      icon: 'layout-dashboard',
      label: '概览',
      active: currentPage === 'dashboard',
      onClick: () => setCurrentPage('dashboard'),
      variant: 'default' as const,
    },
    
    // 扫描部分
    {
      label: '扫描',
      variant: 'section-header' as const,
    },
    {
      icon: 'search',
      label: '发现',
      active: currentPage === 'discovery',
      onClick: () => setCurrentPage('discovery'),
      badge: 3,
    },
    {
      icon: 'target',
      label: '目标',
      active: currentPage === 'targets',
      onClick: () => setCurrentPage('targets'),
      badge: 12,
    },
    {
      icon: 'list',
      label: '任务',
      active: currentPage === 'scans',
      onClick: () => setCurrentPage('scans'),
      badge: 2,
    },
    
    // 结果部分
    {
      label: '结果',
      variant: 'section-header' as const,
    },
    {
      icon: 'bug',
      label: '漏洞',
      active: currentPage === 'vulnerabilities',
      onClick: () => setCurrentPage('vulnerabilities'),
      badge: 17,
    },
    {
      icon: 'file-text',
      label: '报告',
      active: currentPage === 'reports',
      onClick: () => setCurrentPage('reports'),
    },
    
    // 管理部分
    {
      label: '管理',
      variant: 'section-header' as const,
    },
    {
      icon: 'settings',
      label: '设置',
      active: currentPage === 'settings',
      onClick: () => setCurrentPage('settings'),
    },
  ];

  /**
   * 处理创建新扫描
   */
  const handleCreateScan = () => {
    console.log('创建新扫描任务');
    // TODO: 打开创建扫描对话框
  };

  /**
   * 处理导入 YAML 配置
   */
  const handleImportYAML = () => {
    console.log('导入 YAML 配置');
    // TODO: 打开导入对话框
  };

  /**
   * 处理创建任务
   */
  const handleCreateTask = () => {
    console.log('创建新任务');
    // TODO: 打开创建任务对话框
  };

  /**
   * 处理查看任务详情
   */
  const handleViewTask = (taskId: string) => {
    console.log('查看任务:', taskId);
    // TODO: 导航到任务详情页面
  };

  /**
   * 处理停止任务
   */
  const handleStopTask = (taskId: string) => {
    console.log('停止任务:', taskId);
    // TODO: 发送停止任务请求
  };

  /**
   * 获取当前页面的标题
   */
  const getPageTitle = () => {
    const titleMap: Record<string, string> = {
      dashboard: '概览',
      discovery: '发现',
      targets: '目标',
      scans: '任务',
      vulnerabilities: '漏洞',
      reports: '报告',
      settings: '设置',
    };
    return titleMap[currentPage] || '概览';
  };

  /**
   * 获取当前页面的面包屑导航
   */
  const getBreadcrumb = () => {
    const breadcrumbMap: Record<string, string> = {
      dashboard: '概览',
      discovery: '扫描 / 发现',
      targets: '扫描 / 目标',
      scans: '扫描 / 任务',
      vulnerabilities: '结果 / 漏洞',
      reports: '结果 / 报告',
      settings: '管理 / 设置',
    };
    return breadcrumbMap[currentPage] || '概览';
  };

  return (
    <AppShell
      currentPage={getPageTitle()}
      navItems={navItems}
      breadcrumb={getBreadcrumb()}
      onNewScan={handleCreateScan}
    >
      {currentPage === 'dashboard' && (
        <Dashboard onCreateScan={handleCreateScan} />
      )}
      {currentPage === 'scans' && (
        <TaskList
          onImportYAML={handleImportYAML}
          onCreateTask={handleCreateTask}
          onViewTask={handleViewTask}
          onStopTask={handleStopTask}
        />
      )}
      {/* 其他页面占位符 */}
      {(currentPage === 'discovery' || currentPage === 'targets' || currentPage === 'vulnerabilities' || currentPage === 'reports' || currentPage === 'settings') && (
        <div className="w-full h-full flex items-center justify-center bg-[var(--card)] rounded-lg border border-[var(--border)]">
          <div className="text-center">
            <div className="text-[var(--titleText)] font-inter text-[24px] font-[700] mb-2">
              {getPageTitle()}
            </div>
            <div className="text-[var(--mutedText)] font-inter text-[14px] font-normal">
              此页面正在开发中...
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
};

export default App;
