import React, { useState } from 'react';
import AppShell from './components/AppShell';
import Dashboard from './components/Dashboard';
import TaskList from './components/TaskList';

const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<'dashboard' | 'tasks'>('dashboard');

  const navItems = [
    {
      icon: 'layout-dashboard',
      label: '概览',
      active: currentPage === 'dashboard',
      onClick: () => setCurrentPage('dashboard')
    },
    {
      icon: 'list',
      label: '任务',
      active: currentPage === 'tasks',
      onClick: () => setCurrentPage('tasks')
    },
    {
      icon: 'bug',
      label: '漏洞',
      active: false,
      onClick: () => console.log('漏洞页面待实现')
    }
  ];

  const handleCreateScan = () => {
    console.log('创建新扫描任务');
  };

  const handleImportYAML = () => {
    console.log('导入 YAML 配置');
  };

  const handleCreateTask = () => {
    console.log('创建新任务');
  };

  const handleViewTask = (taskId: string) => {
    console.log('查看任务:', taskId);
  };

  const handleStopTask = (taskId: string) => {
    console.log('停止任务:', taskId);
  };

  return (
    <AppShell
      currentPage={currentPage === 'dashboard' ? '概览' : '任务'}
      navItems={navItems}
      breadcrumb={currentPage === 'dashboard' ? '概览' : '任务'}
    >
      {currentPage === 'dashboard' ? (
        <Dashboard onCreateScan={handleCreateScan} />
      ) : (
        <TaskList
          onImportYAML={handleImportYAML}
          onCreateTask={handleCreateTask}
          onViewTask={handleViewTask}
          onStopTask={handleStopTask}
        />
      )}
    </AppShell>
  );
};

export default App;