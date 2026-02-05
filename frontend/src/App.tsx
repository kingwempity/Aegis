import React, { useState } from 'react';
import AppShell from './components/AppShell';
import Dashboard from './components/Dashboard';
import TaskList from './components/TaskList';
import VulnerabilityList from './components/VulnerabilityList';
import TargetList from './components/TargetList';
import NewScanModal from './components/NewScanModal';

const App: React.FC = () => {
  const [currentPage, setCurrentPage] = useState<'overview' | 'discovery' | 'targets' | 'scans' | 'vulnerabilities' | 'reports' | 'users' | 'settings'>('overview');
  const [isNewScanModalOpen, setIsNewScanModalOpen] = useState(false);

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

  const renderContent = () => {
    switch (currentPage) {
      case 'overview':
        return <Dashboard />;
      case 'scans':
        return (
          <TaskList
            onCreateTask={() => setIsNewScanModalOpen(true)}
          />
        );
      case 'vulnerabilities':
        return <VulnerabilityList />;
      case 'targets':
        return <TargetList />;
      default:
        return (
          <div className="w-full h-full flex items-center justify-center bg-white rounded-2xl border border-gray-100 shadow-sm">
            <div className="text-center">
              <div className="text-[#2d3343] text-2xl font-bold mb-2">
                {currentPage.charAt(0).toUpperCase() + currentPage.slice(1)}
              </div>
              <p className="text-gray-400">页面正在根据 Figma 设计稿开发中...</p>
            </div>
          </div>
        );
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

export default App;
