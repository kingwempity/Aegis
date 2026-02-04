import React from 'react';
import NavItem from './NavItem';

interface NavItemData {
  icon?: string;
  label: string;
  active?: boolean;
  onClick?: () => void;
  badge?: string | number;
  variant?: 'default' | 'section-header';
}

interface AppShellProps {
  children: React.ReactNode;
  currentPage?: string;
  navItems?: NavItemData[];
  breadcrumb?: string;
  userName?: string;
  onNewScan?: () => void;
}

const AppShell: React.FC<AppShellProps> = ({
  children,
  navItems = [],
  onNewScan
}) => {
  return (
    <div className="flex h-screen bg-[#f8f9fa]">
      {/* ==================== 侧边栏 ==================== */}
      <div className="w-64 h-full bg-[#1a1c23] flex flex-col shadow-xl z-20">
        {/* Logo 区域 */}
        <div className="px-6 py-8 flex items-center gap-3">
          <div className="w-8 h-8 bg-[#ff6b00] rounded-lg flex items-center justify-center text-white">
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="text-white text-xl font-bold tracking-tight">Aegis</span>
        </div>

        {/* 导航菜单 */}
        <div className="flex-1 overflow-y-auto py-2">
          {navItems.map((item, index) => (
            <NavItem
              key={index}
              icon={item.icon}
              label={item.label}
              active={item.active}
              onClick={item.onClick}
              badge={item.badge}
              variant={item.variant}
            />
          ))}
        </div>

        {/* 侧边栏底部 */}
        <div className="p-6 border-t border-gray-800">
          <div className="flex items-center gap-3 text-[#8a92a6] hover:text-white cursor-pointer transition-colors">
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <polyline points="16 17 21 12 16 7" />
              <line x1="21" y1="12" x2="9" y2="12" />
            </svg>
            <span className="text-sm font-medium">退出登录</span>
          </div>
        </div>
      </div>

      {/* ==================== 主内容区域 ==================== */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* ==================== 顶部导航栏 ==================== */}
        <header className="h-16 bg-white border-b border-gray-100 flex items-center justify-between px-8 z-10">
          <div className="flex items-center gap-4">
            {/* 搜索框占位 */}
            <div className="relative hidden md:block">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="11" cy="11" r="8" />
                  <path d="m21 21-4.35-4.35" />
                </svg>
              </span>
              <input 
                type="text" 
                placeholder="搜索..." 
                className="pl-10 pr-4 py-1.5 bg-gray-50 border-none rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 w-64"
              />
            </div>
          </div>

          <div className="flex items-center gap-6">
            {/* 新建扫描按钮 */}
            <button
              onClick={onNewScan}
              className="bg-[#ff6b00] text-white px-5 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover:bg-[#e66000] transition-all shadow-lg shadow-orange-500/20"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
              新扫描
            </button>

            <div className="h-6 w-px bg-gray-200 mx-2"></div>

            {/* 图标按钮组 */}
            <div className="flex items-center gap-4 text-gray-500">
              <button className="hover:text-[#ff6b00] transition-colors">查看帮助</button>
              <button className="hover:text-[#ff6b00] transition-colors">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
              </button>
              <button className="relative hover:text-[#ff6b00] transition-colors">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                  <path d="M13.73 21a2 2 0 0 1-3.46 0" />
                </svg>
                <span className="absolute top-0 right-0 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
              </button>
            </div>
          </div>
        </header>

        {/* ==================== 内容滚动区域 ==================== */}
        <main className="flex-1 overflow-y-auto p-8">
          {children}
        </main>
      </div>
    </div>
  );
};

export default AppShell;
