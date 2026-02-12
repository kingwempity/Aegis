import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { LayoutDashboard, Target, Shield, FileText, Settings, Bot, Plus, Search, LogOut, HelpCircle, Bell } from './Icons';

interface NavItemData {
  icon?: React.FC<any>; // Changed to React.FC<any> to accept custom icon components
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
  navItems: propNavItems = [], // Rename to avoid conflict with local navItems
  onNewScan
}) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isMobile, setIsMobile] = useState(false);
  const location = useLocation();

  // 监听窗口大小以自动处理移动端适配
  useEffect(() => {
    const handleResize = () => {
      const mobile = window.innerWidth < 1024;
      setIsMobile(mobile);
      if (mobile) setIsSidebarOpen(false);
      else setIsSidebarOpen(true);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const navItems = [
    { name: 'Dashboard', href: '/', icon: LayoutDashboard },
    { name: 'Targets', href: '/targets', icon: Target },
    { name: 'Scans', href: '/scans', icon: Shield },
    { name: 'Reports', href: '/reports', icon: FileText },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  return (
    <div className="flex h-screen bg-[#f8f9fa] overflow-hidden">
      {/* ==================== 侧边栏 ==================== */}
      <aside 
        className={`
          ${isSidebarOpen ? 'w-64' : 'w-20'} 
          h-full bg-[#1a1c23] flex flex-col shadow-2xl z-30 
          transition-all duration-300 ease-in-out relative
        `}
      >
        {/* Logo 区域 */}
        <div className="px-6 py-8 flex items-center gap-3 overflow-hidden">
          <div className="w-8 h-8 bg-[#ff6b00] rounded-lg flex items-center justify-center text-white flex-shrink-0 shadow-lg shadow-orange-500/20">
            <Bot size={20} />
          </div>
          <span className={`text-white text-xl font-bold tracking-tight transition-opacity duration-300 ${isSidebarOpen ? 'opacity-100' : 'opacity-0 w-0'}`}>
            Aegis
          </span>
        </div>

        {/* 导航菜单 */}
        <div className="flex-1 overflow-y-auto py-2 scrollbar-hide">
          {navItems.map((item, index) => (
            <NavLink
              key={index}
              to={item.href}
              className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all ${
                location.pathname === item.href
                  ? 'bg-[#ff6b00] text-white shadow-lg shadow-orange-200'
                  : 'text-gray-500 hover:bg-gray-100 hover:text-gray-700'
              }`}
            >
              <item.icon size={20} strokeWidth={location.pathname === item.href ? 3 : 2} />
              <span>{item.name}</span>
            </NavLink>
          ))}
        </div>

        {/* 侧边栏底部 */}
        <div className="p-6 border-t border-gray-800/50">
          <div className="flex items-center gap-3 text-[#8a92a6] hover:text-white cursor-pointer transition-colors overflow-hidden">
            <div className="flex-shrink-0">
              <LogOut size={20} />
            </div>
            <span className={`text-sm font-medium transition-opacity duration-300 ${isSidebarOpen ? 'opacity-100' : 'opacity-0 w-0'}`}>
              退出登录
            </span>
          </div>
        </div>
      </aside>

      {/* ==================== 主内容区域 ==================== */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* ==================== 顶部导航栏 ==================== */}
        <header className="h-16 bg-white border-b border-gray-100 flex items-center justify-between px-8 z-20 shadow-sm">
          <div className="flex items-center gap-4">
            {/* 折叠按钮 */}
            <button 
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="p-2 hover:bg-gray-50 rounded-lg text-gray-400 transition-colors"
            >
              <svg className={`w-6 h-6 transition-transform duration-300 ${isSidebarOpen ? '' : 'rotate-180'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>

            {/* 搜索框占位 */}
            <div className="relative hidden md:block ml-2">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                <Search size={16} />
              </span>
              <input 
                type="text" 
                placeholder="搜索..." 
                className="pl-10 pr-4 py-1.5 bg-gray-50 border-none rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 w-64 outline-none"
              />
            </div>
          </div>

          <div className="flex items-center gap-6">
            {/* 新建扫描按钮 */}
            <button
              onClick={onNewScan}
              className="bg-[#ff6b00] text-white px-5 py-2 rounded-lg text-sm font-bold flex items-center gap-2 hover:bg-[#e66000] transition-all shadow-lg shadow-orange-500/20"
            >
              <Plus size={16} strokeWidth={3} />
              新扫描
            </button>

            <div className="h-6 w-px bg-gray-200 mx-2"></div>

            {/* 图标按钮组 */}
            <div className="flex items-center gap-4 text-gray-500">
              <button className="text-sm font-medium hover:text-[#ff6b00] transition-colors hidden sm:block">查看帮助</button>
              <button className="p-2 hover:bg-gray-50 rounded-lg transition-colors">
                <HelpCircle size={20} />
              </button>
              <button className="relative p-2 hover:bg-gray-50 rounded-lg transition-colors">
                <Bell size={20} />
                <span className="absolute top-2 right-2 w-2 h-2 bg-red-500 rounded-full border-2 border-white"></span>
              </button>
            </div>
          </div>
        </header>

        {/* ==================== 内容滚动区域 ==================== */}
        <main className="flex-1 overflow-y-auto p-8 bg-[#f8f9fa]">
          {children}
        </main>
      </div>
    </div>
  );
};

export default AppShell;
