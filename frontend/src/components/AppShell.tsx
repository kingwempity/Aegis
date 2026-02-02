import React, { useState } from 'react';
import NavItem from './NavItem';

interface NavItem {
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
  navItems?: NavItem[];
  breadcrumb?: string;
  userName?: string;
  onNewScan?: () => void;
}

/**
 * AppShell 组件
 * 
 * Aegis DAST 平台的主容器组件，提供 AWVS 风格的布局框架。
 * 包含深色侧边栏、顶部导航栏和主内容区域。
 * 
 * @param children - 主内容区域的子组件
 * @param currentPage - 当前页面标题
 * @param navItems - 导航菜单项数组
 * @param breadcrumb - 面包屑导航文本
 * @param userName - 当前登录用户名
 * @param onNewScan - 新建扫描按钮的点击事件处理
 */
const AppShell: React.FC<AppShellProps> = ({
  children,
  currentPage = "概览",
  navItems = [],
  breadcrumb = "概览",
  userName = "管理员",
  onNewScan
}) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-[var(--background)]">
      {/* ==================== 侧边栏 ==================== */}
      <div className={`
        ${sidebarCollapsed ? 'w-20' : 'w-60'} 
        h-full bg-[#2d2d2d] border-r border-solid border-[var(--sidebarBorder)] 
        flex flex-col gap-3 p-4 transition-all duration-300
      `}>
        {/* 品牌区域 */}
        <div className="w-full h-10 flex items-center gap-[10px] bg-[#2d2d2d]">
          <div className="text-[var(--onDarkText)] flex-shrink-0">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          {!sidebarCollapsed && (
            <span className="text-[var(--onDarkText)] font-inter text-[16px] font-[700]">
              Aegis
            </span>
          )}
        </div>

        {/* 导航菜单 */}
        <div className="flex-1 w-full bg-[#2d2d2d] flex flex-col gap-[6px] overflow-y-auto">
          {navItems.map((item, index) => (
            <NavItem
              key={index}
              icon={item.icon}
              label={sidebarCollapsed ? '' : item.label}
              active={item.active}
              onClick={item.onClick}
              badge={item.badge}
              variant={item.variant}
            />
          ))}
        </div>

        {/* 侧边栏底部 */}
        <div className="w-full bg-[#2d2d2d] flex flex-col gap-1 border-t border-[#3d3d3d] pt-3">
          {!sidebarCollapsed && (
            <>
              <div className="text-[var(--onDarkMuted)] font-inter text-[12px] font-[500]">
                DAST 扫描器
              </div>
              <div className="text-[var(--onDarkMuted)] font-inter text-[12px] font-normal">
                v1.0
              </div>
            </>
          )}
        </div>
      </div>

      {/* ==================== 主内容区域 ==================== */}
      <div className="flex-1 h-full bg-[#f5f5f5] flex flex-col">
        {/* ==================== 顶部导航栏 ==================== */}
        <div className="w-full h-14 bg-[#000000] border-b border-solid border-[var(--border)] flex items-center justify-between px-6 py-[16px]">
          {/* 左侧：面包屑和页面标题 */}
          <div className="flex items-center gap-4">
            {/* 侧边栏折叠按钮 */}
            <button
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
              className="text-[#ffffff] hover:text-[#cccccc] transition-colors"
              title={sidebarCollapsed ? '展开侧边栏' : '折叠侧边栏'}
            >
              <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>
            
            <div className="text-[#ffffff] font-inter text-[14px] font-[600]">
              {breadcrumb}
            </div>
          </div>

          {/* 右侧：用户菜单和操作 */}
          <div className="flex items-center gap-6">
            {/* 通知图标 */}
            <button className="text-[#ffffff] hover:text-[#cccccc] transition-colors relative">
              <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
                <path d="M13.73 21a2 2 0 0 1-3.46 0" />
              </svg>
              {/* 通知徽章 */}
              <div className="absolute top-0 right-0 w-2 h-2 bg-[#ff4d4f] rounded-full"></div>
            </button>

            {/* 用户菜单 */}
            <div className="flex items-center gap-3 pl-6 border-l border-[#333333]">
              <div className="text-[#ffffff]">
                <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                  <circle cx="12" cy="7" r="4" />
                </svg>
              </div>
              <span className="text-[#ffffff] font-inter text-[14px] font-normal">
                {userName}
              </span>
              <button className="text-[#ffffff] hover:text-[#cccccc] transition-colors">
                <svg className="w-[16px] h-[16px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </button>
            </div>
          </div>
        </div>

        {/* ==================== 主内容区域 ==================== */}
        <div className="flex-1 flex flex-col gap-4 p-6 overflow-auto">
          {children}
        </div>
      </div>
    </div>
  );
};

export default AppShell;
