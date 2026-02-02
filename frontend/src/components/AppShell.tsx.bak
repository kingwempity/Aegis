import React from 'react';
import NavItem from './NavItem';

interface AppShellProps {
  children: React.ReactNode;
  currentPage?: string;
  navItems?: Array<{
    icon: string;
    label: string;
    active?: boolean;
    onClick?: () => void;
  }>;
  breadcrumb?: string;
  userName?: string;
}

const AppShell: React.FC<AppShellProps> = ({
  children,
  currentPage = "概览",
  navItems = [],
  breadcrumb = "概览",
  userName = "管理员"
}) => {
  return (
    <div className="flex h-screen bg-[var(--background)]">
      {/* Sidebar */}
      <div className="w-60 h-full bg-[#2d2d2d] border-r border-solid border-[var(--sidebarBorder)] flex flex-col gap-3 p-4">
        {/* Brand */}
        <div className="w-full h-10 flex items-center gap-[10px] bg-[#2d2d2d]">
          <div className="text-[var(--onDarkText)]">
            <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <span className="text-[var(--onDarkText)] font-inter text-[16px] font-[700]">
            Aegis
          </span>
        </div>

        {/* Navigation */}
        <div className="flex-1 w-full bg-[#2d2d2d] flex flex-col gap-[6px]">
          {navItems.map((item, index) => (
            <NavItem
              key={index}
              icon={item.icon}
              label={item.label}
              active={item.active}
              onClick={item.onClick}
            />
          ))}
        </div>

        {/* Footer */}
        <div className="w-full bg-[#2d2d2d] flex flex-col gap-1">
          <div className="text-[var(--onDarkMuted)] font-inter text-[12px] font-[500]">
            DAST 扫描器
          </div>
          <div className="text-[var(--onDarkMuted)] font-inter text-[12px] font-normal">
            v1.0
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 h-full bg-[#f5f5f5] flex flex-col">
        {/* Header */}
        <div className="w-full h-14 bg-[#000000] border-b border-solid border-[var(--border)] flex items-center justify-between px-4 py-[16px]">
          <div className="text-[#ffffff] font-inter text-[14px] font-[600]">
            {breadcrumb}
          </div>
          <div className="flex items-center gap-[10px]">
            <div className="text-[#ffffff]">
              <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
            </div>
            <span className="text-[#ffffff] font-inter text-[14px] font-normal">
              {userName}
            </span>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 flex flex-col gap-4 p-6 overflow-auto">
          {children}
        </div>
      </div>
    </div>
  );
};

export default AppShell;