import React from 'react';

interface NavItemProps {
  icon?: string;
  label: string;
  active?: boolean;
  onClick?: () => void;
  badge?: string | number;
  variant?: 'default' | 'section-header';
}

/**
 * 获取图标 SVG 元素
 * 支持多种常用图标用于导航菜单
 */
const getIcon = (iconName: string) => {
  const icons: Record<string, JSX.Element> = {
    // 仪表盘和概览
    'layout-dashboard': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
      </svg>
    ),
    
    // 列表和任务
    'list': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <line x1="8" y1="6" x2="21" y2="6" />
        <line x1="8" y1="12" x2="21" y2="12" />
        <line x1="8" y1="18" x2="21" y2="18" />
        <line x1="3" y1="6" x2="3.01" y2="6" />
        <line x1="3" y1="12" x2="3.01" y2="12" />
        <line x1="3" y1="18" x2="3.01" y2="18" />
      </svg>
    ),
    
    // 漏洞和安全
    'bug': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
        <circle cx="12" cy="12" r="1" />
      </svg>
    ),
    
    // 盾牌 - 安全
    'shield': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    
    // 用户
    'user': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    ),
    
    // 发现和扫描
    'search': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.35-4.35" />
      </svg>
    ),
    
    // 目标
    'target': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="1" />
        <circle cx="12" cy="12" r="5" />
        <circle cx="12" cy="12" r="9" />
      </svg>
    ),
    
    // 报告
    'file-text': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="12" y1="13" x2="12" y2="17" />
        <line x1="9" y1="15" x2="15" y2="15" />
      </svg>
    ),
    
    // 设置
    'settings': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="3" />
        <path d="M12 1v6m0 6v6M4.22 4.22l4.24 4.24m3.08 3.08l4.24 4.24M1 12h6m6 0h6m-1.78 7.78l-4.24-4.24m-3.08-3.08l-4.24-4.24" />
      </svg>
    ),
  };
  return icons[iconName] || null;
};

/**
 * NavItem 组件
 * 
 * 用于侧边栏导航菜单的单个项目。支持活跃状态、徽章和不同的变体。
 * 
 * @param icon - 图标名称
 * @param label - 菜单项标签
 * @param active - 是否为活跃状态
 * @param onClick - 点击事件处理
 * @param badge - 徽章内容（通常用于显示数字）
 * @param variant - 组件变体（default 或 section-header）
 */
const NavItem: React.FC<NavItemProps> = ({ 
  icon, 
  label, 
  active = false, 
  onClick,
  badge,
  variant = 'default'
}) => {
  // 分组标题样式
  if (variant === 'section-header') {
    return (
      <div className="w-full px-[10px] py-2 mt-2">
        <span className="text-[var(--onDarkMuted)] font-inter text-[11px] font-[600] uppercase tracking-wide">
          {label}
        </span>
      </div>
    );
  }

  return (
    <div
      onClick={onClick}
      className={`
        w-full h-11 flex items-center gap-[10px] px-[10px] py-3 rounded-[6px]
        bg-[#2d2d2d] border border-solid border-[#2b2b2b] cursor-pointer
        transition-all duration-200 hover:bg-[#3d3d3d]
        ${active ? 'bg-[#3d3d3d] border-[#ff4d4f]' : ''}
      `}
    >
      {/* 活跃指示器 */}
      {active && (
        <div className="w-[3px] h-[18px] bg-[#ff4d4f] rounded-[2px]" />
      )}
      
      {/* 图标 */}
      {icon && (
        <div className={`text-[var(--onDarkText)] flex-shrink-0`}>
          {getIcon(icon)}
        </div>
      )}
      
      {/* 标签 */}
      <span className="text-[var(--onDarkText)] font-inter text-[14px] font-[500] flex-1">
        {label}
      </span>
      
      {/* 徽章 */}
      {badge && (
        <div className="flex items-center justify-center min-w-[20px] h-5 px-1.5 bg-[#ff4d4f] rounded-full">
          <span className="text-[var(--onDarkText)] font-inter text-[11px] font-[600]">
            {badge}
          </span>
        </div>
      )}
    </div>
  );
};

export default NavItem;
