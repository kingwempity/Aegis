import React from 'react';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { 
  LayoutDashboard, 
  Search, 
  Target, 
  ShieldCheck, 
  AlertTriangle, 
  FileText, 
  Settings, 
  Bot 
} from './Icons';

interface NavItemProps {
  icon?: string;
  label: string;
  active?: boolean;
  onClick?: () => void;
  badge?: string | number;
  variant?: 'default' | 'section-header';
  isCollapsed?: boolean;
}

const getIcon = (iconName: string) => {
  const iconProps = { size: 20, strokeWidth: 2 };
  const icons: Record<string, JSX.Element> = {
    'overview': <LayoutDashboard {...iconProps} />,
    'discovery': <Search {...iconProps} />,
    'targets': <Target {...iconProps} />,
    'scans': <ShieldCheck {...iconProps} />,
    'vulnerabilities': <AlertTriangle {...iconProps} />,
    'reports': <FileText {...iconProps} />,
    'users': <Bot {...iconProps} />,
    'settings': <Settings {...iconProps} />,
  };
  return icons[iconName] || null;
};

const NavItem: React.FC<NavItemProps> = ({ 
  icon, 
  label, 
  active = false, 
  onClick,
  badge,
  variant = 'default',
  isCollapsed = false
}) => {
  if (variant === 'section-header') {
    return (
      <div className={`px-6 py-4 mt-4 transition-opacity duration-300 ${isCollapsed ? 'opacity-0 h-0 py-0 mt-0' : 'opacity-100'}`}>
        <span className="text-[#4e5d78] text-[11px] font-bold uppercase tracking-widest whitespace-nowrap">
          {label}
        </span>
      </div>
    );
  }

  return (
    <div
      onClick={onClick}
      className={`
        group flex items-center px-6 py-3 cursor-pointer transition-all duration-300
        ${active ? 'bg-[#2d3343] text-white' : 'text-[#8a92a6] hover:text-white hover:bg-[#2d3343]/50'}
        ${isCollapsed ? 'justify-center px-0' : 'gap-4'}
      `}
      title={isCollapsed ? label : ''}
    >
      {icon && (
        <div className={`flex-shrink-0 transition-transform duration-200 ${active ? 'text-white scale-110' : 'text-[#8a92a6] group-hover:text-white group-hover:scale-110'}`}>
          {getIcon(icon)}
        </div>
      )}
      
      {!isCollapsed && (
        <>
          <span className="flex-1 text-[14px] font-medium whitespace-nowrap overflow-hidden transition-opacity duration-300">
            {label}
          </span>

          {badge && (
            <div className="bg-[#ff6b00] text-white text-[10px] font-bold px-1.5 py-0.5 rounded">
              {badge}
            </div>
          )}

          {!badge && (
            <svg className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="9 18 15 12 9 6" />
            </svg>
          )}
        </>
      )}
    </div>
  );
};

export default NavItem;
