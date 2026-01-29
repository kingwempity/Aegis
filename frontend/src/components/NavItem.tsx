import React from 'react';

interface NavItemProps {
  icon?: string;
  label: string;
  active?: boolean;
  onClick?: () => void;
}

const getIcon = (iconName: string) => {
  const icons: Record<string, JSX.Element> = {
    'layout-dashboard': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" />
        <rect x="14" y="3" width="7" height="7" />
        <rect x="14" y="14" width="7" height="7" />
        <rect x="3" y="14" width="7" height="7" />
      </svg>
    ),
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
    'bug': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M6 9l2-2m4 4l2-2m-8 4l2 2m4-4l2 2" />
        <circle cx="12" cy="12" r="8" />
      </svg>
    ),
    'shield': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      </svg>
    ),
    'user': (
      <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
        <circle cx="12" cy="7" r="4" />
      </svg>
    )
  };
  return icons[iconName] || null;
};

const NavItem: React.FC<NavItemProps> = ({ icon, label, active = false, onClick }) => {
  return (
    <div
      onClick={onClick}
      className={`
        w-full h-11 flex items-center gap-[10px] px-[10px] py-3 rounded-[6px]
        bg-[#2d2d2d] border border-solid border-[#2b2b2b] cursor-pointer
        transition-colors duration-200 hover:bg-[#3d3d3d]
      `}
    >
      {active && (
        <div className="w-[3px] h-[18px] bg-[var(--destructive)] rounded-[2px]" />
      )}
      {icon && (
        <div className="text-[var(--onDarkText)]">
          {getIcon(icon)}
        </div>
      )}
      <span className="text-[var(--onDarkText)] font-inter text-[14px] font-[500]">
        {label}
      </span>
    </div>
  );
};

export default NavItem;