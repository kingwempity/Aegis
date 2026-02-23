import React, { useState, useEffect, useRef } from 'react';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { LayoutDashboard, Target, Shield, FileText, Settings, Bot, Plus, Search, LogOut, HelpCircle, Bell, Compass, Users, X, ExternalLink, BookOpen, MessageCircle, CheckCircle, AlertCircle } from './Icons';

interface NavItemData {
  icon?: React.FC<any> | string;
  label: string;
  active?: boolean;
  onClick?: () => void;
  badge?: string | number;
  variant?: 'default' | 'section-header';
  href?: string;
}

interface AppShellProps {
  children: React.ReactNode;
  currentPage?: string;
  navItems?: NavItemData[];
  breadcrumb?: string;
  userName?: string;
  onNewScan?: () => void;
}

const iconMap: Record<string, React.FC<any>> = {
  overview: LayoutDashboard,
  discovery: Compass,
  targets: Target,
  scans: Shield,
  vulnerabilities: Shield,
  reports: FileText,
  users: Users,
  settings: Settings,
};

const fallbackNavItems: NavItemData[] = [
  { label: 'Dashboard', href: '/', icon: LayoutDashboard },
  { label: 'Targets', href: '/targets', icon: Target },
  { label: 'Scans', href: '/scans', icon: Shield },
  { label: 'Reports', href: '/reports', icon: FileText },
  { label: 'Settings', href: '/settings', icon: Settings },
];

const AppShell: React.FC<AppShellProps> = ({
  children,
  navItems: propNavItems = [],
  onNewScan,
}) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [showHelpModal, setShowHelpModal] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showAllNotifications, setShowAllNotifications] = useState(false);
  const notificationRef = useRef<HTMLDivElement>(null);

  // 模拟通知数据
  const [notifications, setNotifications] = useState([
    { id: 1, type: 'success', title: '扫描完成', message: '目标 example.com 的扫描已完成', time: '5分钟前', read: false },
    { id: 2, type: 'warning', title: '发现漏洞', message: '在 target.com 发现 2 个高危漏洞', time: '15分钟前', read: false },
    { id: 3, type: 'info', title: '系统更新', message: '系统已更新至最新版本 v2.1.0', time: '1小时前', read: true },
  ]);

  // 标记单条通知为已读
  const markAsRead = (id: number) => {
    setNotifications(prev => 
      prev.map(n => n.id === id ? { ...n, read: true } : n)
    );
  };

  // 标记所有通知为已读
  const markAllAsRead = () => {
    setNotifications(prev => prev.map(n => ({ ...n, read: true })));
  };

  // 查看全部通知
  const handleViewAllNotifications = () => {
    setShowNotifications(false);
    setShowAllNotifications(true);
  };

  // 监听窗口大小以自动处理移动端适配
  useEffect(() => {
    const handleResize = () => {
      const mobile = window.innerWidth < 1024;
      if (mobile) setIsSidebarOpen(false);
      else setIsSidebarOpen(true);
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // 点击外部关闭通知面板
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // ESC键关闭模态框
  useEffect(() => {
    const handleEsc = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setShowHelpModal(false);
        setShowNotifications(false);
        setShowAllNotifications(false);
      }
    };
    document.addEventListener('keydown', handleEsc);
    return () => document.removeEventListener('keydown', handleEsc);
  }, []);

  const resolvedNavItems = propNavItems.length > 0 ? propNavItems : fallbackNavItems;

  const unreadCount = notifications.filter(n => !n.read).length;

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'success': return <CheckCircle size={16} className="text-green-500" />;
      case 'warning': return <AlertCircle size={16} className="text-yellow-500" />;
      default: return <AlertCircle size={16} className="text-blue-500" />;
    }
  };

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
          {resolvedNavItems.map((item, index) => {
            if (item.variant === 'section-header') {
              return (
                <div key={`${item.label}-${index}`} className="px-4 pt-4 pb-2 text-xs tracking-wider text-gray-500 font-semibold">
                  {item.label}
                </div>
              );
            }

            const Icon = typeof item.icon === 'string' ? iconMap[item.icon] : item.icon;

            return (
              <button
                key={`${item.label}-${index}`}
                onClick={item.onClick}
                className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-bold transition-all text-left ${
                  item.active
                    ? 'bg-[#ff6b00] text-white shadow-lg shadow-orange-200'
                    : 'text-gray-500 hover:bg-gray-100 hover:text-gray-700'
                }`}
              >
                {Icon ? <Icon size={20} strokeWidth={item.active ? 3 : 2} /> : null}
                <span>{item.label}</span>
              </button>
            );
          })}
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
              <button 
                onClick={() => setShowHelpModal(true)}
                className="text-sm font-medium hover:text-[#ff6b00] transition-colors hidden sm:block"
              >
                查看帮助
              </button>
              <button 
                onClick={() => setShowHelpModal(true)}
                className="p-2 hover:bg-gray-50 rounded-lg transition-colors"
              >
                <HelpCircle size={20} />
              </button>
              <div className="relative" ref={notificationRef}>
                <button 
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="relative p-2 hover:bg-gray-50 rounded-lg transition-colors"
                >
                  <Bell size={20} />
                  {unreadCount > 0 && (
                    <span className="absolute top-1 right-1 w-4 h-4 bg-red-500 rounded-full border-2 border-white text-white text-xs flex items-center justify-center">
                      {unreadCount}
                    </span>
                  )}
                </button>
                
                {/* 通知下拉面板 */}
                {showNotifications && (
                  <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl shadow-2xl border border-gray-100 overflow-hidden z-50">
                    <div className="px-4 py-3 border-b border-gray-100 flex items-center justify-between">
                      <h3 className="font-semibold text-gray-800">通知</h3>
                      {unreadCount > 0 && (
                        <span className="text-xs text-[#ff6b00] font-medium">{unreadCount} 条未读</span>
                      )}
                    </div>
                    <div className="max-h-80 overflow-y-auto">
                      {notifications.map((notification) => (
                        <div 
                          key={notification.id}
                          onClick={() => markAsRead(notification.id)}
                          className={`px-4 py-3 border-b border-gray-50 hover:bg-gray-50 transition-colors cursor-pointer ${
                            !notification.read ? 'bg-orange-50/50' : ''
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <div className="mt-0.5">{getNotificationIcon(notification.type)}</div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-gray-800">{notification.title}</p>
                              <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{notification.message}</p>
                              <p className="text-xs text-gray-400 mt-1">{notification.time}</p>
                            </div>
                            {!notification.read && (
                              <div className="w-2 h-2 bg-[#ff6b00] rounded-full mt-1.5"></div>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="px-4 py-3 border-t border-gray-100 flex gap-2">
                      {unreadCount > 0 && (
                        <button 
                          onClick={markAllAsRead}
                          className="flex-1 text-center text-sm text-gray-500 font-medium hover:text-gray-700 transition-colors"
                        >
                          全部已读
                        </button>
                      )}
                      <button 
                        onClick={handleViewAllNotifications}
                        className="flex-1 text-center text-sm text-[#ff6b00] font-medium hover:text-[#e66000] transition-colors"
                      >
                        查看全部
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        {/* ==================== 内容滚动区域 ==================== */}
        <main className="flex-1 overflow-y-auto p-8 bg-[#f8f9fa]">
          {children}
        </main>
      </div>

      {/* ==================== 全部通知模态框 ==================== */}
      {showAllNotifications && (
        <div 
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setShowAllNotifications(false)}
        >
          <div 
            className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* 模态框头部 */}
            <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-[#ff6b00]/10 rounded-lg flex items-center justify-center">
                  <Bell size={24} className="text-[#ff6b00]" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-gray-800">全部通知</h2>
                  <p className="text-sm text-gray-500">共 {notifications.length} 条通知</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {unreadCount > 0 && (
                  <button 
                    onClick={markAllAsRead}
                    className="px-3 py-1.5 text-sm text-[#ff6b00] font-medium hover:bg-[#ff6b00]/10 rounded-lg transition-colors"
                  >
                    全部标记已读
                  </button>
                )}
                <button 
                  onClick={() => setShowAllNotifications(false)}
                  className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
                >
                  <X size={20} className="text-gray-500" />
                </button>
              </div>
            </div>
            
            {/* 模态框内容 */}
            <div className="max-h-[60vh] overflow-y-auto">
              {notifications.length === 0 ? (
                <div className="py-12 text-center text-gray-500">
                  <Bell size={48} className="mx-auto mb-4 text-gray-300" />
                  <p>暂无通知</p>
                </div>
              ) : (
                notifications.map((notification) => (
                  <div 
                    key={notification.id}
                    onClick={() => markAsRead(notification.id)}
                    className={`px-6 py-4 border-b border-gray-50 hover:bg-gray-50 transition-colors cursor-pointer ${
                      !notification.read ? 'bg-orange-50/50' : ''
                    }`}
                  >
                    <div className="flex items-start gap-4">
                      <div className="mt-1">{getNotificationIcon(notification.type)}</div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <p className="text-base font-semibold text-gray-800">{notification.title}</p>
                          {!notification.read && (
                            <span className="px-2 py-0.5 text-xs bg-[#ff6b00]/10 text-[#ff6b00] rounded-full font-medium">未读</span>
                          )}
                        </div>
                        <p className="text-sm text-gray-600 mt-1">{notification.message}</p>
                        <p className="text-xs text-gray-400 mt-2">{notification.time}</p>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
            
            {/* 模态框底部 */}
            <div className="px-6 py-4 border-t border-gray-100 bg-gray-50">
              <button 
                onClick={() => setShowAllNotifications(false)}
                className="w-full px-4 py-2 bg-[#ff6b00] text-white rounded-lg text-sm font-medium hover:bg-[#e66000] transition-colors"
              >
                关闭
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================== 帮助模态框 ==================== */}
      {showHelpModal && (
        <div 
          className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
          onClick={() => setShowHelpModal(false)}
        >
          <div 
            className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* 模态框头部 */}
            <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between bg-gradient-to-r from-[#ff6b00] to-[#ff8c00]">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
                  <HelpCircle size={24} className="text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">Aegis 帮助中心</h2>
                  <p className="text-sm text-white/80">快速了解系统功能</p>
                </div>
              </div>
              <button 
                onClick={() => setShowHelpModal(false)}
                className="p-2 hover:bg-white/20 rounded-lg transition-colors"
              >
                <X size={20} className="text-white" />
              </button>
            </div>
            
            {/* 模态框内容 */}
            <div className="p-6 max-h-[60vh] overflow-y-auto">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* 快速入门 */}
                <div className="p-4 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors cursor-pointer">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-8 h-8 bg-[#ff6b00]/10 rounded-lg flex items-center justify-center">
                      <BookOpen size={18} className="text-[#ff6b00]" />
                    </div>
                    <h3 className="font-semibold text-gray-800">快速入门</h3>
                  </div>
                  <p className="text-sm text-gray-500">了解如何创建第一个扫描任务，配置扫描目标。</p>
                </div>
                
                {/* 扫描指南 */}
                <div className="p-4 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors cursor-pointer">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-8 h-8 bg-blue-500/10 rounded-lg flex items-center justify-center">
                      <Shield size={18} className="text-blue-500" />
                    </div>
                    <h3 className="font-semibold text-gray-800">扫描指南</h3>
                  </div>
                  <p className="text-sm text-gray-500">学习不同扫描类型的配置方法和最佳实践。</p>
                </div>
                
                {/* 报告解读 */}
                <div className="p-4 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors cursor-pointer">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-8 h-8 bg-green-500/10 rounded-lg flex items-center justify-center">
                      <FileText size={18} className="text-green-500" />
                    </div>
                    <h3 className="font-semibold text-gray-800">报告解读</h3>
                  </div>
                  <p className="text-sm text-gray-500">理解漏洞扫描报告，分析安全风险等级。</p>
                </div>
                
                {/* 联系支持 */}
                <div className="p-4 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors cursor-pointer">
                  <div className="flex items-center gap-3 mb-2">
                    <div className="w-8 h-8 bg-purple-500/10 rounded-lg flex items-center justify-center">
                      <MessageCircle size={18} className="text-purple-500" />
                    </div>
                    <h3 className="font-semibold text-gray-800">联系支持</h3>
                  </div>
                  <p className="text-sm text-gray-500">遇到问题？联系技术支持获取帮助。</p>
                </div>
              </div>
              
              {/* 常用快捷键 */}
              <div className="mt-6 pt-6 border-t border-gray-100">
                <h3 className="font-semibold text-gray-800 mb-3">快捷键</h3>
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">新建扫描</span>
                    <kbd className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">Ctrl + N</kbd>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">搜索</span>
                    <kbd className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">Ctrl + K</kbd>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">帮助</span>
                    <kbd className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">?</kbd>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500">关闭弹窗</span>
                    <kbd className="px-2 py-1 bg-gray-100 rounded text-xs font-mono">Esc</kbd>
                  </div>
                </div>
              </div>
            </div>
            
            {/* 模态框底部 */}
            <div className="px-6 py-4 border-t border-gray-100 bg-gray-50 flex items-center justify-between">
              <a 
                href="#" 
                className="text-sm text-[#ff6b00] font-medium hover:text-[#e66000] flex items-center gap-1 transition-colors"
              >
                查看完整文档
                <ExternalLink size={14} />
              </a>
              <button 
                onClick={() => setShowHelpModal(false)}
                className="px-4 py-2 bg-[#ff6b00] text-white rounded-lg text-sm font-medium hover:bg-[#e66000] transition-colors"
              >
                知道了
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AppShell;
