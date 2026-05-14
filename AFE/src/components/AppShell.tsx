import React, { useState, useEffect, useRef, useCallback } from 'react';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { LayoutDashboard, Target, Shield, FileText, Settings, Bot, Plus, Search, LogOut, HelpCircle, Bell, Compass, Users, X, ExternalLink, BookOpen, MessageCircle, CheckCircle, AlertCircle, KeyRound, FlaskConical } from './Icons';
import ChangePasswordModal from './ChangePasswordModal';
import { api } from '../api';
import type { HelpContent, Notification } from '../api';

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
  onLogout?: () => void;
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
  lab: FlaskConical,
};

const fallbackNavItems: NavItemData[] = [
  { label: 'Dashboard', href: '/', icon: LayoutDashboard },
  { label: 'Targets', href: '/targets', icon: Target },
  { label: 'Attack Validation', href: '/scans', icon: Shield },
  { label: 'Attack Reports', href: '/reports', icon: FileText },
  { label: 'Settings', href: '/settings', icon: Settings },
];

/** 通知已读状态存储 Key */
const NOTIFICATION_READ_KEY = 'aegis_notification_read_ids';

const AppShell: React.FC<AppShellProps> = ({
  children,
  navItems: propNavItems = [],
  onNewScan,
  onLogout,
}) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [showHelpModal, setShowHelpModal] = useState(false);
  const [showNotifications, setShowNotifications] = useState(false);
  const [showAllNotifications, setShowAllNotifications] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);
  const notificationRef = useRef<HTMLDivElement>(null);
  
  // 帮助内容相关状态
  const [helpContents, setHelpContents] = useState<HelpContent[]>([]);
  const [helpLoading, setHelpLoading] = useState(false);
  const [selectedHelpContent, setSelectedHelpContent] = useState<HelpContent | null>(null);

  // 获取帮助内容
  const fetchHelpContents = async () => {
    try {
      setHelpLoading(true);
      const data = await api.getHelpContents(true); // 只获取启用的内容
      console.log('[AppShell] Fetched help contents:', data);
      setHelpContents(data);
    } catch (error) {
      console.error('[AppShell] Failed to fetch help contents:', error);
      // 如果获取失败，尝试初始化默认内容
      try {
        await api.initDefaultHelpContents();
        // 重新获取
        const data = await api.getHelpContents(true);
        setHelpContents(data);
      } catch (initError) {
        console.error('[AppShell] Failed to init default help contents:', initError);
      }
    } finally {
      setHelpLoading(false);
    }
  };

  // 当帮助模态框打开时获取数据
  useEffect(() => {
    if (showHelpModal) {
      fetchHelpContents();
    }
  }, [showHelpModal]);

  // ==================== 通知相关状态 ====================
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [selectedNotifyCategory, setSelectedNotifyCategory] = useState<string>('all');
  const wsRef = useRef<WebSocket | null>(null);
  const wsReconnectTimerRef = useRef<number | undefined>(undefined);

  // 获取通知列表 (HTTP 轮询作为降级方案)
  const fetchNotifications = useCallback(async (category?: string) => {
    try {
      setNotificationsLoading(true);
      const cat = category !== 'all' ? category : undefined;
      const response = await api.getNotifications(cat);
      setNotifications(response.notifications);
      setUnreadCount(response.unread_count);
    } catch (error) {
      console.error('[AppShell] Failed to fetch notifications:', error);
    } finally {
      setNotificationsLoading(false);
    }
  }, []);

  // WebSocket 重连延迟管理（指数退避）
  const wsReconnectDelayRef = useRef<number>(5000);

  // 重置重连延迟
  const resetReconnectDelay = useCallback(() => {
    wsReconnectDelayRef.current = 5000;
  }, []);

  // 增加重连延迟（最多 60 秒）
  const increaseReconnectDelay = useCallback(() => {
    wsReconnectDelayRef.current = Math.min(wsReconnectDelayRef.current * 2, 60000);
  }, []);

  // 建立 WebSocket 实时连接
  const connectWebSocket = useCallback(() => {
    // 如果已有连接则不重复建立
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      resetReconnectDelay();
      return;
    }

    // 获取认证令牌
    const token = localStorage.getItem('aegis_token');
    
    // 根据当前页面协议和主机构建 WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/notifications${token ? `?token=${encodeURIComponent(token)}` : ''}`;

    try {
      console.log('[AppShell] Connecting to WebSocket:', wsUrl.replace(token || '', '***'));
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[AppShell] WebSocket connected successfully');
        resetReconnectDelay();
        fetchNotifications();
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          
          if (message.type === 'notification') {
            // 实时推送的新通知
            const newNotification: Notification = message.data;
            console.log('[AppShell]  New notification received via WebSocket:', newNotification.title);

            setNotifications(prev => {
              // 防止重复添加（用 id 去重）
              if (prev.some(n => n.id === newNotification.id)) {
                return prev;
              }
              return [newNotification, ...prev];
            });
            // 仅在通知为未读状态时才增加未读计数
            if (!newNotification.read) {
              setUnreadCount(prev => prev + 1);
            }
          } else if (message.type === 'heartbeat') {
            // 心跳消息，忽略
          } else if (message.type === 'connection_established') {
            console.log('[AppShell] WebSocket connection confirmed:', message.data);
          } else if (message.type === 'unread_count') {
            // 未读数更新
            setUnreadCount(message.data.unread_count);
          }
        } catch (e) {
          console.error('[AppShell] Failed to parse WebSocket message:', e);
        }
      };

      ws.onclose = (event) => {
        wsRef.current = null;
        
        // 1000: 正常关闭, 1001: 离开, 1005: 未指定状态码
        if (event.code === 1000 || event.code === 1001 || event.code === 1005) {
          console.log('[AppShell] WebSocket closed normally, code:', event.code);
          return;
        }

        // 1006: 异常断开（网络问题、服务器重启、代理配置错误等）
        const reason = event.code === 1006 
          ? 'Abnormal closure (network/server/proxy issue)' 
          : (event.reason || 'N/A');
        console.warn('[AppShell] WebSocket disconnected, code:', event.code, '- reason:', reason);

        increaseReconnectDelay();
        const delay = wsReconnectDelayRef.current;
        console.log(`[AppShell] Reconnecting in ${delay / 1000}s...`);
        
        wsReconnectTimerRef.current = setTimeout(() => {
          connectWebSocket();
        }, delay);
      };

      ws.onerror = (error) => {
        console.error('[AppShell] WebSocket error (check network/proxy config)');
      };
    } catch (error) {
      console.error('[AppShell] Failed to create WebSocket:', error);
      // 连接失败，指数退避重试
      increaseReconnectDelay();
      wsReconnectTimerRef.current = setTimeout(() => {
        connectWebSocket();
      }, wsReconnectDelayRef.current);
    }
  }, [fetchNotifications, resetReconnectDelay, increaseReconnectDelay]);

  // WebSocket 生命周期管理
  useEffect(() => {
    // 建立 WebSocket 连接
    connectWebSocket();

    // 清理函数：关闭 WebSocket 连接和重连定时器
    return () => {
      if (wsRef.current) {
        // 标记为手动关闭，避免触发 onclose 重连
        wsRef.current.onclose = null;
        wsRef.current.onerror = null;
        wsRef.current.close(1000, 'Component unmount');
        wsRef.current = null;
      }
      if (wsReconnectTimerRef.current) {
        clearTimeout(wsReconnectTimerRef.current);
        wsReconnectTimerRef.current = undefined;
      }
    };
  }, [connectWebSocket]);

  // 兜底轮询：WebSocket 不可用时的降级方案（60秒间隔，比之前的30秒长）
  useEffect(() => {
    // 如果 WebSocket 连接成功，降低轮询频率
    const interval = setInterval(() => {
      // 仅当 WebSocket 未连接时才主动轮询
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) {
        fetchNotifications();
      }
    }, 60000);
    return () => clearInterval(interval);
  }, [fetchNotifications]);

  // 标记单条通知为已读
  const markAsRead = async (id: string) => {
    try {
      await api.markNotificationAsRead(id);
      // 更新本地状态
      setNotifications(prev => 
        prev.map(n => n.id === id ? { ...n, read: true } : n)
      );
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (error) {
      console.error('[AppShell] Failed to mark notification as read:', error);
    }
  };

  // 标记所有通知为已读
  const markAllAsRead = async () => {
    try {
      await api.markAllNotificationsAsRead();
      // 更新本地状态
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      setUnreadCount(0);
    } catch (error) {
      console.error('[AppShell] Failed to mark all notifications as read:', error);
    }
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

  const getNotificationIcon = (type: string, priority?: string, category?: string) => {
    // 安全类通知按优先级/严重程度显示颜色
    if (category === 'security') {
      if (priority === 'critical') return <AlertCircle size={16} className="text-red-600" />;
      if (priority === 'high') return <AlertCircle size={16} className="text-red-500" />;
      if (priority === 'medium') return <AlertCircle size={16} className="text-orange-500" />;
      if (priority === 'low') return <AlertCircle size={16} className="text-yellow-500" />;
    }
    // 扫描类通知
    if (category === 'scan') {
      if (type === 'error') return <AlertCircle size={16} className="text-red-500" />;
      if (type === 'warning') return <AlertCircle size={16} className="text-orange-500" />;
      return <CheckCircle size={16} className="text-blue-500" />;
    }
    switch (type) {
      case 'error': return <AlertCircle size={16} className="text-red-500" />;
      case 'success': return <CheckCircle size={16} className="text-green-500" />;
      case 'warning': return <AlertCircle size={16} className="text-yellow-500" />;
      default: return <AlertCircle size={16} className="text-blue-500" />;
    }
  };

  const getCategoryLabel = (category: string) => {
    const labels: Record<string, string> = {
      'user_management': '用户管理',
      'scan': '扫描任务',
      'system': '系统',
      'security': '安全',
    };
    return labels[category] || category;
  };

  const getCategoryColor = (category: string) => {
    const colors: Record<string, string> = {
      'user_management': 'bg-blue-100 text-blue-700',
      'scan': 'bg-purple-100 text-purple-700',
      'system': 'bg-gray-100 text-gray-700',
      'security': 'bg-red-100 text-red-700',
    };
    return colors[category] || 'bg-gray-100 text-gray-700';
  };

  return (
    <div className="flex h-screen bg-[#f8f9fa] overflow-hidden">
      {/* ==================== 侧边栏 ==================== */}
      <aside
        className={`
          ${isSidebarOpen ? 'w-64' : 'w-16'}
          h-full bg-awvs-sidebar flex flex-col shadow-2xl z-30
          transition-all duration-300 ease-in-out relative border-r border-awvs-border
        `}
      >
        {/* Logo 区域 */}
        <div className="px-4 py-6 flex items-center gap-3 overflow-hidden border-b border-awvs-border">
          <div className="w-10 h-10 rounded-xl flex-shrink-0 bg-gradient-to-br from-awvs-primary to-awvs-primary-light p-0.5 shadow-lg shadow-orange-500/30">
            <div className="w-full h-full rounded-[8px] bg-awvs-primary flex items-center justify-center overflow-hidden">
              <img
                src="/logo.png"
                alt="Aegis Logo"
                className="w-full h-full rounded-[8px] object-contain p-1 bg-[#ffb780]"
              />
            </div>
          </div>
          <span className={`text-awvs-text-primary text-xl font-bold tracking-tight transition-all duration-300 whitespace-nowrap ${isSidebarOpen ? 'opacity-100 w-auto' : 'opacity-0 w-0 overflow-hidden'}`}>
            Aegis
          </span>
        </div>

        {/* 导航菜单 */}
        <div className="flex-1 overflow-y-auto py-3 scrollbar-hide">
          <div className="px-3 mb-2">
            {resolvedNavItems.map((item, index) => {
              if (item.variant === 'section-header') {
                return (
                  <div key={`${item.label}-${index}`} className={`px-3 pt-4 pb-2 text-[10px] tracking-wider text-awvs-text-muted font-semibold uppercase transition-all duration-300 ${isSidebarOpen ? 'opacity-100' : 'opacity-0 h-0 overflow-hidden'}`}>
                    {item.label}
                  </div>
                );
              }

              const Icon = typeof item.icon === 'string' ? iconMap[item.icon] : item.icon;

              return (
                <button
                  key={`${item.label}-${index}`}
                  onClick={item.onClick}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-semibold transition-all text-left mb-0.5 border-l-[3px] ${
                    item.active
                      ? 'bg-orange-50 border-l-awvs-primary shadow-sm text-awvs-primary'
                      : 'text-awvs-text-secondary hover:bg-gray-100 hover:text-awvs-text-primary border-l-transparent'
                  }`}
                >
                  {Icon ? (
                    <Icon
                      size={22}
                      strokeWidth={item.active ? 2.5 : 1.5}
                      className={`flex-shrink-0 ${item.active ? 'text-awvs-primary' : 'text-awvs-text-secondary'}`}
                    />
                  ) : null}
                  <span className={`transition-all duration-300 whitespace-nowrap font-semibold ${item.active ? 'text-awvs-primary' : 'text-awvs-text-secondary'} ${isSidebarOpen ? 'opacity-100 w-auto' : 'opacity-0 w-0 overflow-hidden'}`}>{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* 侧边栏底部 */}
        <div className="p-3 border-t border-awvs-border space-y-1">
          <button
            onClick={() => setShowChangePassword(true)}
            className="w-full flex items-center gap-3 text-awvs-text-secondary hover:text-awvs-primary cursor-pointer transition-colors overflow-hidden px-3 py-2.5 rounded-lg hover:bg-gray-100"
          >
            <div className="flex-shrink-0">
              <KeyRound size={18} />
            </div>
            <span className={`text-sm font-medium transition-all duration-300 whitespace-nowrap ${isSidebarOpen ? 'opacity-100 w-auto' : 'opacity-0 w-0 overflow-hidden'}`}>
              修改密码
            </span>
          </button>

          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 text-awvs-text-secondary hover:text-red-500 cursor-pointer transition-colors overflow-hidden px-3 py-2.5 rounded-lg hover:bg-red-50"
          >
            <div className="flex-shrink-0">
              <LogOut size={18} />
            </div>
            <span className={`text-sm font-medium transition-all duration-300 whitespace-nowrap ${isSidebarOpen ? 'opacity-100 w-auto' : 'opacity-0 w-0 overflow-hidden'}`}>
              退出登录
            </span>
          </button>
        </div>
      </aside>

      {/* ==================== 主内容区域 ==================== */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* ==================== 顶部导航栏 ==================== */}
        <header className="h-14 bg-white border-b border-[#e2e8f0] flex items-center justify-between px-6 z-20 shadow-sm">
          <div className="flex items-center gap-4">
            {/* 折叠按钮 */}
            <button
              onClick={() => setIsSidebarOpen(!isSidebarOpen)}
              className="p-1.5 hover:bg-[#f1f5f9] rounded-lg text-[#64748b] transition-colors"
            >
              <svg className={`w-5 h-5 transition-transform duration-300 ${isSidebarOpen ? '' : 'rotate-180'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="3" y1="12" x2="21" y2="12" />
                <line x1="3" y1="6" x2="21" y2="6" />
                <line x1="3" y1="18" x2="21" y2="18" />
              </svg>
            </button>

            {/* 搜索框 */}
            <div className="relative hidden md:block ml-2">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-[#94a3b8]">
                <Search size={16} />
              </span>
              <input
                type="text"
                placeholder="搜索目标、任务或漏洞..."
                className="pl-10 pr-4 py-1.5 bg-[#f8fafc] border border-[#e2e8f0] rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] w-72 outline-none transition-all"
              />
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* 新建扫描按钮 */}
            <button
              onClick={onNewScan}
              className="bg-gradient-to-r from-[#ff6b00] to-[#ff8c00] text-white px-4 py-1.5 rounded-lg text-sm font-semibold flex items-center gap-2 hover:from-[#e66000] hover:to-[#e67a00] transition-all shadow-md shadow-orange-500/20"
            >
              <Plus size={16} strokeWidth={2.5} />
              新建验证
            </button>

            <div className="h-5 w-px bg-[#e2e8f0] mx-1"></div>

            {/* 图标按钮组 */}
            <div className="flex items-center gap-3 text-[#64748b]">
              <button 
                onClick={() => setShowHelpModal(true)}
                className="text-sm font-medium hover:text-[#ff6b00] transition-colors hidden sm:block"
              >
                查看帮助
              </button>
              <button 
                onClick={() => setShowHelpModal(true)}
                className="p-1.5 hover:bg-[#f1f5f9] rounded-lg transition-colors"
              >
                <HelpCircle size={18} />
              </button>
              <div className="relative" ref={notificationRef}>
                <button 
                  onClick={() => setShowNotifications(!showNotifications)}
                  className="relative p-1.5 hover:bg-[#f1f5f9] rounded-lg transition-colors"
                >
                  <Bell size={18} />
                  {unreadCount > 0 && (
                    <span className="absolute top-0.5 right-0.5 w-4 h-4 bg-red-500 rounded-full text-white text-[10px] flex items-center justify-center font-semibold">
                      {unreadCount > 99 ? '99+' : unreadCount}
                    </span>
                  )}
                </button>
                
                {/* 通知下拉面板 */}
                {showNotifications && (
                  <div className="absolute right-0 top-full mt-2 w-[380px] bg-white rounded-xl shadow-2xl border border-[#e2e8f0] overflow-hidden z-50">
                    <div className="px-4 py-3 border-b border-[#e2e8f0] flex items-center justify-between bg-[#f8fafc]">
                      <h3 className="font-semibold text-[#1e293b]">消息中心</h3>
                      {unreadCount > 0 && (
                        <span className="text-xs text-[#ff6b00] font-semibold">{unreadCount} 条未读</span>
                      )}
                    </div>
                    {/* 分类筛选标签 */}
                    <div className="px-3 py-2 border-b border-[#f1f5f9] flex gap-1.5 overflow-x-auto">
                      {[
                        { key: 'all', label: '全部' },
                        { key: 'security', label: '安全' },
                        { key: 'scan', label: '扫描' },
                        { key: 'user_management', label: '用户' },
                        { key: 'system', label: '系统' },
                      ].map(tab => (
                        <button
                          key={tab.key}
                          onClick={() => {
                            setSelectedNotifyCategory(tab.key);
                            fetchNotifications(tab.key);
                          }}
                          className={`px-2.5 py-1 text-xs rounded-md font-medium whitespace-nowrap transition-all ${
                            selectedNotifyCategory === tab.key
                              ? 'bg-[#ff6b00] text-white shadow-sm'
                              : 'bg-[#f1f5f9] text-[#64748b] hover:bg-[#e2e8f0]'
                          }`}
                        >
                          {tab.label}
                        </button>
                      ))}
                    </div>
                    <div className="max-h-80 overflow-y-auto">
                      {notifications.length === 0 ? (
                        <div className="py-10 text-center text-[#94a3b8]">
                          <Bell size={32} className="mx-auto mb-2 text-[#cbd5e1]" />
                          <p className="text-sm">暂无通知</p>
                        </div>
                      ) : (
                        notifications.map((notification) => (
                        <div 
                          key={notification.id}
                          onClick={() => markAsRead(notification.id)}
                          className={`px-4 py-3 border-b border-[#f1f5f9] hover:bg-[#f8fafc] transition-colors cursor-pointer ${
                            !notification.read ? 'bg-orange-50/50' : ''
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <div className="mt-0.5">{getNotificationIcon(notification.type, notification.priority, notification.category)}</div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={`px-1.5 py-0.5 text-[10px] rounded font-medium ${getCategoryColor(notification.category)}`}>
                                  {getCategoryLabel(notification.category)}
                                </span>
                              </div>
                              <p className="text-sm font-semibold text-[#1e293b] leading-tight">{notification.title}</p>
                              <p className="text-xs text-[#64748b] mt-0.5 line-clamp-2">{notification.message}</p>
                              <p className="text-xs text-[#94a3b8] mt-1">{notification.time}</p>
                            </div>
                            {!notification.read && (
                              <div className="w-2 h-2 bg-[#ff6b00] rounded-full mt-2 flex-shrink-0"></div>
                            )}
                          </div>
                        </div>
                      )))}
                    </div>
                    <div className="px-4 py-3 border-t border-[#e2e8f0] bg-[#f8fafc] flex gap-2">
                      {unreadCount > 0 && (
                        <button 
                          onClick={markAllAsRead}
                          className="flex-1 text-center text-sm text-[#64748b] font-medium hover:text-[#1e293b] transition-colors"
                        >
                          全部已读
                        </button>
                      )}
                      <button 
                        onClick={handleViewAllNotifications}
                        className="flex-1 text-center text-sm text-[#ff6b00] font-semibold hover:text-[#e66000] transition-colors"
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
        <main className="flex-1 overflow-y-auto p-6 bg-[#f5f6f8]">
          {children}
        </main>
      </div>

      {/* ==================== 全部通知模态框 ==================== */}
      {showAllNotifications && (
        <div 
          className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
          onClick={() => setShowAllNotifications(false)}
        >
          <div 
            className="bg-white rounded-xl shadow-2xl w-full max-w-3xl mx-4 overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* 模态框头部 */}
            <div className="px-6 py-4 border-b border-[#e2e8f0] flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-[#ff6b00]/10 rounded-lg flex items-center justify-center">
                  <Bell size={22} className="text-[#ff6b00]" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-[#1e293b]">消息中心</h2>
                  <p className="text-sm text-[#64748b]">共 {notifications.length} 条通知</p>
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
                  className="p-2 hover:bg-[#f1f5f9] rounded-lg transition-colors"
                >
                  <X size={20} className="text-[#64748b]" />
                </button>
              </div>
            </div>
            
            {/* 分类筛选标签 */}
            <div className="px-6 py-2 border-b border-gray-50 flex gap-2 bg-gray-50/50">
              {[
                { key: 'all', label: '全部' },
                { key: 'security', label: '安全漏洞' },
                { key: 'scan', label: '扫描任务' },
                { key: 'user_management', label: '用户管理' },
                { key: 'system', label: '系统通知' },
              ].map(tab => (
                <button
                  key={tab.key}
                  onClick={() => {
                    setSelectedNotifyCategory(tab.key);
                    fetchNotifications(tab.key);
                  }}
                  className={`px-3 py-1.5 text-sm rounded-lg font-medium transition-colors ${
                    selectedNotifyCategory === tab.key
                      ? 'bg-[#ff6b00] text-white shadow-sm'
                      : 'bg-white text-gray-600 hover:bg-gray-100 border border-gray-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
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
                      !notification.read ? 'bg-orange-50/30' : ''
                    }`}
                  >
                    <div className="flex items-start gap-4">
                      <div className="mt-1">{getNotificationIcon(notification.type, notification.priority, notification.category)}</div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${getCategoryColor(notification.category)}`}>
                            {getCategoryLabel(notification.category)}
                          </span>
                          {notification.priority && (
                            <span className={`px-2 py-0.5 text-xs rounded-full font-medium ${
                              notification.priority === 'critical' ? 'bg-red-100 text-red-700' :
                              notification.priority === 'high' ? 'bg-orange-100 text-orange-700' :
                              notification.priority === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                              'bg-gray-100 text-gray-600'
                            }`}>
                              {notification.priority === 'critical' ? '严重' :
                               notification.priority === 'high' ? '高危' :
                               notification.priority === 'medium' ? '中等' :
                               notification.priority === 'low' ? '低' : notification.priority}
                            </span>
                          )}
                          {!notification.read && (
                            <span className="px-2 py-0.5 text-xs bg-[#ff6b00]/10 text-[#ff6b00] rounded-full font-medium">未读</span>
                          )}
                        </div>
                        <p className="text-base font-semibold text-gray-800">{notification.title}</p>
                        <p className="text-sm text-gray-600 mt-1 whitespace-pre-wrap">{notification.message}</p>
                        {notification.extra_data && notification.category === 'security' && (
                          <div className="mt-2 flex flex-wrap gap-2">
                            {notification.extra_data.vuln_type && (
                              <span className="px-2 py-0.5 text-xs bg-blue-50 text-blue-600 rounded">
                                类型: {notification.extra_data.vuln_type}
                              </span>
                            )}
                            {notification.extra_data.cvss_score != null && (
                              <span className="px-2 py-0.5 text-xs bg-purple-50 text-purple-600 rounded">
                                CVSS: {notification.extra_data.cvss_score}
                              </span>
                            )}
                            {notification.extra_data.method && (
                              <span className="px-2 py-0.5 text-xs bg-gray-50 text-gray-600 rounded">
                                {notification.extra_data.method}
                              </span>
                            )}
                            {notification.extra_data.parameter && (
                              <span className="px-2 py-0.5 text-xs bg-cyan-50 text-cyan-600 rounded">
                                参数: {notification.extra_data.parameter}
                              </span>
                            )}
                          </div>
                        )}
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
          onClick={() => { setShowHelpModal(false); setSelectedHelpContent(null); }}
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
                onClick={() => { setShowHelpModal(false); setSelectedHelpContent(null); }}
                className="p-2 hover:bg-white/20 rounded-lg transition-colors"
              >
                <X size={20} className="text-white" />
              </button>
            </div>
            
            {/* 模态框内容 */}
            <div className="p-6 max-h-[60vh] overflow-y-auto">
              {selectedHelpContent ? (
                // 显示详细内容
                <div>
                  <button
                    onClick={() => setSelectedHelpContent(null)}
                    className="text-sm text-gray-500 hover:text-gray-700 mb-4 flex items-center gap-1"
                  >
                    ← 返回列表
                  </button>
                  <div className="flex items-center gap-3 mb-4">
                    <div 
                      className="w-10 h-10 rounded-lg flex items-center justify-center"
                      style={{ backgroundColor: `${selectedHelpContent.icon_color}20` }}
                    >
                      {selectedHelpContent.icon === 'Shield' ? (
                        <Shield size={24} style={{ color: selectedHelpContent.icon_color }} />
                      ) : selectedHelpContent.icon === 'FileText' ? (
                        <FileText size={24} style={{ color: selectedHelpContent.icon_color }} />
                      ) : selectedHelpContent.icon === 'MessageCircle' ? (
                        <MessageCircle size={24} style={{ color: selectedHelpContent.icon_color }} />
                      ) : (
                        <BookOpen size={24} style={{ color: selectedHelpContent.icon_color }} />
                      )}
                    </div>
                    <h3 className="text-xl font-bold text-gray-800">{selectedHelpContent.title}</h3>
                  </div>
                  {selectedHelpContent.description && (
                    <p className="text-gray-600 mb-4">{selectedHelpContent.description}</p>
                  )}
                  {selectedHelpContent.content && (
                    <div className="prose prose-sm max-w-none bg-gray-50 rounded-lg p-4 whitespace-pre-wrap font-mono text-sm">
                      {selectedHelpContent.content}
                    </div>
                  )}
                  {selectedHelpContent.link && (
                    <div className="mt-4">
                      <a 
                        href={selectedHelpContent.link} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-[#ff6b00] hover:underline flex items-center gap-1"
                      >
                        了解更多
                        <ExternalLink size={14} />
                      </a>
                    </div>
                  )}
                </div>
              ) : (
                // 显示卡片列表
                <>
                  {helpLoading ? (
                    <div className="py-12 text-center text-gray-400">
                      <div className="w-8 h-8 border-2 border-[#ff6b00]/30 border-t-[#ff6b00] rounded-full animate-spin mx-auto mb-4"></div>
                      加载中...
                    </div>
                  ) : helpContents.length === 0 ? (
                    <div className="py-12 text-center text-gray-400">
                      <BookOpen size={48} className="mx-auto mb-4 text-gray-300" />
                      <p>暂无帮助内容</p>
                      <p className="text-sm mt-2">请联系管理员添加帮助内容</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {helpContents.map((content) => (
                        <div 
                          key={content.id}
                          onClick={() => setSelectedHelpContent(content)}
                          className="p-4 bg-gray-50 rounded-xl hover:bg-gray-100 transition-colors cursor-pointer"
                        >
                          <div className="flex items-center gap-3 mb-2">
                            <div 
                              className="w-8 h-8 rounded-lg flex items-center justify-center"
                              style={{ backgroundColor: `${content.icon_color}20` }}
                            >
                              {content.icon === 'Shield' ? (
                                <Shield size={18} style={{ color: content.icon_color }} />
                              ) : content.icon === 'FileText' ? (
                                <FileText size={18} style={{ color: content.icon_color }} />
                              ) : content.icon === 'MessageCircle' ? (
                                <MessageCircle size={18} style={{ color: content.icon_color }} />
                              ) : (
                                <BookOpen size={18} style={{ color: content.icon_color }} />
                              )}
                            </div>
                            <h3 className="font-semibold text-gray-800">{content.title}</h3>
                          </div>
                          <p className="text-sm text-gray-500">{content.description || '点击查看详情'}</p>
                        </div>
                      ))}
                    </div>
                  )}
                  
                  {/* 常用快捷键 */}
                  <div className="mt-6 pt-6 border-t border-gray-100">
                    <h3 className="font-semibold text-gray-800 mb-3">快捷键</h3>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-gray-500">新建验证</span>
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
                </>
              )}
            </div>
            
            {/* 模态框底部 */}
            <div className="px-6 py-4 border-t border-gray-100 bg-gray-50 flex items-center justify-between">
              <span className="text-sm text-gray-400">管理员可在设置中编辑帮助内容</span>
              <button 
                onClick={() => { setShowHelpModal(false); setSelectedHelpContent(null); }}
                className="px-4 py-2 bg-[#ff6b00] text-white rounded-lg text-sm font-medium hover:bg-[#e66000] transition-colors"
              >
                知道了
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================== 修改密码模态框 ==================== */}
      <ChangePasswordModal 
        isOpen={showChangePassword}
        onClose={() => setShowChangePassword(false)}
        onSuccess={() => {
          setShowChangePassword(false);
          // 密码修改成功后执行登出
          if (onLogout) {
            onLogout();
          }
        }}
      />
    </div>
  );
};

export default AppShell;
