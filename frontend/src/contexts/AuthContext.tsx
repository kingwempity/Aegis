/**
 * 认证上下文
 * 
 * 管理用户登录状态、Token 存储和认证相关操作。
 * 
 * 优化说明：
 * - 本地 JWT 解析验证，减少网络请求
 * - 网络失败时保持本地有效 token 的登录状态
 * - 后台静默刷新机制
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

/**
 * 用户信息接口
 */
export interface UserInfo {
  id: number;
  username: string;
  email: string;
  role: string;
}

/**
 * 认证上下文接口
 */
interface AuthContextType {
  /** 当前登录用户 */
  user: UserInfo | null;
  /** 是否已登录 */
  isAuthenticated: boolean;
  /** 是否正在加载 */
  isLoading: boolean;
  /** 登录成功回调 */
  login: (token: string, user: UserInfo) => void;
  /** 登出 */
  logout: () => void;
  /** 获取认证头 */
  getAuthHeader: () => Record<string, string>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

/** Token 存储 Key */
const TOKEN_KEY = 'aegis_token';
const USER_KEY = 'aegis_user';

/** Token 刷新阈值（秒）- 当 token 剩余有效期少于此值时尝试刷新 */
const TOKEN_REFRESH_THRESHOLD_SECONDS = 30 * 60; // 30 分钟

/**
 * 解析 JWT Token（不验证签名，仅用于读取 payload）
 * 
 * @param token - JWT Token 字符串
 * @returns 解码后的 payload 或 null
 */
function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }
    // Base64Url 解码
    const payload = parts[1];
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.warn('Failed to parse JWT:', error);
    return null;
  }
}

/**
 * 检查 JWT Token 是否过期
 * 
 * @param token - JWT Token 字符串
 * @returns true 表示已过期，false 表示未过期
 */
function isTokenExpired(token: string): boolean {
  const payload = parseJwt(token);
  if (!payload) {
    return true;
  }
  
  const exp = payload.exp as number | undefined;
  if (!exp) {
    return true;
  }
  
  // exp 是秒级时间戳，Date.now() 是毫秒
  return Date.now() >= exp * 1000;
}

/**
 * 获取 Token 剩余有效时间（秒）
 * 
 * @param token - JWT Token 字符串
 * @returns 剩余有效时间（秒），无效 token 返回 0
 */
function getTokenRemainingTime(token: string): number {
  const payload = parseJwt(token);
  if (!payload) {
    return 0;
  }
  
  const exp = payload.exp as number | undefined;
  if (!exp) {
    return 0;
  }
  
  const remaining = exp * 1000 - Date.now();
  return Math.max(0, Math.floor(remaining / 1000));
}

/**
 * 认证提供者组件
 */
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const refreshTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const verifyInProgressRef = useRef(false);

  /**
   * 清除刷新定时器
   */
  const clearRefreshTimer = useCallback(() => {
    if (refreshTimerRef.current) {
      clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
    }
  }, []);

  /**
   * 安排 Token 刷新定时器
   * 在 token 快过期时自动触发验证
   */
  const scheduleTokenRefresh = useCallback((token: string) => {
    clearRefreshTimer();
    
    const remainingTime = getTokenRemainingTime(token);
    if (remainingTime <= 0) {
      return; // Token 已过期，不需要刷新
    }
    
    // 计算刷新时间：在过期前 30 分钟刷新，或者剩余时间的一半
    const refreshTime = Math.min(
      remainingTime - TOKEN_REFRESH_THRESHOLD_SECONDS,
      remainingTime / 2
    );
    
    if (refreshTime <= 0) {
      // 已经接近过期，不设置定时器
      console.log('[Auth] Token 即将过期，下次操作时将重新验证');
      return;
    }
    
    refreshTimerRef.current = setTimeout(() => {
      // 定时器触发时，执行静默验证
      performSilentVerification();
    }, refreshTime * 1000);
    
    console.log(`[Auth] Token 刷新已安排在 ${Math.floor(refreshTime / 60)} 分钟后`);
  }, [clearRefreshTimer]);

  /**
   * 执行静默验证（不依赖 useCallback，避免循环引用）
   * 使用 ref 防止并发验证
   */
  const performSilentVerification = async () => {
    // 防止并发验证
    if (verifyInProgressRef.current) {
      return;
    }
    verifyInProgressRef.current = true;
    
    const token = localStorage.getItem(TOKEN_KEY);
    if (!token) {
      verifyInProgressRef.current = false;
      return;
    }
    
    // 先检查本地是否过期
    if (isTokenExpired(token)) {
      console.log('[Auth] Token 本地验证已过期，执行登出');
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      setUser(null);
      verifyInProgressRef.current = false;
      return;
    }
    
    try {
      const response = await fetch('/api/v1/auth/verify-token', {
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });
      
      if (!response.ok) {
        // 网络请求失败，但本地 token 有效，保持登录状态
        console.warn('[Auth] Token 服务端验证失败，但本地 token 有效，保持登录');
        verifyInProgressRef.current = false;
        return;
      }
      
      const data = await response.json();
      if (!data.valid) {
        // 服务端明确说 token 无效
        console.log('[Auth] Token 服务端确认无效，执行登出');
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
        setUser(null);
      } else {
        console.log('[Auth] Token 验证成功');
        // 重新安排刷新
        scheduleTokenRefresh(token);
      }
    } catch (error) {
      // 网络错误，本地 token 有效则保持登录
      console.warn('[Auth] Token 验证网络错误，保持本地登录状态:', error);
    } finally {
      verifyInProgressRef.current = false;
    }
  };

  /**
   * 初始化时检查本地存储的登录状态
   * 优化：先进行本地 JWT 验证，减少网络请求
   */
  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = localStorage.getItem(TOKEN_KEY);
        const savedUser = localStorage.getItem(USER_KEY);

        if (token && savedUser) {
          // 第一步：本地验证 JWT 是否过期
          if (isTokenExpired(token)) {
            console.log('[Auth] Token 本地验证已过期');
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
            setIsLoading(false);
            return;
          }
          
          // 本地验证通过，先恢复用户状态（不等待网络请求）
          const userInfo = JSON.parse(savedUser);
          setUser(userInfo);
          setIsLoading(false);
          
          // 第二步：后台静默验证 token（不阻塞应用加载）
          // 延迟执行，让应用先完全加载
          setTimeout(() => {
            performSilentVerification();
          }, 1000);
          
          // 设置自动刷新
          scheduleTokenRefresh(token);
        } else {
          setIsLoading(false);
        }
      } catch (error) {
        console.error('[Auth] 初始化错误:', error);
        // 出错时保留本地 token，让用户可以继续使用
        setIsLoading(false);
      }
    };

    initAuth();
    
    // 清理定时器
    return () => {
      clearRefreshTimer();
    };
  }, [scheduleTokenRefresh, clearRefreshTimer]);

  /**
   * 登录成功后保存状态
   * 同时设置 token 自动刷新
   */
  const login = useCallback((token: string, userInfo: UserInfo) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(userInfo));
    setUser(userInfo);
    
    // 设置自动刷新定时器
    scheduleTokenRefresh(token);
    
    console.log(`[Auth] 用户登录成功: ${userInfo.username}，Token 有效期剩余 ${getTokenRemainingTime(token)} 秒`);
  }, [scheduleTokenRefresh]);

  /**
   * 登出
   * 清除定时器并通知服务端
   */
  const logout = useCallback(async () => {
    // 清除刷新定时器
    clearRefreshTimer();
    
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      // 调用后端登出接口（静默执行，不阻塞登出流程）
      fetch('/api/v1/auth/logout', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      }).catch(err => console.warn('[Auth] 登出接口调用失败（可忽略）:', err));
    }
    
    // 清除本地存储
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setUser(null);
    console.log('[Auth] 用户已登出');
  }, [clearRefreshTimer]);

  /**
   * 获取认证头
   */
  const getAuthHeader = useCallback((): Record<string, string> => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      return { 'Authorization': `Bearer ${token}` };
    }
    return {};
  }, []);

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    getAuthHeader,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * 使用认证上下文的 Hook
 */
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;