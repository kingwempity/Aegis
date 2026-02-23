/**
 * 认证上下文
 * 
 * 管理用户登录状态、Token 存储和认证相关操作。
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

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

/**
 * 认证提供者组件
 */
export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  /**
   * 初始化时检查本地存储的登录状态
   */
  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = localStorage.getItem(TOKEN_KEY);
        const savedUser = localStorage.getItem(USER_KEY);

        if (token && savedUser) {
          // 验证 Token 是否有效
          const response = await fetch('/api/v1/auth/verify-token', {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          });

          if (response.ok) {
            const data = await response.json();
            if (data.valid) {
              setUser(JSON.parse(savedUser));
            } else {
              // Token 无效，清除存储
              localStorage.removeItem(TOKEN_KEY);
              localStorage.removeItem(USER_KEY);
            }
          } else {
            // 验证失败，清除存储
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(USER_KEY);
          }
        }
      } catch (error) {
        console.error('Auth initialization error:', error);
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(USER_KEY);
      } finally {
        setIsLoading(false);
      }
    };

    initAuth();
  }, []);

  /**
   * 登录成功后保存状态
   */
  const login = useCallback((token: string, userInfo: UserInfo) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(userInfo));
    setUser(userInfo);
  }, []);

  /**
   * 登出
   */
  const logout = useCallback(async () => {
    try {
      const token = localStorage.getItem(TOKEN_KEY);
      if (token) {
        // 调用后端登出接口
        await fetch('/api/v1/auth/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      // 清除本地存储
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      setUser(null);
    }
  }, []);

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