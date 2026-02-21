import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import { AuthContextType, User, LoginRequest, RegisterRequest, AuthResponse } from '../types';
import { apiService } from '../services/api';

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

// 认证状态枚举
enum AuthStatus {
  LOADING = 'loading',
  AUTHENTICATED = 'authenticated',
  UNAUTHENTICATED = 'unauthenticated',
  ERROR = 'error'
}

interface AuthState {
  user: User | null;
  status: AuthStatus;
  error: string | null;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    status: AuthStatus.LOADING,
    error: null
  });

  // 检查认证状态
  const checkAuthStatus = useCallback(async () => {
    const token = localStorage.getItem('access_token');
    if (!token) {
      setAuthState({
        user: null,
        status: AuthStatus.UNAUTHENTICATED,
        error: null
      });
      return;
    }

    try {
      setAuthState(prev => ({ ...prev, status: AuthStatus.LOADING }));
      const userData = await apiService.getCurrentUser();
      setAuthState({
        user: userData,
        status: AuthStatus.AUTHENTICATED,
        error: null
      });
    } catch (error: any) {
      console.error('认证状态检查失败:', error);
      // 清除无效token
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      setAuthState({
        user: null,
        status: AuthStatus.UNAUTHENTICATED,
        error: error.response?.data?.message || '认证已过期，请重新登录'
      });
    }
  }, []);

  // 初始化时检查认证状态
  useEffect(() => {
    checkAuthStatus();
  }, [checkAuthStatus]);

  // 登录函数
  const login = async (credentials: LoginRequest): Promise<void> => {
    try {
      setAuthState(prev => ({ ...prev, status: AuthStatus.LOADING, error: null }));

      const response: AuthResponse = await apiService.login(credentials);

      // 存储token
      localStorage.setItem('access_token', response.access_token);
      localStorage.setItem('refresh_token', response.refresh_token);

      // 更新状态
      setAuthState({
        user: response.user,
        status: AuthStatus.AUTHENTICATED,
        error: null
      });

    } catch (error: any) {
      console.error('登录失败:', error);

      let errorMessage = '登录失败，请稍后重试';

      if (error.response?.status === 401) {
        errorMessage = '用户名或密码错误';
      } else if (error.response?.status === 400) {
        errorMessage = error.response.data?.message || '请求参数错误';
      } else if (error.response?.status >= 500) {
        errorMessage = '服务器错误，请稍后重试';
      } else if (error.code === 'NETWORK_ERROR') {
        errorMessage = '网络连接失败，请检查网络连接';
      }

      setAuthState({
        user: null,
        status: AuthStatus.ERROR,
        error: errorMessage
      });

      throw new Error(errorMessage);
    }
  };

  // 注册函数
  const register = async (userData: RegisterRequest): Promise<void> => {
    try {
      setAuthState(prev => ({ ...prev, status: AuthStatus.LOADING, error: null }));

      await apiService.register(userData);

      // 注册成功后清除错误状态
      setAuthState(prev => ({ ...prev, status: AuthStatus.UNAUTHENTICATED, error: null }));

    } catch (error: any) {
      console.error('注册失败:', error);

      let errorMessage = '注册失败，请稍后重试';

      if (error.response?.status === 400) {
        errorMessage = error.response.data?.message || '注册信息不符合要求';
      } else if (error.response?.status === 409) {
        errorMessage = '用户名或邮箱已被注册';
      } else if (error.response?.status >= 500) {
        errorMessage = '服务器错误，请稍后重试';
      }

      setAuthState(prev => ({
        ...prev,
        status: AuthStatus.ERROR,
        error: errorMessage
      }));

      throw new Error(errorMessage);
    }
  };

  // 登出函数
  const logout = useCallback(() => {
    // 清除本地存储
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');

    // 重置状态
    setAuthState({
      user: null,
      status: AuthStatus.UNAUTHENTICATED,
      error: null
    });
  }, []);

  // 刷新token函数
  const refreshToken = async (): Promise<void> => {
    try {
      const response: AuthResponse = await apiService.refreshToken();
      localStorage.setItem('access_token', response.access_token);
      localStorage.setItem('refresh_token', response.refresh_token);
    } catch (error) {
      console.error('Token刷新失败:', error);
      logout();
      throw error;
    }
  };

  // 清除错误状态
  const clearError = useCallback(() => {
    setAuthState(prev => ({ ...prev, error: null }));
  }, []);

  const value: AuthContextType & {
    error: string | null;
    clearError: () => void;
    isLoading: boolean;
    isError: boolean;
  } = {
    user: authState.user,
    isAuthenticated: authState.status === AuthStatus.AUTHENTICATED,
    loading: authState.status === AuthStatus.LOADING,
    error: authState.error,
    clearError,
    isLoading: authState.status === AuthStatus.LOADING,
    isError: authState.status === AuthStatus.ERROR,
    login,
    register,
    logout,
    refreshToken,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
