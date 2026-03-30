import { useContext } from 'react';
import { AuthContext } from '../contexts/AuthContext';
import { AuthContextType } from '../types';

// 自定义Hook - 使用认证上下文
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

// 便捷的认证状态检查Hook
export const useAuthStatus = () => {
  const { isAuthenticated, loading, isLoading, isError, error } = useAuth();

  return {
    isAuthenticated,
    isLoading: loading || isLoading,
    isError,
    error,
    isIdle: !loading && !isLoading && !isError,
  };
};