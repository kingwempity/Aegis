/**
 * 修改密码模态框组件
 * 
 * 功能：
 * - 提供用户修改密码的界面
 * - 验证旧密码和新密码格式
 * - 调用后端 API 完成密码修改
 * 
 * Notes:
 * - 新密码长度至少6位
 * - 修改成功后需要提示用户重新登录
 */

import React, { useState } from 'react';
import { X, Eye, EyeOff, Key, Lock, CheckCircle, AlertCircle, Loader } from './Icons';

interface ChangePasswordModalProps {
  /** 是否显示模态框 */
  isOpen: boolean;
  /** 关闭模态框回调 */
  onClose: () => void;
  /** 修改成功回调（可选，用于登出用户） */
  onSuccess?: () => void;
}

/**
 * 修改密码模态框
 */
const ChangePasswordModal: React.FC<ChangePasswordModalProps> = ({
  isOpen,
  onClose,
  onSuccess,
}) => {
  // 表单状态
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  // UI 状态
  const [showOldPassword, setShowOldPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  /**
   * 重置表单状态
   */
  const resetForm = () => {
    setOldPassword('');
    setNewPassword('');
    setConfirmPassword('');
    setShowOldPassword(false);
    setShowNewPassword(false);
    setShowConfirmPassword(false);
    setError(null);
    setSuccess(false);
  };

  /**
   * 关闭模态框并重置表单
   */
  const handleClose = () => {
    resetForm();
    onClose();
  };

  /**
   * 验证表单
   */
  const validateForm = (): string | null => {
    if (!oldPassword.trim()) {
      return '请输入当前密码';
    }
    if (!newPassword.trim()) {
      return '请输入新密码';
    }
    if (newPassword.length < 6) {
      return '新密码长度至少6位';
    }
    if (newPassword === oldPassword) {
      return '新密码不能与当前密码相同';
    }
    if (newPassword !== confirmPassword) {
      return '两次输入的新密码不一致';
    }
    return null;
  };

  /**
   * 提交修改密码请求
   */
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // 验证表单
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      // 获取 token
      const token = localStorage.getItem('aegis_token');
      if (!token) {
        setError('未登录或登录已过期，请重新登录');
        setIsLoading(false);
        return;
      }

      const response = await fetch('/api/v1/auth/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
        body: JSON.stringify({
          old_password: oldPassword,
          new_password: newPassword,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || '密码修改失败');
      }

      // 修改成功
      setSuccess(true);
      
      // 3秒后自动关闭并触发成功回调
      setTimeout(() => {
        handleClose();
        if (onSuccess) {
          onSuccess();
        }
      }, 2000);

    } catch (err) {
      setError(err instanceof Error ? err.message : '密码修改失败，请稍后重试');
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={handleClose}
    >
      <div 
        className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* 模态框头部 */}
        <div className="px-6 py-4 border-b border-gray-100 flex items-center justify-between bg-gradient-to-r from-[#ff6b00] to-[#ff8c00]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-lg flex items-center justify-center">
              <Key size={24} className="text-white" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">修改密码</h2>
              <p className="text-sm text-white/80">更新您的账户密码</p>
            </div>
          </div>
          <button 
            onClick={handleClose}
            className="p-2 hover:bg-white/20 rounded-lg transition-colors"
            disabled={isLoading}
          >
            <X size={20} className="text-white" />
          </button>
        </div>
        
        {/* 成功状态 */}
        {success ? (
          <div className="p-8 text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckCircle size={32} className="text-green-500" />
            </div>
            <h3 className="text-lg font-semibold text-gray-800 mb-2">密码修改成功</h3>
            <p className="text-gray-500 text-sm">请使用新密码重新登录</p>
          </div>
        ) : (
          /* 表单内容 */
          <form onSubmit={handleSubmit} className="p-6 space-y-5">
            {/* 错误提示 */}
            {error && (
              <div className="flex items-center gap-2 p-3 bg-red-50 border border-red-100 rounded-lg text-red-600 text-sm">
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            {/* 当前密码 */}
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                当前密码
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                  <Lock size={16} />
                </div>
                <input
                  type={showOldPassword ? 'text' : 'password'}
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  placeholder="请输入当前密码"
                  className="w-full pl-10 pr-10 py-2.5 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowOldPassword(!showOldPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600"
                >
                  {showOldPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* 新密码 */}
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                新密码
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                  <Lock size={16} />
                </div>
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="请输入新密码（至少6位）"
                  className="w-full pl-10 pr-10 py-2.5 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600"
                >
                  {showNewPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* 确认新密码 */}
            <div className="space-y-2">
              <label className="block text-sm font-medium text-gray-700">
                确认新密码
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                  <Lock size={16} />
                </div>
                <input
                  type={showConfirmPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="请再次输入新密码"
                  className="w-full pl-10 pr-10 py-2.5 border border-gray-200 rounded-lg text-sm focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] outline-none transition-all"
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-gray-600"
                >
                  {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {/* 密码匹配提示 */}
              {confirmPassword && newPassword !== confirmPassword && (
                <p className="text-xs text-red-500 flex items-center gap-1">
                  <AlertCircle size={12} />
                  两次输入的密码不一致
                </p>
              )}
              {confirmPassword && newPassword === confirmPassword && newPassword.length >= 6 && (
                <p className="text-xs text-green-500 flex items-center gap-1">
                  <CheckCircle size={12} />
                  密码匹配
                </p>
              )}
            </div>

            {/* 密码强度提示 */}
            <div className="bg-gray-50 rounded-lg p-3 text-xs text-gray-500">
              <p className="font-medium text-gray-700 mb-1">密码要求：</p>
              <ul className="space-y-1">
                <li className={`flex items-center gap-1 ${newPassword.length >= 6 ? 'text-green-500' : ''}`}>
                  {newPassword.length >= 6 ? <CheckCircle size={12} /> : <span className="w-3 h-3 rounded-full border border-gray-300" />}
                  长度至少6位
                </li>
                <li className={`flex items-center gap-1 ${newPassword !== oldPassword && newPassword ? 'text-green-500' : ''}`}>
                  {newPassword !== oldPassword && newPassword ? <CheckCircle size={12} /> : <span className="w-3 h-3 rounded-full border border-gray-300" />}
                  不能与当前密码相同
                </li>
              </ul>
            </div>

            {/* 按钮组 */}
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={handleClose}
                className="flex-1 px-4 py-2.5 border border-gray-200 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-50 transition-colors"
                disabled={isLoading}
              >
                取消
              </button>
              <button
                type="submit"
                className="flex-1 px-4 py-2.5 bg-[#ff6b00] text-white rounded-lg text-sm font-medium hover:bg-[#e66000] transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader size={16} className="animate-spin" />
                    修改中...
                  </>
                ) : (
                  '确认修改'
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default ChangePasswordModal;