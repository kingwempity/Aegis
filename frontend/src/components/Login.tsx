/**
 * 登录页面组件
 * 
 * 支持双登录方式：
 * - 用户名/邮箱 + 密码登录
 * - 邮箱 + 验证码登录
 * 
 * 默认密码格式：用户名@123
 */

import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import type { UserInfo } from '../contexts/AuthContext';
import { Shield, User, Lock, ArrowRight, Loader2, Eye, EyeOff, Mail, KeyRound } from './Icons';

/**
 * 登录方式类型
 */
type LoginMode = 'password' | 'email';

/**
 * 登录页面属性
 */
interface LoginProps {
  /** 登录成功回调 */
  onLoginSuccess?: () => void;
}

/**
 * 登录页面组件
 */
const Login: React.FC<LoginProps> = ({ onLoginSuccess }) => {
  const { login } = useAuth();
  
  // 登录方式
  const [loginMode, setLoginMode] = useState<LoginMode>('password');
  
  // 密码登录表单状态
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  
  // 邮箱验证码登录表单状态
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [countdown, setCountdown] = useState(0);
  
  // UI 状态
  const [isLoading, setIsLoading] = useState(false);
  const [isSendingCode, setIsSendingCode] = useState(false);
  const [error, setError] = useState('');

  // 倒计时效果
  useEffect(() => {
    if (countdown > 0) {
      const timer = setTimeout(() => setCountdown(countdown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [countdown]);

  /**
   * 密码登录
   */
  const handlePasswordLogin = async () => {
    if (!username) {
      setError('请输入用户名或邮箱');
      return;
    }

    if (!password) {
      setError('请输入密码');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || '登录失败');
      }

      if (data.success && data.token && data.user) {
        login(data.token, data.user as UserInfo);
        onLoginSuccess?.();
      } else {
        setError(data.message || '登录失败');
      }
    } catch (err: any) {
      setError(err.message || '登录失败，请稍后重试');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * 发送验证码
   */
  const handleSendCode = async () => {
    if (!email) {
      setError('请输入邮箱地址');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('请输入有效的邮箱地址');
      return;
    }

    setIsSendingCode(true);
    setError('');

    try {
      const response = await fetch('/api/v1/auth/send-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || '发送验证码失败');
      }

      if (data.success) {
        setCountdown(60);
        // 开发模式下显示验证码
        if (data.code) {
          console.log(`📧 验证码: ${data.code}`);
          setError(`验证码已发送（开发模式: ${data.code}）`);
        } else {
          setError('验证码已发送到您的邮箱');
        }
      } else {
        setError(data.message || '发送验证码失败');
      }
    } catch (err: any) {
      setError(err.message || '发送验证码失败，请稍后重试');
    } finally {
      setIsSendingCode(false);
    }
  };

  /**
   * 邮箱验证码登录
   */
  const handleEmailLogin = async () => {
    if (!email) {
      setError('请输入邮箱地址');
      return;
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('请输入有效的邮箱地址');
      return;
    }

    if (!code || code.length !== 6) {
      setError('请输入6位验证码');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const response = await fetch('/api/v1/auth/login-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || '登录失败');
      }

      if (data.success && data.token && data.user) {
        login(data.token, data.user as UserInfo);
        onLoginSuccess?.();
      } else {
        setError(data.message || '登录失败');
      }
    } catch (err: any) {
      setError(err.message || '登录失败，请稍后重试');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * 处理登录
   */
  const handleLogin = () => {
    if (loginMode === 'password') {
      handlePasswordLogin();
    } else {
      handleEmailLogin();
    }
  };

  /**
   * 处理键盘事件
   */
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleLogin();
    }
  };

  /**
   * 切换登录方式
   */
  const toggleLoginMode = () => {
    setLoginMode(loginMode === 'password' ? 'email' : 'password');
    setError('');
    setUsername('');
    setPassword('');
    setEmail('');
    setCode('');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#1a1d2e] via-[#2d3343] to-[#1a1d2e] flex items-center justify-center p-4">
      {/* 背景装饰 */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[#ff6b00]/10 rounded-full blur-3xl"></div>
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[#ff6b00]/5 rounded-full blur-3xl"></div>
      </div>

      {/* 登录卡片 */}
      <div className="relative w-full max-w-md">
        {/* Logo 和标题 */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl shadow-2xl shadow-orange-500/40 mb-4 overflow-hidden bg-gradient-to-br from-[#ff6b00] to-[#ff8c00] p-1">
            <div className="w-full h-full rounded-xl bg-[#1a1d2e] flex items-center justify-center overflow-hidden">
              <img 
                src="/logo.png" 
                alt="Aegis Logo" 
                className="w-full h-full rounded-xl object-cover"
              />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white mb-2">Aegis</h1>
          <p className="text-gray-400">Web 应用程序漏洞检测系统</p>
        </div>

        {/* 表单卡片 */}
        <div className="bg-white/5 backdrop-blur-xl rounded-2xl border border-white/10 p-8 shadow-2xl">
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-xl font-semibold text-white mb-2">登录您的账户</h2>
              <p className="text-gray-400 text-sm">
                {loginMode === 'password' ? '使用用户名和密码登录' : '使用邮箱验证码登录'}
              </p>
            </div>

            {/* 登录方式切换标签 */}
            <div className="flex bg-white/5 rounded-lg p-1">
              <button
                onClick={() => setLoginMode('password')}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all ${
                  loginMode === 'password'
                    ? 'bg-[#ff6b00] text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <span className="flex items-center justify-center gap-2">
                  <Lock size={16} />
                  密码登录
                </span>
              </button>
              <button
                onClick={() => setLoginMode('email')}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-all ${
                  loginMode === 'email'
                    ? 'bg-[#ff6b00] text-white'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                <span className="flex items-center justify-center gap-2">
                  <Mail size={16} />
                  验证码登录
                </span>
              </button>
            </div>

            {/* 密码登录表单 */}
            {loginMode === 'password' && (
              <>
                {/* 用户名输入 */}
                <div className="space-y-2">
                  <label className="text-xs font-bold text-gray-400 uppercase tracking-wider">用户名 / 邮箱</label>
                  <div className="relative">
                    <User size={20} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                    <input
                      type="text"
                      placeholder="输入用户名或邮箱"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      onKeyDown={handleKeyDown}
                      className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/50 focus:border-[#ff6b00] transition-all"
                      disabled={isLoading}
                    />
                  </div>
                </div>

                {/* 密码输入 */}
                <div className="space-y-2">
                  <label className="text-xs font-bold text-gray-400 uppercase tracking-wider">密码</label>
                  <div className="relative">
                    <Lock size={20} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                    <input
                      type={showPassword ? "text" : "password"}
                      placeholder="输入密码"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onKeyDown={handleKeyDown}
                      className="w-full pl-12 pr-12 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/50 focus:border-[#ff6b00] transition-all"
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300 transition-colors"
                    >
                      {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                    </button>
                  </div>
                </div>
              </>
            )}

            {/* 邮箱验证码登录表单 */}
            {loginMode === 'email' && (
              <>
                {/* 邮箱输入 */}
                <div className="space-y-2">
                  <label className="text-xs font-bold text-gray-400 uppercase tracking-wider">邮箱地址</label>
                  <div className="relative">
                    <Mail size={20} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                    <input
                      type="email"
                      placeholder="输入注册邮箱"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      onKeyDown={handleKeyDown}
                      className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/50 focus:border-[#ff6b00] transition-all"
                      disabled={isLoading}
                    />
                  </div>
                </div>

                {/* 验证码输入 */}
                <div className="space-y-2">
                  <label className="text-xs font-bold text-gray-400 uppercase tracking-wider">验证码</label>
                  <div className="flex gap-3">
                    <div className="relative flex-1">
                      <KeyRound size={20} className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400" />
                      <input
                        type="text"
                        placeholder="6位验证码"
                        value={code}
                        onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        onKeyDown={handleKeyDown}
                        maxLength={6}
                        className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/50 focus:border-[#ff6b00] transition-all tracking-widest text-center"
                        disabled={isLoading}
                      />
                    </div>
                    <button
                      onClick={handleSendCode}
                      disabled={isSendingCode || countdown > 0 || !email}
                      className="px-4 py-3 bg-white/10 border border-white/10 rounded-xl text-white text-sm font-medium hover:bg-white/20 transition-all disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
                    >
                      {isSendingCode ? (
                        <Loader2 size={18} className="animate-spin" />
                      ) : countdown > 0 ? (
                        `${countdown}s`
                      ) : (
                        '获取验证码'
                      )}
                    </button>
                  </div>
                </div>
              </>
            )}

            {error && (
              <p className={`text-sm text-center ${
                error.includes('验证码已发送') || error.includes('开发模式')
                  ? 'text-green-400' 
                  : 'text-red-400'
              }`}>{error}</p>
            )}

            <button
              onClick={handleLogin}
              disabled={isLoading}
              className="w-full py-3 bg-gradient-to-r from-[#ff6b00] to-[#ff8c00] text-white rounded-xl font-bold text-sm hover:from-[#e66000] hover:to-[#e67a00] transition-all shadow-lg shadow-orange-500/30 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
            >
              {isLoading ? (
                <>
                  <Loader2 size={18} className="animate-spin" />
                  登录中...
                </>
              ) : (
                <>
                  登录
                  <ArrowRight size={18} />
                </>
              )}
            </button>

            {/* 登录方式切换提示 */}
            <div className="text-center">
              <button
                onClick={toggleLoginMode}
                className="text-gray-400 text-sm hover:text-[#ff6b00] transition-colors"
              >
                {loginMode === 'password' 
                  ? '忘记密码？使用邮箱验证码登录' 
                  : '使用用户名密码登录'}
              </button>
            </div>
          </div>
        </div>

        {/* 安全提示 */}
        <div className="mt-6 text-center">
          <p className="text-gray-500 text-xs">
            登录即表示您同意遵守系统使用规范
          </p>
          <p className="text-gray-600 text-xs mt-1">
            🔒 支持多重身份验证 | 全链路加密传输
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;