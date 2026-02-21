import React, { useState, useEffect } from 'react';
import { Form, Input, Button, Card, message, Divider, Typography, Alert } from 'antd';
import { UserOutlined, LockOutlined, MailOutlined, ExclamationCircleOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';
import { LoginRequest, RegisterRequest } from '../types';

const { Title, Text } = Typography;

const Login: React.FC = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const { login, register, error, clearError, isError } = useAuth();
  const navigate = useNavigate();

  const [form] = Form.useForm();

  // 清除错误状态
  useEffect(() => {
    if (clearError) {
      clearError();
    }
  }, [isLogin, clearError]);

  // 处理表单提交
  const handleSubmit = async (values: LoginRequest | RegisterRequest) => {
    setLoading(true);
    try {
      if (isLogin) {
        await login(values as LoginRequest);
        message.success('登录成功！正在跳转...');
        // 延迟跳转，让用户看到成功消息
        setTimeout(() => {
          navigate('/dashboard');
        }, 1000);
      } else {
        await register(values as RegisterRequest);
        message.success('注册成功！请使用您的账户登录。');
        setIsLogin(true);
        form.resetFields();
      }
    } catch (error: any) {
      // 错误已在认证上下文中处理，这里只需要显示
      console.error(`${isLogin ? '登录' : '注册'}失败:`, error);
    } finally {
      setLoading(false);
    }
  };

  // 切换登录/注册模式
  const toggleMode = () => {
    setIsLogin(!isLogin);
    form.resetFields();
    if (clearError) {
      clearError();
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-100 via-primary-200 to-primary-300 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-white bg-opacity-80"></div>

      <Card
        className="w-full max-w-md shadow-large border-0 relative z-10 card-modern"
        styles={{ body: { padding: '2rem' } }}
      >
        {/* Logo区域 */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-brand-primary rounded-xl flex items-center justify-center mx-auto mb-4 shadow-soft">
            <span className="text-3xl">🔍</span>
          </div>
          <Title level={2} className="text-brand-primary mb-2">
            漏洞检测系统
          </Title>
          <Text className="text-primary-600">
            基于模拟攻击的专业安全检测平台
          </Text>
        </div>

        {/* 错误提示 */}
        {isError && error && (
          <Alert
            message="认证错误"
            description={error}
            type="error"
            showIcon
            closable
            onClose={clearError}
            className="mb-6"
            icon={<ExclamationCircleOutlined />}
          />
        )}

        {/* 表单 */}
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSubmit}
          size="large"
          disabled={loading}
        >
          {!isLogin && (
            <Form.Item
              name="full_name"
              label="姓名"
              rules={[{ required: true, message: '请输入您的姓名' }]}
            >
              <Input
                prefix={<UserOutlined />}
                placeholder="请输入您的姓名"
                className="rounded-lg"
              />
            </Form.Item>
          )}

          <Form.Item
            name="username"
            label="用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { min: 3, max: 20, message: '用户名长度应为3-20个字符' },
              { pattern: /^[a-zA-Z0-9_]+$/, message: '用户名只能包含字母、数字和下划线' }
            ]}
          >
            <Input
              prefix={<UserOutlined />}
              placeholder="请输入用户名"
              className="rounded-lg"
              autoComplete="username"
            />
          </Form.Item>

          {!isLogin && (
            <Form.Item
              name="email"
              label="邮箱"
              rules={[
                { required: true, message: '请输入邮箱地址' },
                { type: 'email', message: '请输入有效的邮箱地址' }
              ]}
            >
              <Input
                prefix={<MailOutlined />}
                placeholder="请输入邮箱地址"
                className="rounded-lg"
                autoComplete="email"
              />
            </Form.Item>
          )}

          <Form.Item
            name="password"
            label="密码"
            rules={[
              { required: true, message: '请输入密码' },
              { min: 8, message: '密码至少8个字符' },
              isLogin ? {} : {
                pattern: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
                message: '密码必须包含大小写字母和数字'
              }
            ]}
          >
            <Input.Password
              prefix={<LockOutlined />}
              placeholder="请输入密码"
              className="rounded-lg"
              autoComplete={isLogin ? "current-password" : "new-password"}
            />
          </Form.Item>

          <Form.Item className="mb-4">
            <Button
              type="primary"
              htmlType="submit"
              loading={false}
              block
              className="h-12 rounded-lg font-medium"
            >
              {isLogin ? '登录' : '注册'}
            </Button>
          </Form.Item>
        </Form>

        <Divider className="my-6">
          <Text className="text-gray-500">或</Text>
        </Divider>

        {/* 切换登录/注册 */}
        <div className="text-center">
          <Text className="text-gray-600">
            {isLogin ? '还没有账户？' : '已有账户？'}
          </Text>
          <Button
            type="link"
            onClick={toggleMode}
            className="text-tape-brown hover:text-tape-dark p-1"
            disabled={loading}
          >
            {isLogin ? '立即注册' : '立即登录'}
          </Button>
        </div>

      </Card>
    </div>
  );
};

export default Login;
