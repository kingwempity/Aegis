import React, { useEffect, useMemo, useState } from 'react';
import { Card, Form, Switch, Select, Button, Divider, message, Alert, Space } from 'antd';
import { ReloadOutlined, SaveOutlined, SyncOutlined } from '@ant-design/icons';
import { useTheme } from '../contexts/ThemeContext';

type ThemeOption = 'light' | 'dark';

interface Preferences {
  appearance: {
    theme: ThemeOption;
    compactSidebar: boolean;
    defaultPage: string;
  };
  notifications: {
    taskUpdates: boolean;
    systemAlerts: boolean;
    securityEvents: boolean;
  };
  privacy: {
    keepSession: boolean;
    shareTelemetry: boolean;
    autoLock: boolean;
  };
}

const STORAGE_KEY = 'app_preferences';

const defaultPreferences: Preferences = {
  appearance: {
    theme: 'light',
    compactSidebar: false,
    defaultPage: '/dashboard',
  },
  notifications: {
    taskUpdates: true,
    systemAlerts: true,
    securityEvents: true,
  },
  privacy: {
    keepSession: true,
    shareTelemetry: false,
    autoLock: false,
  },
};

const Settings: React.FC = () => {
  const [form] = Form.useForm<Preferences>();
  const { isDark, toggleTheme } = useTheme();
  const [saving, setSaving] = useState(false);

  // 从本地加载偏好设置
  useEffect(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        form.setFieldsValue({
          ...defaultPreferences,
          ...parsed,
          appearance: { ...defaultPreferences.appearance, ...parsed.appearance },
          notifications: { ...defaultPreferences.notifications, ...parsed.notifications },
          privacy: { ...defaultPreferences.privacy, ...parsed.privacy },
        });
        // 保持主题与存储一致
        const targetTheme: ThemeOption = parsed.appearance?.theme || defaultPreferences.appearance.theme;
        if ((targetTheme === 'dark') !== isDark) {
          toggleTheme();
        }
        return;
      } catch (error) {
        console.warn('解析本地设置失败，将使用默认设置', error);
      }
    }
    form.setFieldsValue(defaultPreferences);
  }, [form, isDark, toggleTheme]);

  const handleSave = async () => {
    try {
      const values = await form.validateFields();
      setSaving(true);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(values));

      // 立即同步主题设置
      const wantDark = values.appearance.theme === 'dark';
      if (wantDark !== isDark) {
        toggleTheme();
      }

      message.success('设置已保存并立即生效');
    } catch (error: any) {
      if (error?.errorFields) {
        message.error('请检查表单后再保存');
      } else {
        message.error('保存设置时出现问题，请稍后重试');
      }
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    form.setFieldsValue(defaultPreferences);
    localStorage.removeItem(STORAGE_KEY);
    if (isDark) {
      toggleTheme();
    }
    message.success('已恢复默认设置');
  };

  const handleThemeSwitch = (checked: boolean) => {
    form.setFieldValue(['appearance', 'theme'], checked ? 'dark' : 'light');
    if (checked !== isDark) {
      toggleTheme();
    }
  };

  const defaultPageOptions = useMemo(
    () => [
      { value: '/dashboard', label: '仪表板' },
      { value: '/tasks', label: '扫描任务' },
      { value: '/reports', label: '检测报告' },
      { value: '/statistics', label: '统计分析' },
      { value: '/settings', label: '系统设置' },
    ],
    []
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">系统设置</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">配置界面、通知和隐私偏好</p>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={handleReset}>
            恢复默认
          </Button>
          <Button type="primary" icon={<SaveOutlined />} loading={saving} onClick={handleSave}>
            保存设置
          </Button>
        </Space>
      </div>

      <Alert
        type="info"
        showIcon
        message="提示"
        description="所有设置将立即生效，并在本地保存，跨页保持一致。"
        className="card-retro"
      />

      <Form form={form} layout="vertical" initialValues={defaultPreferences}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card title="外观与布局" className="card-retro">
            <Form.Item label="深色模式" tooltip="切换后全局立即生效" colon={false}>
              <Switch
                checked={form.getFieldValue(['appearance', 'theme']) === 'dark' || isDark}
                onChange={handleThemeSwitch}
                checkedChildren="暗色"
                unCheckedChildren="亮色"
              />
            </Form.Item>
            <Divider />
            <Form.Item
              label="侧边栏紧凑模式"
              valuePropName="checked"
              name={['appearance', 'compactSidebar']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              label="默认打开页面"
              name={['appearance', 'defaultPage']}
              rules={[{ required: true, message: '请选择默认页面' }]}
            >
              <Select options={defaultPageOptions} className="w-full" />
            </Form.Item>
          </Card>

          <Card title="通知中心" className="card-retro">
            <Form.Item
              label="任务状态提醒"
              valuePropName="checked"
              name={['notifications', 'taskUpdates']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              label="系统公告提醒"
              valuePropName="checked"
              name={['notifications', 'systemAlerts']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              label="安全事件提醒"
              valuePropName="checked"
              name={['notifications', 'securityEvents']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
          </Card>

          <Card title="安全与隐私" className="card-retro">
            <Form.Item
              label="保持登录状态"
              valuePropName="checked"
              name={['privacy', 'keepSession']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              label="自动锁定（无操作10分钟）"
              valuePropName="checked"
              name={['privacy', 'autoLock']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              label="匿名使用统计"
              tooltip="仅用于改进体验，不包含个人数据"
              valuePropName="checked"
              name={['privacy', 'shareTelemetry']}
              colon={false}
            >
              <Switch checkedChildren="开启" unCheckedChildren="关闭" />
            </Form.Item>
          </Card>

          <Card title="偏好同步" className="card-retro">
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
              设置存储在浏览器本地，如需跨设备同步请手动导出导入。
            </p>
            <Space>
              <Button
                icon={<SyncOutlined />}
                onClick={() => {
                  const stored = localStorage.getItem(STORAGE_KEY);
                  if (stored) {
                    message.success('已从本地偏好同步');
                    form.setFieldsValue(JSON.parse(stored));
                  } else {
                    message.info('当前未发现已保存的偏好');
                  }
                }}
              >
                从本地同步
              </Button>
              <Button
                danger
                onClick={() => {
                  localStorage.removeItem(STORAGE_KEY);
                  message.success('已清除本地偏好缓存');
                }}
              >
                清除本地缓存
              </Button>
            </Space>
          </Card>
        </div>
      </Form>
    </div>
  );
};

export default Settings;
