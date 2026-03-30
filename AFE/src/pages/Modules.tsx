import React, { useEffect, useState } from 'react';
import { Card, Table, Tag, Button, Space, message, Drawer, Descriptions, Result, Spin } from 'antd';
import { ReloadOutlined, SyncOutlined, InfoCircleOutlined, SafetyOutlined } from '@ant-design/icons';
import { apiService } from '../services/api';
import { useAuth } from '../hooks/useAuth';

interface ModuleItem {
  id: string;
  name: string;
  category?: string;
  description?: string;
  enabled?: boolean;
  version?: string;
  [key: string]: any;
}

const Modules: React.FC = () => {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [loading, setLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [modules, setModules] = useState<ModuleItem[]>([]);
  const [detailOpen, setDetailOpen] = useState(false);
  const [current, setCurrent] = useState<ModuleItem | null>(null);

  const loadModules = async () => {
    setLoading(true);
    try {
      const res = await apiService.getModules();
      const list = res?.modules || res;
      setModules(list || []);
    } catch (error) {
      console.error('加载漏洞模块失败', error);
      message.error('加载漏洞模块失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  const handleUpdate = async () => {
    setUpdating(true);
    try {
      const res = await apiService.updateModules();
      message.success(res?.message || '漏洞库更新已触发');
    } catch (error: any) {
      message.error(error?.message || '更新失败，请稍后再试');
    } finally {
      setUpdating(false);
    }
  };

  const handleShowDetail = async (record: ModuleItem) => {
    setCurrent(record);
    setDetailOpen(true);
    try {
      const detail = await apiService.getModuleDetail(record.id);
      setCurrent(detail || record);
    } catch (error) {
      console.warn('获取模块详情失败，使用列表数据回显');
    }
  };

  useEffect(() => {
    loadModules();
  }, []);

  if (!isAdmin) {
    return (
      <Result
        status="403"
        title="无权限"
        subTitle="仅管理员可访问漏洞库管理"
      />
    );
  }

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: ModuleItem) => (
        <Space>
          <SafetyOutlined className="text-brand-primary" />
          <span className="font-medium">{text}</span>
          <Tag>{record.category || '未知分类'}</Tag>
        </Space>
      )
    },
    {
      title: '版本',
      dataIndex: 'version',
      key: 'version',
      width: 120,
      render: (v: string) => v || '-'
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      width: 120,
      render: (enabled: boolean) => (
        <Tag color={enabled ? 'green' : 'volcano'}>{enabled ? '启用' : '禁用'}</Tag>
      )
    },
    {
      title: '描述',
      dataIndex: 'description',
      key: 'description',
      ellipsis: true,
      render: (text: string) => text || '-'
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: ModuleItem) => (
        <Button type="link" onClick={() => handleShowDetail(record)}>
          详情
        </Button>
      )
    }
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">漏洞库管理</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">查看并更新系统漏洞检测模块</p>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadModules} disabled={loading}>
            刷新
          </Button>
          <Button
            type="primary"
            icon={<SyncOutlined />}
            loading={updating}
            onClick={handleUpdate}
          >
            更新漏洞库
          </Button>
        </Space>
      </div>

      <Card className="card-modern">
        <Spin spinning={loading}>
          <Table
            rowKey="id"
            columns={columns}
            dataSource={modules}
            pagination={false}
          />
        </Spin>
      </Card>

      <Drawer
        width={520}
        title={current?.name || '模块详情'}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      >
        {current ? (
          <Descriptions column={1} bordered labelStyle={{ width: 120 }}>
            <Descriptions.Item label="模块ID">{current.id}</Descriptions.Item>
            <Descriptions.Item label="名称">{current.name}</Descriptions.Item>
            <Descriptions.Item label="分类">{current.category || '-'}</Descriptions.Item>
            <Descriptions.Item label="版本">{current.version || '-'}</Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={current.enabled ? 'green' : 'volcano'}>
                {current.enabled ? '启用' : '禁用'}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="描述">{current.description || '暂无描述'}</Descriptions.Item>
            {current.attack_vectors && (
              <Descriptions.Item label="攻击向量">
                <Space wrap>
                  {(current.attack_vectors as string[]).map((v) => (
                    <Tag key={v}>{v}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
            )}
            {current.configurable_options && (
              <Descriptions.Item label="可配置项">
                <pre className="whitespace-pre-wrap text-sm bg-primary-50 dark:bg-primary-800 p-3 rounded">
                  {JSON.stringify(current.configurable_options, null, 2)}
                </pre>
              </Descriptions.Item>
            )}
            {current.supported_databases && (
              <Descriptions.Item label="支持的数据库">
                <Space wrap>
                  {(current.supported_databases as string[]).map((v) => (
                    <Tag key={v}>{v}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
            )}
            {current.supported_types && (
              <Descriptions.Item label="支持类型">
                <Space wrap>
                  {(current.supported_types as string[]).map((v) => (
                    <Tag key={v}>{v}</Tag>
                  ))}
                </Space>
              </Descriptions.Item>
            )}
            {current.last_updated && (
              <Descriptions.Item label="最近更新">{current.last_updated}</Descriptions.Item>
            )}
          </Descriptions>
        ) : (
          <Result icon={<InfoCircleOutlined />} title="暂无数据" />
        )}
      </Drawer>
    </div>
  );
};

export default Modules;

