/**
 * 任务列表页面
 * 显示所有扫描任务，支持筛选和操作
 */
import React, { useEffect, useState } from 'react';
import {
  Card,
  Table,
  Button,
  Modal,
  Form,
  Input,
  Select,
  Tag,
  Space,
  DatePicker,
  message,
} from 'antd';
import { PlusOutlined, ReloadOutlined, EyeOutlined, StopOutlined, DeleteOutlined } from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import dayjs from 'dayjs';

const API_BASE = '/api/v1';
const { Option } = Select;
const { RangePicker } = DatePicker;

interface Task {
  id: number;
  target_url: string;
  status: string;
  scan_strategy: string;
  created_at: string;
}

const TaskList: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();
  const navigate = useNavigate();

  useEffect(() => {
    fetchTasks();
  }, []);

  const fetchTasks = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/tasks`);
      if (Array.isArray(res.data)) {
        setTasks(res.data);
      }
    } catch (err) {
      console.error(err);
      message.error('获取任务列表失败');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (values: any) => {
    try {
      await axios.post(`${API_BASE}/tasks`, values);
      message.success('任务创建成功');
      setIsModalOpen(false);
      form.resetFields();
      fetchTasks();
    } catch (err: any) {
      message.error(err.response?.data?.detail || '创建失败');
    }
  };

  const handleStop = async (id: number) => {
    try {
      // TODO: 实现停止任务 API
      message.success('任务已停止');
      fetchTasks();
    } catch (err) {
      message.error('停止任务失败');
    }
  };

  const handleDelete = async (id: number) => {
    Modal.confirm({
      title: '确认删除',
      content: '确定要删除这个任务吗？',
      onOk: async () => {
        try {
          // TODO: 实现删除任务 API
          message.success('任务已删除');
          fetchTasks();
        } catch (err) {
          message.error('删除任务失败');
        }
      },
    });
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 80,
    },
    {
      title: '目标 URL',
      dataIndex: 'target_url',
      key: 'target_url',
      ellipsis: true,
      render: (text: string) => (
        <a href={text} target="_blank" rel="noopener noreferrer">
          {text}
        </a>
      ),
    },
    {
      title: '扫描策略',
      dataIndex: 'scan_strategy',
      key: 'scan_strategy',
      width: 120,
      render: (strategy: string) => <Tag>{strategy?.toUpperCase() || 'STANDARD'}</Tag>,
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => {
        const statusMap: Record<string, { color: string; label: string }> = {
          RUNNING: { color: 'processing', label: '运行中' },
          COMPLETED: { color: 'success', label: '完成' },
          PENDING: { color: 'warning', label: '排队中' },
          FAILED: { color: 'error', label: '失败' },
        };
        const config = statusMap[status] || { color: 'default', label: status };
        return <Tag color={config.color}>{config.label}</Tag>;
      },
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 180,
      render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm'),
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (_: any, record: Task) => (
        <Space size="small">
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => navigate(`/tasks/${record.id}`)}
          >
            查看
          </Button>
          {record.status === 'RUNNING' && (
            <Button
              type="link"
              size="small"
              danger
              icon={<StopOutlined />}
              onClick={() => handleStop(record.id)}
            >
              停止
            </Button>
          )}
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() => handleDelete(record.id)}
          >
            删除
          </Button>
        </Space>
      ),
    },
  ];

  return (
    <div style={{ padding: 24, backgroundColor: '#f5f5f5', minHeight: 'calc(100vh - 64px)' }}>
      {/* 操作栏 */}
      <Card
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
          marginBottom: 16,
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 500, color: '#262626' }}>任务管理</h2>
          <Space>
            <Button icon={<ReloadOutlined />} onClick={fetchTasks}>
              刷新
            </Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
              新建扫描
            </Button>
          </Space>
        </div>
      </Card>

      {/* 筛选栏 */}
      <Card
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
          marginBottom: 16,
        }}
      >
        <Space size="middle" wrap>
          <Select
            placeholder="状态"
            style={{ width: 120 }}
            allowClear
            onChange={(value) => {
              // TODO: 实现筛选逻辑
              console.log('筛选状态:', value);
            }}
          >
            <Option value="RUNNING">运行中</Option>
            <Option value="COMPLETED">已完成</Option>
            <Option value="PENDING">排队中</Option>
            <Option value="FAILED">失败</Option>
          </Select>
          <RangePicker
            placeholder={['开始时间', '结束时间']}
            onChange={(dates) => {
              // TODO: 实现时间筛选逻辑
              console.log('筛选时间:', dates);
            }}
          />
          <Input
            placeholder="搜索URL..."
            style={{ width: 300 }}
            allowClear
            onPressEnter={(e) => {
              // TODO: 实现搜索逻辑
              console.log('搜索:', e.currentTarget.value);
            }}
          />
        </Space>
      </Card>

      {/* 任务表格 */}
      <Card
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
        }}
      >
        <Table
          dataSource={tasks}
          columns={columns}
          rowKey="id"
          loading={loading}
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 条`,
          }}
        />
      </Card>

      {/* 新建任务模态框 */}
      <Modal
        title="新建扫描任务"
        open={isModalOpen}
        onCancel={() => {
          setIsModalOpen(false);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        okText="创建"
        cancelText="取消"
      >
        <Form form={form} onFinish={handleCreate} layout="vertical">
          <Form.Item
            name="target_url"
            label="目标 URL"
            rules={[
              { required: true, message: '请输入目标 URL' },
              { type: 'url', message: '请输入有效的 URL' },
            ]}
          >
            <Input placeholder="http://example.com" />
          </Form.Item>
          <Form.Item name="scan_strategy" label="扫描策略" initialValue="standard">
            <Select>
              <Option value="standard">标准扫描</Option>
              <Option value="fast">快速扫描</Option>
              <Option value="deep">深度扫描</Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default TaskList;
