import React, { useEffect, useState } from 'react';
import {
  Table, Button, Tag, Space, Modal, Form, Input, Select, message,
  Card, Progress, Tooltip, Dropdown, Popconfirm, InputNumber
} from 'antd';
import {
  PlusOutlined, EyeOutlined, DeleteOutlined, PlayCircleOutlined,
  PauseCircleOutlined, StopOutlined, MoreOutlined, ExperimentOutlined,
  FileTextOutlined, ReloadOutlined
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import { Task, CreateTaskRequest } from '../types';

const { Option } = Select;

const Tasks: React.FC = () => {
  const navigate = useNavigate();
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [createModalVisible, setCreateModalVisible] = useState(false);
  const [createForm] = Form.useForm();
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0,
  });

  useEffect(() => {
    loadTasks();
  }, [pagination.current, pagination.pageSize]);

  const loadTasks = async () => {
    setLoading(true);
    try {
      const response = await apiService.getTasks({
        page: pagination.current,
        page_size: pagination.pageSize,
        sort_by: 'created_at',
        order: 'desc'
      });
      setTasks(response.tasks);
      setPagination(prev => ({
        ...prev,
        total: response.total,
      }));
    } catch (error) {
      message.error('加载任务列表失败');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTask = async (values: CreateTaskRequest) => {
    try {
      await apiService.createTask(values);
      message.success('任务创建成功');
      setCreateModalVisible(false);
      createForm.resetFields();
      loadTasks();
    } catch (error) {
      message.error('创建任务失败');
    }
  };

  const handleCancelTask = async (taskId: string) => {
    try {
      await apiService.cancelTask(taskId);
      message.success('任务已取消');
      loadTasks();
    } catch (error) {
      message.error('取消任务失败');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'green';
      case 'running': return 'blue';
      case 'failed': return 'red';
      case 'queued': return 'orange';
      case 'cancelled': return 'gray';
      default: return 'default';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'completed': return '已完成';
      case 'running': return '运行中';
      case 'failed': return '失败';
      case 'queued': return '队列中';
      case 'cancelled': return '已取消';
      default: return status;
    }
  };

  const columns = [
    {
      title: '任务名称',
      dataIndex: 'task_name',
      key: 'task_name',
      render: (text: string, record: Task) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-gray-100">{text}</div>
          <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
            {record.target_url}
          </div>
        </div>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string, record: Task) => (
        <div className="space-y-2">
          <Tag color={getStatusColor(status)} className="mb-0">
            {getStatusText(status)}
          </Tag>
          {status === 'running' && (
            <div className="w-24">
              <Progress
                percent={record.progress}
                size="small"
                status="active"
                strokeColor="#8B4513"
              />
            </div>
          )}
        </div>
      ),
    },
    {
      title: '扫描配置',
      dataIndex: 'scan_profile',
      key: 'scan_profile',
      render: (profile: string) => (
        <Tag color="blue">{profile === 'full' ? '完整扫描' : profile === 'quick' ? '快速扫描' : '自定义'}</Tag>
      ),
    },
    {
      title: '漏洞数量',
      dataIndex: 'vulnerabilities_found',
      key: 'vulnerabilities_found',
      render: (count: number) => (
        <span className={count > 0 ? 'text-red-600 font-medium' : 'text-gray-600'}>
          {count || 0}
        </span>
      ),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date: string) => new Date(date).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Task) => {
        const menuItems = [
          {
            key: 'view',
            icon: <EyeOutlined />,
            label: '查看详情',
            onClick: () => navigate(`/tasks/${record.task_id}`),
          },
          {
            key: 'report',
            icon: <FileTextOutlined />,
            label: '查看报告',
            disabled: record.status !== 'completed',
            onClick: () => navigate(`/reports?taskId=${record.task_id}`),
          },
        ];

        // 只对非完成和非失败的任务显示取消选项
        if (record.status === 'queued' || record.status === 'running') {
          menuItems.push({
            key: 'cancel',
            icon: <StopOutlined />,
            label: '取消任务',
            onClick: () => handleCancelTask(record.task_id),
          });
        }

        return (
          <Space size="small">
            <Dropdown
              menu={{ items: menuItems }}
              trigger={['click']}
              placement="bottomRight"
            >
              <Button type="text" icon={<MoreOutlined />} />
            </Dropdown>
          </Space>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      {/* 标题和操作 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            扫描任务
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            管理您的安全扫描任务
          </p>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={loadTasks}
            loading={loading}
          >
            刷新
          </Button>
          <Button
            type="primary"
            icon={<PlusOutlined />}
            onClick={() => setCreateModalVisible(true)}
          >
            新建任务
          </Button>
        </Space>
      </div>

      {/* 任务列表 */}
      <Card className="card-modern">
        <Table
          columns={columns}
          dataSource={tasks}
          rowKey="task_id"
          loading={loading}
          pagination={{
            ...pagination,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
            pageSizeOptions: ['10', '20', '50'],
          }}
          onChange={(paginationInfo) => {
            setPagination({
              current: paginationInfo.current || 1,
              pageSize: paginationInfo.pageSize || 10,
              total: pagination.total,
            });
          }}
          size="middle"
        />
      </Card>

      {/* 创建任务模态框 */}
      <Modal
        title={
          <div className="flex items-center">
            <ExperimentOutlined className="text-accent-primary mr-2" />
            新建扫描任务
          </div>
        }
        open={createModalVisible}
        onCancel={() => {
          setCreateModalVisible(false);
          createForm.resetFields();
        }}
        footer={null}
        width={600}
        className="retro-modal"
      >
        <Form
          form={createForm}
          layout="vertical"
          onFinish={handleCreateTask}
          initialValues={{
            scan_profile: 'full',
            max_depth: 5,
            max_pages: 100,
            timeout: 30,
          }}
        >
          <Form.Item
            name="target_url"
            label="目标URL"
            rules={[
              { required: true, message: '请输入目标URL' },
              { type: 'url', message: '请输入有效的URL' }
            ]}
          >
            <Input
              placeholder="https://example.com"
              prefix={<ExperimentOutlined className="text-gray-400" />}
            />
          </Form.Item>

          <Form.Item
            name="task_name"
            label="任务名称"
            rules={[{ required: true, message: '请输入任务名称' }]}
          >
            <Input placeholder="为任务设置一个描述性名称" />
          </Form.Item>

          <Form.Item
            name="scan_profile"
            label="扫描配置"
            rules={[{ required: true, message: '请选择扫描配置' }]}
          >
            <Select placeholder="选择扫描类型">
              <Option value="quick">快速扫描 - 基础安全检查</Option>
              <Option value="full">完整扫描 - 全面安全检测</Option>
              <Option value="custom">自定义扫描 - 选择特定模块</Option>
            </Select>
          </Form.Item>

          <Form.Item
            noStyle
            shouldUpdate={(prevValues, currentValues) => prevValues.scan_profile !== currentValues.scan_profile}
          >
            {({ getFieldValue }) =>
              getFieldValue('scan_profile') === 'custom' && (
                <Form.Item
                  name="custom_modules"
                  label="选择检测模块"
                  rules={[{ required: true, message: '请选择至少一个检测模块' }]}
                >
                  <Select
                    mode="multiple"
                    placeholder="选择要启用的检测模块"
                    style={{ width: '100%' }}
                  >
                    <Option value="sql_injection">SQL注入</Option>
                    <Option value="xss">跨站脚本(XSS)</Option>
                    <Option value="csrf">跨站请求伪造(CSRF)</Option>
                    <Option value="file_upload">文件上传漏洞</Option>
                    <Option value="path_traversal">路径遍历</Option>
                    <Option value="idor">越权访问(IDOR)</Option>
                  </Select>
                </Form.Item>
              )
            }
          </Form.Item>

          <div className="grid grid-cols-2 gap-4">
            <Form.Item
              name="max_depth"
              label="最大爬取深度"
            >
              <InputNumber
                min={1}
                max={10}
                className="w-full"
                placeholder="1-10"
              />
            </Form.Item>

            <Form.Item
              name="max_pages"
              label="最大扫描页面数"
            >
              <InputNumber
                min={10}
                max={1000}
                className="w-full"
                placeholder="10-1000"
              />
            </Form.Item>
          </div>

          <Form.Item
            name="timeout"
            label="请求超时时间(秒)"
          >
            <InputNumber
              min={10}
              max={300}
              className="w-full"
              placeholder="10-300"
            />
          </Form.Item>

          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => {
                setCreateModalVisible(false);
                createForm.resetFields();
              }}>
                取消
              </Button>
              <Button
                type="primary"
                htmlType="submit"
              >
                创建任务
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default Tasks;
