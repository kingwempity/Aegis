import React, { useEffect, useState } from 'react';
import { Row, Col, Card, Statistic, Table, Tag, Button, Tabs, Avatar, Modal, Form, Input, Select, Space, message, Spin, Empty } from 'antd';
import {
  UserOutlined,
  ExperimentOutlined,
  AlertOutlined,
  BarChartOutlined,
  SettingOutlined,
  EditOutlined,
  DeleteOutlined,
  PlusOutlined,
  EyeOutlined,
  LockOutlined
} from '@ant-design/icons';
import { useTheme } from '../contexts/ThemeContext';
import { apiService } from '../services/api';
import { User as UserType, Task, Statistics } from '../types';

const { TabPane } = Tabs;
const { Option } = Select;

interface AdminStats extends Statistics {
  total_users: number;
  active_users: number;
  total_tasks_all: number;
  total_vulnerabilities_all: number;
}

interface SystemUser extends UserType {
  is_active: boolean;
  is_superuser: boolean;
  last_login?: string;
}

const AdminPanel: React.FC = () => {
  const { isDark } = useTheme();
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [users, setUsers] = useState<SystemUser[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(true);
  const [userModalVisible, setUserModalVisible] = useState(false);
  const [selectedUser, setSelectedUser] = useState<SystemUser | null>(null);
  const [form] = Form.useForm();

  useEffect(() => {
    loadAdminData();
  }, []);

  const loadAdminData = async () => {
    try {
      setLoading(true);
      const [statsData, usersData, tasksData] = await Promise.all([
        apiService.getAdminStatistics(),
        apiService.getAllUsers(),
        apiService.getAllTasks({ page: 1, page_size: 10 })
      ]);

      setStats(statsData);
      setUsers(usersData);
      setTasks(tasksData.tasks);
    } catch (error) {
      console.error('加载管理员数据失败:', error);
      message.error('加载数据失败');
    } finally {
      setLoading(false);
    }
  };

  const handleEditUser = (user: SystemUser) => {
    setSelectedUser(user);
    form.setFieldsValue({
      username: user.username,
      email: user.email,
      role: user.role,
      is_active: user.is_active
    });
    setUserModalVisible(true);
  };

  const handleDeleteUser = async (userId: string) => {
    Modal.confirm({
      title: '确认删除',
      content: '确定要删除此用户吗？此操作不可恢复。',
      okText: '删除',
      okType: 'danger',
      cancelText: '取消',
      onOk: async () => {
        try {
          await apiService.deleteUser(userId);
          message.success('用户删除成功');
          loadAdminData();
        } catch (error) {
          message.error('删除用户失败');
        }
      }
    });
  };

  const handleSaveUser = async (values: any) => {
    try {
      const userData = {
        ...values,
        is_superuser: values.role === 'admin'
      };

      if (selectedUser) {
        await apiService.updateUser(selectedUser.user_id, userData);
        message.success('用户更新成功');
      } else {
        await apiService.createUser(userData);
        message.success('用户创建成功');
      }

      setUserModalVisible(false);
      setSelectedUser(null);
      form.resetFields();
      loadAdminData();
    } catch (error) {
      message.error(selectedUser ? '更新用户失败' : '创建用户失败');
    }
  };

  const handleTaskAction = async (taskId: string, action: string) => {
    try {
      switch (action) {
        case 'cancel':
          await apiService.cancelTask(taskId);
          message.success('任务已取消');
          break;
        case 'delete':
          await apiService.deleteTask(taskId);
          message.success('任务已删除');
          break;
      }
      loadAdminData();
    } catch (error) {
      message.error('操作失败');
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

  const userColumns = [
    {
      title: '用户',
      dataIndex: 'username',
      key: 'username',
      render: (username: string, record: SystemUser) => (
        <Space>
          <Avatar icon={<UserOutlined />} />
          <div>
            <div className="font-medium">{username}</div>
            <div className="text-xs text-gray-500">{record.email}</div>
          </div>
        </Space>
      )
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => (
        <Tag color={role === 'admin' ? 'red' : 'blue'}>
          {role === 'admin' ? '管理员' : '普通用户'}
        </Tag>
      )
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (is_active: boolean) => (
        <Tag color={is_active ? 'green' : 'red'}>
          {is_active ? '活跃' : '禁用'}
        </Tag>
      )
    },
    {
      title: '任务数',
      dataIndex: 'total_tasks',
      key: 'total_tasks',
      render: (total_tasks: number) => total_tasks || 0
    },
    {
      title: '最后登录',
      dataIndex: 'last_login',
      key: 'last_login',
      render: (last_login?: string) =>
        last_login ? new Date(last_login).toLocaleString('zh-CN') : '从未登录'
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: SystemUser) => (
        <Space size="small">
          <Button
            type="text"
            icon={<EditOutlined />}
            onClick={() => handleEditUser(record)}
            className="text-blue-500"
          />
          <Button
            type="text"
            icon={<DeleteOutlined />}
            onClick={() => handleDeleteUser(record.user_id)}
            className="text-red-500"
            disabled={record.role === 'admin' && users.filter(u => u.role === 'admin').length === 1}
          />
        </Space>
      )
    }
  ];

  const taskColumns = [
    {
      title: '任务名称',
      dataIndex: 'task_name',
      key: 'task_name',
      render: (task_name: string, record: Task) => (
        <div>
          <div className="font-medium">{task_name || `任务 ${record.task_id.slice(-6)}`}</div>
          <div className="text-xs text-gray-500">{record.target_url}</div>
        </div>
      )
    },
    {
      title: '创建者',
      dataIndex: 'created_by',
      key: 'created_by',
      render: (created_by: any) => created_by?.username || '未知'
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => (
        <Tag color={getStatusColor(status)}>
          {getStatusText(status)}
        </Tag>
      )
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      render: (progress: number, record: Task) => {
        if (record.status === 'running') {
          return `${progress}%`;
        }
        return record.status === 'completed' ? '100%' : '0%';
      }
    },
    {
      title: '漏洞数',
      dataIndex: 'vulnerabilities_found',
      key: 'vulnerabilities_found',
      render: (count: number) => count || 0
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (created_at: string) => new Date(created_at).toLocaleString('zh-CN')
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Task) => (
        <Space size="small">
          <Button
            type="text"
            icon={<EyeOutlined />}
            onClick={() => window.open(`/tasks/${record.task_id}`, '_blank')}
            className="text-blue-500"
          />
          {record.status === 'running' && (
            <Button
              type="text"
              onClick={() => handleTaskAction(record.task_id, 'cancel')}
              className="text-orange-500"
            >
              取消
            </Button>
          )}
          <Button
            type="text"
            icon={<DeleteOutlined />}
            onClick={() => handleTaskAction(record.task_id, 'delete')}
            className="text-red-500"
          />
        </Space>
      )
    }
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <Spin size="large" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 标题 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            管理员面板
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            系统管理与监控中心
          </p>
        </div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            setSelectedUser(null);
            form.resetFields();
            setUserModalVisible(true);
          }}
        >
          添加用户
        </Button>
      </div>

      {/* 系统统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card hover:shadow-medium transition-shadow">
            <Statistic
              title={<span className={isDark ? 'text-gray-100' : ''}>总用户数</span>}
              value={stats?.total_users || 0}
              prefix={<UserOutlined className="text-blue-500" />}
              valueStyle={{ color: isDark ? '#93c5fd' : '#1677ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card hover:shadow-medium transition-shadow">
            <Statistic
              title={<span className={isDark ? 'text-gray-100' : ''}>活跃用户</span>}
              value={stats?.active_users || 0}
              prefix={<UserOutlined className="text-green-500" />}
              valueStyle={{ color: isDark ? '#86efac' : '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card hover:shadow-medium transition-shadow">
            <Statistic
              title={<span className={isDark ? 'text-gray-100' : ''}>总扫描任务</span>}
              value={stats?.total_tasks_all || 0}
              prefix={<ExperimentOutlined className="text-purple-500" />}
              valueStyle={{ color: isDark ? '#c4b5fd' : '#722ed1' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card hover:shadow-medium transition-shadow">
            <Statistic
              title={<span className={isDark ? 'text-gray-100' : ''}>发现漏洞</span>}
              value={stats?.total_vulnerabilities_all || 0}
              prefix={<AlertOutlined className="text-red-500" />}
              valueStyle={{ color: isDark ? '#fca5a5' : '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 管理选项卡 */}
      <Card>
        <Tabs defaultActiveKey="users" className="admin-tabs">
          <TabPane
            tab={
              <span className="flex items-center">
                <UserOutlined className="mr-2" />
                用户管理
              </span>
            }
            key="users"
          >
            <Table
              columns={userColumns}
              dataSource={users}
              rowKey="user_id"
              pagination={{ pageSize: 10 }}
              locale={{ emptyText: '暂无用户数据' }}
            />
          </TabPane>

          <TabPane
            tab={
              <span className="flex items-center">
                <ExperimentOutlined className="mr-2" />
                任务管理
              </span>
            }
            key="tasks"
          >
            <Table
              columns={taskColumns}
              dataSource={tasks}
              rowKey="task_id"
              pagination={{ pageSize: 10 }}
              locale={{ emptyText: '暂无任务数据' }}
            />
          </TabPane>

          <TabPane
            tab={
              <span className="flex items-center">
                <BarChartOutlined className="mr-2" />
                系统统计
              </span>
            }
            key="stats"
          >
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={12}>
                <Card title="扫描统计" className="stat-card">
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span>总扫描次数</span>
                      <span className="font-medium">{stats?.total_scans || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>活跃任务数</span>
                      <span className="font-medium">{stats?.active_tasks || 0}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>危急漏洞数</span>
                      <span className="font-medium text-red-500">{stats?.critical_vulnerabilities || 0}</span>
                    </div>
                  </div>
                </Card>
              </Col>
              <Col xs={24} lg={12}>
                <Card title="用户统计" className="stat-card">
                  <div className="space-y-4">
                    <div className="flex justify-between">
                      <span>管理员用户</span>
                      <span className="font-medium">{users.filter(u => u.role === 'admin').length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>普通用户</span>
                      <span className="font-medium">{users.filter(u => u.role === 'user').length}</span>
                    </div>
                    <div className="flex justify-between">
                      <span>禁用用户</span>
                      <span className="font-medium text-gray-500">{users.filter(u => !u.is_active).length}</span>
                    </div>
                  </div>
                </Card>
              </Col>
            </Row>
          </TabPane>
        </Tabs>
      </Card>

      {/* 用户编辑模态框 */}
      <Modal
        title={selectedUser ? "编辑用户" : "添加用户"}
        open={userModalVisible}
        onCancel={() => {
          setUserModalVisible(false);
          setSelectedUser(null);
          form.resetFields();
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleSaveUser}
          className="mt-4"
        >
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: true, message: '请输入用户名' }]}
          >
            <Input prefix={<UserOutlined />} disabled={!!selectedUser} />
          </Form.Item>

          <Form.Item
            name="email"
            label="邮箱"
            rules={[
              { required: true, message: '请输入邮箱' },
              { type: 'email', message: '请输入有效的邮箱地址' }
            ]}
          >
            <Input prefix={<LockOutlined />} />
          </Form.Item>

          {!selectedUser && (
            <Form.Item
              name="password"
              label="密码"
              rules={[
                { required: true, message: '请输入密码' },
                { min: 8, message: '密码至少8位' }
              ]}
            >
              <Input.Password prefix={<LockOutlined />} />
            </Form.Item>
          )}

          <Form.Item
            name="role"
            label="角色"
            rules={[{ required: true, message: '请选择角色' }]}
          >
            <Select>
              <Option value="user">普通用户</Option>
              <Option value="admin">管理员</Option>
            </Select>
          </Form.Item>

          <Form.Item
            name="is_active"
            label="状态"
            valuePropName="checked"
          >
            <Select>
              <Option value={true}>活跃</Option>
              <Option value={false}>禁用</Option>
            </Select>
          </Form.Item>

          <Form.Item className="mb-0 text-right">
            <Space>
              <Button onClick={() => {
                setUserModalVisible(false);
                setSelectedUser(null);
                form.resetFields();
              }}>
                取消
              </Button>
              <Button type="primary" htmlType="submit">
                {selectedUser ? '更新' : '创建'}
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AdminPanel;
