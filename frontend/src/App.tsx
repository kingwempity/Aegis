import React, { useEffect, useState } from 'react';
import { 
  Layout, Table, Button, Modal, Form, Input, Select, Tag, 
  message, Menu, Card, Row, Col, Statistic, Breadcrumb, Avatar, Dropdown, theme
} from 'antd';
import { 
  PlusOutlined, ReloadOutlined, DashboardOutlined, 
  BugOutlined, SafetyCertificateOutlined, UserOutlined,
  LogoutOutlined, SettingOutlined
} from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Header, Content, Sider } = Layout;
const { Option } = Select;

const API_BASE = '/api/v1';

interface Task {
  id: number;
  target_url: string;
  status: string;
  scan_strategy: string;
  created_at: string;
}

const App: React.FC = () => {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [form] = Form.useForm();
  
  const { token: { colorBgContainer, borderRadiusLG } } = theme.useToken();

  // 关键修改：调用列表接口
  const fetchTasks = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/tasks`);
      if (Array.isArray(res.data)) {
        setTasks(res.data);
      }
    } catch (err) {
      console.error(err);
      message.error('获取任务列表失败，请检查后端服务');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, []);

  const handleCreate = async (values: any) => {
    try {
      await axios.post(`${API_BASE}/tasks`, values);
      message.success('任务创建成功');
      setIsModalOpen(false);
      fetchTasks(); // 刷新列表
    } catch (err) {
      message.error('创建失败');
    }
  };

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id', width: 80 },
    { 
      title: '目标 URL', 
      dataIndex: 'target_url', 
      key: 'target_url',
      render: (text: string) => <a href={text} target="_blank" rel="noopener noreferrer">{text}</a> 
    },
    { 
      title: '策略', 
      dataIndex: 'scan_strategy', 
      key: 'scan_strategy',
      render: (t: string) => <Tag>{t.toUpperCase()}</Tag>
    },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status',
      width: 120,
      render: (status: string) => {
        let color = 'default';
        let label = status;
        if (status === 'COMPLETED') { color = 'success'; label = '完成'; }
        if (status === 'RUNNING') { color = 'processing'; label = '扫描中'; }
        if (status === 'PENDING') { color = 'warning'; label = '排队中'; }
        if (status === 'FAILED') { color = 'error'; label = '失败'; }
        return <Tag color={color}>{label}</Tag>;
      }
    },
    { 
      title: '创建时间', 
      dataIndex: 'created_at', 
      key: 'created_at',
      width: 180,
      render: (t: string) => dayjs(t).format('YYYY-MM-DD HH:mm')
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: Task) => (
        <Button type="link" size="small" href={`${API_BASE}/reports/${record.id}/html`} target="_blank">
          查看报告
        </Button>
      ),
    },
  ];

  const userMenuItems = [
    { key: '1', label: '个人中心', icon: <UserOutlined /> },
    { key: '3', label: '退出登录', icon: <LogoutOutlined />, danger: true },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={(value) => setCollapsed(value)}>
        <div style={{ height: 64, margin: 16, background: 'rgba(255, 255, 255, 0.2)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 'bold', fontSize: collapsed ? 12 : 18, overflow: 'hidden', whiteSpace: 'nowrap' }}>
          {collapsed ? 'A' : 'AEGIS 宙斯盾'}
        </div>
        <Menu theme="dark" defaultSelectedKeys={['1']} mode="inline" items={[
          { key: '1', icon: <DashboardOutlined />, label: '任务概览' },
        ]} />
      </Sider>
      <Layout>
        <Header style={{ padding: '0 24px', background: colorBgContainer, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Breadcrumb items={[{ title: '首页' }, { title: '任务概览' }]} />
          <Dropdown menu={{ items: userMenuItems as any }}>
            <div style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Avatar style={{ backgroundColor: '#1890ff' }} icon={<UserOutlined />} />
              <span>Admin User</span>
            </div>
          </Dropdown>
        </Header>
        <Content style={{ margin: '24px 16px 0', overflow: 'initial' }}>
          <div style={{ padding: 24, background: colorBgContainer, borderRadius: borderRadiusLG }}>
            <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 16, fontWeight: 500 }}>最近扫描任务</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <Button icon={<ReloadOutlined />} onClick={fetchTasks}>刷新</Button>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
                  新建扫描
                </Button>
              </div>
            </div>
            <Table dataSource={tasks} columns={columns} rowKey="id" loading={loading} />
          </div>
        </Content>
      </Layout>
      <Modal title="新建扫描任务" open={isModalOpen} onCancel={() => setIsModalOpen(false)} onOk={() => form.submit()}>
        <Form form={form} onFinish={handleCreate} layout="vertical">
          <Form.Item name="target_url" label="目标 URL" rules={[{ required: true, type: 'url' }]}>
            <Input placeholder="http://example.com" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
};

export default App;
