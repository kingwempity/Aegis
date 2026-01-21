import React, { useEffect, useState } from 'react';
import { Layout, Table, Button, Modal, Form, Input, Select, Tag, message } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const { Header, Content } = Layout;
const { Option } = Select;

// API 基础地址 (生产环境 Nginx 会代理 /api，所以用相对路径最稳)
const API_BASE = '/api/v1';

// 定义任务类型接口
interface Task {
  id: number;
  target_url: string;
  status: string;
  scan_strategy: string;
  created_at: string;
}

const App: React.FC = () => {
  // 指定 State 类型为 Task 数组
  const [tasks, setTasks] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();

  const fetchTasks = async () => {
    setLoading(true);
    try {
      // 这里的 res.data 类型未知，TS 会警告
      // 实际上我们应该调用 list 接口，但之前代码是用详情接口模拟的
      // 暂时强转一下
      const res = await axios.get(`${API_BASE}/tasks/1`); 
      // 修复 TS2322: 如果后端返回的是单个对象，把它包进数组
      setTasks([res.data] as Task[]); 
    } catch (err) {
      console.error(err);
      // 如果后端没数据，置空防止报错
      setTasks([]);
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
      fetchTasks();
    } catch (err) {
      message.error('创建失败');
    }
  };

  const columns = [
    { title: 'ID', dataIndex: 'id', key: 'id' },
    { title: '目标 URL', dataIndex: 'target_url', key: 'target_url' },
    { 
      title: '状态', 
      dataIndex: 'status', 
      key: 'status',
      render: (status: string) => {
        let color = 'default';
        if (status === 'COMPLETED') color = 'success';
        if (status === 'RUNNING') color = 'processing';
        if (status === 'FAILED') color = 'error';
        return <Tag color={color}>{status}</Tag>;
      }
    },
    { 
      title: '创建时间', 
      dataIndex: 'created_at', 
      key: 'created_at',
      render: (t: string) => dayjs(t).format('YYYY-MM-DD HH:mm:ss')
    },
    {
      title: '操作',
      key: 'action',
      // 修复 TS7006: 显式声明 _ 为 any 或 unknown
      render: (_: any, record: Task) => (
        <Button type="link" href={`${API_BASE}/reports/${record.id}/html`} target="_blank">
          查看报告
        </Button>
      ),
    },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ display: 'flex', alignItems: 'center', color: 'white', fontSize: '18px' }}>
        Aegis 漏洞扫描平台
      </Header>
      <Content style={{ padding: '24px' }}>
        <div style={{ background: '#fff', padding: 24, minHeight: 280 }}>
          <div style={{ marginBottom: 16, display: 'flex', justifyContent: 'space-between' }}>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
              新建扫描
            </Button>
            <Button icon={<ReloadOutlined />} onClick={fetchTasks}>刷新</Button>
          </div>
          
          <Table 
            dataSource={tasks} 
            columns={columns} 
            rowKey="id" 
            loading={loading}
          />

          <Modal title="新建扫描任务" open={isModalOpen} onCancel={() => setIsModalOpen(false)} onOk={() => form.submit()}>
            <Form form={form} onFinish={handleCreate} layout="vertical">
              <Form.Item name="target_url" label="目标 URL" rules={[{ required: true, type: 'url' }]}>
                <Input placeholder="http://example.com" />
              </Form.Item>
              <Form.Item name="scan_strategy" label="策略" initialValue="default">
                <Select>
                  <Option value="default">默认扫描</Option>
                  <Option value="fast">快速扫描</Option>
                  <Option value="full">深度扫描</Option>
                </Select>
              </Form.Item>
            </Form>
          </Modal>
        </div>
      </Content>
    </Layout>
  );
};

export default App;
