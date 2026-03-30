import React, { useEffect, useState, useCallback } from 'react';
import {
  Card, Row, Col, Statistic, Table, Tag, Button, Space, Modal, Form, Input, Select,
  Progress, Tabs, List, Avatar, Descriptions, Badge, Timeline, Drawer, message,
  Tooltip, Dropdown, Menu, Switch, InputNumber, Collapse, Alert, Spin, Empty, Divider,
  Typography, Steps, Popconfirm, notification
} from 'antd';
import {
  ThunderboltOutlined, BugOutlined, CodeOutlined, BranchesOutlined, PlayCircleOutlined,
  PauseCircleOutlined, StopOutlined, ReloadOutlined, SettingOutlined, FileTextOutlined,
  SafetyOutlined, AlertOutlined, CheckCircleOutlined, ClockCircleOutlined, ApiOutlined,
  DatabaseOutlined, CloudServerOutlined, LockOutlined, UnlockOutlined, RocketOutlined,
  ScanOutlined, ExperimentOutlined, EyeOutlined, DownloadOutlined, CopyOutlined,
  PlusOutlined, DeleteOutlined, EditOutlined, HistoryOutlined, NodeIndexOutlined
} from '@ant-design/icons';
import { apiService } from '../services/api';
import { Task, Vulnerability } from '../types';

const { TabPane } = Tabs;
const { Panel } = Collapse;
const { Title, Text, Paragraph } = Typography;
const { Step } = Steps;
const { Option } = Select;
const { TextArea } = Input;

interface AttackScript {
  id: string;
  name: string;
  type: 'sql_injection' | 'xss' | 'csrf' | 'file_upload' | 'path_traversal' | 'command_injection' | 'ssrf' | 'idor';
  target: string;
  payload: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  headers: Record<string, string>;
  parameters: Record<string, string>;
  status: 'draft' | 'ready' | 'executing' | 'success' | 'failed';
  created_at: string;
  executed_at?: string;
  result?: string;
}

interface AttackPath {
  id: string;
  name: string;
  target: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  status: 'pending' | 'exploring' | 'completed' | 'failed';
  progress: number;
  current_node?: string;
  discovered_vulnerabilities: string[];
  created_at: string;
}

interface AttackNode {
  id: string;
  type: 'entry' | 'endpoint' | 'parameter' | 'vulnerability' | 'exploit';
  label: string;
  url?: string;
  method?: string;
  parameter?: string;
  vulnerability_type?: string;
  status: 'unvisited' | 'visiting' | 'visited' | 'vulnerable' | 'safe';
  depth: number;
  children: string[];
  parent?: string;
}

interface AttackEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  type: 'crawl' | 'form' | 'ajax' | 'redirect' | 'exploit';
}

interface AttackModule {
  id: string;
  name: string;
  category: string;
  description: string;
  enabled: boolean;
  version: string;
  payloads: string[];
  detection_patterns: string[];
}

const AttackEngine: React.FC = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [loading, setLoading] = useState(false);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [attackScripts, setAttackScripts] = useState<AttackScript[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [modules, setModules] = useState<AttackModule[]>([]);
  const [selectedScript, setSelectedScript] = useState<AttackScript | null>(null);
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [scriptModalVisible, setScriptModalVisible] = useState(false);
  const [pathModalVisible, setPathModalVisible] = useState(false);
  const [detailDrawerVisible, setDetailDrawerVisible] = useState(false);
  const [scriptForm] = Form.useForm();
  const [pathForm] = Form.useForm();
  const [executingScript, setExecutingScript] = useState<string | null>(null);
  const [exploringPath, setExploringPath] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    try {
      const [tasksRes, modulesRes] = await Promise.all([
        apiService.getTasks({ page: 1, page_size: 10 }),
        apiService.getModules()
      ]);
      setTasks(tasksRes.tasks);
      const moduleList = modulesRes?.modules || modulesRes || [];
      setModules(moduleList.map((m: any) => ({
        ...m,
        payloads: getDefaultPayloads(m.id),
        detection_patterns: getDefaultPatterns(m.id)
      })));
      loadMockData();
    } catch (error) {
      console.error('加载数据失败:', error);
      loadMockData();
    } finally {
      setLoading(false);
    }
  };

  const loadMockData = () => {
    setAttackScripts([
      {
        id: 'script_001',
        name: 'SQL注入测试脚本 - 登录表单',
        type: 'sql_injection',
        target: 'https://example.com/login.php',
        payload: "' OR '1'='1' --",
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        parameters: { username: "' OR '1'='1' --", password: 'test' },
        status: 'ready',
        created_at: new Date().toISOString()
      },
      {
        id: 'script_002',
        name: 'XSS反射型测试',
        type: 'xss',
        target: 'https://example.com/search?q=',
        payload: '<script>alert("XSS")</script>',
        method: 'GET',
        headers: {},
        parameters: { q: '<script>alert("XSS")</script>' },
        status: 'success',
        created_at: new Date(Date.now() - 3600000).toISOString(),
        executed_at: new Date().toISOString(),
        result: '发现XSS漏洞，payload被反射到响应中'
      }
    ]);

    setAttackPaths([
      {
        id: 'path_001',
        name: 'DVWA攻击路径探索',
        target: 'http://dvwa.example.com',
        nodes: [
          { id: 'n1', type: 'entry', label: '首页', url: '/', status: 'visited', depth: 0, children: ['n2', 'n3'] },
          { id: 'n2', type: 'endpoint', label: '登录页面', url: '/login.php', method: 'POST', status: 'vulnerable', depth: 1, children: ['n4'], parent: 'n1' },
          { id: 'n3', type: 'endpoint', label: '搜索功能', url: '/search.php', method: 'GET', status: 'visited', depth: 1, children: [], parent: 'n1' },
          { id: 'n4', type: 'vulnerability', label: 'SQL注入', vulnerability_type: 'sql_injection', status: 'vulnerable', depth: 2, children: [], parent: 'n2' }
        ],
        edges: [
          { id: 'e1', source: 'n1', target: 'n2', label: '导航', type: 'crawl' },
          { id: 'e2', source: 'n1', target: 'n3', label: '导航', type: 'crawl' },
          { id: 'e3', source: 'n2', target: 'n4', label: '发现漏洞', type: 'exploit' }
        ],
        status: 'completed',
        progress: 100,
        discovered_vulnerabilities: ['SQL注入 - 登录表单'],
        created_at: new Date(Date.now() - 7200000).toISOString()
      },
      {
        id: 'path_002',
        name: 'Web应用渗透测试',
        target: 'https://target-app.com',
        nodes: [
          { id: 'n1', type: 'entry', label: '入口点', url: '/', status: 'visited', depth: 0, children: ['n2'] },
          { id: 'n2', type: 'endpoint', label: '用户中心', url: '/user/profile', status: 'visiting', depth: 1, children: [], parent: 'n1' }
        ],
        edges: [
          { id: 'e1', source: 'n1', target: 'n2', label: '认证后访问', type: 'form' }
        ],
        status: 'exploring',
        progress: 45,
        current_node: 'n2',
        discovered_vulnerabilities: [],
        created_at: new Date().toISOString()
      }
    ]);
  };

  const getDefaultPayloads = (moduleId: string): string[] => {
    const payloads: Record<string, string[]> = {
      sql_injection: ["' OR '1'='1", "' UNION SELECT NULL--", "1; DROP TABLE users--", "' AND 1=1--"],
      xss: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)'],
      csrf: ['<form action="..." method="POST">', '<img src="..." />'],
      path_traversal: ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam'],
      command_injection: ['; ls -la', '| whoami', '`cat /etc/passwd`'],
      ssrf: ['http://127.0.0.1:8080', 'file:///etc/passwd', 'dict://localhost:11211'],
      idor: ['/user/1', '/user/2', '/account/1'],
      file_upload: ['test.php', 'shell.jsp', 'backdoor.asp']
    };
    return payloads[moduleId] || [];
  };

  const getDefaultPatterns = (moduleId: string): string[] => {
    const patterns: Record<string, string[]> = {
      sql_injection: ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite'],
      xss: ['<script>', 'onerror=', 'onload=', 'javascript:'],
      csrf: ['csrf_token', '_token', 'authenticity_token'],
      path_traversal: ['root:', '[boot loader]', 'Windows Registry'],
      command_injection: ['total ', 'drwx', 'uid=', 'gid='],
      ssrf: ['Internal Server Error', 'Connection refused', 'timeout'],
      idor: ['Unauthorized', 'Access Denied', 'Forbidden'],
      file_upload: ['uploaded successfully', 'file saved', 'Upload complete']
    };
    return patterns[moduleId] || [];
  };

  const handleCreateScript = async (values: any) => {
    const newScript: AttackScript = {
      id: `script_${Date.now()}`,
      name: values.name,
      type: values.type,
      target: values.target,
      payload: values.payload,
      method: values.method,
      headers: values.headers ? JSON.parse(values.headers) : {},
      parameters: values.parameters ? JSON.parse(values.parameters) : {},
      status: 'draft',
      created_at: new Date().toISOString()
    };
    setAttackScripts(prev => [newScript, ...prev]);
    setScriptModalVisible(false);
    scriptForm.resetFields();
    notification.success({ message: '攻击脚本创建成功' });
  };

  const handleCreatePath = async (values: any) => {
    const newPath: AttackPath = {
      id: `path_${Date.now()}`,
      name: values.name,
      target: values.target,
      nodes: [
        { id: 'n1', type: 'entry', label: '入口点', url: values.target, status: 'unvisited', depth: 0, children: [] }
      ],
      edges: [],
      status: 'pending',
      progress: 0,
      discovered_vulnerabilities: [],
      created_at: new Date().toISOString()
    };
    setAttackPaths(prev => [newPath, ...prev]);
    setPathModalVisible(false);
    pathForm.resetFields();
    notification.success({ message: '攻击路径创建成功' });
  };

  const handleExecuteScript = async (script: AttackScript) => {
    setExecutingScript(script.id);
    try {
      await new Promise(resolve => setTimeout(resolve, 2000));
      const success = Math.random() > 0.3;
      const updatedScript = {
        ...script,
        status: success ? 'success' : 'failed',
        executed_at: new Date().toISOString(),
        result: success 
          ? `成功发现${script.type.toUpperCase()}漏洞，目标: ${script.target}` 
          : '未发现漏洞或目标不可达'
      } as AttackScript;
      setAttackScripts(prev => prev.map(s => s.id === script.id ? updatedScript : s));
      notification[success ? 'success' : 'warning']({ 
        message: success ? '脚本执行成功' : '脚本执行完成',
        description: updatedScript.result
      });
    } finally {
      setExecutingScript(null);
    }
  };

  const handleExplorePath = async (path: AttackPath) => {
    setExploringPath(path.id);
    try {
      for (let i = 0; i <= 100; i += 10) {
        await new Promise(resolve => setTimeout(resolve, 500));
        setAttackPaths(prev => prev.map(p => {
          if (p.id === path.id) {
            return { ...p, progress: i, status: 'exploring' };
          }
          return p;
        }));
      }
      const hasVuln = Math.random() > 0.4;
      const updatedPath: AttackPath = {
        ...path,
        status: 'completed',
        progress: 100,
        discovered_vulnerabilities: hasVuln ? ['发现潜在SQL注入点', 'XSS反射型漏洞'] : [],
        nodes: path.nodes.map(n => ({ ...n, status: 'visited' as const }))
      };
      setAttackPaths(prev => prev.map(p => p.id === path.id ? updatedPath : p));
      notification.success({ message: '路径探索完成' });
    } finally {
      setExploringPath(null);
    }
  };

  const handleDeleteScript = (scriptId: string) => {
    setAttackScripts(prev => prev.filter(s => s.id !== scriptId));
    notification.success({ message: '脚本已删除' });
  };

  const handleDeletePath = (pathId: string) => {
    setAttackPaths(prev => prev.filter(p => p.id !== pathId));
    notification.success({ message: '攻击路径已删除' });
  };

  const handleExportScript = (script: AttackScript) => {
    const content = `# 攻击脚本导出
# 名称: ${script.name}
# 类型: ${script.type}
# 目标: ${script.target}
# 方法: ${script.method}
# Payload: ${script.payload}
# 参数: ${JSON.stringify(script.parameters, null, 2)}
# 请求头: ${JSON.stringify(script.headers, null, 2)}`;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${script.name}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    notification.success({ message: '脚本导出成功' });
  };

  const getScriptTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      sql_injection: 'red',
      xss: 'orange',
      csrf: 'blue',
      file_upload: 'purple',
      path_traversal: 'cyan',
      command_injection: 'magenta',
      ssrf: 'geekblue',
      idor: 'green'
    };
    return colors[type] || 'default';
  };

  const getScriptStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      draft: 'default',
      ready: 'blue',
      executing: 'processing',
      success: 'success',
      failed: 'error'
    };
    return colors[status] || 'default';
  };

  const getScriptStatusText = (status: string) => {
    const texts: Record<string, string> = {
      draft: '草稿',
      ready: '就绪',
      executing: '执行中',
      success: '成功',
      failed: '失败'
    };
    return texts[status] || status;
  };

  const getPathStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      pending: 'default',
      exploring: 'processing',
      completed: 'success',
      failed: 'error'
    };
    return colors[status] || 'default';
  };

  const getPathStatusText = (status: string) => {
    const texts: Record<string, string> = {
      pending: '待探索',
      exploring: '探索中',
      completed: '已完成',
      failed: '失败'
    };
    return texts[status] || status;
  };

  const getNodeStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      unvisited: '#d9d9d9',
      visiting: '#1677ff',
      visited: '#52c41a',
      vulnerable: '#ff4d4f',
      safe: '#52c41a'
    };
    return colors[status] || '#d9d9d9';
  };

  const scriptColumns = [
    {
      title: '脚本名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: AttackScript) => (
        <Space>
          <CodeOutlined className="text-primary-500" />
          <span className="font-medium">{text}</span>
        </Space>
      )
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (type: string) => (
        <Tag color={getScriptTypeColor(type)}>{type.toUpperCase()}</Tag>
      )
    },
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
      ellipsis: true,
      render: (text: string) => (
        <Tooltip title={text}>
          <span className="text-gray-600">{text}</span>
        </Tooltip>
      )
    },
    {
      title: '方法',
      dataIndex: 'method',
      key: 'method',
      width: 80,
      render: (method: string) => <Tag>{method}</Tag>
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={getScriptStatusColor(status)}>{getScriptStatusText(status)}</Tag>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date: string) => new Date(date).toLocaleString('zh-CN')
    },
    {
      title: '操作',
      key: 'action',
      width: 200,
      render: (_: any, record: AttackScript) => (
        <Space size="small">
          <Tooltip title="执行">
            <Button
              type="primary"
              size="small"
              icon={<PlayCircleOutlined />}
              loading={executingScript === record.id}
              onClick={() => handleExecuteScript(record)}
              disabled={record.status === 'executing'}
            />
          </Tooltip>
          <Tooltip title="编辑">
            <Button
              size="small"
              icon={<EditOutlined />}
              onClick={() => {
                setSelectedScript(record);
                setDetailDrawerVisible(true);
              }}
            />
          </Tooltip>
          <Tooltip title="导出">
            <Button
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => handleExportScript(record)}
            />
          </Tooltip>
          <Popconfirm
            title="确定删除此脚本?"
            onConfirm={() => handleDeleteScript(record.id)}
          >
            <Tooltip title="删除">
              <Button size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      )
    }
  ];

  const pathColumns = [
    {
      title: '路径名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: AttackPath) => (
        <Space>
          <BranchesOutlined className="text-primary-500" />
          <span className="font-medium">{text}</span>
        </Space>
      )
    },
    {
      title: '目标',
      dataIndex: 'target',
      key: 'target',
      ellipsis: true,
      render: (text: string) => (
        <Tooltip title={text}>
          <span className="text-gray-600">{text}</span>
        </Tooltip>
      )
    },
    {
      title: '进度',
      dataIndex: 'progress',
      key: 'progress',
      width: 150,
      render: (progress: number, record: AttackPath) => (
        <Progress 
          percent={progress} 
          size="small" 
          status={record.status === 'exploring' ? 'active' : undefined}
        />
      )
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (status: string) => (
        <Tag color={getPathStatusColor(status)}>{getPathStatusText(status)}</Tag>
      )
    },
    {
      title: '发现漏洞',
      dataIndex: 'discovered_vulnerabilities',
      key: 'vulnerabilities',
      width: 120,
      render: (vulns: string[]) => (
        <Badge count={vulns.length} showZero color={vulns.length > 0 ? '#ff4d4f' : '#52c41a'}>
          <BugOutlined className="text-xl" />
        </Badge>
      )
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date: string) => new Date(date).toLocaleString('zh-CN')
    },
    {
      title: '操作',
      key: 'action',
      width: 180,
      render: (_: any, record: AttackPath) => (
        <Space size="small">
          <Tooltip title="探索">
            <Button
              type="primary"
              size="small"
              icon={<RocketOutlined />}
              loading={exploringPath === record.id}
              onClick={() => handleExplorePath(record)}
              disabled={record.status === 'exploring'}
            />
          </Tooltip>
          <Tooltip title="查看详情">
            <Button
              size="small"
              icon={<EyeOutlined />}
              onClick={() => {
                setSelectedPath(record);
                setDetailDrawerVisible(true);
              }}
            />
          </Tooltip>
          <Popconfirm
            title="确定删除此攻击路径?"
            onConfirm={() => handleDeletePath(record.id)}
          >
            <Tooltip title="删除">
              <Button size="small" danger icon={<DeleteOutlined />} />
            </Tooltip>
          </Popconfirm>
        </Space>
      )
    }
  ];

  const renderAttackPathGraph = (path: AttackPath) => {
    const renderNode = (node: AttackNode, depth: number = 0) => {
      const children = path.nodes.filter(n => n.parent === node.id);
      return (
        <div key={node.id} className="mb-4">
          <div 
            className="flex items-center p-3 rounded-lg border transition-all hover:shadow-md"
            style={{ 
              marginLeft: depth * 24,
              borderColor: getNodeStatusColor(node.status),
              backgroundColor: node.status === 'vulnerable' ? '#fff2f0' : '#fafafa'
            }}
          >
            <div 
              className="w-3 h-3 rounded-full mr-3"
              style={{ backgroundColor: getNodeStatusColor(node.status) }}
            />
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <Space>
                  {node.type === 'entry' && <ApiOutlined />}
                  {node.type === 'endpoint' && <CloudServerOutlined />}
                  {node.type === 'parameter' && <CodeOutlined />}
                  {node.type === 'vulnerability' && <BugOutlined className="text-red-500" />}
                  {node.type === 'exploit' && <ThunderboltOutlined className="text-orange-500" />}
                  <Text strong>{node.label}</Text>
                  <Tag color={getNodeStatusColor(node.status)}>{node.status}</Tag>
                </Space>
                {node.url && (
                  <Text type="secondary" className="text-xs">{node.method} {node.url}</Text>
                )}
              </div>
              {node.vulnerability_type && (
                <Alert 
                  message={`发现漏洞: ${node.vulnerability_type}`} 
                  type="error" 
                  showIcon 
                  className="mt-2"
                />
              )}
            </div>
          </div>
          {children.length > 0 && (
            <div className="mt-2 border-l-2 border-gray-200 pl-4">
              {children.map(child => renderNode(child, depth + 1))}
            </div>
          )}
        </div>
      );
    };

    const rootNodes = path.nodes.filter(n => !n.parent);
    return (
      <div className="p-4 bg-gray-50 rounded-lg">
        {rootNodes.map(node => renderNode(node))}
      </div>
    );
  };

  const renderDashboard = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Title level={3} className="mb-2">
            <ThunderboltOutlined className="mr-2 text-primary-500" />
            模拟攻击引擎
          </Title>
          <Text type="secondary">攻击脚本生成与路径探索系统</Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadData} loading={loading}>
            刷新
          </Button>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="shadow-sm">
            <Statistic
              title="攻击脚本"
              value={attackScripts.length}
              prefix={<CodeOutlined className="text-primary-500" />}
              valueStyle={{ color: '#1677ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="shadow-sm">
            <Statistic
              title="攻击路径"
              value={attackPaths.length}
              prefix={<BranchesOutlined className="text-green-500" />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="shadow-sm">
            <Statistic
              title="检测模块"
              value={modules.filter(m => m.enabled).length}
              prefix={<BugOutlined className="text-orange-500" />}
              valueStyle={{ color: '#fa8c16' }}
              suffix={`/ ${modules.length}`}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="shadow-sm">
            <Statistic
              title="发现漏洞"
              value={attackPaths.reduce((acc, p) => acc + p.discovered_vulnerabilities.length, 0)}
              prefix={<AlertOutlined className="text-red-500" />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      <Card 
        title={
          <Space>
            <ClockCircleOutlined />
            <span>最近任务</span>
          </Space>
        }
        className="shadow-sm"
      >
        <List
          dataSource={tasks.slice(0, 5)}
          renderItem={(task) => (
            <List.Item>
              <List.Item.Meta
                avatar={
                  <Avatar 
                    icon={task.status === 'completed' ? <CheckCircleOutlined /> : <ClockCircleOutlined />}
                    style={{ 
                      backgroundColor: task.status === 'completed' ? '#f6ffed' : '#e6f7ff',
                      color: task.status === 'completed' ? '#52c41a' : '#1677ff'
                    }}
                  />
                }
                title={<Text strong>{task.task_name}</Text>}
                description={
                  <Space split={<Divider type="vertical" />}>
                    <Text type="secondary">{task.target_url}</Text>
                    <Tag color={task.status === 'completed' ? 'green' : 'blue'}>{task.status}</Tag>
                  </Space>
                }
              />
            </List.Item>
          )}
          locale={{ emptyText: <Empty description="暂无任务" /> }}
        />
      </Card>
    </div>
  );

  const renderScriptGenerator = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Title level={4} className="mb-2">
            <CodeOutlined className="mr-2 text-primary-500" />
            攻击脚本生成器
          </Title>
          <Text type="secondary">创建、编辑和管理攻击测试脚本</Text>
        </div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setScriptModalVisible(true)}
        >
          新建脚本
        </Button>
      </div>

      <Card className="shadow-sm">
        <Table
          columns={scriptColumns}
          dataSource={attackScripts}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          loading={loading}
        />
      </Card>

      <Card title="快速脚本模板" className="shadow-sm">
        <Row gutter={[16, 16]}>
          {modules.filter(m => m.enabled).slice(0, 4).map(module => (
            <Col xs={24} sm={12} lg={6} key={module.id}>
              <Card
                hoverable
                className="h-full"
                onClick={() => {
                  scriptForm.setFieldsValue({
                    name: `${module.name}测试脚本`,
                    type: module.id,
                    payload: module.payloads[0] || ''
                  });
                  setScriptModalVisible(true);
                }}
              >
                <div className="text-center">
                  <BugOutlined className="text-3xl text-primary-500 mb-2" />
                  <Title level={5}>{module.name}</Title>
                  <Text type="secondary" className="text-xs">{module.category}</Text>
                </div>
              </Card>
            </Col>
          ))}
        </Row>
      </Card>
    </div>
  );

  const renderPathExplorer = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Title level={4} className="mb-2">
            <BranchesOutlined className="mr-2 text-green-500" />
            攻击路径探索
          </Title>
          <Text type="secondary">自动发现和探索Web应用的攻击面</Text>
        </div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setPathModalVisible(true)}
        >
          新建路径
        </Button>
      </div>

      <Card className="shadow-sm">
        <Table
          columns={pathColumns}
          dataSource={attackPaths}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          loading={loading}
          expandable={{
            expandedRowRender: (record) => renderAttackPathGraph(record),
            rowExpandable: (record) => record.nodes.length > 0
          }}
        />
      </Card>

      <Card title="探索算法配置" className="shadow-sm">
        <Row gutter={[24, 24]}>
          <Col xs={24} lg={12}>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="广度优先搜索">
                <Switch defaultChecked /> <Text type="secondary" className="ml-2">逐层探索URL结构</Text>
              </Descriptions.Item>
              <Descriptions.Item label="深度优先搜索">
                <Switch /> <Text type="secondary" className="ml-2">深入探索每个分支</Text>
              </Descriptions.Item>
              <Descriptions.Item label="智能优先级">
                <Switch defaultChecked /> <Text type="secondary" className="ml-2">基于漏洞概率排序</Text>
              </Descriptions.Item>
              <Descriptions.Item label="最大深度">
                <InputNumber min={1} max={20} defaultValue={5} /> <Text type="secondary" className="ml-2">层</Text>
              </Descriptions.Item>
            </Descriptions>
          </Col>
          <Col xs={24} lg={12}>
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="并发数">
                <InputNumber min={1} max={10} defaultValue={3} /> <Text type="secondary" className="ml-2">个线程</Text>
              </Descriptions.Item>
              <Descriptions.Item label="请求延迟">
                <InputNumber min={0} max={5000} defaultValue={100} /> <Text type="secondary" className="ml-2">毫秒</Text>
              </Descriptions.Item>
              <Descriptions.Item label="超时时间">
                <InputNumber min={5} max={60} defaultValue={10} /> <Text type="secondary" className="ml-2">秒</Text>
              </Descriptions.Item>
              <Descriptions.Item label="自动利用">
                <Switch /> <Text type="secondary" className="ml-2">发现漏洞后自动尝试利用</Text>
              </Descriptions.Item>
            </Descriptions>
          </Col>
        </Row>
      </Card>
    </div>
  );

  const renderModules = () => (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <Title level={4} className="mb-2">
            <BugOutlined className="mr-2 text-orange-500" />
            攻击模块管理
          </Title>
          <Text type="secondary">配置和管理各类漏洞检测模块</Text>
        </div>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={loadData}>
            刷新
          </Button>
          <Button type="primary" icon={<ThunderboltOutlined />}>
            更新模块库
          </Button>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        {modules.map(module => (
          <Col xs={24} sm={12} lg={8} xl={6} key={module.id}>
            <Card
              hoverable
              className="h-full"
              actions={[
                <Switch 
                  key="enable" 
                  checked={module.enabled} 
                  onChange={(checked) => {
                    setModules(prev => prev.map(m => 
                      m.id === module.id ? { ...m, enabled: checked } : m
                    ));
                  }}
                />,
                <SettingOutlined key="setting" />,
                <EyeOutlined key="view" />
              ]}
            >
              <div className="text-center mb-4">
                <Badge dot={module.enabled} color="green">
                  <Avatar 
                    size={48} 
                    icon={<BugOutlined />}
                    style={{ backgroundColor: getScriptTypeColor(module.id) }}
                  />
                </Badge>
              </div>
              <Title level={5} className="text-center">{module.name}</Title>
              <Text type="secondary" className="text-xs block text-center">{module.category}</Text>
              <Divider />
              <div className="text-xs text-gray-500">
                <div>版本: {module.version}</div>
                <div>载荷数: {module.payloads.length}</div>
              </div>
            </Card>
          </Col>
        ))}
      </Row>
    </div>
  );

  return (
    <div className="p-6 bg-gray-50 min-h-screen">
      <Tabs activeKey={activeTab} onChange={setActiveTab} size="large">
        <TabPane 
          tab={<span><ThunderboltOutlined />仪表板</span>} 
          key="dashboard"
        >
          {renderDashboard()}
        </TabPane>
        <TabPane 
          tab={<span><CodeOutlined />脚本生成</span>} 
          key="scripts"
        >
          {renderScriptGenerator()}
        </TabPane>
        <TabPane 
          tab={<span><BranchesOutlined />路径探索</span>} 
          key="paths"
        >
          {renderPathExplorer()}
        </TabPane>
        <TabPane 
          tab={<span><BugOutlined />模块管理</span>} 
          key="modules"
        >
          {renderModules()}
        </TabPane>
      </Tabs>

      <Modal
        title={
          <Space>
            <CodeOutlined className="text-primary-500" />
            <span>新建攻击脚本</span>
          </Space>
        }
        open={scriptModalVisible}
        onCancel={() => {
          setScriptModalVisible(false);
          scriptForm.resetFields();
        }}
        footer={null}
        width={700}
      >
        <Form
          form={scriptForm}
          layout="vertical"
          onFinish={handleCreateScript}
          initialValues={{ method: 'POST' }}
        >
          <Row gutter={16}>
            <Col span={12}>
              <Form.Item
                name="name"
                label="脚本名称"
                rules={[{ required: true, message: '请输入脚本名称' }]}
              >
                <Input placeholder="输入描述性名称" />
              </Form.Item>
            </Col>
            <Col span={12}>
              <Form.Item
                name="type"
                label="攻击类型"
                rules={[{ required: true, message: '请选择攻击类型' }]}
              >
                <Select placeholder="选择攻击类型">
                  <Option value="sql_injection">SQL注入</Option>
                  <Option value="xss">跨站脚本(XSS)</Option>
                  <Option value="csrf">跨站请求伪造(CSRF)</Option>
                  <Option value="file_upload">文件上传</Option>
                  <Option value="path_traversal">路径遍历</Option>
                  <Option value="command_injection">命令注入</Option>
                  <Option value="ssrf">服务端请求伪造(SSRF)</Option>
                  <Option value="idor">越权访问(IDOR)</Option>
                </Select>
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="target"
            label="目标URL"
            rules={[{ required: true, message: '请输入目标URL' }]}
          >
            <Input placeholder="https://example.com/vulnerable.php" />
          </Form.Item>
          <Row gutter={16}>
            <Col span={8}>
              <Form.Item
                name="method"
                label="HTTP方法"
                rules={[{ required: true }]}
              >
                <Select>
                  <Option value="GET">GET</Option>
                  <Option value="POST">POST</Option>
                  <Option value="PUT">PUT</Option>
                  <Option value="DELETE">DELETE</Option>
                </Select>
              </Form.Item>
            </Col>
            <Col span={16}>
              <Form.Item
                name="payload"
                label="攻击载荷"
                rules={[{ required: true, message: '请输入攻击载荷' }]}
              >
                <Input placeholder="' OR '1'='1" />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item
            name="parameters"
            label="请求参数 (JSON格式)"
          >
            <TextArea 
              rows={3} 
              placeholder='{"username": "admin", "password": "test"}'
            />
          </Form.Item>
          <Form.Item
            name="headers"
            label="自定义请求头 (JSON格式)"
          >
            <TextArea 
              rows={2} 
              placeholder='{"Content-Type": "application/json"}'
            />
          </Form.Item>
          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => {
                setScriptModalVisible(false);
                scriptForm.resetFields();
              }}>
                取消
              </Button>
              <Button type="primary" htmlType="submit">
                创建脚本
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title={
          <Space>
            <BranchesOutlined className="text-green-500" />
            <span>新建攻击路径</span>
          </Space>
        }
        open={pathModalVisible}
        onCancel={() => {
          setPathModalVisible(false);
          pathForm.resetFields();
        }}
        footer={null}
        width={600}
      >
        <Form
          form={pathForm}
          layout="vertical"
          onFinish={handleCreatePath}
        >
          <Form.Item
            name="name"
            label="路径名称"
            rules={[{ required: true, message: '请输入路径名称' }]}
          >
            <Input placeholder="输入描述性名称" />
          </Form.Item>
          <Form.Item
            name="target"
            label="目标URL"
            rules={[{ required: true, message: '请输入目标URL' }]}
          >
            <Input placeholder="https://example.com" />
          </Form.Item>
          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => {
                setPathModalVisible(false);
                pathForm.resetFields();
              }}>
                取消
              </Button>
              <Button type="primary" htmlType="submit">
                创建路径
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title="详细信息"
        placement="right"
        width={600}
        onClose={() => {
          setDetailDrawerVisible(false);
          setSelectedScript(null);
          setSelectedPath(null);
        }}
        open={detailDrawerVisible}
      >
        {selectedScript && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="脚本ID">{selectedScript.id}</Descriptions.Item>
            <Descriptions.Item label="名称">{selectedScript.name}</Descriptions.Item>
            <Descriptions.Item label="类型">
              <Tag color={getScriptTypeColor(selectedScript.type)}>
                {selectedScript.type.toUpperCase()}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="目标">{selectedScript.target}</Descriptions.Item>
            <Descriptions.Item label="方法">{selectedScript.method}</Descriptions.Item>
            <Descriptions.Item label="Payload">
              <code className="bg-gray-100 p-1 rounded">{selectedScript.payload}</code>
            </Descriptions.Item>
            <Descriptions.Item label="参数">
              <pre className="bg-gray-50 p-2 rounded text-xs">
                {JSON.stringify(selectedScript.parameters, null, 2)}
              </pre>
            </Descriptions.Item>
            <Descriptions.Item label="请求头">
              <pre className="bg-gray-50 p-2 rounded text-xs">
                {JSON.stringify(selectedScript.headers, null, 2)}
              </pre>
            </Descriptions.Item>
            <Descriptions.Item label="状态">
              <Tag color={getScriptStatusColor(selectedScript.status)}>
                {getScriptStatusText(selectedScript.status)}
              </Tag>
            </Descriptions.Item>
            {selectedScript.result && (
              <Descriptions.Item label="执行结果">{selectedScript.result}</Descriptions.Item>
            )}
          </Descriptions>
        )}
        {selectedPath && (
          <div className="space-y-4">
            <Descriptions column={1} bordered>
              <Descriptions.Item label="路径ID">{selectedPath.id}</Descriptions.Item>
              <Descriptions.Item label="名称">{selectedPath.name}</Descriptions.Item>
              <Descriptions.Item label="目标">{selectedPath.target}</Descriptions.Item>
              <Descriptions.Item label="状态">
                <Tag color={getPathStatusColor(selectedPath.status)}>
                  {getPathStatusText(selectedPath.status)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="进度">
                <Progress percent={selectedPath.progress} />
              </Descriptions.Item>
            </Descriptions>
            <Divider>攻击路径图</Divider>
            {renderAttackPathGraph(selectedPath)}
            {selectedPath.discovered_vulnerabilities.length > 0 && (
              <>
                <Divider>发现的漏洞</Divider>
                <List
                  dataSource={selectedPath.discovered_vulnerabilities}
                  renderItem={(vuln) => (
                    <List.Item>
                      <Alert 
                        message={vuln} 
                        type="error" 
                        showIcon 
                        icon={<BugOutlined />}
                      />
                    </List.Item>
                  )}
                />
              </>
            )}
          </div>
        )}
      </Drawer>
    </div>
  );
};

export default AttackEngine;
