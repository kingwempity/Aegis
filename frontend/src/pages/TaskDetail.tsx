/**
 * 任务详情页面
 * 显示任务信息、实时日志和已发现漏洞
 */
import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Card,
  Tag,
  Button,
  Tabs,
  Table,
  Space,
  Descriptions,
  message,
} from 'antd';
import {
  PauseOutlined,
  StopOutlined,
  DeleteOutlined,
  ArrowLeftOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';
import ScanProgress from '../components/Task/ScanProgress';
import SeverityBadge from '../components/Vuln/SeverityBadge';
import { useWebSocket } from '../hooks/useWebSocket';

const API_BASE = '/api/v1';

interface Task {
  id: number;
  target_url: string;
  status: string;
  scan_strategy: string;
  created_at: string;
  updated_at?: string;
}

interface LogEntry {
  timestamp: string;
  level: 'INFO' | 'WARN' | 'ERROR';
  message: string;
}

interface Vulnerability {
  id: number;
  name: string;
  severity: string;
  found_at: string;
}

const TaskDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<Task | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const { isConnected, lastMessage } = useWebSocket({
    url: `ws://${window.location.host}/ws/tasks/${id}`,
    onMessage: (message) => {
      if (message.type === 'LOG') {
        setLogs((prev) => [...prev, message.data]);
      } else if (message.type === 'VULN_FOUND') {
        setVulnerabilities((prev) => [...prev, message.data]);
        message.success('发现新漏洞！');
      } else if (message.type === 'PROGRESS') {
        // 更新任务进度
        setTask((prev) => (prev ? { ...prev, ...message.data } : null));
      }
    },
    autoConnect: !!id,
  });

  useEffect(() => {
    if (id) {
      fetchTaskDetail();
      fetchVulnerabilities();
    }
  }, [id]);

  useEffect(() => {
    // 自动滚动到底部
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const fetchTaskDetail = async () => {
    setLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/tasks/${id}`);
      setTask(res.data);
    } catch (err) {
      message.error('获取任务详情失败');
      navigate('/tasks');
    } finally {
      setLoading(false);
    }
  };

  const fetchVulnerabilities = async () => {
    try {
      // TODO: 实现获取漏洞列表 API
      // const res = await axios.get(`${API_BASE}/tasks/${id}/vulnerabilities`);
      // setVulnerabilities(res.data);
    } catch (err) {
      console.error('获取漏洞列表失败:', err);
    }
  };

  const handlePause = async () => {
    try {
      // TODO: 实现暂停任务 API
      message.success('任务已暂停');
      fetchTaskDetail();
    } catch (err) {
      message.error('暂停任务失败');
    }
  };

  const handleStop = async () => {
    try {
      // TODO: 实现停止任务 API
      message.success('任务已停止');
      fetchTaskDetail();
    } catch (err) {
      message.error('停止任务失败');
    }
  };

  const handleDelete = () => {
    // TODO: 实现删除确认和删除逻辑
    message.info('删除功能待实现');
  };

  const getProgress = () => {
    if (!task) return 0;
    if (task.status === 'COMPLETED') return 100;
    if (task.status === 'FAILED') return 0;
    // 根据任务状态估算进度
    return 50; // 临时值
  };

  const logColumns = [
    {
      title: '时间',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 180,
      render: (time: string) => dayjs(time).format('HH:mm:ss'),
    },
    {
      title: '级别',
      dataIndex: 'level',
      key: 'level',
      width: 80,
      render: (level: string) => {
        const colorMap: Record<string, string> = {
          INFO: 'default',
          WARN: 'warning',
          ERROR: 'error',
        };
        return <Tag color={colorMap[level] || 'default'}>{level}</Tag>;
      },
    },
    {
      title: '消息',
      dataIndex: 'message',
      key: 'message',
    },
  ];

  const vulnColumns = [
    {
      title: '漏洞名称',
      dataIndex: 'name',
      key: 'name',
    },
    {
      title: '严重程度',
      dataIndex: 'severity',
      key: 'severity',
      width: 120,
      render: (severity: string) => <SeverityBadge severity={severity} />,
    },
    {
      title: '发现时间',
      dataIndex: 'found_at',
      key: 'found_at',
      width: 180,
      render: (time: string) => dayjs(time).format('YYYY-MM-DD HH:mm:ss'),
    },
    {
      title: '操作',
      key: 'action',
      width: 120,
      render: (_: any, record: Vulnerability) => (
        <Button
          type="link"
          size="small"
          onClick={() => navigate(`/vulnerabilities/${record.id}`)}
        >
          查看详情
        </Button>
      ),
    },
  ];

  const tabItems = [
    {
      key: 'logs',
      label: '实时日志',
      children: (
        <div>
          <div
            style={{
              backgroundColor: '#1e1e1e',
              padding: 16,
              borderRadius: 4,
              fontFamily: 'Monaco, Consolas, monospace',
              fontSize: 13,
              color: '#ffffff',
              height: 400,
              overflow: 'auto',
              marginBottom: 16,
            }}
          >
            {logs.length === 0 ? (
              <div style={{ color: '#8c8c8c', textAlign: 'center', padding: 20 }}>
                暂无日志
              </div>
            ) : (
              logs.map((log, index) => (
                <div
                  key={index}
                  style={{
                    marginBottom: 4,
                    color:
                      log.level === 'ERROR'
                        ? '#ff4d4f'
                        : log.level === 'WARN'
                        ? '#faad14'
                        : '#ffffff',
                  }}
                >
                  <span style={{ color: '#8c8c8c', marginRight: 8 }}>
                    [{dayjs(log.timestamp).format('HH:mm:ss')}]
                  </span>
                  <span style={{ marginRight: 8 }}>[{log.level}]</span>
                  <span>{log.message}</span>
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
          <div style={{ color: '#8c8c8c', fontSize: 12 }}>
            WebSocket 状态: {isConnected ? '已连接' : '未连接'}
          </div>
        </div>
      ),
    },
    {
      key: 'vulnerabilities',
      label: `已发现漏洞 (${vulnerabilities.length})`,
      children: (
        <Table
          dataSource={vulnerabilities}
          columns={vulnColumns}
          rowKey="id"
          pagination={false}
        />
      ),
    },
    {
      key: 'config',
      label: '扫描配置',
      children: (
        <Descriptions column={1} bordered>
          <Descriptions.Item label="扫描策略">
            {task?.scan_strategy?.toUpperCase() || 'STANDARD'}
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {task?.created_at ? dayjs(task.created_at).format('YYYY-MM-DD HH:mm:ss') : '-'}
          </Descriptions.Item>
          <Descriptions.Item label="更新时间">
            {task?.updated_at ? dayjs(task.updated_at).format('YYYY-MM-DD HH:mm:ss') : '-'}
          </Descriptions.Item>
        </Descriptions>
      ),
    },
  ];

  if (!task) {
    return <div>加载中...</div>;
  }

  return (
    <div style={{ padding: 24, backgroundColor: '#f5f5f5', minHeight: 'calc(100vh - 64px)' }}>
      {/* 返回按钮 */}
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate('/tasks')}
        style={{ marginBottom: 16 }}
      >
        返回
      </Button>

      {/* 任务信息卡片 */}
      <Card
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
          marginBottom: 16,
        }}
        loading={loading}
      >
        <div style={{ marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 18, fontWeight: 500, color: '#262626', marginBottom: 8 }}>
            {task.target_url}
          </h2>
          <Space style={{ marginBottom: 16 }}>
            <Tag
              color={
                task.status === 'RUNNING'
                  ? 'processing'
                  : task.status === 'COMPLETED'
                  ? 'success'
                  : task.status === 'FAILED'
                  ? 'error'
                  : 'warning'
              }
            >
              {task.status === 'RUNNING'
                ? '运行中'
                : task.status === 'COMPLETED'
                ? '完成'
                : task.status === 'FAILED'
                ? '失败'
                : '排队中'}
            </Tag>
            <span style={{ color: '#8c8c8c', fontSize: 14 }}>
              创建时间: {dayjs(task.created_at).format('YYYY-MM-DD HH:mm:ss')}
            </span>
          </Space>
        </div>

        {task.status === 'RUNNING' && (
          <div style={{ marginBottom: 16 }}>
            <ScanProgress progress={getProgress()} />
          </div>
        )}

        <Space>
          {task.status === 'RUNNING' && (
            <>
              <Button icon={<PauseOutlined />} onClick={handlePause}>
                暂停
              </Button>
              <Button icon={<StopOutlined />} danger onClick={handleStop}>
                停止
              </Button>
            </>
          )}
          <Button icon={<DeleteOutlined />} danger onClick={handleDelete}>
            删除
          </Button>
        </Space>
      </Card>

      {/* 标签页 */}
      <Card
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
        }}
      >
        <Tabs items={tabItems} />
      </Card>
    </div>
  );
};

export default TaskDetail;
