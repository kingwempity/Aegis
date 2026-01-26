/**
 * 仪表盘页面
 * 显示统计信息和图表
 */
import React, { useEffect, useState } from 'react';
import { Card, Row, Col, Statistic, Table, Tag } from 'antd';
import {
  FileTextOutlined,
  PlayCircleOutlined,
  BugOutlined,
  WarningOutlined,
  ArrowUpOutlined,
  ArrowDownOutlined,
} from '@ant-design/icons';
import axios from 'axios';
import dayjs from 'dayjs';

const API_BASE = '/api/v1';

interface DashboardStats {
  totalTasks: number;
  runningTasks: number;
  totalVulnerabilities: number;
  highRiskVulnerabilities: number;
}

interface RecentTask {
  id: number;
  target_url: string;
  status: string;
  created_at: string;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    totalTasks: 0,
    runningTasks: 0,
    totalVulnerabilities: 0,
    highRiskVulnerabilities: 0,
  });
  const [recentTasks, setRecentTasks] = useState<RecentTask[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setLoading(true);
    try {
      // 获取任务列表
      const tasksRes = await axios.get(`${API_BASE}/tasks`);
      const tasks = Array.isArray(tasksRes.data) ? tasksRes.data : [];

      // 计算统计信息
      const totalTasks = tasks.length;
      const runningTasks = tasks.filter((t: any) => t.status === 'RUNNING').length;
      
      // 这里应该从 API 获取漏洞统计，暂时使用模拟数据
      setStats({
        totalTasks,
        runningTasks,
        totalVulnerabilities: 45,
        highRiskVulnerabilities: 12,
      });

      // 获取最近任务
      const sortedTasks = [...tasks]
        .sort((a: any, b: any) => 
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        )
        .slice(0, 5);
      setRecentTasks(sortedTasks);
    } catch (error) {
      console.error('获取仪表盘数据失败:', error);
    } finally {
      setLoading(false);
    }
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
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      width: 100,
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
  ];

  return (
    <div style={{ padding: 24, backgroundColor: '#f5f5f5', minHeight: 'calc(100vh - 64px)' }}>
      {/* 统计卡片 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <Statistic
              title="总任务数"
              value={stats.totalTasks}
              prefix={<FileTextOutlined />}
              valueStyle={{ color: '#262626', fontSize: 24, fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <Statistic
              title="运行中任务"
              value={stats.runningTasks}
              prefix={<PlayCircleOutlined />}
              valueStyle={{ color: '#1677ff', fontSize: 24, fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <Statistic
              title="发现漏洞数"
              value={stats.totalVulnerabilities}
              prefix={<BugOutlined />}
              suffix={<ArrowUpOutlined style={{ color: '#52c41a' }} />}
              valueStyle={{ color: '#262626', fontSize: 24, fontWeight: 'bold' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <Statistic
              title="高风险漏洞"
              value={stats.highRiskVulnerabilities}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#ff4d4f', fontSize: 24, fontWeight: 'bold' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 图表区域 - 暂时使用占位 */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} lg={12}>
          <Card
            title="漏洞分布"
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8c8c8c' }}>
              图表组件（需要集成 ECharts 或 Ant Design Charts）
            </div>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card
            title="扫描趋势"
            style={{
              backgroundColor: '#ffffff',
              borderRadius: 4,
              boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
            }}
          >
            <div style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#8c8c8c' }}>
              图表组件（需要集成 ECharts 或 Ant Design Charts）
            </div>
          </Card>
        </Col>
      </Row>

      {/* 最近任务列表 */}
      <Card
        title="最近任务"
        style={{
          backgroundColor: '#ffffff',
          borderRadius: 4,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.06)',
        }}
      >
        <Table
          dataSource={recentTasks}
          columns={columns}
          rowKey="id"
          loading={loading}
          pagination={false}
          size="small"
        />
      </Card>
    </div>
  );
};

export default Dashboard;
