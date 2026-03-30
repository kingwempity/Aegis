import React, { useEffect, useMemo, useState } from 'react';
import { Row, Col, Card, Statistic, List, Avatar, Tag, Button, Spin, Empty } from 'antd';
import {
  ExperimentOutlined,
  CheckCircleOutlined,
  AlertOutlined,
  ClockCircleOutlined,
  PlusOutlined,
  EyeOutlined
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import { Task, Statistics, ChartData } from '../types';
import ReactECharts from 'echarts-for-react';
import { useTheme } from '../contexts/ThemeContext';

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { isDark } = useTheme();
  const [stats, setStats] = useState<Statistics | null>(null);
  const [recentTasks, setRecentTasks] = useState<Task[]>([]);
  const [chartData, setChartData] = useState<ChartData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const [statsData, tasksData, chartDataResponse] = await Promise.all([
        apiService.getStatistics(),
        apiService.getTasks({ page: 1, page_size: 5, sort_by: 'created_at', order: 'desc' }),
        apiService.getChartData('risk_distribution', '30d')
      ]);

      setStats(statsData);
      setRecentTasks(tasksData.tasks);
      setChartData(chartDataResponse);
    } catch (error) {
      console.error('加载仪表板数据失败:', error);
    } finally {
      setLoading(false);
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleOutlined />;
      case 'running': return <ExperimentOutlined />;
      case 'failed': return <AlertOutlined />;
      case 'queued': return <ClockCircleOutlined />;
      default: return <ClockCircleOutlined />;
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

  const chartOption = useMemo(() => chartData ? {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: isDark ? 'rgba(55, 59, 66, 0.9)' : 'rgba(255,255,255,0.9)',
      borderColor: isDark ? '#334155' : '#e5e7eb',
      textStyle: { color: isDark ? '#e5e7eb' : '#1f2937' }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: chartData.data.labels,
      axisLine: { lineStyle: { color: isDark ? '#475569' : '#e5e7eb' } },
      axisLabel: { color: isDark ? '#cbd5e1' : '#4b5563' },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: isDark ? '#334155' : '#e5e7eb' } },
      axisLabel: { color: isDark ? '#cbd5e1' : '#4b5563' },
    },
    series: [{
      name: '漏洞数量',
      type: 'bar',
      data: chartData.data.values,
      itemStyle: {
        color: (params: any) => chartData.data.colors[params.dataIndex] || (isDark ? '#22d3ee' : '#8B4513')
      },
      label: {
        show: true,
        position: 'top',
        color: isDark ? '#e5e7eb' : '#4b5563'
      }
    }]
  } : null, [chartData, isDark]);

  const cardHeadStyle = useMemo(() => ({
    background: 'transparent',
    color: isDark ? '#e9ecef' : '#121416',
    borderBottom: isDark ? '1px solid #343a40' : '1px solid #dee2e6',
    padding: '24px 32px 16px 32px'
  }), [isDark]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <Spin size="large" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* 标题 */}
      <div className="flex items-center justify-between fade-in-elegant">
        <div>
          <h1 className="text-3xl font-bold text-elegant-900 dark:text-elegant-100 tracking-tight">
            仪表板
          </h1>
          <p className="text-elegant-600 dark:text-elegant-400 mt-2 text-lg">
            欢迎使用漏洞检测系统，查看您的安全检测概况
          </p>
        </div>
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => navigate('/tasks')}
          className="btn-elegant"
        >
          新建扫描任务
        </Button>
      </div>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card scale-in-elegant" styles={{ header: cardHeadStyle }}>
            <Statistic
                title={<span className="text-elegant-600 dark:text-elegant-300 font-medium">总扫描次数</span>}
              value={stats?.total_scans || 0}
              prefix={<ExperimentOutlined className="text-accent-primary text-xl" />}
                valueStyle={{ color: isDark ? '#e9ecef' : '#121416', fontSize: '28px', fontWeight: '600' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card scale-in-elegant" styles={{ header: cardHeadStyle }}>
            <Statistic
                title={<span className="text-elegant-600 dark:text-elegant-300 font-medium">发现漏洞</span>}
              value={stats?.vulnerabilities_found || 0}
              prefix={<AlertOutlined className="text-error text-xl" />}
                valueStyle={{ color: isDark ? '#fca5a5' : '#dc2626', fontSize: '28px', fontWeight: '600' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card scale-in-elegant" styles={{ header: cardHeadStyle }}>
            <Statistic
                title={<span className="text-elegant-600 dark:text-elegant-300 font-medium">危急漏洞</span>}
              value={stats?.critical_vulnerabilities || 0}
              prefix={<AlertOutlined className="text-error text-xl" />}
                valueStyle={{ color: isDark ? '#f87171' : '#b91c1c', fontSize: '28px', fontWeight: '600' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="stat-card scale-in-elegant" styles={{ header: cardHeadStyle }}>
            <Statistic
                title={<span className="text-elegant-600 dark:text-elegant-300 font-medium">活跃任务</span>}
              value={stats?.active_tasks || 0}
              prefix={<ClockCircleOutlined className="text-accent-primary text-xl" />}
                valueStyle={{ color: isDark ? '#a5b4fc' : '#1d4ed8', fontSize: '28px', fontWeight: '600' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        {/* 风险分布图表 */}
        <Col xs={24} lg={12}>
          <Card
            title={
              <div className="flex items-center">
                <AlertOutlined className="text-accent-primary mr-3 text-lg" />
                <span className="text-elegant-900 dark:text-elegant-100 font-semibold tracking-tight">风险等级分布</span>
              </div>
            }
            className="card-elegant slide-in-elegant"
            styles={{ header: cardHeadStyle }}
          >
            {chartData ? (
              <ReactECharts
                option={chartOption}
                style={{ height: '300px' }}
                className="w-full"
              />
            ) : (
              <Empty description="暂无数据" />
            )}
          </Card>
        </Col>

        {/* 最近任务 */}
        <Col xs={24} lg={12}>
          <Card
            title={
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <ClockCircleOutlined className="text-accent-primary mr-3 text-lg" />
                  <span className="text-elegant-900 dark:text-elegant-100 font-semibold tracking-tight">最近任务</span>
                </div>
                <Button
                  type="link"
                  size="small"
                  onClick={() => navigate('/tasks')}
                  className="text-accent-primary hover:text-accent-secondary font-medium"
                >
                  查看全部
                </Button>
              </div>
            }
            className="card-elegant slide-in-elegant"
            styles={{ header: cardHeadStyle }}
          >
            <List
              dataSource={recentTasks}
              renderItem={(task) => (
                <List.Item
                  className="hover:bg-elegant-50 dark:hover:bg-elegant-800 px-6 py-4 rounded-xl cursor-pointer transition-all duration-300 hover:shadow-elegant"
                  onClick={() => navigate(`/tasks/${task.task_id}`)}
                  actions={[
                    <Button
                      type="text"
                      icon={<EyeOutlined />}
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/tasks/${task.task_id}`);
                      }}
                      className="text-elegant-500 hover:text-accent-primary rounded-lg"
                    />
                  ]}
                >
                  <List.Item.Meta
                    avatar={
                      <Avatar
                        icon={getStatusIcon(task.status)}
                        className={`bg-${getStatusColor(task.status)}-100`}
                        style={{
                          backgroundColor: task.status === 'completed' ? '#f6ffed' :
                                         task.status === 'running' ? '#e6f7ff' :
                                         task.status === 'failed' ? '#fff2f0' : '#fff7e6'
                        }}
                      />
                    }
                    title={
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-elegant-900 dark:text-elegant-100 tracking-tight">
                          {task.task_name}
                        </span>
                        <Tag color={getStatusColor(task.status)} className="font-medium">
                          {getStatusText(task.status)}
                        </Tag>
                      </div>
                    }
                    description={
                      <div className="space-y-2">
                        <div className="text-sm text-elegant-600 dark:text-elegant-400">
                          目标: {task.target_url}
                        </div>
                        <div className="flex items-center justify-between text-xs text-elegant-500">
                          <span>
                            {new Date(task.created_at).toLocaleString('zh-CN')}
                          </span>
                          {task.status === 'running' && (
                            <span className="font-medium">进度: {task.progress}%</span>
                          )}
                        </div>
                        {task.status === 'running' && (
                          <div className="mt-2">
                            <div className="progress-elegant">
                              <div
                                className="progress-bar"
                                style={{ width: `${task.progress}%` }}
                              ></div>
                            </div>
                          </div>
                        )}
                      </div>
                    }
                  />
                </List.Item>
              )}
            />
            {recentTasks.length === 0 && (
              <Empty
                description="暂无扫描任务"
                image={Empty.PRESENTED_IMAGE_SIMPLE}
              >
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => navigate('/tasks')}
                >
                  创建第一个任务
                </Button>
              </Empty>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;
