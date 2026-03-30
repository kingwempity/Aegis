import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Card, Spin, Alert, Button, Tag, Progress, Descriptions, Space,
  List, Avatar, message, Modal
} from 'antd';
import {
  ArrowLeftOutlined, ExperimentOutlined, CheckCircleOutlined,
  AlertOutlined, ClockCircleOutlined, StopOutlined,
  FileTextOutlined, ReloadOutlined
} from '@ant-design/icons';
import { apiService } from '../services/api';
import { Task, ScanReport, Vulnerability } from '../types';

const TaskDetail: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<Task | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [reportLoading, setReportLoading] = useState(false);
  const [cancelModalVisible, setCancelModalVisible] = useState(false);

  useEffect(() => {
    if (taskId) {
      loadTaskDetail();
    }
  }, [taskId]);

  const loadTaskDetail = async () => {
    if (!taskId) return;

    setLoading(true);
    try {
      const taskData = await apiService.getTaskDetail(taskId);
      setTask(taskData);

      // 如果任务已完成，自动加载报告
      if (taskData.status === 'completed') {
        loadReport();
      }
    } catch (error) {
      message.error('加载任务详情失败');
    } finally {
      setLoading(false);
    }
  };

  const loadReport = async () => {
    if (!taskId) return;

    setReportLoading(true);
    try {
      const reportData = await apiService.getScanReport(taskId);
      if (typeof reportData === 'object' && 'task_id' in reportData) {
        setReport(reportData);
      }
    } catch (error) {
      // 报告可能还没生成，不显示错误
    } finally {
      setReportLoading(false);
    }
  };

  const handleCancelTask = async () => {
    if (!taskId) return;

    try {
      await apiService.cancelTask(taskId);
      message.success('任务已取消');
      setCancelModalVisible(false);
      loadTaskDetail();
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

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircleOutlined />;
      case 'running': return <ExperimentOutlined />;
      case 'failed': return <AlertOutlined />;
      case 'queued': return <ClockCircleOutlined />;
      case 'cancelled': return <StopOutlined />;
      default: return <ClockCircleOutlined />;
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'blue';
      case 'info': return 'gray';
      default: return 'default';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <Spin size="large" />
      </div>
    );
  }

  if (!task) {
    return (
      <div className="space-y-6">
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={() => navigate('/tasks')}
          className="mb-4"
        >
          返回任务列表
        </Button>
        <Card className="card-retro">
          <Alert
            message="任务不存在"
            description="无法找到指定的任务，请检查任务ID是否正确"
            type="error"
            showIcon
          />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 导航 */}
      <div className="flex items-center justify-between">
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={() => navigate('/tasks')}
        >
          返回任务列表
        </Button>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={loadTaskDetail}
            loading={loading}
          >
            刷新
          </Button>
          {(task.status === 'queued' || task.status === 'running') && (
            <Button
              danger
              icon={<StopOutlined />}
              onClick={() => setCancelModalVisible(true)}
            >
              取消任务
            </Button>
          )}
        </Space>
      </div>

      {/* 任务基本信息 */}
      <Card
        className="card-modern"
        title={
          <div className="flex items-center">
            <ExperimentOutlined className="text-brand-primary mr-2" />
            <span className="font-bold">{task.task_name}</span>
          </div>
        }
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="任务ID">{task.task_id}</Descriptions.Item>
              <Descriptions.Item label="目标URL">
                <a
                  href={task.target_url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-tape-brown hover:text-tape-dark"
                >
                  {task.target_url}
                </a>
              </Descriptions.Item>
              <Descriptions.Item label="扫描配置">
                <Tag color="blue">
                  {task.scan_profile === 'full' ? '完整扫描' :
                   task.scan_profile === 'quick' ? '快速扫描' : '自定义'}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="创建者">
                {task.created_by?.username || '未知用户'}
              </Descriptions.Item>
            </Descriptions>
          </div>
          <div>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="状态">
                <Tag color={getStatusColor(task.status)} icon={getStatusIcon(task.status)}>
                  {getStatusText(task.status)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {new Date(task.created_at).toLocaleString('zh-CN')}
              </Descriptions.Item>
              {task.started_at && (
                <Descriptions.Item label="开始时间">
                  {new Date(task.started_at).toLocaleString('zh-CN')}
                </Descriptions.Item>
              )}
              {task.completed_at && (
                <Descriptions.Item label="完成时间">
                  {new Date(task.completed_at).toLocaleString('zh-CN')}
                </Descriptions.Item>
              )}
              {task.duration_seconds && (
                <Descriptions.Item label="耗时">
                  {Math.floor(task.duration_seconds / 60)}分 {task.duration_seconds % 60}秒
                </Descriptions.Item>
              )}
            </Descriptions>
          </div>
        </div>

        {/* 进度条 */}
        {task.status === 'running' && (
          <div className="mt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-medium">扫描进度</span>
              <span className="text-sm text-gray-600">{task.progress}%</span>
            </div>
            <Progress
              percent={task.progress}
              size="small"
              status="active"
              strokeColor="#1677ff"
            />
            {task.current_phase && (
              <div className="mt-2 text-sm text-gray-600">
                当前阶段: {task.current_phase}
              </div>
            )}
          </div>
        )}

        {/* 统计信息 */}
        {task.status === 'completed' && (
          <div className="mt-6 grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card size="small" className="text-center">
              <div className="text-2xl font-bold text-tape-brown">{task.pages_scanned || 0}</div>
              <div className="text-sm text-gray-600">扫描页面数</div>
            </Card>
            <Card size="small" className="text-center">
              <div className="text-2xl font-bold text-red-500">{task.vulnerabilities_found || 0}</div>
              <div className="text-sm text-gray-600">发现漏洞</div>
            </Card>
            <Card size="small" className="text-center">
              <div className="text-2xl font-bold text-blue-500">{task.modules_enabled?.length || 0}</div>
              <div className="text-sm text-gray-600">启用模块</div>
            </Card>
            <Card size="small" className="text-center">
              <div className="text-2xl font-bold text-green-500">
                {task.duration_seconds ? Math.floor(task.duration_seconds / 60) : 0}
              </div>
              <div className="text-sm text-gray-600">耗时(分钟)</div>
            </Card>
          </div>
        )}
      </Card>

      {/* 扫描报告 */}
      {task.status === 'completed' && (
        <Card
          className="card-retro"
          title={
            <div className="flex items-center">
              <FileTextOutlined className="text-tape-brown mr-2" />
              <span className="font-bold">扫描报告</span>
            </div>
          }
          extra={
            <Button
              icon={<FileTextOutlined />}
              onClick={() => navigate(`/reports?taskId=${taskId}`)}
            >
              查看完整报告
            </Button>
          }
        >
          {reportLoading ? (
            <div className="flex items-center justify-center py-8">
              <Spin size="large" />
            </div>
          ) : report ? (
            <div className="space-y-6">
              {/* 漏洞统计 */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                <Card size="small" className="text-center border-red-200">
                  <div className="text-3xl font-bold text-red-600">{report.summary.critical}</div>
                  <div className="text-sm text-gray-600">危急</div>
                </Card>
                <Card size="small" className="text-center border-orange-200">
                  <div className="text-3xl font-bold text-orange-600">{report.summary.high}</div>
                  <div className="text-sm text-gray-600">高危</div>
                </Card>
                <Card size="small" className="text-center border-yellow-200">
                  <div className="text-3xl font-bold text-yellow-600">{report.summary.medium}</div>
                  <div className="text-sm text-gray-600">中危</div>
                </Card>
                <Card size="small" className="text-center border-blue-200">
                  <div className="text-3xl font-bold text-blue-600">{report.summary.low}</div>
                  <div className="text-sm text-gray-600">低危</div>
                </Card>
                <Card size="small" className="text-center border-gray-200">
                  <div className="text-3xl font-bold text-gray-600">{report.summary.info || 0}</div>
                  <div className="text-sm text-gray-600">信息</div>
                </Card>
              </div>

              {/* 漏洞列表 */}
              {report.vulnerabilities.length > 0 ? (
                <List
                  dataSource={report.vulnerabilities.slice(0, 5)}
                  renderItem={(vuln: Vulnerability) => (
                    <List.Item className="hover:bg-gray-50 dark:hover:bg-gray-800 px-4 py-3 rounded-lg">
                      <List.Item.Meta
                        avatar={
                          <Avatar
                            icon={<AlertOutlined />}
                            className={`bg-${getRiskColor(vuln.risk_level)}-100`}
                          />
                        }
                        title={
                          <div className="flex items-center justify-between">
                            <span className="font-medium">{vuln.name}</span>
                            <Tag color={getRiskColor(vuln.risk_level)}>
                              {vuln.risk_level.toUpperCase()}
                            </Tag>
                          </div>
                        }
                        description={
                          <div className="space-y-1">
                            <div className="text-sm text-gray-600">
                              URL: {vuln.url} ({vuln.method})
                            </div>
                            {vuln.parameter && (
                              <div className="text-sm text-gray-600">
                                参数: {vuln.parameter}
                              </div>
                            )}
                            <div className="text-sm text-gray-500 line-clamp-2">
                              {vuln.description}
                            </div>
                          </div>
                        }
                      />
                    </List.Item>
                  )}
                />
              ) : (
                <div className="text-center py-8">
                  <CheckCircleOutlined className="text-4xl text-green-500 mb-4" />
                  <div className="text-lg font-medium text-gray-900 dark:text-gray-100">
                    扫描完成，未发现安全漏洞
                  </div>
                  <div className="text-gray-600 dark:text-gray-400">
                    目标系统安全性良好
                  </div>
                </div>
              )}

              {report.vulnerabilities.length > 5 && (
                <div className="text-center">
                  <Button
                    onClick={() => navigate(`/reports?taskId=${taskId}`)}
                    className="text-tape-brown hover:text-tape-dark"
                  >
                    查看全部 {report.vulnerabilities.length} 个漏洞
                  </Button>
                </div>
              )}
            </div>
          ) : (
            <Alert
              message="报告未生成"
              description="扫描报告正在生成中，请稍后再试"
              type="warning"
              showIcon
            />
          )}
        </Card>
      )}

      {/* 取消任务确认模态框 */}
      <Modal
        title="确认取消任务"
        open={cancelModalVisible}
        onOk={handleCancelTask}
        onCancel={() => setCancelModalVisible(false)}
        okText="确认取消"
        cancelText="继续运行"
        okButtonProps={{ danger: true }}
      >
        <p>确定要取消这个扫描任务吗？取消后将无法恢复。</p>
      </Modal>
    </div>
  );
};

export default TaskDetail;