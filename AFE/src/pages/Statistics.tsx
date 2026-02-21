import React, { useEffect, useState, useRef } from 'react';
import { Card, Row, Col, Statistic, Select, DatePicker, Space, Spin, Empty, message, Button } from 'antd';
import {
  ExperimentOutlined, AlertOutlined, CheckCircleOutlined,
  ClockCircleOutlined, BarChartOutlined, PieChartOutlined,
  LineChartOutlined, ReloadOutlined
} from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import { apiService } from '../services/api';
import { Statistics as StatsType, ChartData } from '../types';

const { Option } = Select;
const { RangePicker } = DatePicker;

const Statistics: React.FC = () => {
  const [stats, setStats] = useState<StatsType | null>(null);
  const [chartData, setChartData] = useState<ChartData | null>(null);
  const [loading, setLoading] = useState(false);
  const [chartLoading, setChartLoading] = useState(false);
  const [chartType, setChartType] = useState('risk_distribution');
  const [timeRange, setTimeRange] = useState('30d');
  const echartsRef = useRef<any>(null);

  useEffect(() => {
    loadStatistics();
    loadChartData();
  }, []);

  // 组件卸载时清理 ECharts 实例
  useEffect(() => {
    return () => {
      if (echartsRef.current) {
        try {
          const echartsInstance = echartsRef.current?.getEchartsInstance?.();
          if (echartsInstance && typeof echartsInstance.dispose === 'function') {
            echartsInstance.dispose();
          }
        } catch (error) {
          // 忽略清理时的错误，避免在开发模式下重复卸载导致的错误
          console.debug('ECharts cleanup error (safe to ignore):', error);
        }
      }
    };
  }, []);

  useEffect(() => {
    loadChartData();
  }, [chartType, timeRange]);

  const loadStatistics = async () => {
    try {
      const statsData = await apiService.getStatistics();
      setStats(statsData);
    } catch (error) {
      message.error('加载统计数据失败');
    }
  };

  const loadChartData = async () => {
    setChartLoading(true);
    try {
      const chartResponse = await apiService.getChartData(chartType, timeRange);
      setChartData(chartResponse);
    } catch (error) {
      console.error('加载图表数据失败:', error);
    } finally {
      setChartLoading(false);
    }
  };

  const getChartOption = () => {
    if (!chartData || !chartData.data) return {};

    // 安全获取数据，提供默认值
    const labels = chartData.data.labels || [];
    const values = chartData.data.values || [];

    const baseConfig = {
      tooltip: {
        trigger: 'axis',
        axisPointer: {
          type: 'shadow'
        }
      },
      grid: {
        left: '3%',
        right: '4%',
        bottom: '3%',
        containLabel: true
      },
      textStyle: {
        color: '#666'
      }
    };

    switch (chartType) {
      case 'risk_distribution':
        return {
          ...baseConfig,
          title: {
            text: '漏洞风险等级分布',
            left: 'center',
            textStyle: { color: '#1677ff', fontWeight: 'bold' }
          },
          xAxis: {
            type: 'category',
            data: labels,
            axisLabel: { color: '#666' }
          },
          yAxis: {
            type: 'value',
            axisLabel: { color: '#666' }
          },
          series: [{
            name: '漏洞数量',
            type: 'bar',
            data: values,
            itemStyle: {
              color: function(params: any) {
                const colors = ['#ff4d4f', '#ff7a45', '#faad14', '#52c41a', '#d9d9d9'];
                return colors[params.dataIndex] || '#1677ff';
              }
            },
            label: {
              show: true,
              position: 'top',
              color: '#666'
            }
          }]
        };

      case 'vulnerability_trend':
        return {
          ...baseConfig,
          title: {
            text: '漏洞发现趋势',
            left: 'center',
            textStyle: { color: '#1677ff', fontWeight: 'bold' }
          },
          xAxis: {
            type: 'category',
            data: labels,
            axisLabel: { color: '#666' }
          },
          yAxis: {
            type: 'value',
            axisLabel: { color: '#666' }
          },
          series: [{
            name: '漏洞数量',
            type: 'line',
            data: values,
            smooth: true,
            itemStyle: { color: '#1677ff' },
            areaStyle: {
              color: {
                type: 'linear',
                x: 0, y: 0, x2: 0, y2: 1,
                colorStops: [{
                  offset: 0, color: 'rgba(22, 119, 255, 0.3)'
                }, {
                  offset: 1, color: 'rgba(22, 119, 255, 0.1)'
                }]
              }
            }
          }]
        };

      case 'module_statistics':
        return {
          title: {
            text: '检测模块使用统计',
            left: 'center',
            textStyle: { color: '#1677ff', fontWeight: 'bold' }
          },
          tooltip: {
            trigger: 'item',
            formatter: '{a} <br/>{b}: {c} ({d}%)'
          },
          legend: {
            orient: 'vertical',
            left: 'left'
          },
          series: [{
            name: '检测次数',
            type: 'pie',
            radius: '50%',
            data: labels.map((label, index) => ({
              name: label,
              value: values[index] || 0
            })),
            emphasis: {
              itemStyle: {
                shadowBlur: 10,
                shadowOffsetX: 0,
                shadowColor: 'rgba(0, 0, 0, 0.5)'
              }
            }
          }]
        };

      default:
        return {};
    }
  };

  const refreshData = () => {
    loadStatistics();
    loadChartData();
  };

  return (
    <div className="space-y-6">
      {/* 标题和控制 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            统计分析
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            查看系统统计数据和图表分析
          </p>
        </div>
        <Space>
          <Button
            icon={<ReloadOutlined />}
            onClick={refreshData}
            loading={loading || chartLoading}
          >
            刷新数据
          </Button>
        </Space>
      </div>

      {/* 统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="card-retro hover:shadow-lg transition-shadow">
            <Statistic
              title="总扫描次数"
              value={stats?.total_scans || 0}
              prefix={<ExperimentOutlined className="text-tape-brown" />}
              valueStyle={{ color: '#8B4513' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="card-retro hover:shadow-lg transition-shadow">
            <Statistic
              title="发现漏洞总数"
              value={stats?.vulnerabilities_found || 0}
              prefix={<AlertOutlined className="text-red-500" />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="card-retro hover:shadow-lg transition-shadow">
            <Statistic
              title="危急漏洞"
              value={stats?.critical_vulnerabilities || 0}
              prefix={<AlertOutlined className="text-red-600" />}
              valueStyle={{ color: '#cf1322' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="card-retro hover:shadow-lg transition-shadow">
            <Statistic
              title="活跃任务"
              value={stats?.active_tasks || 0}
              prefix={<ClockCircleOutlined className="text-blue-500" />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
      </Row>

      {/* 图表控制 */}
      <Card className="card-retro">
        <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between mb-6">
          <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
            <div>
              <label className="block text-sm font-medium mb-1">图表类型</label>
              <Select
                value={chartType}
                onChange={setChartType}
                style={{ width: 180 }}
              >
                <Option value="risk_distribution">
                  <BarChartOutlined className="mr-2" />
                  风险等级分布
                </Option>
                <Option value="vulnerability_trend">
                  <LineChartOutlined className="mr-2" />
                  漏洞发现趋势
                </Option>
                <Option value="module_statistics">
                  <PieChartOutlined className="mr-2" />
                  检测模块统计
                </Option>
              </Select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">时间范围</label>
              <Select
                value={timeRange}
                onChange={setTimeRange}
                style={{ width: 120 }}
              >
                <Option value="7d">最近7天</Option>
                <Option value="30d">最近30天</Option>
                <Option value="90d">最近90天</Option>
                <Option value="1y">最近一年</Option>
              </Select>
            </div>
          </div>
        </div>

        {/* 图表展示 */}
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4">
          {chartLoading ? (
            <div className="flex items-center justify-center h-96">
              <Spin size="large" />
            </div>
          ) : chartData ? (
            <ReactECharts
              ref={echartsRef}
              option={getChartOption()}
              style={{ height: '400px', width: '100%' }}
              className="w-full"
              notMerge={true}
              lazyUpdate={true}
            />
          ) : (
            <Empty
              description="暂无图表数据"
              image={Empty.PRESENTED_IMAGE_SIMPLE}
            />
          )}
        </div>
      </Card>

      {/* 额外统计信息 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card
            className="card-retro"
            title={
              <div className="flex items-center">
                <CheckCircleOutlined className="text-tape-brown mr-2" />
                系统状态
              </div>
            }
          >
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">系统运行时间</span>
                <span className="font-medium">
                  {stats?.system_uptime_hours || 0} 小时
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">平均扫描时间</span>
                <span className="font-medium">
                  {stats?.total_scans ? Math.round((stats.system_uptime_hours * 60) / stats.total_scans) : 0} 分钟/次
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">漏洞发现率</span>
                <span className="font-medium">
                  {stats?.total_scans ?
                    Math.round((stats.vulnerabilities_found / stats.total_scans) * 100) : 0}%
                </span>
              </div>
            </div>
          </Card>
        </Col>

        <Col xs={24} lg={12}>
          <Card
            className="card-retro"
            title={
              <div className="flex items-center">
                <AlertOutlined className="text-tape-brown mr-2" />
                风险概览
              </div>
            }
          >
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">危急风险比例</span>
                <span className="font-medium text-red-600">
                  {stats?.vulnerabilities_found ?
                    Math.round((stats.critical_vulnerabilities / stats.vulnerabilities_found) * 100) : 0}%
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">高危风险比例</span>
                <span className="font-medium text-orange-600">
                  {stats?.vulnerabilities_found ?
                    Math.round(((stats.vulnerabilities_found - stats.critical_vulnerabilities) * 0.3 / stats.vulnerabilities_found) * 100) : 0}%
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-gray-600 dark:text-gray-400">安全任务比例</span>
                <span className="font-medium text-green-600">
                  {stats?.total_scans ?
                    Math.round(((stats.total_scans - stats.vulnerabilities_found) / stats.total_scans) * 100) : 0}%
                </span>
              </div>
            </div>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Statistics;
