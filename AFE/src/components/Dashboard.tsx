import React, { useEffect, useState } from 'react';
import { api } from '../api';
import type { DashboardStats } from '../api';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { ShieldCheck, Info } from './Icons';

/**
 * Figma 风格的大型环形图表
 */
const LargeDonutChart: React.FC<{
  value: number;
  total: number;
  color: string;
  label: string;
}> = ({ value, total, color, label }) => {
  const size = 180;
  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  
  // 计算进度百分比
  const percentage = total > 0 ? Math.min(value / total, 1) : 0;
  const offset = circumference - percentage * circumference;

  return (
    <div className="flex flex-col items-center gap-6">
      <div className="relative" style={{ width: size, height: size }}>
        {/* 背景圆环 */}
        <svg className="transform -rotate-90 w-full h-full">
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#f1f3f5"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* 进度圆环 */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        {/* 中间数字 */}
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-5xl font-bold text-awvs-text-primary">{value}</span>
        </div>
      </div>
      <span className="text-aegis-text-muted text-sm font-medium">{label}</span>
    </div>
  );
};

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    try {
      const data = await api.getStats();
      setStats(data);
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // 每 30 秒自动刷新一次仪表盘数据
    const interval = setInterval(fetchStats, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !stats) {
    return (
      <div className="w-full h-full flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-awvs-primary"></div>
      </div>
    );
  }

  const totalVulns = stats ? (
    stats.vulnerabilities.critical + 
    stats.vulnerabilities.high + 
    stats.vulnerabilities.medium + 
    stats.vulnerabilities.low
  ) : 0;

  const validatedFindings = totalVulns;
  const attackCoverage = stats ? (
    stats.total_scans > 0
      ? Math.round(((stats.running_scans + validatedFindings) / Math.max(stats.total_scans, 1)) * 100)
      : 0
  ) : 0;

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      {/* 顶部概览卡片 */}
      <div className="rounded-xl border border-awvs-border bg-white px-8 py-6 shadow-sm">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <div className="inline-flex rounded-md border border-awvs-border bg-awvs-bg-light px-3 py-1 text-xs font-semibold tracking-wide text-awvs-text-secondary">
              BAS-Inspired Web Validation
            </div>
            <h1 className="mt-3 text-2xl font-bold leading-tight text-awvs-text-primary">基于模拟攻击的 Web 应用验证总览</h1>
            <p className="mt-2 text-sm leading-6 text-awvs-text-secondary">
              通过无害化攻击载荷、攻击路径验证和证据链留存，对目标系统进行验证式扫描，帮助你快速判断漏洞是否真正可利用。
            </p>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg border border-awvs-border bg-awvs-bg-light px-4 py-3">
              <div className="text-xs text-awvs-text-secondary">验证中任务</div>
              <div className="mt-1 text-xl font-bold text-awvs-text-primary">{stats?.running_scans || 0}</div>
            </div>
            <div className="rounded-lg border border-awvs-border bg-awvs-bg-light px-4 py-3">
              <div className="text-xs text-awvs-text-secondary">已验证发现</div>
              <div className="mt-1 text-xl font-bold text-awvs-text-primary">{validatedFindings}</div>
            </div>
            <div className="rounded-lg border border-awvs-border bg-awvs-bg-light px-4 py-3">
              <div className="text-xs text-awvs-text-secondary">验证覆盖感知</div>
              <div className="mt-1 text-xl font-bold text-awvs-text-primary">{attackCoverage}%</div>
            </div>
          </div>
        </div>
      </div>

      {/* ==================== 第一行：大型漏洞统计图表 ==================== */}
      <div className="bg-white rounded-xl p-8 shadow-sm border border-awvs-border flex justify-around items-center">
        <LargeDonutChart
          value={stats?.vulnerabilities.critical || 0}
          total={totalVulns}
          color="var(--color-awvs-critical)"
          label="严重验证发现"
        />
        <LargeDonutChart
          value={stats?.vulnerabilities.high || 0}
          total={totalVulns}
          color="var(--color-awvs-high)"
          label="高危验证发现"
        />
        <LargeDonutChart
          value={stats?.vulnerabilities.low || 0}
          total={totalVulns}
          color="var(--color-awvs-low)"
          label="低危验证发现"
        />
      </div>

      {/* ==================== 第二行：横向数据指标 ==================== */}
      <div className="bg-white rounded-xl p-6 shadow-sm border border-awvs-border grid grid-cols-5 divide-x divide-awvs-border">
        <div className="flex flex-col items-center gap-2 px-4">
          <span className="text-awvs-text-secondary text-xs font-semibold uppercase tracking-wider">验证正在运行</span>
          <span className="text-2xl font-bold text-awvs-critical">{stats?.running_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2 px-4">
          <span className="text-awvs-text-secondary text-xs font-semibold uppercase tracking-wider">等待验证</span>
          <span className="text-2xl font-bold text-awvs-high">{stats?.pending_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2 px-4">
          <span className="text-awvs-text-secondary text-xs font-semibold uppercase tracking-wider">验证式扫描总数</span>
          <span className="text-2xl font-bold text-awvs-text-primary">{stats?.total_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2 px-4">
          <span className="text-awvs-text-secondary text-xs font-semibold uppercase tracking-wider">攻击面端口</span>
          <span className="text-2xl font-bold text-awvs-low">{stats?.open_ports || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2 px-4">
          <span className="text-awvs-text-secondary text-xs font-semibold uppercase tracking-wider">验证目标总数</span>
          <span className="text-2xl font-bold text-awvs-text-primary">{stats?.total_targets || 0}</span>
        </div>
      </div>

      {/* ==================== 第三行：最近扫描目标与主要威胁 ==================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 最近扫描目标 */}
        <div className="bg-white rounded-xl p-6 shadow-sm border border-awvs-border flex flex-col gap-4">
          <h3 className="text-awvs-text-primary text-base font-bold">最近验证目标</h3>
          <div className="flex items-center justify-between rounded-lg bg-awvs-bg-light p-4 border border-awvs-border">
            <div>
              <span className="text-awvs-text-primary font-medium text-sm">已纳入攻击验证视图的目标资产</span>
              <p className="mt-1 text-xs text-awvs-text-secondary">结合任务、载荷和证据链判断风险是否真实可利用。</p>
            </div>
            <div className="w-8 h-8 bg-green-50 text-green-600 rounded-lg flex items-center justify-center">
              <ShieldCheck size={18} strokeWidth={2} />
            </div>
          </div>
        </div>

        {/* 主要威胁 */}
        <div className="bg-white rounded-xl p-6 shadow-sm border border-awvs-border flex flex-col gap-4 min-w-0">
          <h3 className="text-awvs-text-primary text-base font-bold">主要攻击验证发现</h3>
          <div className="flex flex-col gap-3">
            {stats?.top_threats && stats.top_threats.length > 0 ? (
              stats.top_threats.map((threat) => (
                <div key={threat.id} className="flex items-start gap-3 min-w-0">
                  <div className={`mt-0.5 w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                    threat.severity === 'critical' ? 'bg-red-50 text-red-600' :
                    threat.severity === 'high' ? 'bg-orange-50 text-orange-600' :
                    threat.severity === 'medium' ? 'bg-yellow-50 text-yellow-600' :
                    'bg-blue-50 text-blue-600'
                  }`}>
                    <Info size={18} />
                  </div>
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-awvs-text-primary font-bold text-sm break-words">{threat.title}</span>
                    <span className="text-awvs-text-secondary text-xs truncate max-w-full" title={threat.target_url || '全部目标'}>
                      {threat.target_url || '全部目标'} · 已纳入模拟攻击证据判断
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center py-8 text-awvs-text-muted">
                <span>暂无攻击验证数据</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
