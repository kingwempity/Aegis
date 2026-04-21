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
          <span className="text-5xl font-bold text-[#2d3343]">{value}</span>
        </div>
      </div>
      <span className="text-[#8a92a6] text-sm font-medium">{label}</span>
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
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[#ff6b00]"></div>
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
    <div className="flex flex-col gap-8 max-w-7xl mx-auto">
      <div className="rounded-3xl border border-[#e7ebf0] bg-gradient-to-r from-[#f8fbfd] via-[#fdfefe] to-[#f4f8fb] px-10 py-8 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <div className="inline-flex rounded-full border border-[#e5ecf3] bg-[#eef4f8] px-3 py-1 text-xs font-semibold tracking-wide text-[#6b85a0]">
              BAS-Inspired Web Validation
            </div>
            <h1 className="mt-4 text-3xl font-bold leading-tight text-[#1f4260]">基于模拟攻击的 Web 应用验证总览</h1>
            <p className="mt-3 text-sm leading-6 text-[#698299]">
              通过无害化攻击载荷、攻击路径验证和证据链留存，对目标系统进行验证式扫描，帮助你快速判断漏洞是否真正可利用。
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <div className="rounded-2xl border border-[#edf2f7] bg-white px-4 py-4">
              <div className="text-xs text-[#8ba0b3]">验证中任务</div>
              <div className="mt-2 text-2xl font-bold text-[#1f4260]">{stats?.running_scans || 0}</div>
            </div>
            <div className="rounded-2xl border border-[#edf2f7] bg-white px-4 py-4">
              <div className="text-xs text-[#8ba0b3]">已验证发现</div>
              <div className="mt-2 text-2xl font-bold text-[#1f4260]">{validatedFindings}</div>
            </div>
            <div className="rounded-2xl border border-[#edf2f7] bg-white px-4 py-4 col-span-2 sm:col-span-1">
              <div className="text-xs text-[#8ba0b3]">验证覆盖感知</div>
              <div className="mt-2 text-2xl font-bold text-[#1f4260]">{attackCoverage}%</div>
            </div>
          </div>
        </div>
      </div>

      {/* ==================== 第一行：大型漏洞统计图表 ==================== */}
      <div className="bg-white rounded-2xl p-12 shadow-sm border border-gray-100 flex justify-around items-center">
        <LargeDonutChart 
          value={stats?.vulnerabilities.critical || 0} 
          total={totalVulns}
          color="#343a40" 
          label="严重验证发现" 
        />
        <LargeDonutChart 
          value={stats?.vulnerabilities.high || 0} 
          total={totalVulns}
          color="#ff7a00" 
          label="高危验证发现" 
        />
        <LargeDonutChart 
          value={stats?.vulnerabilities.low || 0} 
          total={totalVulns}
          color="#4dabf7" 
          label="低危验证发现" 
        />
      </div>

      {/* ==================== 第二行：横向数据指标 ==================== */}
      <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 grid grid-cols-5 divide-x divide-gray-100">
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">验证正在运行</span>
          <span className="text-3xl font-bold text-red-500">{stats?.running_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">等待验证</span>
          <span className="text-3xl font-bold text-red-500">{stats?.pending_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">验证式扫描总数</span>
          <span className="text-3xl font-bold text-red-500">{stats?.total_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">攻击面端口</span>
          <span className="text-3xl font-bold text-red-500">{stats?.open_ports || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">验证目标总数</span>
          <span className="text-3xl font-bold text-red-500">{stats?.total_targets || 0}</span>
        </div>
      </div>

      {/* ==================== 第三行：最近扫描目标与主要威胁 ==================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* 最近扫描目标 */}
        <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 flex flex-col gap-6">
          <h3 className="text-[#2d3343] text-lg font-bold">最近验证目标</h3>
          <div className="flex items-center justify-between rounded-xl bg-gray-50 p-4">
            <div>
              <span className="text-gray-700 font-medium">已纳入攻击验证视图的目标资产</span>
              <p className="mt-1 text-xs text-gray-400">结合任务、载荷和证据链判断风险是否真实可利用。</p>
            </div>
            <div className="w-6 h-6 bg-green-100 text-green-600 rounded-full flex items-center justify-center">
              <ShieldCheck size={16} strokeWidth={3} />
            </div>
          </div>
        </div>

        {/* 主要威胁 */}
        <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 flex flex-col gap-6">
          <h3 className="text-[#2d3343] text-lg font-bold">主要攻击验证发现</h3>
          <div className="flex flex-col gap-4">
            {stats?.top_threats && stats.top_threats.length > 0 ? (
              stats.top_threats.map((threat) => (
                <div key={threat.id} className="flex items-start gap-4">
                  <div className={`mt-1 w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${
                    threat.severity === 'critical' ? 'bg-red-100 text-red-600' :
                    threat.severity === 'high' ? 'bg-orange-100 text-orange-600' :
                    threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-600' :
                    'bg-blue-100 text-blue-600'
                  }`}>
                    <Info size={20} />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-gray-800 font-bold text-sm">{threat.title}</span>
                    <span className="text-gray-400 text-xs">{threat.target_url || '全部目标'} · 已纳入模拟攻击证据判断</span>
                  </div>
                </div>
              ))
            ) : (
              <div className="flex items-center justify-center py-8 text-gray-400">
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
