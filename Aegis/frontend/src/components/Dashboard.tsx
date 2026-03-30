import React, { useEffect, useState } from 'react';
import { api, DashboardStats } from '../api';
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

  return (
    <div className="flex flex-col gap-8 max-w-7xl mx-auto">
      {/* ==================== 第一行：大型漏洞统计图表 ==================== */}
      <div className="bg-white rounded-2xl p-12 shadow-sm border border-gray-100 flex justify-around items-center">
        <LargeDonutChart 
          value={stats?.vulnerabilities.critical || 0} 
          total={totalVulns}
          color="#343a40" 
          label="高严重性漏洞" 
        />
        <LargeDonutChart 
          value={stats?.vulnerabilities.high || 0} 
          total={totalVulns}
          color="#ff7a00" 
          label="中严重性漏洞" 
        />
        <LargeDonutChart 
          value={stats?.vulnerabilities.low || 0} 
          total={totalVulns}
          color="#4dabf7" 
          label="低严重性漏洞" 
        />
      </div>

      {/* ==================== 第二行：横向数据指标 ==================== */}
      <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 grid grid-cols-5 divide-x divide-gray-100">
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">扫描正在运行</span>
          <span className="text-3xl font-bold text-red-500">{stats?.running_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">扫描等待</span>
          <span className="text-3xl font-bold text-red-500">{stats?.pending_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">时间的总扫描数</span>
          <span className="text-3xl font-bold text-red-500">{stats?.total_scans || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">开放端口</span>
          <span className="text-3xl font-bold text-red-500">{stats?.open_ports || 0}</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium uppercase tracking-wider">目标总数</span>
          <span className="text-3xl font-bold text-red-500">{stats?.total_targets || 0}</span>
        </div>
      </div>

      {/* ==================== 第三行：最近扫描目标与主要威胁 ==================== */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* 最近扫描目标 */}
        <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 flex flex-col gap-6">
          <h3 className="text-[#2d3343] text-lg font-bold">最近扫描目标</h3>
          <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
            <span className="text-gray-700 font-medium">192.168.10.156</span>
            <div className="w-6 h-6 bg-green-100 text-green-600 rounded-full flex items-center justify-center">
              <ShieldCheck size={16} strokeWidth={3} />
            </div>
          </div>
        </div>

        {/* 主要威胁 */}
        <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 flex flex-col gap-6">
          <h3 className="text-[#2d3343] text-lg font-bold">主要威胁</h3>
          <div className="flex flex-col gap-4">
            {/* 威胁项 1 */}
            <div className="flex items-start gap-4">
              <div className="mt-1 w-8 h-8 bg-orange-100 text-orange-600 rounded-lg flex items-center justify-center flex-shrink-0">
                <Info size={20} />
              </div>
              <div className="flex flex-col">
                <span className="text-gray-800 font-bold text-sm">组件 PHP allow_url_fopen</span>
                <span className="text-gray-400 text-xs">全部</span>
              </div>
            </div>
            {/* 威胁项 2 */}
            <div className="flex items-start gap-4">
              <div className="mt-1 w-8 h-8 bg-orange-100 text-orange-600 rounded-lg flex items-center justify-center flex-shrink-0">
                <Info size={20} />
              </div>
              <div className="flex flex-col">
                <span className="text-gray-800 font-bold text-sm">组件 PHP allow_url_include</span>
                <span className="text-gray-400 text-xs">全部</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
