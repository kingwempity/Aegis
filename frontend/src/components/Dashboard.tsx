import React from 'react';

interface DashboardProps {
  onCreateScan?: () => void;
}

/**
 * Figma 风格的大型环形图表
 */
const LargeDonutChart: React.FC<{
  value: number;
  color: string;
  label: string;
}> = ({ value, color, label }) => {
  const size = 180;
  const strokeWidth = 16;
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;
  // 假设最大值为 10，用于计算进度
  const progress = Math.min(value / 10, 1);
  const offset = circumference - progress * circumference;

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

const Dashboard: React.FC<DashboardProps> = () => {
  return (
    <div className="flex flex-col gap-8 max-w-7xl mx-auto">
      {/* ==================== 第一行：大型漏洞统计图表 ==================== */}
      <div className="bg-white rounded-2xl p-12 shadow-sm border border-gray-100 flex justify-around items-center">
        <LargeDonutChart value={0} color="#343a40" label="高严重性漏洞" />
        <LargeDonutChart value={8} color="#ff7a00" label="中严重性漏洞" />
        <LargeDonutChart value={2} color="#4dabf7" label="低严重性漏洞" />
      </div>

      {/* ==================== 第二行：横向数据指标 ==================== */}
      <div className="bg-white rounded-2xl p-8 shadow-sm border border-gray-100 grid grid-cols-5 divide-x divide-gray-100">
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium">扫描正在运行</span>
          <span className="text-3xl font-bold text-red-500">0</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium">扫描等待</span>
          <span className="text-3xl font-bold text-red-500">0</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium">时间的总扫描数</span>
          <span className="text-3xl font-bold text-red-500">1</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium">开放端口</span>
          <span className="text-3xl font-bold text-red-500">10</span>
        </div>
        <div className="flex flex-col items-center gap-2">
          <span className="text-gray-500 text-xs font-medium">目标总数</span>
          <span className="text-3xl font-bold text-red-500">1</span>
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
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                <polyline points="20 6 9 17 4 12" />
              </svg>
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
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
              </div>
              <div className="flex flex-col">
                <span className="text-gray-800 font-bold text-sm">组件 PHP allow_url_fopen</span>
                <span className="text-gray-400 text-xs">全部</span>
              </div>
            </div>
            {/* 威胁项 2 */}
            <div className="flex items-start gap-4">
              <div className="mt-1 w-8 h-8 bg-orange-100 text-orange-600 rounded-lg flex items-center justify-center flex-shrink-0">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
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
