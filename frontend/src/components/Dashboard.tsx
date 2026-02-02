import React, { useMemo } from 'react';

interface DashboardProps {
  onCreateScan?: () => void;
}

/**
 * 简单的环形图表组件
 * 用于显示漏洞分布统计
 */
const DonutChart: React.FC<{
  data: Array<{ label: string; value: number; color: string }>;
  size?: number;
}> = ({ data, size = 120 }) => {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const radius = size / 2 - 10;
  
  let currentAngle = -90;
  const segments = data.map((item, index) => {
    const sliceAngle = (item.value / total) * 360;
    const startAngle = currentAngle;
    const endAngle = currentAngle + sliceAngle;
    
    const startRad = (startAngle * Math.PI) / 180;
    const endRad = (endAngle * Math.PI) / 180;
    
    const x1 = size / 2 + radius * Math.cos(startRad);
    const y1 = size / 2 + radius * Math.sin(startRad);
    const x2 = size / 2 + radius * Math.cos(endRad);
    const y2 = size / 2 + radius * Math.sin(endRad);
    
    const largeArc = sliceAngle > 180 ? 1 : 0;
    const pathData = [
      `M ${size / 2} ${size / 2}`,
      `L ${x1} ${y1}`,
      `A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}`,
      'Z'
    ].join(' ');
    
    currentAngle = endAngle;
    
    return (
      <path
        key={index}
        d={pathData}
        fill={item.color}
        stroke="white"
        strokeWidth="2"
      />
    );
  });
  
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      {segments}
    </svg>
  );
};

/**
 * Dashboard 组件
 * 
 * Aegis 平台的主仪表盘，显示扫描任务统计、漏洞分布和最近任务列表。
 * 采用 AWVS 风格的卡片布局和色彩系统。
 * 
 * @param onCreateScan - 新建扫描按钮的点击事件处理
 */
const Dashboard: React.FC<DashboardProps> = ({ onCreateScan }) => {
  // 漏洞分布数据
  const vulnerabilityData = useMemo(() => [
    { label: '高危', value: 4, color: '#ff4d4f' },
    { label: '中危', value: 7, color: '#ffa940' },
    { label: '低危', value: 6, color: '#1890ff' },
  ], []);

  return (
    <div className="flex flex-col gap-4 w-full h-full">
      {/* ==================== 页面头部 ==================== */}
      <div className="w-full flex items-center justify-between">
        <div className="flex flex-col gap-1">
          <div className="text-[var(--titleText)] font-inter text-[20px] font-[700]">
            概览
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal">
            实时状态与漏洞汇总
          </div>
        </div>
        <button
          onClick={onCreateScan}
          className="h-9 bg-[#2d2d2d] rounded-[6px] gap-2 px-[10px] py-[14px] flex items-center text-[var(--card)] hover:bg-[#3d3d3d] transition-colors duration-200"
        >
          <div className="w-4 h-4 flex items-center justify-center">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
          </div>
          <span className="font-inter text-[14px] font-[600]">
            新建扫描
          </span>
        </button>
      </div>

      {/* ==================== 关键指标行 ==================== */}
      <div className="w-full h-[120px] flex gap-4">
        {/* 运行任务 */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4 hover:shadow-md transition-shadow">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            运行任务
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            2
          </div>
          <div className="text-[#52c41a] font-inter text-[12px] font-normal">
            ↑ 相比昨日 +1
          </div>
        </div>

        {/* 漏洞总数 */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4 hover:shadow-md transition-shadow">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            漏洞总数
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            17
          </div>
          <div className="text-[#ff4d4f] font-inter text-[12px] font-normal">
            ↑ 相比昨日 +3
          </div>
        </div>

        {/* 高危漏洞 */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4 hover:shadow-md transition-shadow">
          <div className="w-full flex items-center gap-2">
            <div className="w-2 h-2 bg-[#ff4d4f] rounded-full"></div>
            <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
              高危
            </div>
          </div>
          <div className="text-[#ff4d4f] font-inter text-[32px] font-[700]">
            4
          </div>
          <div className="text-[#8c8c8c] font-inter text-[12px] font-normal">
            需要立即处理
          </div>
        </div>

        {/* 最近扫描 */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4 hover:shadow-md transition-shadow">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            最近扫描
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            3 分钟前
          </div>
          <div className="text-[#1890ff] font-inter text-[12px] font-normal">
            https://demo.test
          </div>
        </div>
      </div>

      {/* ==================== 第二行：任务列表和漏洞分布 ==================== */}
      <div className="flex-1 w-full flex gap-4 min-h-0">
        {/* 最近任务卡片 */}
        <div className="flex-1 bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-3 p-4 overflow-hidden">
          <div className="w-full flex items-center justify-between">
            <div className="text-[var(--titleText)] font-inter text-[16px] font-[700]">
              最近任务
            </div>
            <div className="text-[#1890ff] font-inter text-[13px] font-normal cursor-pointer hover:text-[#0050b3] transition-colors">
              查看全部 →
            </div>
          </div>

          {/* 任务表格 */}
          <div className="flex-1 w-full flex flex-col overflow-auto">
            {/* 表头 */}
            <div className="w-full h-9 bg-[var(--background)] border-b border-solid border-[var(--border)] flex items-center gap-3 px-[8px] py-[10px] sticky top-0">
              <div className="flex-1 text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                目标
              </div>
              <div className="w-20 text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                状态
              </div>
              <div className="w-16 text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                进度
              </div>
              <div className="w-24 text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                更新时间
              </div>
            </div>

            {/* 任务行 1 */}
            <div className="w-full h-11 border-b border-solid border-[var(--border)] flex items-center gap-3 p-[10px] hover:bg-[#fafafa] transition-colors">
              <div className="flex-1 text-[var(--bodyText)] font-inter text-[13px] font-normal truncate">
                https://demo.test
              </div>
              <div className="w-20 flex items-center gap-1">
                <div className="w-2 h-2 bg-[#52c41a] rounded-full"></div>
                <span className="text-[#52c41a] font-inter text-[13px] font-[600]">
                  运行中
                </span>
              </div>
              <div className="w-16 text-[var(--bodyText)] font-inter text-[13px] font-normal">
                62%
              </div>
              <div className="w-24 text-[var(--mutedText)] font-inter text-[13px] font-normal">
                刚刚
              </div>
            </div>

            {/* 任务行 2 */}
            <div className="w-full h-11 border-b border-solid border-[var(--border)] flex items-center gap-3 p-[10px] hover:bg-[#fafafa] transition-colors">
              <div className="flex-1 text-[var(--bodyText)] font-inter text-[13px] font-normal truncate">
                https://shop.example
              </div>
              <div className="w-20 flex items-center gap-1">
                <div className="w-2 h-2 bg-[#1890ff] rounded-full"></div>
                <span className="text-[#1890ff] font-inter text-[13px] font-[600]">
                  已完成
                </span>
              </div>
              <div className="w-16 text-[var(--bodyText)] font-inter text-[13px] font-normal">
                100%
              </div>
              <div className="w-24 text-[var(--mutedText)] font-inter text-[13px] font-normal">
                2 分钟前
              </div>
            </div>

            {/* 任务行 3 */}
            <div className="w-full h-11 flex items-center gap-3 p-[10px] hover:bg-[#fafafa] transition-colors">
              <div className="flex-1 text-[var(--bodyText)] font-inter text-[13px] font-normal truncate">
                https://api.service.io
              </div>
              <div className="w-20 flex items-center gap-1">
                <div className="w-2 h-2 bg-[#ff4d4f] rounded-full"></div>
                <span className="text-[#ff4d4f] font-inter text-[13px] font-[600]">
                  失败
                </span>
              </div>
              <div className="w-16 text-[var(--bodyText)] font-inter text-[13px] font-normal">
                0%
              </div>
              <div className="w-24 text-[var(--mutedText)] font-inter text-[13px] font-normal">
                5 分钟前
              </div>
            </div>
          </div>
        </div>

        {/* 漏洞分布卡片 */}
        <div className="w-[420px] bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-4 p-4">
          <div className="text-[var(--titleText)] font-inter text-[16px] font-[700]">
            漏洞分布
          </div>

          {/* 环形图表 */}
          <div className="w-full flex justify-center py-4">
            <DonutChart data={vulnerabilityData} size={140} />
          </div>

          {/* 图例 */}
          <div className="w-full flex flex-col gap-[10px]">
            {/* 高危 */}
            <div className="w-full flex items-center justify-between">
              <div className="flex items-center gap-[10px]">
                <div className="w-2 h-2 bg-[#ff4d4f] rounded-full flex-shrink-0"></div>
                <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                  高危
                </div>
              </div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                4
              </div>
            </div>

            {/* 中危 */}
            <div className="w-full flex items-center justify-between">
              <div className="flex items-center gap-[10px]">
                <div className="w-2 h-2 bg-[#ffa940] rounded-full flex-shrink-0"></div>
                <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                  中危
                </div>
              </div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                7
              </div>
            </div>

            {/* 低危 */}
            <div className="w-full flex items-center justify-between">
              <div className="flex items-center gap-[10px]">
                <div className="w-2 h-2 bg-[#1890ff] rounded-full flex-shrink-0"></div>
                <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                  低危
                </div>
              </div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                6
              </div>
            </div>
          </div>

          {/* 统计信息 */}
          <div className="w-full border-t border-[var(--border)] pt-3 mt-2">
            <div className="text-[var(--mutedText)] font-inter text-[12px] font-normal">
              总计: <span className="text-[var(--titleText)] font-[600]">17 个漏洞</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
