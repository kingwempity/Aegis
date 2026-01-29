import React from 'react';

interface DashboardProps {
  onCreateScan?: () => void;
}

const Dashboard: React.FC<DashboardProps> = ({ onCreateScan }) => {
  return (
    <div className="flex flex-col gap-4 w-full h-full">
      {/* Page Header */}
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

      {/* Metrics Row */}
      <div className="w-full h-[120px] flex gap-4">
        {/* Active Tasks Metric */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            运行任务
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            2
          </div>
        </div>

        {/* Total Vulnerabilities Metric */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            漏洞总数
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            17
          </div>
        </div>

        {/* High Risk Metric */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4">
          <div className="w-full flex items-center gap-2">
            <div className="w-2 h-2 bg-[var(--destructive)] rounded-full"></div>
            <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
              高危
            </div>
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            4
          </div>
        </div>

        {/* Latest Scan Metric */}
        <div className="flex-1 h-full bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-[6px] p-4">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-[500]">
            最近扫描
          </div>
          <div className="text-[var(--titleText)] font-inter text-[32px] font-[700]">
            3 分钟前
          </div>
        </div>
      </div>

      {/* Second Row - Recent Tasks and Vulnerability Distribution */}
      <div className="flex-1 w-full flex gap-4 min-h-0">
        {/* Recent Tasks Card */}
        <div className="flex-1 bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-3 p-4">
          <div className="w-full flex items-center justify-between">
            <div className="text-[var(--titleText)] font-inter text-[16px] font-[700]">
              最近任务
            </div>
            <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal cursor-pointer hover:text-[var(--bodyText)] transition-colors">
              查看全部
            </div>
          </div>

          {/* Tasks Table */}
          <div className="flex-1 w-full flex flex-col overflow-auto">
            {/* Header */}
            <div className="w-full h-9 bg-[var(--background)] border-b border-solid border-[var(--border)] flex items-center gap-3 px-[8px] py-[10px]">
              <div className="text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                目标
              </div>
              <div className="text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                状态
              </div>
              <div className="text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                进度
              </div>
              <div className="text-[var(--mutedText)] font-inter text-[12px] font-[600]">
                更新时间
              </div>
            </div>

            {/* Row 1 */}
            <div className="w-full h-11 border-b border-solid border-[var(--border)] flex items-center gap-3 p-[10px]">
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
                https://demo.test
              </div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                运行中
              </div>
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
                62%
              </div>
              <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal">
                刚刚
              </div>
            </div>

            {/* Row 2 */}
            <div className="w-full h-11 border-b border-solid border-[var(--border)] flex items-center gap-3 p-[10px]">
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
                https://shop.example
              </div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                已完成
              </div>
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
                100%
              </div>
              <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal">
                2 分钟前
              </div>
            </div>
          </div>
        </div>

        {/* Vulnerability Distribution Card */}
        <div className="w-[420px] bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col gap-3 p-4">
          <div className="text-[var(--titleText)] font-inter text-[16px] font-[700]">
            漏洞分布
          </div>

          {/* Legend */}
          <div className="w-full flex flex-col gap-[10px]">
            {/* High Risk */}
            <div className="w-full h-6 flex items-center gap-[10px]">
              <div className="w-2 h-2 bg-[var(--destructive)] rounded-full"></div>
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                高危
              </div>
              <div className="flex-1 h-2 bg-[var(--background)] rounded"></div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                4
              </div>
            </div>

            {/* Medium Risk */}
            <div className="w-full h-6 flex items-center gap-[10px]">
              <div className="w-2 h-2 bg-[var(--titleText)] rounded-full"></div>
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                中危
              </div>
              <div className="flex-1 h-2 bg-[var(--background)] rounded"></div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                7
              </div>
            </div>

            {/* Low Risk */}
            <div className="w-full h-6 flex items-center gap-[10px]">
              <div className="w-2 h-2 bg-[var(--mutedText)] rounded-full"></div>
              <div className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
                低危
              </div>
              <div className="flex-1 h-2 bg-[var(--background)] rounded"></div>
              <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                6
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;