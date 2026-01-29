import React, { useState } from 'react';

interface Task {
  id: string;
  target: string;
  status: string;
  progress: string;
  vulnerabilities: number;
  updateTime: string;
}

interface TaskListProps {
  onImportYAML?: () => void;
  onCreateTask?: () => void;
  onViewTask?: (taskId: string) => void;
  onStopTask?: (taskId: string) => void;
}

const TaskList: React.FC<TaskListProps> = ({
  onImportYAML,
  onCreateTask,
  onViewTask,
  onStopTask
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('全部');

  const tasks: Task[] = [
    {
      id: 'T-24018',
      target: 'https://demo.test',
      status: '运行中',
      progress: '62%',
      vulnerabilities: 3,
      updateTime: '刚刚'
    },
    {
      id: 'T-24017',
      target: 'https://shop.example',
      status: '已完成',
      progress: '100%',
      vulnerabilities: 12,
      updateTime: '2 分钟前'
    },
    {
      id: 'T-24016',
      target: 'https://staging.app',
      status: '已暂停',
      progress: '41%',
      vulnerabilities: 2,
      updateTime: '8 分钟前'
    }
  ];

  return (
    <div className="flex flex-col gap-4 w-full h-full">
      {/* Toolbar */}
      <div className="w-full flex items-center justify-between">
        {/* Left Section */}
        <div className="flex-1 h-10 flex items-center gap-3">
          {/* Search */}
          <div className="w-[360px] h-9 bg-[var(--card)] rounded-[6px] border border-solid border-[var(--border)] flex items-center gap-2 px-[10px] py-3">
            <div className="text-[var(--mutedText)] w-4 h-4 flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" />
                <path d="m21 21-4.35-4.35" />
              </svg>
            </div>
            <input
              type="text"
              placeholder="搜索目标/任务ID"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="flex-1 bg-transparent text-[var(--mutedText)] font-inter text-[13px] font-normal outline-none placeholder-[var(--mutedText)]"
            />
          </div>

          {/* Filter */}
          <div className="h-9 bg-[var(--card)] rounded-[6px] border border-solid border-[var(--border)] flex items-center gap-2 px-[10px] py-3 cursor-pointer hover:bg-gray-50 transition-colors">
            <div className="text-[var(--mutedText)] w-4 h-4 flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
              </svg>
            </div>
            <span className="text-[var(--bodyText)] font-inter text-[13px] font-[600]">
              状态：{statusFilter}
            </span>
          </div>
        </div>

        {/* Right Section - Actions */}
        <div className="h-10 flex items-center gap-[10px]">
          {/* Import YAML Button */}
          <button
            onClick={onImportYAML}
            className="h-9 bg-[var(--card)] rounded-[6px] border border-solid border-[var(--border)] flex items-center gap-2 px-[10px] py-3 hover:bg-gray-50 transition-colors"
          >
            <div className="text-[var(--titleText)] w-4 h-4 flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
            </div>
            <span className="text-[var(--titleText)] font-inter text-[14px] font-[600]">
              导入 YAML
            </span>
          </button>

          {/* Create Task Button */}
          <button
            onClick={onCreateTask}
            className="h-9 bg-[#2d2d2d] rounded-[6px] gap-2 px-[10px] py-3 flex items-center text-[var(--card)] hover:bg-[#3d3d3d] transition-colors"
          >
            <div className="w-4 h-4 flex items-center justify-center">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="12" y1="5" x2="12" y2="19" />
                <line x1="5" y1="12" x2="19" y2="12" />
              </svg>
            </div>
            <span className="font-inter text-[14px] font-[600]">
              创建任务
            </span>
          </button>
        </div>
      </div>

      {/* Task Table */}
      <div className="flex-1 bg-[var(--card)] rounded-[10px] border border-solid border-[var(--border)] flex flex-col overflow-auto">
        {/* Table Header */}
        <div className="w-full h-11 bg-[var(--background)] border-b border-solid border-[var(--border)] flex items-center gap-3 px-[10px] py-[14px]">
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            ID
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            目标
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            状态
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            进度
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            漏洞
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            更新时间
          </div>
          <div className="text-[var(--mutedText)] font-inter text-[12px] font-[700]">
            操作
          </div>
        </div>

        {/* Table Rows */}
        {tasks.map((task, index) => (
          <div key={index} className="w-full h-13 border-b border-solid border-[var(--border)] flex items-center gap-3 px-[10px] py-[14px]">
            <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
              {task.id}
            </div>
            <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
              {task.target}
            </div>
            <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
              {task.status}
            </div>
            <div className="text-[var(--bodyText)] font-inter text-[13px] font-normal">
              {task.progress}
            </div>
            <div className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
              {task.vulnerabilities}
            </div>
            <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal">
              {task.updateTime}
            </div>
            <div className="h-8 flex items-center gap-2">
              {/* View Button */}
              <button
                onClick={() => onViewTask?.(task.id)}
                className="w-8 h-8 bg-[var(--card)] rounded-[8px] border border-solid border-[var(--border)] flex items-center justify-center hover:bg-gray-50 transition-colors"
              >
                <div className="text-[var(--titleText)] w-4 h-4 flex items-center justify-center">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                    <circle cx="12" cy="12" r="3" />
                  </svg>
                </div>
              </button>

              {/* Stop Button (only show for running tasks) */}
              {task.status === '运行中' && (
                <button
                  onClick={() => onStopTask?.(task.id)}
                  className="w-8 h-8 bg-[var(--card)] rounded-[8px] border border-solid border-[var(--destructive)] flex items-center justify-center hover:bg-red-50 transition-colors"
                >
                  <div className="text-[var(--destructive)] w-4 h-4 flex items-center justify-center">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                    </svg>
                  </div>
                </button>
              )}
            </div>
          </div>
        ))}

        {/* Table Footer */}
        <div className="w-full h-11 bg-[var(--background)] flex items-center justify-between px-[10px] py-[14px]">
          <div className="text-[var(--mutedText)] font-inter text-[13px] font-normal">
            共 3 个任务
          </div>
          <div className="h-8 flex items-center gap-2">
            {/* Page 1 */}
            <div className="w-8 h-8 bg-[var(--card)] rounded-[8px] border border-solid border-[var(--border)] flex items-center justify-center cursor-pointer hover:bg-gray-50 transition-colors">
              <span className="text-[var(--titleText)] font-inter text-[13px] font-[600]">
                1
              </span>
            </div>
            {/* Page 2 */}
            <div className="w-8 h-8 bg-[var(--card)] rounded-[8px] border border-solid border-[var(--border)] flex items-center justify-center cursor-pointer hover:bg-gray-50 transition-colors">
              <span className="text-[var(--mutedText)] font-inter text-[13px] font-[600]">
                2
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TaskList;