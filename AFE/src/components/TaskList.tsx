import React, { useEffect, useState, useCallback } from 'react';
import { api, ScanTask } from '../api';
import { getScanStrategyMeta } from '../utils/scanStrategy';
import { formatDateTime } from '../utils/formatDateTime';
import { Plus, Eye, StopSquare, Search, Trash2, Activity, ChevronLeft, ChevronRight } from './Icons';
import ValidationWorkflow from './ValidationWorkflow';

interface TaskListProps {
  onCreateTask?: () => void;
  onViewReport?: (taskId: number) => void;
  onViewExecution?: (taskId: number) => void;
}

const PAGE_SIZE = 20;

const TaskList: React.FC<TaskListProps> = ({ onCreateTask, onViewReport, onViewExecution }) => {
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchTasks = useCallback(async () => {
    try {
      const skip = (page - 1) * PAGE_SIZE;
      const data = await api.getTasks(skip, PAGE_SIZE);
      setTasks(data.items);
      setTotal(data.total);
    } catch (error) {
      console.error('Error fetching tasks:', error);
    } finally {
      setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    fetchTasks();
    const interval = setInterval(fetchTasks, 10000);
    return () => clearInterval(interval);
  }, [fetchTasks]);

  const totalPages = Math.ceil(total / PAGE_SIZE);

  const handleStopTask = async (taskId: number) => {
    try {
      await api.stopTask(taskId);
      fetchTasks();
    } catch (error) {
      alert('停止任务失败');
    }
  };

  const handleDeleteTask = async (task: ScanTask) => {
    if (!window.confirm(`确定要删除任务 #${task.display_id}（${task.target_url}）吗？关联的漏洞记录将一并删除。`)) return;
    try {
      await api.deleteTask(task.id);
      fetchTasks();
    } catch (e: any) {
      alert(e?.message || '删除任务失败');
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'RUNNING':
        return <span className="px-2 py-1 bg-blue-100 text-blue-600 rounded text-[10px] font-bold">验证中</span>;
      case 'COMPLETED':
        return <span className="px-2 py-1 bg-green-100 text-green-600 rounded text-[10px] font-bold">已验证</span>;
      case 'FAILED':
        return <span className="px-2 py-1 bg-red-100 text-red-600 rounded text-[10px] font-bold">验证失败</span>;
      default:
        return <span className="px-2 py-1 bg-gray-100 text-gray-600 rounded text-[10px] font-bold">等待验证</span>;
    }
  };

const formatDuration = (seconds: number): string => {
    if (seconds < 60) {
      return `${Math.round(seconds)}秒`;
    }
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = Math.round(seconds % 60);
    if (remainingSeconds > 0) {
      return `${minutes}分${remainingSeconds}秒`;
    }
    return `${minutes}分钟`;
  };

  const normalizedQuery = searchQuery.trim().replace(/^#/, '');
  const filteredTasks = tasks.filter(task =>
    task.target_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
    task.display_id.toString().includes(normalizedQuery)
  );

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <ValidationWorkflow currentStep="validation" compact />

      {/* Toolbar */}
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-4 flex-1">
          <div>
            <h2 className="text-xl font-bold text-[#1e293b]">模拟攻击验证任务</h2>
            <p className="mt-1 text-sm text-[#64748b]">跟踪攻击载荷验证、证据链留存与可利用性证明。</p>
          </div>
          <div className="relative flex-1 max-w-md">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-4 w-4 text-[#94a3b8]" />
            </div>
            <input
              type="text"
              placeholder="搜索目标 URL 或 显示ID（如 #12）..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-10 pr-3 py-2 border border-[#e2e8f0] rounded-lg text-sm placeholder-[#94a3b8] focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] transition-all bg-white"
            />
          </div>
        </div>
        <button 
          onClick={onCreateTask}
          className="px-5 py-2 bg-gradient-to-r from-[#ff6b00] to-[#ff8c00] text-white rounded-lg font-semibold text-sm hover:from-[#e66000] hover:to-[#e67a00] transition-all shadow-md shadow-orange-500/20 flex items-center gap-2"
        >
          <Plus size={16} strokeWidth={2.5} />
          新建验证
        </button>
      </div>

      {/* Task Table */}
      <div className="bg-white rounded-xl shadow-sm border border-[#e2e8f0] overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-[#f8fafc] border-b border-[#e2e8f0]">
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">ID</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">目标 URL</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">验证模式</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">状态</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">进度</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider">创建时间</th>
              <th className="px-6 py-3.5 text-xs font-semibold text-[#64748b] uppercase tracking-wider text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#f1f5f9]">
            {loading && tasks.length === 0 ? (
              <tr><td colSpan={7} className="px-6 py-12 text-center text-[#94a3b8]">加载中...</td></tr>
            ) : filteredTasks.length === 0 ? (
              <tr><td colSpan={7} className="px-6 py-12 text-center text-[#94a3b8]">暂无匹配的验证任务</td></tr>
            ) : (
              filteredTasks.map((task) => (
                <tr key={task.id} className="hover:bg-[#f8fafc] transition-colors align-top">
                  <td className="px-6 py-4 text-xs font-bold text-[#64748b]">#{task.display_id}</td>
                  <td className="px-6 py-4 font-semibold text-[#1e293b] font-mono text-sm">{task.target_url}</td>
                  <td className="px-6 py-4">
                    {(() => {
                      const strategy = getScanStrategyMeta(task.scan_strategy);
                      const actualDuration = task.status === 'COMPLETED' && task.duration_seconds 
                        ? formatDuration(task.duration_seconds) 
                        : null;
                      const estimatedDuration = strategy.estimatedResults.duration;
                      const speedDisplay = actualDuration 
                        ? <span className="text-xs font-semibold text-green-600">{actualDuration}</span>
                        : task.status === 'RUNNING'
                          ? <span className="text-xs font-semibold text-blue-600">{strategy.speed}</span>
                          : <span className="text-xs text-[#64748b]">{strategy.speed}</span>;
                      return (
                        <div className="flex flex-col gap-1">
                          <span className="inline-flex w-fit rounded-md bg-orange-50 px-2.5 py-1 text-xs font-semibold text-[#c25b00]">
                            {strategy.label}
                          </span>
                          {speedDisplay}
                          {actualDuration && (
                            <div className="text-[10px] text-[#94a3b8]">
                              预计: {estimatedDuration}
                            </div>
                          )}
                        </div>
                      );
                    })()}
                  </td>
                  <td className="px-6 py-4">{getStatusBadge(task.status)}</td>
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3 w-40">
                      <div className="flex-1 h-1.5 bg-[#e2e8f0] rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-[#ff6b00] transition-all duration-500" 
                          style={{ width: `${task.progress || (task.status === 'COMPLETED' ? 100 : 0)}%` }}
                        ></div>
                      </div>
                      <span className="text-xs font-semibold text-[#64748b]">{task.progress || (task.status === 'COMPLETED' ? 100 : 0)}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-[#64748b] text-xs">{formatDateTime(task.created_at)}</td>
                  <td className="px-6 py-4 text-right">
                    <div className="flex justify-end gap-2">
                      {(task.status === 'RUNNING' || task.status === 'COMPLETED') && onViewExecution && (
                        <button
                          onClick={() => onViewExecution(task.id)}
                          className="p-1.5 text-[#2563eb] hover:bg-blue-50 rounded-md transition-colors"
                          title="查看执行"
                        >
                          <Activity size={18} />
                        </button>
                      )}
                      {task.status === 'RUNNING' && (
                        <button 
                          onClick={() => handleStopTask(task.id)}
                          className="p-1.5 text-red-500 hover:bg-red-50 rounded-md transition-colors"
                          title="停止任务"
                        >
                          <StopSquare size={18} />
                        </button>
                      )}
                      {task.status === 'COMPLETED' && (
                        <button 
                          onClick={() => onViewReport && onViewReport(task.id)}
                          className="p-1.5 text-[#ff6b00] hover:bg-orange-50 rounded-md transition-colors" 
                          title="查看报告"
                        >
                          <Eye size={18} />
                        </button>
                      )}
                      <button 
                        onClick={() => handleDeleteTask(task)}
                        className="p-1.5 text-[#94a3b8] hover:text-red-500 hover:bg-red-50 rounded-md transition-colors"
                        title="删除任务"
                      >
                        <Trash2 size={18} strokeWidth={1.5} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center items-center gap-4 mt-4">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronLeft size={18} />
          </button>
          <span className="text-sm text-gray-600">
            第 {page} / {totalPages} 页，共 {total} 条
          </span>
          <button
            onClick={() => setPage(p => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <ChevronRight size={18} />
          </button>
        </div>
      )}
    </div>
  );
};

export default TaskList;
