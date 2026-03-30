import React, { useEffect, useState } from 'react';
import { api, ScanTask } from '../api';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { Plus, Eye, StopSquare, Search, Trash2 } from './Icons';

interface TaskListProps {
  onCreateTask?: () => void;
  onViewReport?: (taskId: number) => void;
}

const TaskList: React.FC<TaskListProps> = ({ onCreateTask, onViewReport }) => {
  const [tasks, setTasks] = useState<ScanTask[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchTasks = async () => {
    try {
      const data = await api.getTasks();
      setTasks(data);
    } catch (error) {
      console.error('Error fetching tasks:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
    // 每 5 秒高频轮询任务状态，确保进度条实时更新
    const interval = setInterval(fetchTasks, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStopTask = async (taskId: number) => {
    try {
      await api.stopTask(taskId);
      fetchTasks();
    } catch (error) {
      alert('停止任务失败');
    }
  };

  const handleDeleteTask = async (task: ScanTask) => {
    if (!window.confirm(`确定要删除任务 #${task.id}（${task.target_url}）吗？关联的漏洞记录将一并删除。`)) return;
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

  const getStrategyLabel = (strategy?: string) => {
    switch (strategy) {
      case 'attack_validation':
        return '模拟攻击验证';
      case 'full_audit':
        return '全量攻击验证';
      case 'focused_probe':
        return '定向漏洞验证';
      case 'default':
      case 'full':
      case 'fast':
        return '基础验证式扫描';
      default:
        return strategy || '基础验证式扫描';
    }
  };

  const filteredTasks = tasks.filter(task => 
    task.target_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
    task.id.toString().includes(searchQuery)
  );

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      {/* Toolbar */}
      <div className="flex justify-between items-center">
        <div className="flex items-center gap-4 flex-1">
          <div>
            <h2 className="text-2xl font-bold text-[#2d3343]">模拟攻击验证任务</h2>
            <p className="mt-1 text-sm text-gray-400">跟踪攻击载荷验证、证据链留存与可利用性证明。</p>
          </div>
          <div className="relative flex-1 max-w-md">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-4 w-4 text-gray-400" />
            </div>
            <input
              type="text"
              placeholder="搜索目标 URL 或 任务 ID..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-10 pr-3 py-2 border border-gray-200 rounded-xl text-sm placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-[#ff6b00]/20 focus:border-[#ff6b00] transition-all"
            />
          </div>
        </div>
        <button 
          onClick={onCreateTask}
          className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center gap-2"
        >
          <Plus size={16} strokeWidth={3} />
          新建验证
        </button>
      </div>

      {/* Task Table */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">ID</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">目标 URL</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">验证模式</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">状态</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">进度</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">创建时间</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider text-right">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading && tasks.length === 0 ? (
              <tr><td colSpan={7} className="px-8 py-12 text-center text-gray-400">加载中...</td></tr>
            ) : filteredTasks.length === 0 ? (
              <tr><td colSpan={7} className="px-8 py-12 text-center text-gray-400">暂无匹配的验证任务</td></tr>
            ) : (
              filteredTasks.map((task) => (
                <tr key={task.id} className="hover:bg-gray-50/50 transition-colors">
                  <td className="px-8 py-5 text-xs font-bold text-gray-400">#{task.id}</td>
                  <td className="px-8 py-5 font-bold text-[#2d3343]">{task.target_url}</td>
                  <td className="px-8 py-5">
                    <span className="inline-flex rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-[#c25b00]">
                      {getStrategyLabel(task.scan_strategy)}
                    </span>
                  </td>
                  <td className="px-8 py-5">{getStatusBadge(task.status)}</td>
                  <td className="px-8 py-5">
                    <div className="flex items-center gap-3 w-48">
                      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-[#ff6b00] transition-all duration-500" 
                          style={{ width: `${task.progress || (task.status === 'COMPLETED' ? 100 : 0)}%` }}
                        ></div>
                      </div>
                      <span className="text-xs font-bold text-gray-400">{task.progress || (task.status === 'COMPLETED' ? 100 : 0)}%</span>
                    </div>
                  </td>
                  <td className="px-8 py-5 text-gray-400 text-xs">{new Date(task.created_at).toLocaleString()}</td>
                  <td className="px-8 py-5 text-right">
                    <div className="flex justify-end gap-2">
                      {task.status === 'RUNNING' && (
                        <button 
                          onClick={() => handleStopTask(task.id)}
                          className="p-2 text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                          title="停止任务"
                        >
                          <StopSquare size={20} />
                        </button>
                      )}
                      {task.status === 'COMPLETED' && (
                        <button 
                          onClick={() => onViewReport && onViewReport(task.id)}
                          className="p-2 text-[#ff6b00] hover:bg-orange-50 rounded-lg transition-colors" 
                          title="查看报告"
                        >
                          <Eye size={20} />
                        </button>
                      )}
                      <button 
                        onClick={() => handleDeleteTask(task)}
                        className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                        title="删除任务"
                      >
                        <Trash2 size={20} strokeWidth={2} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default TaskList;
