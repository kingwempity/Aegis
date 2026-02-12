import React, { useEffect, useState } from 'react';
import { api, Target } from '../api';
import AddTargetModal from './AddTargetModal';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { Plus } from './Icons';

const TargetList: React.FC = () => {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchData = async () => {
    try {
      const data = await api.getTargets(); 
      setTargets(data);
    } catch (error) {
      console.error('Error fetching targets:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">目标管理</h2>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center gap-2"
        >
          <Plus size={16} strokeWidth={3} />
          添加目标
        </button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-400">加载中...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {targets.length === 0 ? (
            <div className="col-span-full text-center py-12 text-gray-400 bg-white rounded-2xl border border-dashed border-gray-200">
              暂无扫描目标，请点击上方按钮添加
            </div>
          ) : (
            targets.map((target) => (
              <div key={target.id} className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4 hover:shadow-lg hover:-translate-y-1 transition-all">
                <div className="flex justify-between items-start">
                  <div className="flex flex-col gap-1">
                    <span className="font-bold text-lg text-[#2d3343]">{target.url}</span>
                    {target.description && <span className="text-xs text-gray-400">{target.description}</span>}
                  </div>
                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${target.status === 'active' || target.is_active ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-500'}`}>
                    {(target.status || (target.is_active ? 'active' : 'inactive')).toUpperCase()}
                  </span>
                </div>
                <div className="text-xs text-gray-400">
                  创建时间: {new Date(target.created_at || target.last_scanned || '').toLocaleString()}
                </div>
                <div className="flex justify-between items-center text-sm mt-4 pt-4 border-t border-gray-100">
                  <div className="flex flex-col items-center">
                    <span className="font-bold text-red-500">{target.critical_vulns || 0}</span>
                    <span className="text-xs text-gray-400">高危</span>
                  </div>
                  <div className="flex flex-col items-center">
                    <span className="font-bold text-orange-500">{target.high_vulns || 0}</span>
                    <span className="text-xs text-gray-400">中危</span>
                  </div>
                  <div className="flex flex-col items-center">
                    <span className="font-bold text-blue-500">{target.low_vulns || 0}</span>
                    <span className="text-xs text-gray-400">低危</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      <AddTargetModal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        onSuccess={fetchData}
      />
    </div>
  );
};

export default TargetList;
