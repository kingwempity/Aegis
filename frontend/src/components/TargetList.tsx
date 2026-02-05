import React, { useEffect, useState } from 'react';
import { api, Target } from '../api';

const TargetList: React.FC = () => {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
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
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">目标管理</h2>
        <button className="btn-new-scan">
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          添加目标
        </button>
      </div>

      {loading ? (
        <div className="text-center py-12 text-gray-400">加载中...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {targets.map((target) => (
            <div key={target.id} className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4 hover:shadow-lg hover:-translate-y-1 transition-all">
              <div className="flex justify-between items-start">
                <span className="font-bold text-lg text-[#2d3343]">{target.url}</span>
                <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${target.is_active ? 'bg-green-100 text-green-600' : 'bg-gray-100 text-gray-500'}`}>
                  {target.is_active ? 'ACTIVE' : 'INACTIVE'}
                </span>
              </div>
              <div className="text-xs text-gray-400">上次扫描: {new Date(target.last_scanned).toLocaleString()}</div>
              <div className="flex justify-between items-center text-sm mt-4 pt-4 border-t border-gray-100">
                <div className="flex flex-col items-center">
                  <span className="font-bold text-red-500">{target.critical_vulns}</span>
                  <span className="text-xs text-gray-400">高危</span>
                </div>
                <div className="flex flex-col items-center">
                  <span className="font-bold text-orange-500">{target.high_vulns}</span>
                  <span className="text-xs text-gray-400">中危</span>
                </div>
                <div className="flex flex-col items-center">
                  <span className="font-bold text-blue-500">{target.low_vulns}</span>
                  <span className="text-xs text-gray-400">低危</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default TargetList;
