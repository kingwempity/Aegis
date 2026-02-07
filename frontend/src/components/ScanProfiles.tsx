import React, { useEffect, useState } from 'react';
import { api, ScanProfile } from '../api';
import AddProfileModal from './AddProfileModal';
import { Plus, Settings2, Trash2, ShieldCheck } from 'lucide-react';

const ScanProfiles: React.FC = () => {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await api.getProfiles();
      setProfiles(data);
    } catch (error) {
      console.error('Error fetching profiles:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-8 max-w-7xl mx-auto p-4 md:p-8">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-3xl font-black text-[#2d3343] tracking-tight">扫描配置</h2>
          <p className="text-gray-400 mt-1 font-medium">管理和自定义您的漏洞扫描策略</p>
        </div>
        <button 
          onClick={() => setIsModalOpen(true)}
          className="flex items-center gap-2 px-6 py-3.5 bg-[#ff6b00] text-white rounded-2xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 active:scale-95"
        >
          <Plus size={18} strokeWidth={3} />
          新建配置
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          Array(3).fill(0).map((_, i) => (
            <div key={i} className="h-48 bg-gray-50 rounded-3xl animate-pulse border border-gray-100" />
          ))
        ) : profiles.length === 0 ? (
          <div className="col-span-full flex flex-col items-center justify-center py-20 bg-gray-50 rounded-3xl border-2 border-dashed border-gray-200">
            <div className="w-16 h-16 bg-white rounded-2xl flex items-center justify-center text-gray-300 mb-4 shadow-sm">
              <ShieldCheck size={32} />
            </div>
            <p className="text-gray-400 font-bold">暂无扫描配置</p>
            <button 
              onClick={() => setIsModalOpen(true)}
              className="mt-4 text-[#ff6b00] font-bold hover:underline"
            >
              立即创建一个
            </button>
          </div>
        ) : (
          profiles.map((profile) => (
            <div 
              key={profile.id} 
              className="bg-white rounded-3xl shadow-sm border border-gray-100 p-7 flex flex-col gap-5 hover:shadow-xl hover:shadow-gray-100 hover:border-[#ff6b00]/20 transition-all relative overflow-hidden group"
            >
              {profile.is_default && (
                <div className="absolute top-0 right-0 bg-[#ff6b00] text-white text-[10px] font-black px-4 py-1.5 rounded-bl-2xl tracking-wider">
                  DEFAULT
                </div>
              )}
              
              <div className="flex flex-col gap-2">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-orange-50 rounded-xl flex items-center justify-center text-[#ff6b00]">
                    <Settings2 size={20} />
                  </div>
                  <span className="font-bold text-xl text-[#2d3343]">{profile.name}</span>
                </div>
                <p className="text-sm text-gray-400 leading-relaxed line-clamp-2 min-h-[2.5rem]">
                  {profile.description || '暂无描述信息'}
                </p>
              </div>

              <div className="flex items-center gap-4 pt-2">
                <div className="flex flex-col">
                  <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">扫描速度</span>
                  <span className="text-xs font-bold text-[#2d3343] capitalize">{profile.speed || 'Standard'}</span>
                </div>
                <div className="w-px h-8 bg-gray-100" />
                <div className="flex flex-col">
                  <span className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">检测类型</span>
                  <span className="text-xs font-bold text-[#2d3343]">
                    {Array.isArray(profile.vuln_types) ? profile.vuln_types.length : 0} 项
                  </span>
                </div>
              </div>

              <div className="flex gap-3 mt-2">
                <button className="flex-1 py-3 bg-gray-50 text-gray-600 rounded-xl text-xs font-bold hover:bg-gray-100 transition-all flex items-center justify-center gap-2">
                  编辑配置
                </button>
                <button className="px-4 py-3 bg-gray-50 text-gray-400 rounded-xl text-xs font-bold hover:text-red-500 hover:bg-red-50 transition-all">
                  <Trash2 size={16} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      <AddProfileModal 
        isOpen={isModalOpen} 
        onClose={() => setIsModalOpen(false)} 
        onSuccess={fetchData}
      />
    </div>
  );
};

export default ScanProfiles;
