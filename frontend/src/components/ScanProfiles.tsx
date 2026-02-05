import React, { useEffect, useState } from 'react';
import { api, ScanProfile } from '../api';

const ScanProfiles: React.FC = () => {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.getProfiles();
        setProfiles(data);
      } catch (error) {
        console.error('Error fetching profiles:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">扫描配置</h2>
        <button className="btn-new-scan">
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          新建配置
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {loading ? (
          <div className="col-span-full text-center py-12 text-gray-400">加载中...</div>
        ) : (
          profiles.map((profile) => (
            <div key={profile.id} className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4 hover:border-[#ff6b00]/30 transition-all relative overflow-hidden group">
              {profile.is_default && (
                <div className="absolute top-0 right-0 bg-[#ff6b00] text-white text-[10px] font-bold px-3 py-1 rounded-bl-xl">
                  DEFAULT
                </div>
              )}
              <div className="flex flex-col">
                <span className="font-bold text-lg text-[#2d3343]">{profile.name}</span>
                <p className="text-sm text-gray-400 mt-1">{profile.description}</p>
              </div>
              <div className="flex gap-3 mt-4">
                <button className="flex-1 py-2 bg-gray-50 text-gray-600 rounded-lg text-xs font-bold hover:bg-gray-100 transition-all">
                  编辑配置
                </button>
                <button className="px-4 py-2 bg-gray-50 text-gray-400 rounded-lg text-xs font-bold hover:text-red-500 transition-all">
                  删除
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ScanProfiles;
