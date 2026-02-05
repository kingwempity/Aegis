import React, { useEffect, useState } from 'react';
import { api, Asset } from '../api';

const Discovery: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.getAssets();
        setAssets(data);
      } catch (error) {
        console.error('Error fetching assets:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">资产发现</h2>
        <button className="btn-new-scan">
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
            <circle cx="11" cy="11" r="8" />
            <path d="m21 21-4.35-4.35" />
          </svg>
          重新扫描网络
        </button>
      </div>

      <div className="bg-white rounded-2xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">IP 地址</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">主机名</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">开放端口</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">服务</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">最后在线</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading ? (
              <tr><td colSpan={5} className="px-8 py-12 text-center text-gray-400">加载中...</td></tr>
            ) : assets.length === 0 ? (
              <tr><td colSpan={5} className="px-8 py-12 text-center text-gray-400">未发现资产</td></tr>
            ) : (
              assets.map((asset) => (
                <tr key={asset.id} className="hover:bg-gray-50/50 transition-colors">
                  <td className="px-8 py-5 font-bold text-[#2d3343]">{asset.ip}</td>
                  <td className="px-8 py-5 text-gray-600">{asset.hostname}</td>
                  <td className="px-8 py-5">
                    <div className="flex flex-wrap gap-1">
                      {asset.ports.map(port => (
                        <span key={port} className="px-2 py-0.5 bg-blue-50 text-blue-600 rounded text-[10px] font-bold">{port}</span>
                      ))}
                    </div>
                  </td>
                  <td className="px-8 py-5 text-gray-500 text-sm">{asset.services.join(', ')}</td>
                  <td className="px-8 py-5 text-gray-400 text-xs">{new Date(asset.last_seen).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Discovery;
