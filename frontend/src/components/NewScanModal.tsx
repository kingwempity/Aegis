import React, { useState } from 'react';
import { api } from '../api';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

const NewScanModal: React.FC<NewScanModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.createTask(url);
      onSuccess?.();
      onClose();
    } catch (error) {
      alert('创建扫描任务失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-8 animate-in fade-in zoom-in duration-300">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-xl font-bold text-[#2d3343]">新建扫描任务</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <svg className="w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-6">
          <div className="flex flex-col gap-2">
            <label className="text-sm font-bold text-gray-500">目标 URL</label>
            <input
              type="url"
              required
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="px-4 py-3 bg-gray-50 border border-gray-100 rounded-xl focus:ring-2 focus:ring-[#ff6b00]/20 outline-none transition-all"
            />
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-sm font-bold text-gray-500">扫描策略</label>
            <select className="px-4 py-3 bg-gray-50 border border-gray-100 rounded-xl focus:ring-2 focus:ring-[#ff6b00]/20 outline-none transition-all">
              <option>全量扫描 (Default)</option>
              <option>仅 XSS 扫描</option>
              <option>仅 SQL 注入扫描</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-4 bg-[#ff6b00] text-white rounded-xl font-bold shadow-lg shadow-orange-500/20 hover:bg-[#e66000] transition-all disabled:opacity-50"
          >
            {loading ? '正在启动...' : '立即开始扫描'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default NewScanModal;
