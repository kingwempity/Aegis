import React, { useState } from 'react';
import { api } from '../api';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { X } from './Icons';

interface NewScanModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

const NewScanModal: React.FC<NewScanModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [url, setUrl] = useState('');
  const [scanStrategy, setScanStrategy] = useState('attack_validation');
  const [loading, setLoading] = useState(false);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await api.createTask({
        target_url: url,
        scan_strategy: scanStrategy,
      });
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
          <h3 className="text-xl font-bold text-[#2d3343]">新建模拟攻击验证任务</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X size={24} />
          </button>
        </div>
        <div className="mb-6 rounded-2xl border border-orange-100 bg-orange-50 px-4 py-3 text-sm text-[#7a4b22]">
          本次任务会通过无害化攻击载荷、攻击路径验证和证据链留存来确认漏洞可利用性，而不是只做静态枚举。
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
            <label className="text-sm font-bold text-gray-500">验证模式</label>
            <select
              value={scanStrategy}
              onChange={(e) => setScanStrategy(e.target.value)}
              className="px-4 py-3 bg-gray-50 border border-gray-100 rounded-xl focus:ring-2 focus:ring-[#ff6b00]/20 outline-none transition-all"
            >
              <option value="attack_validation">模拟攻击验证</option>
              <option value="full_audit">全量攻击验证</option>
              <option value="focused_probe">定向漏洞验证</option>
            </select>
            <p className="text-xs text-gray-400">
              任务将优先输出攻击载荷、攻击路径和可利用性证明。
            </p>
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-4 bg-[#ff6b00] text-white rounded-xl font-bold shadow-lg shadow-orange-500/20 hover:bg-[#e66000] transition-all disabled:opacity-50"
          >
            {loading ? '正在启动验证...' : '立即开始模拟攻击验证'}
          </button>
        </form>
      </div>
    </div>
  );
};

export default NewScanModal;
