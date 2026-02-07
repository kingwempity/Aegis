import React, { useState } from 'react';
import { X, Shield, Zap, Info } from 'lucide-react';
import { api } from '../api';

interface AddProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

const VULN_TYPES = ['SQLi', 'XSS', 'CSRF', 'LFI', 'RCE', 'SSRF', 'Headers', 'SSL/TLS'];

const AddProfileModal: React.FC<AddProfileModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [speed, setSpeed] = useState('standard');
  const [selectedVulns, setSelectedVulns] = useState<string[]>(['SQLi', 'XSS']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError('请输入配置名称');
      return;
    }

    setLoading(true);
    setError('');
    try {
      await api.addProfile(name, description, speed, selectedVulns);
      onSuccess();
      onClose();
      // 重置表单
      setName('');
      setDescription('');
      setSpeed('standard');
      setSelectedVulns(['SQLi', 'XSS']);
    } catch (err) {
      setError('创建配置失败，请稍后再试');
    } finally {
      setLoading(false);
    }
  };

  const toggleVuln = (type: string) => {
    setSelectedVulns(prev => 
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-white rounded-3xl shadow-2xl w-full max-w-2xl overflow-hidden animate-in zoom-in-95 duration-200">
        <div className="flex justify-between items-center px-8 py-6 border-b border-gray-100">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-orange-50 rounded-xl flex items-center justify-center text-[#ff6b00]">
              <Shield size={24} />
            </div>
            <h3 className="text-xl font-bold text-[#2d3343]">新建扫描配置</h3>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 transition-colors">
            <X size={24} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-8 space-y-6">
          {error && (
            <div className="p-4 bg-red-50 text-red-600 rounded-xl text-sm font-medium flex items-center gap-2">
              <Info size={18} />
              {error}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-sm font-bold text-gray-500 ml-1">配置名称</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="例如: 深度 Web 扫描"
                className="w-full px-5 py-3.5 bg-gray-50 border-none rounded-2xl focus:ring-2 focus:ring-orange-500/20 transition-all text-[#2d3343] font-medium placeholder:text-gray-400"
              />
            </div>

            <div className="space-y-2">
              <label className="text-sm font-bold text-gray-500 ml-1">扫描速度</label>
              <div className="flex p-1 bg-gray-50 rounded-2xl">
                {['slow', 'standard', 'fast'].map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setSpeed(s)}
                    className={`flex-1 py-2.5 rounded-xl text-xs font-bold transition-all ${
                      speed === s 
                        ? 'bg-white text-[#ff6b00] shadow-sm' 
                        : 'text-gray-400 hover:text-gray-600'
                    }`}
                  >
                    {s === 'slow' ? '慢速' : s === 'standard' ? '标准' : '快速'}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-bold text-gray-500 ml-1">描述信息</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="简要描述此配置的用途..."
              rows={2}
              className="w-full px-5 py-3.5 bg-gray-50 border-none rounded-2xl focus:ring-2 focus:ring-orange-500/20 transition-all text-[#2d3343] font-medium placeholder:text-gray-400 resize-none"
            />
          </div>

          <div className="space-y-3">
            <label className="text-sm font-bold text-gray-500 ml-1 flex items-center gap-2">
              漏洞检测类型
              <span className="text-[10px] bg-gray-100 text-gray-400 px-2 py-0.5 rounded-full">多选</span>
            </label>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {VULN_TYPES.map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => toggleVuln(type)}
                  className={`px-4 py-3 rounded-xl text-xs font-bold border-2 transition-all flex items-center justify-center gap-2 ${
                    selectedVulns.includes(type)
                      ? 'border-[#ff6b00] bg-orange-50 text-[#ff6b00]'
                      : 'border-gray-100 bg-white text-gray-400 hover:border-gray-200'
                  }`}
                >
                  {selectedVulns.includes(type) && <Zap size={14} fill="currentColor" />}
                  {type}
                </button>
              ))}
            </div>
          </div>

          <div className="pt-4 flex gap-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-6 py-4 bg-gray-100 text-gray-600 rounded-2xl font-bold text-sm hover:bg-gray-200 transition-all"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex-[2] px-6 py-4 bg-[#ff6b00] text-white rounded-2xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 flex items-center justify-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                '创建扫描配置'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddProfileModal;
