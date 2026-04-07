import React, { useState } from 'react';
import { api } from '../api';
import { SCAN_STRATEGY_OPTIONS, getScanStrategyMeta } from '../utils/scanStrategy';
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
  const activeStrategy = getScanStrategyMeta(scanStrategy);

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
    } catch {
      alert('创建扫描任务失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="bg-white rounded-3xl shadow-2xl w-full max-w-2xl p-8 animate-in fade-in zoom-in duration-300">
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
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
            <div className="flex flex-col gap-6">
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
                  {SCAN_STRATEGY_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-gray-400">
                  任务将优先输出攻击载荷、攻击路径和可利用性证明。
                </p>
              </div>

              {/* 动态属性条 */}
              <div className="rounded-2xl border border-gray-100 bg-gradient-to-br from-gray-50 to-white p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-[#2d3343]">模式特性对比</h4>
                  <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold transition-colors duration-300 ${
                    activeStrategy.riskLevel === 'high' ? 'bg-red-100 text-red-600' :
                    activeStrategy.riskLevel === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                    'bg-green-100 text-green-600'
                  }`}>
                    <span className={`w-1.5 h-1.5 rounded-full animate-pulse ${
                      activeStrategy.riskLevel === 'high' ? 'bg-red-500' :
                      activeStrategy.riskLevel === 'medium' ? 'bg-yellow-500' :
                      'bg-green-500'
                    }`} />
                    {activeStrategy.riskLabel}
                  </span>
                </div>

                {[
                  { label: '覆盖范围', key: 'coverage' as const, color: '#ff6b00' },
                  { label: '执行效率', key: 'speed' as const, color: '#10b981' },
                  { label: '验证深度', key: 'depth' as const, color: '#3b82f6' },
                  { label: '资源消耗', key: 'resourceUsage' as const, color: '#8b5cf6' },
                ].map((attr) => (
                  <div key={attr.key} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium text-gray-600">{attr.label}</span>
                      <span className="font-bold text-[#2d3343]">{activeStrategy.attributeScores[attr.key]}%</span>
                    </div>
                    <div className="relative h-2 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className="absolute top-0 left-0 h-full rounded-full transition-all duration-500 ease-out"
                        style={{
                          width: `${activeStrategy.attributeScores[attr.key]}%`,
                          backgroundColor: attr.color,
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>

              {/* 预期结果预估 */}
              <div className="rounded-2xl border border-orange-100 bg-gradient-to-br from-[#fff9f4] to-white p-5">
                <div className="flex items-center gap-2 mb-4">
                  <svg className="w-5 h-5 text-[#ff6b00]" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <h4 className="text-sm font-bold text-[#2d3343]">预期验证结果</h4>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  {[
                    { icon: '🎯', label: '预计漏洞', value: activeStrategy.estimatedResults.vulns },
                    { icon: '⏱️', label: '执行时间', value: activeStrategy.estimatedResults.duration },
                    { icon: '💣', label: '攻击载荷', value: activeStrategy.estimatedResults.payloads },
                    { icon: '🔗', label: '攻击路径', value: activeStrategy.estimatedResults.attackPaths },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="rounded-xl bg-white border border-gray-100 px-4 py-3 transition-all duration-300 hover:shadow-md hover:border-orange-200"
                    >
                      <div className="flex items-center gap-2 text-xs text-gray-400 mb-1">
                        <span>{item.icon}</span>
                        <span>{item.label}</span>
                      </div>
                      <div className="text-base font-bold text-[#2d3343] transition-all duration-300">
                        {item.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* 风险提示卡片 */}
              <div className={`rounded-2xl border p-4 transition-all duration-300 ${
                activeStrategy.riskLevel === 'high' ? 'border-red-200 bg-red-50' :
                activeStrategy.riskLevel === 'medium' ? 'border-yellow-200 bg-yellow-50' :
                'border-green-200 bg-green-50'
              }`}>
                <div className="flex items-start gap-3">
                  <div className={`mt-0.5 w-8 h-8 rounded-full flex items-center justify-center text-lg ${
                    activeStrategy.riskLevel === 'high' ? 'bg-red-100' :
                    activeStrategy.riskLevel === 'medium' ? 'bg-yellow-100' :
                    'bg-green-100'
                  }`}>
                    {activeStrategy.riskLevel === 'high' ? '⚠️' :
                     activeStrategy.riskLevel === 'medium' ? '⚡' : '✅'}
                  </div>
                  <div className="flex-1">
                    <div className={`text-sm font-bold mb-1 ${
                      activeStrategy.riskLevel === 'high' ? 'text-red-700' :
                      activeStrategy.riskLevel === 'medium' ? 'text-yellow-800' :
                      'text-green-700'
                    }`}>
                      {activeStrategy.riskLabel}模式
                    </div>
                    <p className={`text-xs leading-relaxed ${
                      activeStrategy.riskLevel === 'high' ? 'text-red-600/80' :
                      activeStrategy.riskLevel === 'medium' ? 'text-yellow-700/80' :
                      'text-green-600/80'
                    }`}>
                      {activeStrategy.riskDescription}
                    </p>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-3xl border border-[#ffd7b8] bg-gradient-to-br from-[#fff7f1] to-white p-5">
              <div className="inline-flex rounded-full bg-[#ffecd9] px-3 py-1 text-xs font-bold text-[#c25b00]">
                当前模式
              </div>
              <h4 className="mt-4 text-lg font-bold text-[#2d3343]">{activeStrategy.label}</h4>
              <p className="mt-2 text-sm leading-6 text-gray-600">{activeStrategy.summary}</p>

              <div className="mt-5 space-y-3">
                {SCAN_STRATEGY_OPTIONS.map((option) => {
                  const selected = option.value === scanStrategy;
                  return (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => setScanStrategy(option.value)}
                      className={`w-full rounded-2xl border px-4 py-3 text-left transition-all ${
                        selected
                          ? 'border-[#ffb781] bg-[#fff1e4] shadow-sm'
                          : 'border-gray-100 bg-white hover:border-[#ffd0aa] hover:bg-[#fff8f2]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-bold text-[#2d3343]">{option.label}</span>
                        <span className={`rounded-full px-2.5 py-0.5 text-[11px] font-semibold transition-colors duration-300 ${
                          option.riskLevel === 'high' ? 'bg-red-100 text-red-600' :
                          option.riskLevel === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                          'bg-green-100 text-green-600'
                        }`}>
                          {option.riskLabel}
                        </span>
                      </div>
                      <p className="mt-2 text-xs leading-5 text-gray-500">{option.useCase}</p>
                      <div className="mt-2 flex items-center gap-3 text-[11px] text-gray-400">
                        <span>📊 {option.scope}</span>
                        <span>⏱️ {option.speed}</span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* 快速对比提示 */}
              <div className="mt-5 rounded-xl bg-gray-50 p-4 border border-gray-100">
                <h5 className="text-xs font-bold text-gray-500 mb-3">模式快速对比</h5>
                <div className="space-y-2 text-xs">
                  {[
                    { mode: '模拟攻击验证', desc: '日常首选，平衡之选', emoji: '⚖️' },
                    { mode: '全量攻击验证', desc: '全面审计，深度保障', emoji: '🔍' },
                    { mode: '定向漏洞验证', desc: '精准打击，快速响应', emoji: '🎯' },
                  ].map((item) => (
                    <div key={item.mode} className="flex items-center gap-2 text-gray-600">
                      <span>{item.emoji}</span>
                      <span className="font-medium">{item.mode}</span>
                      <span className="text-gray-400">·</span>
                      <span>{item.desc}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
          <div className="rounded-2xl border border-gray-100 bg-gray-50 px-4 py-3 text-sm text-gray-600">
            <span className="font-bold text-[#2d3343]">模式说明：</span>
            {activeStrategy.disclaimer}
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-4 bg-[#ff6b00] text-white rounded-xl font-bold shadow-lg shadow-orange-500/20 hover:bg-[#e66000] transition-all disabled:opacity-50"
          >
            {loading ? '正在启动验证...' : `立即开始${activeStrategy.label}`}
          </button>
        </form>
      </div>
    </div>
  );
};

export default NewScanModal;
