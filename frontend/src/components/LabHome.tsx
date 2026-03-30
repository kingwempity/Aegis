/**
 * LabHome - 漏洞实验室首页
 * 
 * 展示漏洞场景列表，支持按类型和难度筛选。
 */

import React, { useState, useEffect } from 'react';
import { api } from '../api';

// 漏洞类型映射
const VULN_TYPE_NAMES: Record<string, string> = {
  SQLI: 'SQL注入',
  XSS_REFLECTED: '反射型XSS',
  XSS_STORED: '存储型XSS',
  CMD_INJECTION: '命令注入',
  LFI: '本地文件包含',
  RFI: '远程文件包含',
  SSRF: '服务端请求伪造',
  XXE: 'XXE注入',
  PATH_TRAVERSAL: '路径穿越',
  INFO_DISCLOSURE: '信息泄露',
  OPEN_REDIRECT: '开放重定向',
  CSRF: 'CSRF',
};

// 难度颜色映射
const DIFFICULTY_COLORS: Record<string, string> = {
  easy: 'bg-green-500/20 text-green-400 border-green-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  hard: 'bg-red-500/20 text-red-400 border-red-500/30',
};

// 难度中文名
const DIFFICULTY_NAMES: Record<string, string> = {
  easy: '初级',
  medium: '中级',
  hard: '高级',
};

// 漏洞类型颜色
const VULN_TYPE_COLORS: Record<string, string> = {
  SQLI: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  XSS_REFLECTED: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  XSS_STORED: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  CMD_INJECTION: 'bg-red-500/20 text-red-400 border-red-500/30',
  LFI: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  RFI: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  SSRF: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
  XXE: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
  PATH_TRAVERSAL: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
  INFO_DISCLOSURE: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  OPEN_REDIRECT: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30',
  CSRF: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
};

interface AttackStep {
  step: number;
  title: string;
  description?: string;
  request?: Record<string, unknown>;
  response?: Record<string, unknown>;
  payload?: string;
  payload_explanation?: string;
  result?: string;
}

interface Remediation {
  title: string;
  description?: string;
  code?: string;
  language?: string;
}

interface Learning {
  principle?: string;
  cwe?: string;
  owasp?: string;
  impact?: string;
  references?: string[];
}

interface LabScenario {
  id: number;
  name: string;
  vuln_type: string;
  difficulty: string;
  description?: string;
  attack_steps: AttackStep[];
  remediation: Remediation[];
  learning: Learning;
  tags: string[];
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

interface LabScenarioListResponse {
  items: LabScenario[];
  total: number;
}

interface VulnTypeInfo {
  code: string;
  name: string;
  count: number;
}

const LabHome: React.FC = () => {
  const [scenarios, setScenarios] = useState<LabScenario[]>([]);
  const [vulnTypes, setVulnTypes] = useState<VulnTypeInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [selectedDifficulty, setSelectedDifficulty] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScenario, setSelectedScenario] = useState<LabScenario | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [activeTab, setActiveTab] = useState<'attack' | 'remediation' | 'learning'>('attack');

  // 加载场景列表
  const loadScenarios = async () => {
    setLoading(true);
    try {
      const response = await api.getLabScenarios({
        vuln_type: selectedType || undefined,
        difficulty: selectedDifficulty || undefined,
        search: searchQuery || undefined,
      });
      setScenarios(response.items);
    } catch (error) {
      console.error('加载场景失败:', error);
    } finally {
      setLoading(false);
    }
  };

  // 加载漏洞类型
  const loadVulnTypes = async () => {
    try {
      const response = await api.getLabVulnTypes();
      setVulnTypes(response);
    } catch (error) {
      console.error('加载漏洞类型失败:', error);
    }
  };

  useEffect(() => {
    loadVulnTypes();
  }, []);

  useEffect(() => {
    loadScenarios();
  }, [selectedType, selectedDifficulty, searchQuery]);

  // 重置筛选
  const handleResetFilters = () => {
    setSelectedType(null);
    setSelectedDifficulty(null);
    setSearchQuery('');
  };

  // 返回列表
  const handleBackToList = () => {
    setSelectedScenario(null);
    setCurrentStep(0);
    setActiveTab('attack');
  };

  // 场景列表视图
  if (selectedScenario) {
    return (
      <div className="p-6">
        {/* 头部 */}
        <div className="mb-6">
          <button
            onClick={handleBackToList}
            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors mb-4"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            返回场景列表
          </button>

          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-2xl font-bold text-white mb-2">{selectedScenario.name}</h1>
              <div className="flex items-center gap-3">
                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${VULN_TYPE_COLORS[selectedScenario.vuln_type] || 'bg-gray-500/20 text-gray-400'}`}>
                  {VULN_TYPE_NAMES[selectedScenario.vuln_type] || selectedScenario.vuln_type}
                </span>
                <span className={`px-3 py-1 rounded-full text-xs font-medium border ${DIFFICULTY_COLORS[selectedScenario.difficulty] || 'bg-gray-500/20 text-gray-400'}`}>
                  {DIFFICULTY_NAMES[selectedScenario.difficulty] || selectedScenario.difficulty}
                </span>
              </div>
            </div>
          </div>

          {selectedScenario.description && (
            <p className="text-gray-400 mt-4">{selectedScenario.description}</p>
          )}
        </div>

        {/* Tab 切换 */}
        <div className="flex gap-1 mb-6 bg-[#1e2235] rounded-lg p-1">
          <button
            onClick={() => setActiveTab('attack')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'attack'
                ? 'bg-[#ff6b00] text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            🎬 攻击演示
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'remediation'
                ? 'bg-[#ff6b00] text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            🔧 修复方案
          </button>
          <button
            onClick={() => setActiveTab('learning')}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'learning'
                ? 'bg-[#ff6b00] text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            📖 原理讲解
          </button>
        </div>

        {/* 攻击演示 Tab */}
        {activeTab === 'attack' && (
          <div className="bg-[#1e2235] rounded-lg p-6">
            {selectedScenario.attack_steps && selectedScenario.attack_steps.length > 0 ? (
              <>
                {/* 步骤导航 */}
                <div className="flex items-center gap-2 mb-6 overflow-x-auto pb-2">
                  {selectedScenario.attack_steps.map((step, index) => (
                    <button
                      key={index}
                      onClick={() => setCurrentStep(index)}
                      className={`flex-shrink-0 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                        currentStep === index
                          ? 'bg-[#ff6b00] text-white'
                          : 'bg-[#252a3d] text-gray-400 hover:text-white'
                      }`}
                    >
                      Step {step.step}: {step.title}
                    </button>
                  ))}
                </div>

                {/* 当前步骤内容 */}
                {(() => {
                  const step = selectedScenario.attack_steps[currentStep];
                  return (
                    <div className="space-y-6">
                      {/* 步骤描述 */}
                      {step.description && (
                        <div className="bg-[#252a3d] rounded-lg p-4">
                          <h3 className="text-sm font-medium text-gray-400 mb-2">步骤说明</h3>
                          <p className="text-white">{step.description}</p>
                        </div>
                      )}

                      {/* HTTP 请求 */}
                      {step.request && (
                        <div className="bg-[#252a3d] rounded-lg p-4">
                          <h3 className="text-sm font-medium text-gray-400 mb-2">📡 HTTP 请求</h3>
                          <pre className="text-sm text-green-400 overflow-x-auto whitespace-pre-wrap">
                            {typeof step.request === 'object'
                              ? JSON.stringify(step.request, null, 2)
                              : String(step.request)}
                          </pre>
                        </div>
                      )}

                      {/* Payload */}
                      {step.payload && (
                        <div className="bg-[#252a3d] rounded-lg p-4 border border-red-500/30">
                          <h3 className="text-sm font-medium text-red-400 mb-2">💥 恶意 Payload</h3>
                          <code className="text-sm text-red-300 block bg-[#1a1d2e] p-3 rounded overflow-x-auto">
                            {step.payload}
                          </code>
                          {step.payload_explanation && (
                            <p className="text-sm text-gray-400 mt-3">{step.payload_explanation}</p>
                          )}
                        </div>
                      )}

                      {/* HTTP 响应 */}
                      {step.response && (
                        <div className="bg-[#252a3d] rounded-lg p-4">
                          <h3 className="text-sm font-medium text-gray-400 mb-2">📥 HTTP 响应</h3>
                          <pre className="text-sm text-blue-400 overflow-x-auto whitespace-pre-wrap">
                            {typeof step.response === 'object'
                              ? JSON.stringify(step.response, null, 2)
                              : String(step.response)}
                          </pre>
                        </div>
                      )}

                      {/* 执行结果 */}
                      {step.result && (
                        <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                          <h3 className="text-sm font-medium text-green-400 mb-2">✅ 攻击结果</h3>
                          <p className="text-green-300">{step.result}</p>
                        </div>
                      )}

                      {/* 导航按钮 */}
                      <div className="flex justify-between pt-4">
                        <button
                          onClick={() => setCurrentStep(Math.max(0, currentStep - 1))}
                          disabled={currentStep === 0}
                          className="px-4 py-2 bg-[#252a3d] text-gray-400 rounded-lg hover:bg-[#2d3348] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          ← 上一步
                        </button>
                        <button
                          onClick={() => setCurrentStep(Math.min(selectedScenario.attack_steps.length - 1, currentStep + 1))}
                          disabled={currentStep === selectedScenario.attack_steps.length - 1}
                          className="px-4 py-2 bg-[#ff6b00] text-white rounded-lg hover:bg-[#e65c00] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          下一步 →
                        </button>
                      </div>
                    </div>
                  );
                })()}
              </>
            ) : (
              <div className="text-center py-12 text-gray-500">
                暂无攻击演示数据
              </div>
            )}
          </div>
        )}

        {/* 修复方案 Tab */}
        {activeTab === 'remediation' && (
          <div className="space-y-4">
            {selectedScenario.remediation && selectedScenario.remediation.length > 0 ? (
              selectedScenario.remediation.map((item, index) => (
                <div key={index} className="bg-[#1e2235] rounded-lg p-6">
                  <h3 className="text-lg font-medium text-white mb-3">{item.title}</h3>
                  {item.description && (
                    <p className="text-gray-400 mb-4">{item.description}</p>
                  )}
                  {item.code && (
                    <pre className="bg-[#252a3d] rounded-lg p-4 overflow-x-auto">
                      <code className="text-sm text-green-400">{item.code}</code>
                    </pre>
                  )}
                </div>
              ))
            ) : (
              <div className="bg-[#1e2235] rounded-lg p-12 text-center text-gray-500">
                暂无修复方案
              </div>
            )}
          </div>
        )}

        {/* 原理讲解 Tab */}
        {activeTab === 'learning' && (
          <div className="bg-[#1e2235] rounded-lg p-6">
            {selectedScenario.learning ? (
              <div className="space-y-6">
                {/* 漏洞原理 */}
                {selectedScenario.learning.principle && (
                  <div>
                    <h3 className="text-lg font-medium text-white mb-3">🔍 漏洞原理</h3>
                    <p className="text-gray-300 whitespace-pre-wrap">{selectedScenario.learning.principle}</p>
                  </div>
                )}

                {/* CWE/OWASP 分类 */}
                <div className="flex gap-4">
                  {selectedScenario.learning.cwe && (
                    <div className="bg-[#252a3d] rounded-lg px-4 py-3">
                      <span className="text-gray-500 text-sm">CWE: </span>
                      <span className="text-blue-400 font-mono">{selectedScenario.learning.cwe}</span>
                    </div>
                  )}
                  {selectedScenario.learning.owasp && (
                    <div className="bg-[#252a3d] rounded-lg px-4 py-3">
                      <span className="text-gray-500 text-sm">OWASP: </span>
                      <span className="text-orange-400 font-mono">{selectedScenario.learning.owasp}</span>
                    </div>
                  )}
                </div>

                {/* 影响 */}
                {selectedScenario.learning.impact && (
                  <div>
                    <h3 className="text-lg font-medium text-white mb-3">⚠️ 安全影响</h3>
                    <p className="text-gray-300">{selectedScenario.learning.impact}</p>
                  </div>
                )}

                {/* 参考资料 */}
                {selectedScenario.learning.references && selectedScenario.learning.references.length > 0 && (
                  <div>
                    <h3 className="text-lg font-medium text-white mb-3">📚 参考资料</h3>
                    <ul className="space-y-2">
                      {selectedScenario.learning.references.map((ref, index) => (
                        <li key={index}>
                          <a
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                          >
                            {ref}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="text-center py-12 text-gray-500">
                暂无学习资料
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  // 场景列表视图
  return (
    <div className="p-6">
      {/* 标题 */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <span className="text-3xl">🧪</span>
          漏洞实验室
        </h1>
        <p className="text-gray-400 mt-2">
          通过模拟攻击过程，深入了解各类Web漏洞的原理、利用方式和修复方法
        </p>
      </div>

      {/* 筛选区域 */}
      <div className="bg-[#1e2235] rounded-lg p-4 mb-6">
        <div className="flex flex-wrap items-center gap-4">
          {/* 搜索框 */}
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="搜索场景名称或描述..."
              className="w-full bg-[#252a3d] border border-gray-700 rounded-lg px-4 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-[#ff6b00]"
            />
          </div>

          {/* 漏洞类型筛选 */}
          <select
            value={selectedType || ''}
            onChange={(e) => setSelectedType(e.target.value || null)}
            className="bg-[#252a3d] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#ff6b00]"
          >
            <option value="">所有漏洞类型</option>
            {vulnTypes.map((type) => (
              <option key={type.code} value={type.code}>
                {type.name} ({type.count})
              </option>
            ))}
          </select>

          {/* 难度筛选 */}
          <select
            value={selectedDifficulty || ''}
            onChange={(e) => setSelectedDifficulty(e.target.value || null)}
            className="bg-[#252a3d] border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#ff6b00]"
          >
            <option value="">所有难度</option>
            <option value="easy">初级</option>
            <option value="medium">中级</option>
            <option value="hard">高级</option>
          </select>

          {/* 重置按钮 */}
          {(selectedType || selectedDifficulty || searchQuery) && (
            <button
              onClick={handleResetFilters}
              className="text-gray-400 hover:text-white transition-colors"
            >
              清除筛选
            </button>
          )}
        </div>
      </div>

      {/* 场景列表 */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="w-8 h-8 border-2 border-[#ff6b00]/30 border-t-[#ff6b00] rounded-full animate-spin"></div>
        </div>
      ) : scenarios.length === 0 ? (
        <div className="bg-[#1e2235] rounded-lg p-12 text-center">
          <p className="text-gray-500">暂无漏洞场景数据</p>
          <p className="text-gray-600 text-sm mt-2">请先在数据库中添加场景数据</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((scenario) => (
            <div
              key={scenario.id}
              onClick={() => setSelectedScenario(scenario)}
              className="bg-[#1e2235] rounded-lg p-5 cursor-pointer hover:bg-[#252a3d] transition-colors border border-transparent hover:border-[#ff6b00]/30"
            >
              <div className="flex items-start justify-between mb-3">
                <h3 className="text-white font-medium">{scenario.name}</h3>
                <span className={`px-2 py-0.5 rounded text-xs font-medium border ${DIFFICULTY_COLORS[scenario.difficulty]}`}>
                  {DIFFICULTY_NAMES[scenario.difficulty]}
                </span>
              </div>
              
              <div className="mb-3">
                <span className={`px-2 py-0.5 rounded text-xs border ${VULN_TYPE_COLORS[scenario.vuln_type] || 'bg-gray-500/20 text-gray-400'}`}>
                  {VULN_TYPE_NAMES[scenario.vuln_type] || scenario.vuln_type}
                </span>
              </div>

              {scenario.description && (
                <p className="text-gray-400 text-sm line-clamp-2">{scenario.description}</p>
              )}

              <div className="flex items-center gap-2 mt-4 text-xs text-gray-500">
                <span>{scenario.attack_steps?.length || 0} 个攻击步骤</span>
                <span>•</span>
                <span>{scenario.remediation?.length || 0} 个修复方案</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default LabHome;