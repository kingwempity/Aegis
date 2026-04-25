import React, { useState } from 'react';
import type { AttackStep, AttackStepArtifact, AttackStepEvidence } from '../api';
import { ChevronDown, ChevronRight, CheckCircle, XCircle, Clock, Zap, Target, Code, FileText, AlertTriangle } from './Icons';

interface AttackStageCardProps {
  step: AttackStep;
  index: number;
  isLast: boolean;
  isExpanded: boolean;
  onToggle: () => void;
}

const getMethodColor = (method?: string): string => {
  if (!method) return 'bg-gray-100 text-gray-600';
  const m = method.toUpperCase();
  switch (m) {
    case 'GET': return 'bg-emerald-100 text-emerald-700';
    case 'POST': return 'bg-blue-100 text-blue-700';
    case 'PUT': return 'bg-amber-100 text-amber-700';
    case 'DELETE': return 'bg-red-100 text-red-700';
    case 'PATCH': return 'bg-purple-100 text-purple-700';
    default: return 'bg-gray-100 text-gray-600';
  }
};

const getStatusIcon = (success?: boolean, status?: string) => {
  if (status === 'validated' || success === true) {
    return <CheckCircle size={16} className="text-emerald-500" />;
  }
  if (status === 'failed' || success === false) {
    return <XCircle size={16} className="text-red-500" />;
  }
  return <Clock size={16} className="text-amber-500" />;
};

const formatDuration = (ms?: number): string => {
  if (!ms) return '';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${(ms / 60000).toFixed(2)}min`;
};

const safeConditionText = (condition: unknown): string => {
  if (typeof condition === 'string') return condition;
  if (typeof condition === 'number' || typeof condition === 'boolean') return String(condition);
  if (condition && typeof condition === 'object') {
    const obj = condition as Record<string, unknown>;
    const mType = obj.type || 'unknown';
    if (mType === 'word' && Array.isArray(obj.words)) return `关键词匹配: ${obj.words.slice(0, 5).join(', ')}`;
    if (mType === 'regex' && obj.regex) return `正则匹配: ${String(obj.regex).substring(0, 80)}`;
    if (mType === 'status' && Array.isArray(obj.status)) return `状态码匹配: ${obj.status.join(', ')}`;
    if (mType === 'binary') return '二进制模式匹配';
    if (mType === 'dsl' && Array.isArray(obj.dsl)) return `DSL表达式: ${obj.dsl.slice(0, 3).join(', ')}`;
    try { return JSON.stringify(condition); } catch { return `匹配器(${mType})`; }
  }
  return String(condition ?? '');
};

const RequestResponseViewer: React.FC<{
  evidence?: AttackStepEvidence;
  request?: AttackStep['request'];
  response?: AttackStep['response'];
  payload?: string;
}> = ({ evidence, request, response, payload }) => {
  const [activeTab, setActiveTab] = useState<'request' | 'response' | 'evidence'>('request');

  const req = evidence?.request || request;
  const resp = evidence?.response || response;

  const hasRequest = req && (req.url || req.body || req.headers);
  const hasResponse = resp && (resp.status_code || resp.body || resp.headers);
  const hasEvidence = evidence && (
    (evidence.matched_conditions && evidence.matched_conditions.length > 0) ||
    (evidence.matched_patterns && evidence.matched_patterns.length > 0) ||
    evidence.vulnerability_confirmed !== undefined ||
    evidence.timing_ms !== undefined ||
    (evidence.request || evidence.response)
  );

  const evidenceTabContent = () => {
    if (!evidence) {
      return (
        <div className="text-sm text-gray-400 text-center py-4">无证据数据</div>
      );
    }

    const hasMatchedConditions = evidence.matched_conditions && evidence.matched_conditions.length > 0;
    const hasMatchedPatterns = evidence.matched_patterns && evidence.matched_patterns.length > 0;

    if (!hasMatchedConditions && !hasMatchedPatterns && !evidence.vulnerability_confirmed && !evidence.timing_ms) {
      return (
        <div className="space-y-3">
          <div className="text-xs text-gray-500">证据信息</div>
          <div className="bg-gray-50 px-3 py-2 rounded-lg">
            <div className="text-xs text-gray-600">
              {evidence.vulnerability_confirmed !== undefined ? (
                <span>漏洞确认: {evidence.vulnerability_confirmed ? '是' : '否'}</span>
              ) : evidence.timing_ms ? (
                <span>耗时: {formatDuration(evidence.timing_ms)}</span>
              ) : (
                <span className="text-gray-400">暂无详细证据信息</span>
              )}
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {hasMatchedConditions && (
          <>
            <div className="text-xs font-semibold text-gray-500 uppercase">匹配条件</div>
            <div className="space-y-2">
              {evidence.matched_conditions?.map((condition, idx) => (
                <div key={idx} className="flex items-start gap-2 bg-amber-50 px-3 py-2 rounded-lg">
                  <CheckCircle size={14} className="text-amber-500 mt-0.5 shrink-0" />
                  <span className="text-xs text-gray-700">{safeConditionText(condition)}</span>
                </div>
              ))}
            </div>
          </>
        )}

        {hasMatchedPatterns && (
          <>
            <div className="text-xs font-semibold text-gray-500 uppercase mt-4">匹配模式</div>
            <div className="space-y-2">
              {evidence.matched_patterns?.map((pattern, idx) => (
                <div key={idx} className="bg-white px-3 py-2 rounded-lg border border-gray-200">
                  <div className="text-xs font-mono text-purple-600">{pattern?.pattern ?? ''}</div>
                  <div className="text-xs text-gray-500 mt-1">类型: {pattern?.match_type ?? '未知'}</div>
                  {pattern?.matched_text && (
                    <pre className="text-xs bg-gray-50 p-2 rounded mt-2 overflow-x-auto">
                      {pattern?.matched_text}
                    </pre>
                  )}
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    );
  };

  return (
    <div className="mt-4 rounded-xl border border-gray-200 bg-gray-50 overflow-hidden">
      <div className="flex border-b border-gray-200 bg-white">
        <button
          onClick={() => setActiveTab('request')}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'request'
              ? 'text-[#ff6b00] border-b-2 border-[#ff6b00] bg-gray-50'
              : 'text-gray-500 hover:text-gray-700'
          }`}
        >
          <span className="flex items-center gap-1.5">
            <Code size={14} />
            请求
          </span>
        </button>
        <button
          onClick={() => setActiveTab('response')}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'response'
              ? 'text-[#ff6b00] border-b-2 border-[#ff6b00] bg-gray-50'
              : 'text-gray-500 hover:text-gray-700'
          }`}
        >
          <span className="flex items-center gap-1.5">
            <FileText size={14} />
            响应
          </span>
        </button>
        {hasEvidence && (
          <button
            onClick={() => setActiveTab('evidence')}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === 'evidence'
                ? 'text-[#ff6b00] border-b-2 border-[#ff6b00] bg-gray-50'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            <span className="flex items-center gap-1.5">
              <AlertTriangle size={14} />
              证据
            </span>
          </button>
        )}
      </div>

      <div className="p-4 max-h-80 overflow-auto">
        {activeTab === 'request' && (
          <div className="space-y-3">
            {req ? (
              <>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${getMethodColor(req.method)}`}>
                    {req.method || 'GET'}
                  </span>
                  <code className="text-xs text-gray-600 break-all flex-1">{req.url || ''}</code>
                </div>
                {req.headers && Object.keys(req.headers).length > 0 && (
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase">Headers</div>
                    <pre className="text-xs bg-white p-2 rounded border border-gray-200 overflow-x-auto">
                      {Object.entries(req.headers).map(([k, v]) => (
                        <div key={k} className="text-gray-600">
                          <span className="text-emerald-600">{k}</span>: {v}
                        </div>
                      ))}
                    </pre>
                  </div>
                )}
                {(req.body || payload) && (
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase">Body</div>
                    <pre className="text-xs bg-white p-2 rounded border border-gray-200 overflow-x-auto whitespace-pre-wrap break-all">
                      {req.body || payload}
                    </pre>
                  </div>
                )}
                {evidence?.timing_ms && (
                  <div className="text-xs text-gray-400">
                    耗时: {formatDuration(evidence.timing_ms)}
                  </div>
                )}
              </>
            ) : (
              <div className="text-sm text-gray-400 text-center py-4">无请求数据</div>
            )}
          </div>
        )}

        {activeTab === 'response' && (
          <div className="space-y-3">
            {resp ? (
              <>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                    resp.status_code && resp.status_code < 300
                      ? 'bg-emerald-100 text-emerald-700'
                      : resp.status_code && resp.status_code < 400
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-red-100 text-red-700'
                  }`}>
                    {resp.status_code || 'N/A'}
                  </span>
                  <span className="text-xs text-gray-500">{resp.status_text || ''}</span>
                </div>
                {resp.headers && Object.keys(resp.headers).length > 0 && (
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase">Headers</div>
                    <pre className="text-xs bg-white p-2 rounded border border-gray-200 overflow-x-auto">
                      {Object.entries(resp.headers).map(([k, v]) => (
                        <div key={k} className="text-gray-600">
                          <span className="text-blue-600">{k}</span>: {v}
                        </div>
                      ))}
                    </pre>
                  </div>
                )}
                {(resp.body || resp.body_snippet) && (
                  <div className="space-y-1">
                    <div className="text-xs font-semibold text-gray-500 uppercase">Body</div>
                    <pre className="text-xs bg-white p-2 rounded border border-gray-200 overflow-x-auto whitespace-pre-wrap break-all max-h-48">
                      {resp.body || resp.body_snippet}
                    </pre>
                  </div>
                )}
              </>
            ) : (
              <div className="text-sm text-gray-400 text-center py-4">无响应数据</div>
            )}
          </div>
        )}

        {activeTab === 'evidence' && hasEvidence && evidenceTabContent()}
      </div>
    </div>
  );
};

const ArtifactBadge: React.FC<{ artifact: AttackStepArtifact }> = ({ artifact }) => {
  const getArtifactColor = (type?: string): string => {
    switch (type) {
      case 'credential': return 'bg-red-100 text-red-700 border-red-200';
      case 'session': return 'bg-purple-100 text-purple-700 border-purple-200';
      case 'token': return 'bg-blue-100 text-blue-700 border-blue-200';
      case 'data': return 'bg-emerald-100 text-emerald-700 border-emerald-200';
      case 'file': return 'bg-amber-100 text-amber-700 border-amber-200';
      default: return 'bg-slate-100 text-slate-700 border-slate-200';
    }
  };

  return (
    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${getArtifactColor(artifact.artifact_type)}`}
         title={`值: ${String(artifact.value).substring(0, 100)}`}>
      <Zap size={12} />
      <span>{artifact.name}</span>
      {artifact.confidence && (
        <span className="opacity-60">({Math.round(artifact.confidence * 100)}%)</span>
      )}
    </div>
  );
};

const AttackStageCard: React.FC<AttackStageCardProps> = ({
  step,
  index,
  isLast,
  isExpanded,
  onToggle,
}) => {
  const stageTitle = step.stage_title || step.stage_name || `阶段 ${step.step || index + 1}`;
  const method = step.method || step.request?.method;
  const url = step.url || step.request?.url;

  return (
    <div className="relative">
      <div className="absolute left-5 top-12 bottom-0 w-0.5 bg-gradient-to-b from-gray-200 to-transparent" 
           style={{ display: isLast ? 'none' : 'block' }} />
      
      <div className="relative pl-12">
        <div className="absolute left-0 top-0 w-10 h-10 rounded-full bg-white border-2 border-gray-200 flex items-center justify-center shadow-sm">
          {getStatusIcon(step.success, step.status)}
        </div>

        <div className={`rounded-2xl border transition-all ${
          step.success === true || step.status === 'validated'
            ? 'border-emerald-200 bg-emerald-50/50'
            : step.success === false || step.status === 'failed'
              ? 'border-red-200 bg-red-50/50'
              : 'border-gray-200 bg-white'
        }`}>
          <button
            onClick={onToggle}
            className="w-full px-5 py-4 flex items-center justify-between text-left"
          >
            <div className="flex items-center gap-3 flex-1 min-w-0">
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-sm font-bold text-gray-400 shrink-0">#{step.step || index + 1}</span>
                <span className="font-semibold text-[#2d3343] truncate">{stageTitle}</span>
              </div>
              {method && (
                <span className={`px-2 py-0.5 rounded text-xs font-bold shrink-0 ${getMethodColor(method)}`}>
                  {method}
                </span>
              )}
              {step.duration_ms && (
                <span className="text-xs text-gray-400 shrink-0">{formatDuration(step.duration_ms)}</span>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0 ml-2">
              {step.artifacts && step.artifacts.length > 0 && (
                <span className="text-xs text-emerald-600 font-medium">
                  +{step.artifacts.length} 产物
                </span>
              )}
              {isExpanded ? (
                <ChevronDown size={18} className="text-gray-400" />
              ) : (
                <ChevronRight size={18} className="text-gray-400" />
              )}
            </div>
          </button>

          {isExpanded && (
            <div className="px-5 pb-5 border-t border-gray-100">
              {step.stage_goal && (
                <div className="mt-4 flex items-start gap-2 text-sm">
                  <Target size={16} className="text-[#ff6b00] mt-0.5 shrink-0" />
                  <div>
                    <span className="font-medium text-gray-500">目标: </span>
                    <span className="text-gray-700">{step.stage_goal}</span>
                  </div>
                </div>
              )}

              {step.description && (
                <p className="mt-3 text-sm text-gray-600">{step.description}</p>
              )}

              {url && (
                <div className="mt-3 text-sm">
                  <span className="font-medium text-gray-500">URL: </span>
                  <code className="text-xs bg-gray-100 px-2 py-0.5 rounded break-all">{url}</code>
                </div>
              )}

              {step.payload && (
                <div className="mt-3">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-2">攻击载荷</div>
                  <pre className="text-xs bg-gray-900 text-emerald-400 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap break-all">
                    {step.payload}
                  </pre>
                </div>
              )}

              <RequestResponseViewer
                evidence={step.evidence}
                request={step.request}
                response={step.response}
                payload={step.payload}
              />

              {step.artifacts && step.artifacts.length > 0 && (
                <div className="mt-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-2">关键产物</div>
                  <div className="flex flex-wrap gap-2">
                    {step.artifacts.map((artifact, idx) => (
                      <ArtifactBadge key={idx} artifact={artifact} />
                    ))}
                  </div>
                </div>
              )}

              {step.matched_conditions && step.matched_conditions.length > 0 && (
                <div className="mt-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-2">匹配条件</div>
                  <div className="space-y-1">
                    {step.matched_conditions.map((condition, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-xs text-gray-600">
                        <CheckCircle size={12} className="text-emerald-500" />
                        {safeConditionText(condition)}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {step.result && (
                <div className="mt-4 p-3 rounded-lg bg-gray-100">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-1">执行结果</div>
                  <p className="text-sm text-gray-700">{step.result}</p>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

interface AttackChainTimelineProps {
  steps: AttackStep[];
  title?: string;
  summary?: {
    total_stages: number;
    successful_stages: number;
    failed_stages: number;
    total_duration_ms?: number;
    attack_vector?: string;
    entry_point?: string;
  };
}

const AttackChainTimeline: React.FC<AttackChainTimelineProps> = ({
  steps,
  title = '攻击链时间线',
  summary,
}) => {
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set([0]));

  const toggleStep = (index: number) => {
    setExpandedSteps(prev => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  };

  const expandAll = () => {
    setExpandedSteps(new Set(steps.map((_, i) => i)));
  };

  const collapseAll = () => {
    setExpandedSteps(new Set());
  };

  const successfulCount = steps.filter(s => s.success === true || s.status === 'validated').length;
  const failedCount = steps.filter(s => s.success === false || s.status === 'failed').length;
  const totalDuration = steps.reduce((sum, s) => sum + (s.duration_ms || 0), 0);

  return (
    <div className="rounded-2xl border border-gray-200 bg-white overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 bg-gradient-to-r from-gray-50 to-white">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-[#ff6b00] flex items-center justify-center">
              <svg className="w-4 h-4 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
              </svg>
            </div>
            <div>
              <h4 className="font-bold text-[#2d3343]">{title}</h4>
              <p className="text-xs text-gray-500">完整攻击阶段与证据链</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={expandAll}
              className="px-3 py-1.5 text-xs font-medium text-gray-600 hover:text-[#ff6b00] hover:bg-orange-50 rounded-lg transition-colors"
            >
              展开全部
            </button>
            <button
              onClick={collapseAll}
              className="px-3 py-1.5 text-xs font-medium text-gray-600 hover:text-[#ff6b00] hover:bg-orange-50 rounded-lg transition-colors"
            >
              折叠全部
            </button>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-blue-500"></div>
            <span className="text-xs text-gray-600">共 <strong>{steps.length}</strong> 个阶段</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
            <span className="text-xs text-gray-600">成功 <strong>{successfulCount}</strong></span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-red-500"></div>
            <span className="text-xs text-gray-600">失败 <strong>{failedCount}</strong></span>
          </div>
          {totalDuration > 0 && (
            <div className="flex items-center gap-2">
              <Clock size={12} className="text-gray-400" />
              <span className="text-xs text-gray-600">总耗时 <strong>{formatDuration(totalDuration)}</strong></span>
            </div>
          )}
        </div>

        {summary && (
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
            {summary.attack_vector && (
              <div className="rounded-lg bg-slate-50 px-3 py-2">
                <div className="text-xs text-gray-400">攻击向量</div>
                <div className="mt-1 text-sm font-medium text-[#2d3343] truncate">{summary.attack_vector}</div>
              </div>
            )}
            {summary.entry_point && (
              <div className="rounded-lg bg-slate-50 px-3 py-2">
                <div className="text-xs text-gray-400">入口点</div>
                <div className="mt-1 text-sm font-medium text-[#2d3343] truncate">{summary.entry_point}</div>
              </div>
            )}
            <div className="rounded-lg bg-emerald-50 px-3 py-2">
              <div className="text-xs text-gray-400">成功阶段</div>
              <div className="mt-1 text-sm font-bold text-emerald-600">{summary.successful_stages}/{summary.total_stages}</div>
            </div>
            {summary.total_duration_ms && (
              <div className="rounded-lg bg-amber-50 px-3 py-2">
                <div className="text-xs text-gray-400">总耗时</div>
                <div className="mt-1 text-sm font-bold text-amber-600">{formatDuration(summary.total_duration_ms)}</div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="p-6 space-y-4">
        {steps.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            <Target size={32} className="mx-auto mb-2 opacity-50" />
            <p className="text-sm">暂无攻击阶段数据</p>
          </div>
        ) : (
          steps.map((step, index) => (
            <AttackStageCard
              key={step.stage_id || index}
              step={step}
              index={index}
              isLast={index === steps.length - 1}
              isExpanded={expandedSteps.has(index)}
              onToggle={() => toggleStep(index)}
            />
          ))
        )}
      </div>
    </div>
  );
};

export default AttackChainTimeline;
export { AttackStageCard, RequestResponseViewer, ArtifactBadge };
