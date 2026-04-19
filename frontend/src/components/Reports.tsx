import React, { useEffect, useState, useRef, useCallback } from 'react';
import { api, getApiResourceUrl, type Report, type ReportPreview, type ReportPreviewVulnerability } from '../api';
import { getScanStrategyMeta } from '../utils/scanStrategy';
import { Trash2, Download, ChevronDown, X, ChevronRight, CheckCircle, XCircle, Clock, Zap, Target, Code, FileText, AlertTriangle } from './Icons';
import ValidationWorkflow from './ValidationWorkflow';
import AttackChainTimeline from './AttackChainTimeline';

type ExportFormat = 'html' | 'pdf' | 'markdown' | 'excel' | 'json';

interface ExportFormatOption {
  value: ExportFormat;
  label: string;
  icon: string;
  description: string;
}

const EXPORT_FORMATS: ExportFormatOption[] = [
  { value: 'html', label: 'HTML', icon: '🌐', description: '网页格式，可直接在浏览器中查看' },
  { value: 'pdf', label: 'PDF', icon: '📄', description: '文档格式，适合打印和存档' },
  { value: 'markdown', label: 'Markdown', icon: '📝', description: '纯文本格式，可导入到其他工具' },
  { value: 'excel', label: 'Excel', icon: '📊', description: '表格格式，适合数据分析和筛选' },
  { value: 'json', label: 'JSON', icon: '{ }', description: '数据格式，适合程序处理和集成' },
];

const VULN_BATCH_SIZE = 10;
const INITIAL_VULN_COUNT = 10;
const HIGH_RISK_THRESHOLD = 70;
const MEDIUM_RISK_THRESHOLD = 40;

const getRiskScoreColor = (score: number): string => {
  if (score > HIGH_RISK_THRESHOLD) return 'bg-red-100 text-red-600';
  if (score > MEDIUM_RISK_THRESHOLD) return 'bg-orange-100 text-orange-600';
  return 'bg-green-100 text-green-600';
};

interface ReportCardProps {
  report: Report;
  activeDropdown: number | null;
  dropdownRef: React.RefObject<HTMLDivElement | null>;
  onViewReport: (taskId: number) => void;
  onExportReport: (taskId: number, format: ExportFormat) => void;
  onDeleteReport: (taskId: number, targetUrl: string) => void;
  onToggleDropdown: (reportId: number) => void;
}

const ReportCard: React.FC<ReportCardProps> = ({
  report,
  activeDropdown,
  dropdownRef,
  onViewReport,
  onExportReport,
  onDeleteReport,
  onToggleDropdown,
}) => {
  const strategy = getScanStrategyMeta(report.scan_strategy);

  return (
    <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4 hover:shadow-lg transition-all group">
      <div className="flex justify-between items-start">
        <div className="flex flex-col">
          <span className="font-bold text-[#2d3343] truncate max-w-[200px]">{report.target_url}</span>
          <span className="text-xs text-gray-400">{new Date(report.created_at).toLocaleString()}</span>
        </div>
        <div className={`px-3 py-1 rounded-lg text-xs font-bold ${getRiskScoreColor(report.risk_score)}`}>
          Score: {report.risk_score}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-[#c25b00]">
          {strategy.label}
        </span>
        <span className="text-xs text-gray-400">{strategy.scope}</span>
        <span className="text-xs text-gray-300">|</span>
        <span className="text-xs text-gray-400">{strategy.speed}</span>
      </div>

      <div className="flex items-center gap-2 text-sm text-gray-500">
        <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
        </svg>
        发现 {report.vuln_count} 个漏洞
      </div>

      <div className="grid grid-cols-3 gap-2 text-center">
        <div className="rounded-xl bg-orange-50 px-3 py-2">
          <div className="text-xs text-gray-400">已验证攻击</div>
          <div className="mt-1 text-sm font-bold text-[#c25b00]">{report.validated_findings}</div>
        </div>
        <div className="rounded-xl bg-gray-50 px-3 py-2">
          <div className="text-xs text-gray-400">攻击载荷</div>
          <div className="mt-1 text-sm font-bold text-[#2d3343]">{report.payload_count}</div>
        </div>
        <div className="rounded-xl bg-gray-50 px-3 py-2">
          <div className="text-xs text-gray-400">攻击路径</div>
          <div className="mt-1 text-sm font-bold text-[#2d3343]">{report.attack_path_count}</div>
        </div>
      </div>

      <div className="mt-2 flex gap-2">
        <button
          onClick={() => onViewReport(report.task_id)}
          className="flex-1 py-2 bg-gray-50 text-[#2d3343] rounded-lg text-sm font-bold group-hover:bg-[#ff6b00] group-hover:text-white transition-all"
        >
          查看报告
        </button>

        <div className="relative" ref={activeDropdown === report.id ? dropdownRef : undefined}>
          <button
            onClick={() => onToggleDropdown(report.id)}
            className="flex items-center gap-1 py-2 px-3 bg-gray-50 text-[#2d3343] rounded-lg text-sm font-bold hover:bg-gray-100 transition-all"
            title="导出报告"
          >
            <Download size={16} />
            <ChevronDown size={14} />
          </button>

          {activeDropdown === report.id && (
            <div className="absolute right-0 top-full mt-1 w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-2 z-50">
              <div className="px-3 py-2 text-xs font-bold text-gray-400 border-b border-gray-100">
                选择导出格式
              </div>
              {EXPORT_FORMATS.map((format) => (
                <button
                  key={format.value}
                  onClick={() => onExportReport(report.task_id, format.value)}
                  className="w-full px-3 py-2.5 flex items-center gap-3 hover:bg-orange-50 transition-colors text-left"
                >
                  <span className="text-lg">{format.icon}</span>
                  <div className="flex-1">
                    <div className="text-sm font-medium text-[#2d3343]">{format.label}</div>
                    <div className="text-xs text-gray-400">{format.description}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>

        <button
          onClick={() => onDeleteReport(report.task_id, report.target_url)}
          className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
          title="删除报告"
        >
          <Trash2 size={18} strokeWidth={2} />
        </button>
      </div>
    </div>
  );
};

interface VulnerabilityBadgeProps {
  present: boolean;
  label: string;
  colorClass: string;
}

const VulnerabilityBadge: React.FC<VulnerabilityBadgeProps> = ({ present, label, colorClass }) => {
  if (!present) return null;
  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${colorClass}`}>{label}</span>
  );
};

const ATTACK_STATUS_LABELS: Record<string, string> = {
  validated: '已验证',
  exploitable: '可利用',
  partial: '部分完成',
  observed: '已观察',
  blocked: '已阻断',
  running: '执行中',
};

const AttackStatusBadge: React.FC<{ status?: string }> = ({ status }) => {
  if (!status) return null;
  const normalized = status.toLowerCase();
  const colorClass = normalized === 'validated'
    ? 'bg-emerald-100 text-emerald-700'
    : normalized === 'exploitable'
      ? 'bg-orange-100 text-[#c25b00]'
      : normalized === 'partial'
        ? 'bg-yellow-100 text-yellow-700'
        : normalized === 'blocked'
          ? 'bg-red-100 text-red-600'
          : 'bg-gray-100 text-gray-600';

  return (
    <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${colorClass}`}>
      {ATTACK_STATUS_LABELS[normalized] || status}
    </span>
  );
};

interface ReportPreviewModalProps {
  preview: ReportPreview;
  visibleVulnCount: number;
  onClose: () => void;
  onLoadMore: () => void;
  onShowAll: () => void;
}

interface VulnerabilityDetailPanelProps {
  vuln: ReportPreviewVulnerability;
  onClose: () => void;
}

const getSeverityColor = (severity?: string): string => {
  if (!severity) return 'bg-gray-100 text-gray-600';
  const s = severity.toLowerCase();
  switch (s) {
    case 'critical': return 'bg-red-100 text-red-700 border-red-200';
    case 'high': return 'bg-orange-100 text-orange-700 border-orange-200';
    case 'medium': return 'bg-yellow-100 text-yellow-700 border-yellow-200';
    case 'low': return 'bg-green-100 text-green-700 border-green-200';
    default: return 'bg-gray-100 text-gray-600 border-gray-200';
  }
};

const VulnerabilityDetailPanel: React.FC<VulnerabilityDetailPanelProps> = ({ vuln, onClose }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'timeline'>('timeline');

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 px-4 py-8" onClick={onClose}>
      <div
        className="flex flex-col max-h-[90vh] w-full max-w-5xl rounded-3xl bg-white shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between border-b border-gray-100 px-6 py-5 shrink-0 bg-gradient-to-r from-gray-50 to-white">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3">
              <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase ${getSeverityColor(vuln.severity)}`}>
                {vuln.severity || 'INFO'}
              </span>
              <AttackStatusBadge status={vuln.attack_status} />
            </div>
            <h3 className="mt-2 text-xl font-bold text-[#2d3343] truncate">{vuln.title}</h3>
            <p className="mt-1 text-sm text-gray-500">
              {vuln.type || '通用 Web 漏洞'}
              {vuln.parameter && <span className="ml-2">· 参数 {vuln.parameter}</span>}
              {vuln.cvss_score && <span className="ml-2">· CVSS {vuln.cvss_score}</span>}
            </p>
          </div>
          <button
            onClick={onClose}
            className="rounded-xl p-2 text-gray-400 transition-colors hover:bg-gray-50 hover:text-gray-600"
          >
            <X size={22} />
          </button>
        </div>

        <div className="flex border-b border-gray-100 bg-white shrink-0">
          <button
            onClick={() => setActiveTab('timeline')}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'timeline'
                ? 'text-[#ff6b00] border-b-2 border-[#ff6b00] bg-orange-50'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            <span className="flex items-center gap-2">
              <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
              </svg>
              攻击链时间线
            </span>
          </button>
          <button
            onClick={() => setActiveTab('overview')}
            className={`px-6 py-3 text-sm font-medium transition-colors ${
              activeTab === 'overview'
                ? 'text-[#ff6b00] border-b-2 border-[#ff6b00] bg-orange-50'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            <span className="flex items-center gap-2">
              <FileText size={16} />
              概览信息
            </span>
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-6" style={{ maxHeight: 'calc(90vh - 180px)' }}>
          {activeTab === 'timeline' && (
            <AttackChainTimeline
              steps={vuln.attack_steps || []}
              title="攻击阶段时间线"
              summary={vuln.attack_chain_summary ? {
                total_stages: vuln.attack_chain_summary.total_stages || vuln.attack_steps?.length || 0,
                successful_stages: vuln.attack_chain_summary.successful_stages || 0,
                failed_stages: vuln.attack_chain_summary.failed_stages || 0,
                total_duration_ms: vuln.attack_chain_summary.total_duration_ms,
                attack_vector: vuln.attack_chain_summary.attack_vector,
                entry_point: vuln.attack_chain_summary.entry_point,
              } : undefined}
            />
          )}

          {activeTab === 'overview' && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="rounded-xl bg-gray-50 p-4">
                  <div className="text-xs text-gray-400">漏洞类型</div>
                  <div className="mt-1 text-sm font-semibold text-[#2d3343]">{vuln.type || 'N/A'}</div>
                </div>
                <div className="rounded-xl bg-gray-50 p-4">
                  <div className="text-xs text-gray-400">风险等级</div>
                  <div className="mt-1">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity?.toUpperCase() || 'N/A'}
                    </span>
                  </div>
                </div>
                <div className="rounded-xl bg-gray-50 p-4">
                  <div className="text-xs text-gray-400">CVSS 评分</div>
                  <div className="mt-1 text-sm font-semibold text-[#2d3343]">{vuln.cvss_score || 'N/A'}</div>
                </div>
                <div className="rounded-xl bg-gray-50 p-4">
                  <div className="text-xs text-gray-400">攻击状态</div>
                  <div className="mt-1"><AttackStatusBadge status={vuln.attack_status} /></div>
                </div>
              </div>

              {vuln.url && (
                <div className="rounded-xl border border-gray-100 p-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-2">触发 URL</div>
                  <code className="text-sm text-gray-700 break-all">{vuln.url}</code>
                </div>
              )}

              {vuln.description && (
                <div className="rounded-xl border border-gray-100 p-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-2">漏洞描述</div>
                  <p className="text-sm text-gray-700 leading-relaxed">{vuln.description}</p>
                </div>
              )}

              {vuln.attack_final_reason && (
                <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4">
                  <div className="text-xs font-semibold text-emerald-600 uppercase mb-2">验证结论</div>
                  <p className="text-sm text-emerald-700">{vuln.attack_final_reason}</p>
                </div>
              )}

              {vuln.remediation && (
                <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                  <div className="text-xs font-semibold text-blue-600 uppercase mb-2">修复建议</div>
                  <p className="text-sm text-blue-700">{vuln.remediation}</p>
                </div>
              )}

              {vuln.attack_artifacts && vuln.attack_artifacts.length > 0 && (
                <div className="rounded-xl border border-gray-100 p-4">
                  <div className="text-xs font-semibold text-gray-500 uppercase mb-3">关键产物</div>
                  <div className="flex flex-wrap gap-2">
                    {vuln.attack_artifacts.map((artifact, idx) => (
                      <span
                        key={idx}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-100 text-slate-700"
                        title={String(artifact.value)}
                      >
                        <Zap size={12} />
                        {artifact.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const ReportPreviewModal: React.FC<ReportPreviewModalProps> = ({
  preview,
  visibleVulnCount,
  onClose,
  onLoadMore,
  onShowAll,
}) => {
  const [selectedVuln, setSelectedVuln] = useState<ReportPreviewVulnerability | null>(null);
  const [expandedVulns, setExpandedVulns] = useState<Set<number>>(new Set());

  const strategy = getScanStrategyMeta(preview.scan_strategy);
  const hasMore = visibleVulnCount < preview.vulnerabilities.length;

  const toggleVulnExpand = (vulnId: number) => {
    setExpandedVulns(prev => {
      const next = new Set(prev);
      if (next.has(vulnId)) {
        next.delete(vulnId);
      } else {
        next.add(vulnId);
      }
      return next;
    });
  };

  return (
    <>
      <div
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4 py-8"
        onClick={onClose}
      >
        <div
          className="flex flex-col max-h-[85vh] w-full max-w-5xl rounded-3xl bg-white shadow-2xl"
          onClick={(event) => event.stopPropagation()}
        >
          <div className="flex items-start justify-between border-b border-gray-100 px-8 py-6 shrink-0">
            <div>
              <h3 className="text-2xl font-bold text-[#2d3343]">模拟攻击报告预览</h3>
              <p className="mt-1 text-sm text-gray-400">{preview.target_url}</p>
            </div>
            <button
              onClick={onClose}
              className="rounded-xl p-2 text-gray-400 transition-colors hover:bg-gray-50 hover:text-gray-600"
            >
              <X size={22} />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto px-8 py-6 space-y-6" style={{ maxHeight: 'calc(85vh - 100px)' }}>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
              <div className="rounded-2xl bg-orange-50 p-4">
                <div className="text-xs text-gray-400">验证模式</div>
                <div className="mt-2 text-sm font-bold text-[#c25b00]">{strategy.label}</div>
                <div className="mt-1 text-xs leading-5 text-[#9a5a20]">{strategy.intensity}</div>
              </div>
              <div className="rounded-2xl bg-gray-50 p-4">
                <div className="text-xs text-gray-400">已验证攻击</div>
                <div className="mt-2 text-lg font-bold text-[#2d3343]">
                  {preview.attack_simulation_summary?.validated_findings ?? 0}
                </div>
              </div>
              <div className="rounded-2xl bg-gray-50 p-4">
                <div className="text-xs text-gray-400">攻击载荷</div>
                <div className="mt-2 text-lg font-bold text-[#2d3343]">
                  {preview.attack_simulation_summary?.payload_count ?? 0}
                </div>
              </div>
              <div className="rounded-2xl bg-gray-50 p-4">
                <div className="text-xs text-gray-400">攻击路径</div>
                <div className="mt-2 text-lg font-bold text-[#2d3343]">
                  {preview.attack_simulation_summary?.attack_path_count ?? 0}
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-gray-100 p-5">
              <h4 className="text-sm font-bold text-[#2d3343]">风险摘要</h4>
              <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-5">
                <div className="rounded-xl bg-red-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">严重</div>
                  <div className="mt-1 font-bold text-red-600">{preview.summary.critical}</div>
                </div>
                <div className="rounded-xl bg-orange-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">高危</div>
                  <div className="mt-1 font-bold text-orange-600">{preview.summary.high}</div>
                </div>
                <div className="rounded-xl bg-yellow-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">中危</div>
                  <div className="mt-1 font-bold text-yellow-600">{preview.summary.medium}</div>
                </div>
                <div className="rounded-xl bg-blue-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">低危</div>
                  <div className="mt-1 font-bold text-blue-600">{preview.summary.low}</div>
                </div>
                <div className="rounded-xl bg-gray-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">总计</div>
                  <div className="mt-1 font-bold text-[#2d3343]">{preview.summary.total}</div>
                </div>
              </div>
              <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4">
                <div className="rounded-xl bg-emerald-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">已验证攻击链</div>
                  <div className="mt-1 font-bold text-emerald-700">
                    {preview.attack_simulation_summary?.validated_attack_paths ?? 0}
                  </div>
                </div>
                <div className="rounded-xl bg-slate-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">关键产物</div>
                  <div className="mt-1 font-bold text-[#2d3343]">
                    {preview.attack_simulation_summary?.artifact_count ?? 0}
                  </div>
                </div>
                <div className="rounded-xl bg-orange-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">攻击载荷</div>
                  <div className="mt-1 font-bold text-[#c25b00]">
                    {preview.attack_simulation_summary?.payload_count ?? 0}
                  </div>
                </div>
                <div className="rounded-xl bg-blue-50 px-3 py-3 text-center">
                  <div className="text-xs text-gray-400">攻击路径</div>
                  <div className="mt-1 font-bold text-blue-600">
                    {preview.attack_simulation_summary?.attack_path_count ?? 0}
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-2xl border border-gray-100 p-5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <h4 className="text-sm font-bold text-[#2d3343]">漏洞与攻击链证据</h4>
                  <span className="rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-semibold text-gray-500">
                    共 {preview.vulnerabilities.length} 项
                    {hasMore && ` (已显示 ${visibleVulnCount})`}
                  </span>
                </div>
                <button
                  onClick={() => window.open(getApiResourceUrl(`/reports/${preview.task_id}/html`), '_blank')}
                  className="text-sm font-semibold text-[#ff6b00] transition-colors hover:text-[#e66000]"
                >
                  打开完整 HTML 报告
                </button>
              </div>
              <div className="mt-4 space-y-3">
                {preview.vulnerabilities.length === 0 ? (
                  <div className="rounded-xl bg-gray-50 px-4 py-6 text-center text-sm text-gray-400">
                    当前报告未发现可展示的漏洞验证记录。
                  </div>
                ) : (
                  <>
                    {preview.vulnerabilities.slice(0, visibleVulnCount).map((vuln) => {
                      const isExpanded = expandedVulns.has(vuln.id);
                      const hasAttackSteps = vuln.attack_steps && vuln.attack_steps.length > 0;

                      return (
                        <div key={vuln.id} className="rounded-2xl bg-gray-50 overflow-hidden">
                          <button
                            onClick={() => toggleVulnExpand(vuln.id)}
                            className="w-full px-4 py-4 flex items-center justify-between text-left hover:bg-gray-100 transition-colors"
                          >
                            <div className="flex items-center gap-3 min-w-0 flex-1">
                              <span className={`px-2 py-0.5 rounded text-xs font-bold shrink-0 ${getSeverityColor(vuln.severity)}`}>
                                {vuln.severity?.toUpperCase() || 'INFO'}
                              </span>
                              <div className="min-w-0 flex-1">
                                <div className="font-bold text-[#2d3343] truncate">{vuln.title}</div>
                                <div className="mt-1 text-sm text-gray-500 truncate">
                                  {vuln.type || '通用 Web 漏洞'}
                                  {vuln.parameter ? ` · 参数 ${vuln.parameter}` : ''}
                                </div>
                              </div>
                            </div>
                            <div className="flex items-center gap-3 shrink-0 ml-3">
                              <div className="flex items-center gap-2">
                                <AttackStatusBadge status={vuln.attack_status} />
                                {hasAttackSteps && (
                                  <span className="text-xs font-semibold text-gray-500 bg-white px-2 py-0.5 rounded">
                                    {vuln.attack_steps?.length} 阶段
                                  </span>
                                )}
                              </div>
                              {isExpanded ? (
                                <ChevronDown size={18} className="text-gray-400" />
                              ) : (
                                <ChevronRight size={18} className="text-gray-400" />
                              )}
                            </div>
                          </button>

                          {isExpanded && (
                            <div className="px-4 pb-4 border-t border-gray-200">
                              <div className="mt-4 flex flex-wrap gap-2">
                                <VulnerabilityBadge present={vuln.payload_present} label="攻击载荷" colorClass="bg-orange-100 text-[#c25b00]" />
                                <VulnerabilityBadge present={vuln.attack_path_present} label="攻击路径" colorClass="bg-blue-100 text-blue-600" />
                                <VulnerabilityBadge present={vuln.evidence_present} label="证据链" colorClass="bg-green-100 text-green-600" />
                              </div>

                              {vuln.description && (
                                <p className="mt-3 text-sm text-gray-600">{vuln.description}</p>
                              )}

                              {vuln.attack_final_reason && (
                                <div className="mt-3 p-3 rounded-lg bg-emerald-50 border border-emerald-200">
                                  <span className="text-xs font-semibold text-emerald-600">验证结论: </span>
                                  <span className="text-sm text-emerald-700">{vuln.attack_final_reason}</span>
                                </div>
                              )}

                              {hasAttackSteps && (
                                <div className="mt-4">
                                  <div className="flex items-center justify-between mb-3">
                                    <div className="text-xs font-bold uppercase tracking-wide text-gray-400">攻击阶段预览</div>
                                    <button
                                      onClick={() => setSelectedVuln(vuln)}
                                      className="text-xs font-semibold text-[#ff6b00] hover:text-[#e66000] transition-colors"
                                    >
                                      查看完整时间线 →
                                    </button>
                                  </div>
                                  <div className="space-y-2">
                                    {vuln.attack_steps!.slice(0, 3).map((step, index) => (
                                      <div key={step.stage_id || index} className="rounded-lg bg-white px-3 py-2 border border-gray-100">
                                        <div className="flex items-center gap-2 text-sm">
                                          <span className="font-bold text-gray-400">#{step.step || index + 1}</span>
                                          <span className="font-semibold text-[#2d3343]">{step.stage_title || step.stage_name || '阶段'}</span>
                                          {step.method && (
                                            <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                                              step.method.toUpperCase() === 'GET' ? 'bg-emerald-100 text-emerald-700' :
                                              step.method.toUpperCase() === 'POST' ? 'bg-blue-100 text-blue-700' :
                                              'bg-gray-100 text-gray-600'
                                            }`}>
                                              {step.method}
                                            </span>
                                          )}
                                          {step.success !== undefined && (
                                            step.success ? <CheckCircle size={14} className="text-emerald-500" /> : <XCircle size={14} className="text-red-500" />
                                          )}
                                        </div>
                                        {step.url && (
                                          <div className="mt-1 text-xs text-gray-500 truncate">{step.url}</div>
                                        )}
                                      </div>
                                    ))}
                                    {vuln.attack_steps!.length > 3 && (
                                      <button
                                        onClick={() => setSelectedVuln(vuln)}
                                        className="w-full text-center text-xs text-gray-500 hover:text-[#ff6b00] py-2"
                                      >
                                        还有 {vuln.attack_steps!.length - 3} 个阶段...
                                      </button>
                                    )}
                                  </div>
                                </div>
                              )}

                              {vuln.attack_artifacts && vuln.attack_artifacts.length > 0 && (
                                <div className="mt-3 flex flex-wrap gap-2">
                                  {vuln.attack_artifacts.slice(0, 4).map((artifact, index) => (
                                    <span
                                      key={index}
                                      className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600"
                                      title={String(artifact.value)}
                                    >
                                      {artifact.name}
                                    </span>
                                  ))}
                                </div>
                              )}

                              <div className="mt-4 flex justify-end">
                                <button
                                  onClick={() => setSelectedVuln(vuln)}
                                  className="px-4 py-2 bg-[#ff6b00] text-white rounded-lg text-sm font-bold hover:bg-[#e66000] transition-all"
                                >
                                  查看完整攻击链
                                </button>
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}

                    {hasMore && (
                      <div className="flex items-center justify-center gap-3 pt-4 border-t border-gray-100">
                        <button
                          onClick={onLoadMore}
                          className="px-6 py-2.5 bg-[#ff6b00] text-white rounded-xl text-sm font-bold hover:bg-[#e66000] transition-all shadow-sm hover:shadow-md"
                        >
                          加载更多 ({Math.min(VULN_BATCH_SIZE, preview.vulnerabilities.length - visibleVulnCount)} 项)
                        </button>
                        <button
                          onClick={onShowAll}
                          className="px-6 py-2.5 bg-gray-100 text-[#2d3343] rounded-xl text-sm font-semibold hover:bg-gray-200 transition-all"
                        >
                          显示全部 ({preview.vulnerabilities.length - visibleVulnCount} 项剩余)
                        </button>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {selectedVuln && (
        <VulnerabilityDetailPanel
          vuln={selectedVuln}
          onClose={() => setSelectedVuln(null)}
        />
      )}
    </>
  );
};

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<number | null>(null);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [visibleVulnCount, setVisibleVulnCount] = useState(INITIAL_VULN_COUNT);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (preview) {
      setVisibleVulnCount(INITIAL_VULN_COUNT);
    }
  }, [preview?.task_id]);

  const fetchReports = useCallback(async () => {
    try {
      const data = await api.getReports();
      setReports(data);
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setActiveDropdown(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleDeleteReport = async (taskId: number, targetUrl: string) => {
    if (!window.confirm(`确定要删除报告「${targetUrl}」吗？关联的漏洞记录将一并删除。`)) return;
    try {
      await api.deleteReport(taskId);
      fetchReports();
    } catch {
      alert('删除失败');
    }
  };

  const handleViewReport = async (taskId: number) => {
    try {
      setPreviewLoading(true);
      const data = await api.getReportPreview(taskId);
      setPreview(data);
    } catch {
      window.open(getApiResourceUrl(`/reports/${taskId}/html`), '_blank');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleExportReport = useCallback((taskId: number, format: ExportFormat) => {
    const exportUrl = getApiResourceUrl(`/reports/${taskId}/export?format=${format}&include_evidence=true`);
    window.open(exportUrl, '_blank');
    setActiveDropdown(null);
  }, []);

  const toggleDropdown = useCallback((reportId: number) => {
    setActiveDropdown(activeDropdown === reportId ? null : reportId);
  }, [activeDropdown]);

  const handleLoadMoreVulns = useCallback(() => {
    setVisibleVulnCount(prev => Math.min(prev + VULN_BATCH_SIZE, preview?.vulnerabilities.length ?? prev));
  }, [preview?.vulnerabilities.length]);

  const handleShowAllVulns = useCallback(() => {
    if (preview) {
      setVisibleVulnCount(preview.vulnerabilities.length);
    }
  }, [preview]);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <ValidationWorkflow currentStep="reports" compact />

      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-[#2d3343]">攻击验证报告</h2>
          <p className="mt-1 text-sm text-gray-400">聚合展示漏洞数量、攻击路径与可利用性证明。</p>
        </div>
        <button
          onClick={fetchReports}
          className="p-2 text-gray-400 hover:text-[#ff6b00] transition-colors"
          title="刷新列表"
        >
          <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
          </svg>
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full text-center py-12 text-gray-400">加载中...</div>
        ) : reports.length === 0 ? (
          <div className="col-span-full text-center py-12 text-gray-400">暂无报告</div>
        ) : (
          reports.map((report) => (
            <ReportCard
              key={report.id}
              report={report}
              activeDropdown={activeDropdown}
              dropdownRef={dropdownRef}
              onViewReport={handleViewReport}
              onExportReport={handleExportReport}
              onDeleteReport={handleDeleteReport}
              onToggleDropdown={toggleDropdown}
            />
          ))
        )}
      </div>

      {preview && (
        <ReportPreviewModal
          preview={preview}
          visibleVulnCount={visibleVulnCount}
          onClose={() => setPreview(null)}
          onLoadMore={handleLoadMoreVulns}
          onShowAll={handleShowAllVulns}
        />
      )}

      {previewLoading && (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/20">
          <div className="rounded-2xl bg-white px-6 py-4 text-sm font-medium text-gray-500 shadow-xl">
            正在加载模拟攻击报告预览...
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
