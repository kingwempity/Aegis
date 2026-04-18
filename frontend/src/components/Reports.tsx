import React, { useEffect, useState, useRef, useCallback } from 'react';
import { api, getApiResourceUrl, type Report, type ReportPreview } from '../api';
import { getScanStrategyMeta } from '../utils/scanStrategy';
import { Trash2, Download, ChevronDown, X } from './Icons';
import ValidationWorkflow from './ValidationWorkflow';

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

const ReportPreviewModal: React.FC<ReportPreviewModalProps> = ({
  preview,
  visibleVulnCount,
  onClose,
  onLoadMore,
  onShowAll,
}) => {
  const strategy = getScanStrategyMeta(preview.scan_strategy);
  const hasMore = visibleVulnCount < preview.vulnerabilities.length;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4 py-8"
      onClick={onClose}
    >
      <div
        className="flex flex-col max-h-[85vh] w-full max-w-4xl rounded-3xl bg-white shadow-2xl"
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

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <div className="rounded-2xl border border-gray-100 bg-white p-4">
              <div className="text-xs text-gray-400">覆盖范围</div>
              <div className="mt-2 text-sm font-bold text-[#2d3343]">{strategy.scope}</div>
            </div>
            <div className="rounded-2xl border border-gray-100 bg-white p-4">
              <div className="text-xs text-gray-400">执行节奏</div>
              <div className="mt-2 text-sm font-bold text-[#2d3343]">{strategy.speed}</div>
            </div>
            <div className="rounded-2xl border border-gray-100 bg-white p-4">
              <div className="text-xs text-gray-400">适用场景</div>
              <div className="mt-2 text-sm font-bold text-[#2d3343]">{strategy.useCase}</div>
            </div>
          </div>

          <div className="rounded-2xl border border-[#ffe1c7] bg-[#fff9f4] p-5">
            <h4 className="text-sm font-bold text-[#2d3343]">模式解读</h4>
            <p className="mt-3 text-sm leading-6 text-gray-600">{strategy.summary}</p>
            <p className="mt-3 text-sm leading-6 text-[#9a5a20]">{strategy.disclaimer}</p>
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
                <h4 className="text-sm font-bold text-[#2d3343]">典型漏洞与可利用性证明</h4>
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
                  {preview.vulnerabilities.slice(0, visibleVulnCount).map((vuln) => (
                    <div key={vuln.id} className="rounded-2xl bg-gray-50 p-4">
                      <div className="flex flex-wrap items-start justify-between gap-3">
                        <div>
                          <div className="font-bold text-[#2d3343]">{vuln.title}</div>
                          <div className="mt-1 text-sm text-gray-500">
                            {vuln.type || '通用 Web 漏洞'}
                            {vuln.parameter ? ` · 参数 ${vuln.parameter}` : ''}
                            {vuln.cvss_score ? ` · CVSS ${vuln.cvss_score}` : ''}
                          </div>
                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <AttackStatusBadge status={vuln.attack_status} />
                            {typeof vuln.attack_stage_count === 'number' && vuln.attack_stage_count > 0 && (
                              <span className="text-xs font-semibold text-gray-500">{vuln.attack_stage_count} 个阶段</span>
                            )}
                            {typeof vuln.attack_artifact_count === 'number' && vuln.attack_artifact_count > 0 && (
                              <span className="text-xs font-semibold text-gray-500">{vuln.attack_artifact_count} 个关键产物</span>
                            )}
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <VulnerabilityBadge present={vuln.payload_present} label="攻击载荷" colorClass="bg-orange-100 text-[#c25b00]" />
                          <VulnerabilityBadge present={vuln.attack_path_present} label="攻击路径" colorClass="bg-blue-100 text-blue-600" />
                          <VulnerabilityBadge present={vuln.evidence_present} label="证据链" colorClass="bg-green-100 text-green-600" />
                        </div>
                      </div>
                      <p className="mt-3 text-sm text-gray-500">{vuln.description || '暂无详细验证摘要。'}</p>
                      {vuln.attack_final_reason && (
                        <p className="mt-2 text-xs text-gray-500">结论: {vuln.attack_final_reason}</p>
                      )}
                      {vuln.attack_steps && vuln.attack_steps.length > 0 && (
                        <div className="mt-4 rounded-xl border border-gray-100 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-gray-400">攻击阶段</div>
                          <div className="mt-3 space-y-2">
                            {vuln.attack_steps.slice(0, 3).map((step, index) => (
                              <div key={`${vuln.id}-${step.stage_id || index}`} className="rounded-lg bg-gray-50 px-3 py-2">
                                <div className="flex flex-wrap items-center gap-2 text-sm font-semibold text-[#2d3343]">
                                  <span>{step.step ?? index + 1}.</span>
                                  <span>{step.stage_title || step.stage_name || step.stage_id || '阶段'}</span>
                                  {step.method && <span className="rounded bg-[#2d3343] px-2 py-0.5 text-xs text-white">{step.method}</span>}
                                </div>
                                {step.stage_goal && <div className="mt-1 text-xs text-slate-600">目标: {step.stage_goal}</div>}
                                {step.url && <div className="mt-1 break-all text-xs text-gray-500">{step.url}</div>}
                                {step.description && <div className="mt-1 text-xs text-gray-500">{step.description}</div>}
                                {step.artifacts && step.artifacts.length > 0 && (
                                  <div className="mt-2 flex flex-wrap gap-2">
                                    {step.artifacts.slice(0, 3).map((artifact, artifactIndex) => (
                                      <span
                                        key={`${vuln.id}-${step.stage_id || index}-artifact-${artifactIndex}`}
                                        className="rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-semibold text-emerald-700"
                                        title={String(artifact.value)}
                                      >
                                        {artifact.name}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      {vuln.attack_artifacts && vuln.attack_artifacts.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {vuln.attack_artifacts.slice(0, 4).map((artifact, index) => (
                            <span
                              key={`${vuln.id}-artifact-${index}`}
                              className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-semibold text-slate-600"
                              title={String(artifact.value)}
                            >
                              {artifact.name}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}

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
