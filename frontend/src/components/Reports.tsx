import React, { useEffect, useState, useRef } from 'react';
import { api, getApiResourceUrl, type Report, type ReportPreview } from '../api';
import { Trash2, Download, ChevronDown, X } from './Icons';

// 导出格式类型
type ExportFormat = 'html' | 'pdf' | 'markdown' | 'excel' | 'json';

// 导出格式配置
const EXPORT_FORMATS: { value: ExportFormat; label: string; icon: string; description: string }[] = [
  { value: 'html', label: 'HTML', icon: '🌐', description: '网页格式，可直接在浏览器中查看' },
  { value: 'pdf', label: 'PDF', icon: '📄', description: '文档格式，适合打印和存档' },
  { value: 'markdown', label: 'Markdown', icon: '📝', description: '纯文本格式，可导入到其他工具' },
  { value: 'excel', label: 'Excel', icon: '📊', description: '表格格式，适合数据分析和筛选' },
  { value: 'json', label: 'JSON', icon: '{ }', description: '数据格式，适合程序处理和集成' },
];

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeDropdown, setActiveDropdown] = useState<number | null>(null);
  const [preview, setPreview] = useState<ReportPreview | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const fetchReports = async () => {
    try {
      const data = await api.getReports();
      setReports(data);
    } catch (error) {
      console.error('Error fetching reports:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  // 点击外部关闭下拉菜单
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
    } catch (e: any) {
      alert(e?.message || '删除失败');
    }
  };

  const getStrategyLabel = (strategy?: string) => {
    switch (strategy) {
      case 'attack_validation':
        return '模拟攻击验证';
      case 'full_audit':
        return '全量攻击验证';
      case 'focused_probe':
        return '定向漏洞验证';
      case 'default':
      case 'full':
      case 'fast':
        return '基础验证式扫描';
      default:
        return strategy || '基础验证式扫描';
    }
  };

  const handleViewReport = async (taskId: number) => {
    try {
      setPreviewLoading(true);
      const data = await api.getReportPreview(taskId);
      setPreview(data);
    } catch (error) {
      window.open(getApiResourceUrl(`/reports/${taskId}/html`), '_blank');
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleExportReport = (taskId: number, format: ExportFormat) => {
    // 直接下载导出文件
    const exportUrl = getApiResourceUrl(`/reports/${taskId}/export?format=${format}&include_evidence=true`);
    window.open(exportUrl, '_blank');
    setActiveDropdown(null);
  };

  const toggleDropdown = (reportId: number) => {
    setActiveDropdown(activeDropdown === reportId ? null : reportId);
  };

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
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
            <div key={report.id} className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4 hover:shadow-lg transition-all group">
              <div className="flex justify-between items-start">
                <div className="flex flex-col">
                  <span className="font-bold text-[#2d3343] truncate max-w-[200px]">{report.target_url}</span>
                  <span className="text-xs text-gray-400">{new Date(report.created_at).toLocaleString()}</span>
                </div>
                <div className={`px-3 py-1 rounded-lg text-xs font-bold ${
                  report.risk_score > 70 ? 'bg-red-100 text-red-600' : 
                  report.risk_score > 40 ? 'bg-orange-100 text-orange-600' : 'bg-green-100 text-green-600'
                }`}>
                  Score: {report.risk_score}
                </div>
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
              
              {/* 操作按钮区域 */}
              <div className="mt-2 flex gap-2">
                <button 
                  onClick={() => handleViewReport(report.task_id)}
                  className="flex-1 py-2 bg-gray-50 text-[#2d3343] rounded-lg text-sm font-bold group-hover:bg-[#ff6b00] group-hover:text-white transition-all"
                >
                  查看报告
                </button>
                
                {/* 导出下拉按钮 */}
                <div className="relative" ref={activeDropdown === report.id ? dropdownRef : undefined}>
                  <button 
                    onClick={() => toggleDropdown(report.id)}
                    className="flex items-center gap-1 py-2 px-3 bg-gray-50 text-[#2d3343] rounded-lg text-sm font-bold hover:bg-gray-100 transition-all"
                    title="导出报告"
                  >
                    <Download size={16} />
                    <ChevronDown size={14} />
                  </button>
                  
                  {/* 下拉菜单 */}
                  {activeDropdown === report.id && (
                    <div className="absolute right-0 top-full mt-1 w-56 bg-white rounded-xl shadow-lg border border-gray-100 py-2 z-50">
                      <div className="px-3 py-2 text-xs font-bold text-gray-400 border-b border-gray-100">
                        选择导出格式
                      </div>
                      {EXPORT_FORMATS.map((format) => (
                        <button
                          key={format.value}
                          onClick={() => handleExportReport(report.task_id, format.value)}
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
                  onClick={() => handleDeleteReport(report.task_id, report.target_url)}
                  className="p-2 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-colors"
                  title="删除报告"
                >
                  <Trash2 size={18} strokeWidth={2} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {preview && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4"
          onClick={() => setPreview(null)}
        >
          <div
            className="max-h-[85vh] w-full max-w-4xl overflow-hidden rounded-3xl bg-white shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-start justify-between border-b border-gray-100 px-8 py-6">
              <div>
                <h3 className="text-2xl font-bold text-[#2d3343]">模拟攻击报告预览</h3>
                <p className="mt-1 text-sm text-gray-400">{preview.target_url}</p>
              </div>
              <button
                onClick={() => setPreview(null)}
                className="rounded-xl p-2 text-gray-400 transition-colors hover:bg-gray-50 hover:text-gray-600"
              >
                <X size={22} />
              </button>
            </div>

            <div className="space-y-6 overflow-y-auto px-8 py-6">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
                <div className="rounded-2xl bg-orange-50 p-4">
                  <div className="text-xs text-gray-400">验证模式</div>
                  <div className="mt-2 text-sm font-bold text-[#c25b00]">
                    {getStrategyLabel(preview.scan_strategy)}
                  </div>
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
              </div>

              <div className="rounded-2xl border border-gray-100 p-5">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-[#2d3343]">典型漏洞与可利用性证明</h4>
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
                    preview.vulnerabilities.slice(0, 5).map((vuln) => (
                      <div key={vuln.id} className="rounded-2xl bg-gray-50 p-4">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div>
                            <div className="font-bold text-[#2d3343]">{vuln.title}</div>
                            <div className="mt-1 text-sm text-gray-500">
                              {vuln.type || '通用 Web 漏洞'}{vuln.parameter ? ` · 参数 ${vuln.parameter}` : ''}{vuln.cvss_score ? ` · CVSS ${vuln.cvss_score}` : ''}
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            {vuln.payload_present && (
                              <span className="rounded-full bg-orange-100 px-2.5 py-1 text-xs font-semibold text-[#c25b00]">攻击载荷</span>
                            )}
                            {vuln.attack_path_present && (
                              <span className="rounded-full bg-blue-100 px-2.5 py-1 text-xs font-semibold text-blue-600">攻击路径</span>
                            )}
                            {vuln.evidence_present && (
                              <span className="rounded-full bg-green-100 px-2.5 py-1 text-xs font-semibold text-green-600">证据链</span>
                            )}
                          </div>
                        </div>
                        <p className="mt-3 text-sm text-gray-500">{vuln.description || '暂无详细验证摘要。'}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
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
