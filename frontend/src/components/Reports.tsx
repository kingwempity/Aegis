import React, { useEffect, useState, useRef } from 'react';
import { api, getApiResourceUrl, type Report } from '../api';
import { Trash2, Download, ChevronDown } from './Icons';

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

  const handleViewReport = (taskId: number) => {
    // 在新窗口打开HTML报告
    window.open(getApiResourceUrl(`/reports/${taskId}/html`), '_blank');
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
        <h2 className="text-2xl font-bold text-[#2d3343]">扫描报告</h2>
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
    </div>
  );
};

export default Reports;