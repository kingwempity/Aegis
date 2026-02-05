import React, { useEffect, useState } from 'react';
import { api, Report } from '../api';

const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.getReports();
        setReports(data);
      } catch (error) {
        console.error('Error fetching reports:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-bold text-[#2d3343]">扫描报告</h2>
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
                  <span className="text-xs text-gray-400">{new Date(report.created_at).toLocaleDateString()}</span>
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
              <button className="mt-2 w-full py-2 bg-gray-50 text-[#2d3343] rounded-lg text-sm font-bold group-hover:bg-[#ff6b00] group-hover:text-white transition-all">
                查看详细报告
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Reports;
