import React, { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Card, Button, Table, Tag, Space, message, Spin, Empty,
  Descriptions, Progress, List, Avatar, Tooltip, Modal, Select
} from 'antd';
import {
  FileTextOutlined, DownloadOutlined, EyeOutlined,
  AlertOutlined, CheckCircleOutlined, FilterOutlined,
  ExportOutlined, PrinterOutlined, ReloadOutlined
} from '@ant-design/icons';
import { apiService } from '../services/api';
import { ScanReport, Vulnerability, Task } from '../types';
import { useAuth } from '../hooks/useAuth';

const { Option } = Select;

// 将扫描报告生成 HTML 文本
const generateHtmlReport = (report: ScanReport, includeEvidence: boolean): string => {
  const lines: string[] = [];

  lines.push(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>漏洞检测报告 - ${report.task_id}</title>
    <style>
        /* PDF优化样式 */
        * { box-sizing: border-box; }
        body {
            font-family: 'Arial', 'Helvetica', 'Microsoft YaHei', sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.5;
            color: #333;
            background: white;
            font-size: 12px;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%);
            color: white;
            padding: 25px 30px;
            margin-bottom: 25px;
            border-radius: 8px;
            text-align: center;
        }

        .header h1 {
            margin: 0 0 15px 0;
            font-size: 24px;
            font-weight: bold;
        }

        .header p {
            margin: 5px 0;
            font-size: 14px;
        }

        .summary {
            background: #f8f9fa;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 6px;
            border: 1px solid #e9ecef;
        }

        .summary h2 {
            margin: 0 0 20px 0;
            color: #2c3e50;
            font-size: 18px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 8px;
        }

        .vulnerabilities h2 {
            color: #2c3e50;
            font-size: 18px;
            margin: 30px 0 20px 0;
            border-bottom: 2px solid #e74c3c;
            padding-bottom: 8px;
        }

        .vulnerability {
            border: 1px solid #dee2e6;
            padding: 15px;
            margin-bottom: 12px;
            border-radius: 6px;
            background: white;
            page-break-inside: avoid;
        }

        .critical { border-left: 4px solid #e74c3c; background: #fdf2f2; }
        .high { border-left: 4px solid #e67e22; background: #fdf7f0; }
        .medium { border-left: 4px solid #f39c12; background: #fdfdf0; }
        .low { border-left: 4px solid #27ae60; background: #f2fdf2; }
        .info { border-left: 4px solid #3498db; background: #f0f8fd; }

        .vulnerability h3 {
            margin: 0 0 12px 0;
            color: #2c3e50;
            font-size: 16px;
            font-weight: bold;
        }

        /* 统计卡片网格 */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
            margin: 20px 0;
        }

        .stat-card {
            text-align: center;
            padding: 15px 10px;
            border-radius: 6px;
            border: 1px solid #ddd;
            background: white;
        }

        .stat-critical { border-color: #e74c3c; background: #fee; }
        .stat-high { border-color: #e67e22; background: #ffe; }
        .stat-medium { border-color: #f39c12; background: #fff8e1; }
        .stat-low { border-color: #27ae60; background: #efe; }
        .stat-info { border-color: #3498db; background: #eff; }

        .stat-number {
            font-size: 28px;
            font-weight: bold;
            display: block;
            margin-bottom: 5px;
        }

        .stat-critical .stat-number { color: #e74c3c; }
        .stat-high .stat-number { color: #e67e22; }
        .stat-medium .stat-number { color: #f39c12; }
        .stat-low .stat-number { color: #27ae60; }
        .stat-info .stat-number { color: #3498db; }

        .stat-label {
            font-size: 12px;
            color: #666;
            font-weight: 500;
        }

        /* 表格样式 */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 11px;
            background: white;
        }

        th, td {
            border: 1px solid #ddd;
            padding: 8px 10px;
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
            font-size: 12px;
        }

        tr:nth-child(even) {
            background: #f8f9fa;
        }

        /* 代码块样式 */
        .code {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            margin: 10px 0;
            border: 1px solid #e9ecef;
            font-size: 11px;
            line-height: 1.4;
            white-space: pre-wrap;
            word-break: break-all;
        }

        /* 链接样式 */
        .references {
            margin-top: 12px;
        }

        .references a {
            color: #3498db;
            text-decoration: none;
            font-size: 12px;
        }

        .references a:hover {
            text-decoration: underline;
        }

        /* 分页控制 */
        .page-break {
            page-break-before: always;
        }

        /* 避免在元素中间分页 */
        h1, h2, h3 {
            page-break-after: avoid;
        }

        .vulnerability {
            page-break-inside: avoid;
        }

        /* 响应式设计 */
        @media print {
            body { margin: 15px; }
            .header { padding: 20px; }
            .summary, .vulnerability { padding: 12px; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Web应用程序漏洞检测报告</h1>
        <p><strong>任务ID:</strong> ${report.task_id}</p>
        <p><strong>目标URL:</strong> ${report.target_url}</p>
        <p><strong>扫描时间:</strong> ${new Date(report.scan_time).toLocaleString('zh-CN')}</p>
        <p><strong>扫描持续时间:</strong> ${Math.floor(report.scan_duration / 60)}分 ${report.scan_duration % 60}秒</p>
    </div>

    <div class="summary">
        <h2>扫描概览</h2>
        <table>
            <tr><th>扫描页面数</th><td>${report.summary.pages_scanned}</td></tr>
            <tr><th>执行模块数</th><td>${report.summary.modules_executed}</td></tr>
            <tr><th>服务器信息</th><td>${report.technology_stack.server || '未知'}</td></tr>
            <tr><th>编程语言</th><td>${report.technology_stack.language || '未知'}</td></tr>
            <tr><th>框架</th><td>${report.technology_stack.framework || '未知'}</td></tr>
            <tr><th>数据库</th><td>${report.technology_stack.database || '未知'}</td></tr>
        </table>

        <h3>漏洞统计</h3>
        <div class="stats-grid">
            <div class="stat-card stat-critical">
                <div class="stat-number">${report.summary.critical}</div>
                <div class="stat-label">危急</div>
            </div>
            <div class="stat-card stat-high">
                <div class="stat-number">${report.summary.high}</div>
                <div class="stat-label">高危</div>
            </div>
            <div class="stat-card stat-medium">
                <div class="stat-number">${report.summary.medium}</div>
                <div class="stat-label">中危</div>
            </div>
            <div class="stat-card stat-low">
                <div class="stat-number">${report.summary.low}</div>
                <div class="stat-label">低危</div>
            </div>
            <div class="stat-card stat-info">
                <div class="stat-number">${report.summary.info}</div>
                <div class="stat-label">信息</div>
            </div>
        </div>
    </div>

    <div class="vulnerabilities">
        <h2>漏洞详情</h2>`);

  if (!report.vulnerabilities || report.vulnerabilities.length === 0) {
    lines.push('<p>当前报告未发现漏洞。</p>');
  } else {
    report.vulnerabilities.forEach((v, index) => {
      const riskClass = v.risk_level.toLowerCase();
      lines.push(`
        <div class="vulnerability ${riskClass}">
            <h3>${index + 1}. [${v.risk_level.toUpperCase()}] ${v.name} (CVSS: ${v.cvss_score})</h3>
            <table>
                <tr><th>漏洞类型</th><td>${v.type}</td></tr>
                <tr><th>风险等级</th><td>${v.risk_level}</td></tr>
                <tr><th>CVSS评分</th><td>${v.cvss_score}</td></tr>
                <tr><th>CVSS向量</th><td>${v.cvss_vector}</td></tr>
                <tr><th>URL</th><td>${v.url}</td></tr>
                <tr><th>请求方法</th><td>${v.method}</td></tr>`);

      if (v.parameter) {
        lines.push(`<tr><th>参数</th><td>${v.parameter}</td></tr>`);
      }

      if (v.payload) {
        lines.push(`<tr><th>攻击载荷</th><td><div class="code">${v.payload}</div></td></tr>`);
      }

      lines.push(`<tr><th>发现时间</th><td>${new Date(v.detected_at).toLocaleString('zh-CN')}</td></tr>
                <tr><th>描述</th><td>${v.description}</td></tr>
                <tr><th>修复建议</th><td>${v.remediation}</td></tr>
                <tr><th>证据</th><td>${v.evidence || '无证据详情'}</td></tr>`);

      if (includeEvidence) {
        if (v.attack_steps && v.attack_steps.length > 0) {
          lines.push(`<tr><th>攻击过程</th><td>
                    <ol>`);
          v.attack_steps.forEach((step, i) => {
            lines.push(`<li>${step.action} （响应码: ${step.response_code}, 时间: ${step.response_time_ms}ms）</li>`);
          });
          lines.push(`</ol></td></tr>`);
        }

        if (v.screenshots && v.screenshots.length > 0) {
          lines.push(`<tr><th>截图/证据链接</th><td>
                    <ul>`);
          v.screenshots.forEach((screenshot, i) => {
            lines.push(`<li>图 ${i + 1}: ${screenshot.description || '截图'} (${screenshot.url})</li>`);
          });
          lines.push(`</ul></td></tr>`);
        }
      }

      if (v.references && v.references.length > 0) {
        lines.push(`<tr><th>参考资料</th><td class="references">
                    <ul>`);
        v.references.forEach((ref) => {
          lines.push(`<li><a href="${ref}" target="_blank">${ref}</a></li>`);
        });
        lines.push(`</ul></td></tr>`);
      }

      lines.push(`</table>
        </div>`);
    });
  }

  lines.push(`
    </div>
</body>
</html>`);

  return lines.join('\n');
};

// 将扫描报告生成 Markdown 文本，便于本地保存或二次转换为其他格式
const generateMarkdownReport = (report: ScanReport, includeEvidence: boolean): string => {
  const lines: string[] = [];

  lines.push(`# 漏洞检测报告`);
  lines.push('');
  lines.push(`- 任务ID: ${report.task_id}`);
  lines.push(`- 目标URL: ${report.target_url}`);
  lines.push(`- 扫描时间: ${new Date(report.scan_time).toLocaleString('zh-CN')}`);
  lines.push(
    `- 扫描持续时间: ${Math.floor(report.scan_duration / 60)} 分 ${report.scan_duration % 60} 秒`
  );
  lines.push('');

  lines.push(`## 扫描概览`);
  lines.push(`- 扫描页面数: ${report.summary.pages_scanned}`);
  lines.push(`- 执行模块数: ${report.summary.modules_executed}`);
  lines.push('');
  lines.push(`### 技术栈信息`);
  lines.push(`- 服务器: ${report.technology_stack.server || '未知'}`);
  lines.push(`- 编程语言: ${report.technology_stack.language || '未知'}`);
  lines.push(`- 框架: ${report.technology_stack.framework || '未知'}`);
  lines.push(`- 数据库: ${report.technology_stack.database || '未知'}`);
  lines.push('');

  lines.push(`## 漏洞统计`);
  lines.push(`- 总漏洞数: ${report.summary.total_vulnerabilities}`);
  lines.push(`- 危急: ${report.summary.critical}`);
  lines.push(`- 高危: ${report.summary.high}`);
  lines.push(`- 中危: ${report.summary.medium}`);
  lines.push(`- 低危: ${report.summary.low}`);
  lines.push(`- 信息: ${report.summary.info}`);
  lines.push('');

  lines.push(`## 漏洞详情`);
  if (!report.vulnerabilities || report.vulnerabilities.length === 0) {
    lines.push('');
    lines.push(`当前报告未发现漏洞。`);
  } else {
    report.vulnerabilities.forEach((v, index) => {
      lines.push('');
      lines.push(
        `### ${index + 1}. [${v.risk_level.toUpperCase()}] ${v.name} (CVSS: ${v.cvss_score})`
      );
      lines.push(`- 漏洞类型: ${v.type}`);
      lines.push(`- URL: ${v.url}`);
      lines.push(`- 请求方法: ${v.method}`);
      if (v.parameter) {
        lines.push(`- 参数: ${v.parameter}`);
      }
      if (v.payload) {
        lines.push('');
        lines.push(`**攻击载荷**`);
        lines.push('');
        lines.push('```');
        lines.push(v.payload);
        lines.push('```');
      }
      lines.push('');
      lines.push(`- 风险等级: ${v.risk_level}`);
      lines.push(`- CVSS 向量: ${v.cvss_vector}`);
      lines.push(`- 发现时间: ${new Date(v.detected_at).toLocaleString('zh-CN')}`);
      lines.push('');
      lines.push(`**漏洞描述**`);
      lines.push('');
      lines.push(v.description);
      lines.push('');
      lines.push(`**修复建议**`);
      lines.push('');
      lines.push(v.remediation);

      if (includeEvidence) {
        lines.push('');
        lines.push(`**攻击证据**`);
        lines.push('');
        lines.push(v.evidence || '（无证据详情）');

        if (v.attack_steps && v.attack_steps.length > 0) {
          lines.push('');
          lines.push(`**攻击过程**`);
          lines.push('');
          v.attack_steps.forEach((step, i) => {
            lines.push(
              `${i + 1}. ${step.action} （响应码: ${step.response_code}, 时间: ${step.response_time_ms}ms）`
            );
          });
        }

        if (v.screenshots && v.screenshots.length > 0) {
          lines.push('');
          lines.push(`**截图/证据链接**`);
          lines.push('');
          v.screenshots.forEach((screenshot, i) => {
            lines.push(
              `- 图 ${i + 1}: ${screenshot.description || '截图'} (${screenshot.url})`
            );
          });
        }
      }

      if (v.references && v.references.length > 0) {
        lines.push('');
        lines.push(`**参考资料**`);
        lines.push('');
        v.references.forEach((ref) => {
          lines.push(`- ${ref}`);
        });
      }
    });
  }

  lines.push('');
  lines.push(`---`);
  lines.push(`报告由漏洞检测系统自动生成（Markdown 格式），可导入到 Word、Typora 等工具转换为 PDF、HTML 等格式。`);

  return lines.join('\n');
};

const Reports: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const taskId = searchParams.get('taskId');

  const [report, setReport] = useState<ScanReport | null>(null);
  const [reportsList, setReportsList] = useState<Task[]>([]);
  const [loading, setLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [exportModalVisible, setExportModalVisible] = useState(false);
  const [exportFormat, setExportFormat] = useState<'docx' | 'json' | 'html' | 'markdown' | 'pdf'>('docx');
  const [includeEvidence, setIncludeEvidence] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Vulnerability | null>(null);
  const [vulnerabilityModalVisible, setVulnerabilityModalVisible] = useState(false);
  const [pagination, setPagination] = useState({
    current: 1,
    pageSize: 10,
    total: 0,
  });

  useEffect(() => {
    if (taskId) {
      loadReport();
    } else {
      loadReportsList();
    }
  }, [taskId, pagination.current, pagination.pageSize]);

  const loadReport = async () => {
    if (!taskId) return;

    setLoading(true);
    try {
      const reportData = await apiService.getScanReport(taskId);
      if (typeof reportData === 'object' && 'task_id' in reportData) {
        setReport(reportData);
      }
    } catch (error: any) {
      message.error(error.response?.data?.message || '加载报告失败');
      navigate('/reports');
    } finally {
      setLoading(false);
    }
  };

  const loadReportsList = async () => {
    setListLoading(true);
    try {
      const response = await apiService.getTasks({
        page: pagination.current,
        page_size: pagination.pageSize,
        status_filter: 'completed', // 只显示已完成的任务
        sort_by: 'completed_at',
        order: 'desc'
      });
      setReportsList(response.tasks);
      setPagination(prev => ({
        ...prev,
        total: response.total,
      }));
    } catch (error) {
      message.error('加载报告列表失败');
    } finally {
      setListLoading(false);
    }
  };

  const handleExport = async () => {
    if (!taskId) {
      message.error('任务ID不存在');
      return;
    }

    if (!report) {
      message.error('报告数据尚未加载，请稍后重试');
      return;
    }

    try {
      let blob: Blob;
      let filename: string;
      let mimeType: string;

      switch (exportFormat) {
        case 'json':
          // 生成JSON格式
          const jsonData = JSON.stringify(report, null, 2);
          blob = new Blob([jsonData], { type: 'application/json;charset=utf-8' });
          filename = `scan_report_${taskId}.json`;
          mimeType = 'JSON';
          break;

        case 'html':
          // 生成HTML格式
          const htmlContent = generateHtmlReport(report, includeEvidence);
          blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
          filename = `scan_report_${taskId}.html`;
          mimeType = 'HTML';
          break;

        case 'markdown':
          // 生成Markdown格式
          const markdown = generateMarkdownReport(report, includeEvidence);
          blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
          filename = `scan_report_${taskId}.md`;
          mimeType = 'Markdown';
          break;

        case 'pdf':
          // PDF格式通过后端生成
          try {
            const pdfResponse = await apiService.exportReport(taskId, 'pdf', includeEvidence);
            // 后端直接返回PDF文件流
            blob = pdfResponse;
            filename = `scan_report_${taskId}.pdf`;
            mimeType = 'PDF';
          } catch (pdfError) {
            console.error('PDF导出失败:', pdfError);
            message.error('PDF导出失败，请稍后重试');
            return;
          }
          break;

        case 'docx':
          // 生成DOCX格式
          try {
            // 动态导入DOCX生成库
            const {
              Document,
              Packer,
              Paragraph,
              TextRun,
              Table,
              TableCell,
              TableRow,
              WidthType,
              AlignmentType,
            } = await import('docx');

            const children: any[] = [];

            // 标题
            children.push(
              new Paragraph({
                children: [
                  new TextRun({
                    text: 'Web应用程序漏洞检测报告',
                    bold: true,
                    size: 32,
                    color: '2C3E50',
                  }),
                ],
                alignment: AlignmentType.CENTER,
                spacing: { after: 400 },
              })
            );

            // 基本信息
            children.push(
              new Paragraph({
                children: [
                  new TextRun({ text: `任务ID: ${report.task_id}`, size: 24 }),
                ],
                spacing: { after: 200 },
              }),
              new Paragraph({
                children: [
                  new TextRun({ text: `目标URL: ${report.target_url}`, size: 24 }),
                ],
                spacing: { after: 200 },
              }),
              new Paragraph({
                children: [
                  new TextRun({ text: `扫描时间: ${new Date(report.scan_time).toLocaleString('zh-CN')}`, size: 24 }),
                ],
                spacing: { after: 200 },
              }),
              new Paragraph({
                children: [
                  new TextRun({ text: `扫描持续时间: ${Math.floor(report.scan_duration / 60)}分 ${report.scan_duration % 60}秒`, size: 24 }),
                ],
                spacing: { after: 200 },
              })
            );

            // 扫描概览
            children.push(
              new Paragraph({
                children: [
                  new TextRun({
                    text: '扫描概览',
                    bold: true,
                    size: 28,
                    color: '3498DB',
                  }),
                ],
                spacing: { after: 300 },
              })
            );

            // 概览表格
            const overviewTable = new Table({
              width: {
                size: 100,
                type: WidthType.PERCENTAGE,
              },
              rows: [
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '扫描页面数', bold: true })] })],
                      width: { size: 40, type: WidthType.PERCENTAGE },
                    }),
                    new TableCell({
                      children: [new Paragraph(report.summary.pages_scanned.toString())],
                      width: { size: 60, type: WidthType.PERCENTAGE },
                    }),
                  ],
                }),
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '执行模块数', bold: true })] })],
                    }),
                    new TableCell({
                      children: [new Paragraph(report.summary.modules_executed.toString())],
                    }),
                  ],
                }),
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '服务器信息', bold: true })] })],
                    }),
                    new TableCell({
                      children: [new Paragraph(report.technology_stack.server || '未知')],
                    }),
                  ],
                }),
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '编程语言', bold: true })] })],
                    }),
                    new TableCell({
                      children: [new Paragraph(report.technology_stack.language || '未知')],
                    }),
                  ],
                }),
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '框架', bold: true })] })],
                    }),
                    new TableCell({
                      children: [new Paragraph(report.technology_stack.framework || '未知')],
                    }),
                  ],
                }),
                new TableRow({
                  children: [
                    new TableCell({
                      children: [new Paragraph({ children: [new TextRun({ text: '数据库', bold: true })] })],
                    }),
                    new TableCell({
                      children: [new Paragraph(report.technology_stack.database || '未知')],
                    }),
                  ],
                }),
              ],
            });
            children.push(overviewTable);

            // 漏洞统计
            children.push(
              new Paragraph({
                children: [
                  new TextRun({
                    text: '漏洞统计',
                    bold: true,
                    size: 28,
                    color: 'E74C3C',
                  }),
                ],
                spacing: { after: 300 },
              }),
              new Paragraph({
                children: [
                  new TextRun({ text: `危急: ${report.summary.critical}    `, color: 'E74C3C', bold: true }),
                  new TextRun({ text: `高危: ${report.summary.high}    `, color: 'E67E22', bold: true }),
                  new TextRun({ text: `中危: ${report.summary.medium}    `, color: 'F39C12', bold: true }),
                  new TextRun({ text: `低危: ${report.summary.low}    `, color: '27AE60', bold: true }),
                  new TextRun({ text: `信息: ${report.summary.info}`, color: '3498DB', bold: true }),
                ],
                spacing: { after: 200 },
              }),
              new Paragraph({
                children: [
                  new TextRun({
                    text: `总共发现 ${report.summary.total_vulnerabilities} 个安全问题`,
                    size: 24,
                  }),
                ],
                spacing: { after: 300 },
              })
            );

            // 漏洞详情
            if (report.vulnerabilities && report.vulnerabilities.length > 0) {
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({
                      text: '漏洞详情',
                      bold: true,
                      size: 28,
                      color: '2C3E50',
                    }),
                  ],
                  spacing: { after: 300 },
                })
              );

              report.vulnerabilities.forEach((v, index) => {
                // 根据风险等级设置颜色
                const getRiskColor = (level: string) => {
                  switch (level) {
                    case 'critical': return 'E74C3C';
                    case 'high': return 'E67E22';
                    case 'medium': return 'F39C12';
                    case 'low': return '27AE60';
                    case 'info': return '3498DB';
                    default: return '2C3E50';
                  }
                };

                children.push(
                  new Paragraph({
                    children: [
                      new TextRun({
                        text: `${index + 1}. [${v.risk_level.toUpperCase()}] ${v.name} (CVSS: ${v.cvss_score})`,
                        bold: true,
                        size: 26,
                        color: getRiskColor(v.risk_level),
                      }),
                    ],
                    spacing: { after: 250 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `漏洞类型: ${v.type}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `风险等级: ${v.risk_level}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `CVSS评分: ${v.cvss_score}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `URL: ${v.url}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `请求方法: ${v.method}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  })
                );

                if (v.parameter) {
                  children.push(
                    new Paragraph({
                      children: [
                        new TextRun({ text: `参数: ${v.parameter}`, size: 22 }),
                      ],
                      spacing: { after: 150 },
                    })
                  );
                }

                if (v.payload) {
                  children.push(
                    new Paragraph({
                      children: [
                        new TextRun({ text: `攻击载荷: ${v.payload}`, size: 22 }),
                      ],
                      spacing: { after: 150 },
                    })
                  );
                }

                children.push(
                  new Paragraph({
                    children: [
                      new TextRun({ text: `发现时间: ${new Date(v.detected_at).toLocaleString('zh-CN')}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `描述: ${v.description}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `修复建议: ${v.remediation}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  }),
                  new Paragraph({
                    children: [
                      new TextRun({ text: `证据: ${v.evidence || '无证据详情'}`, size: 22 }),
                    ],
                    spacing: { after: 150 },
                  })
                );

                if (includeEvidence) {
                  if (v.attack_steps && v.attack_steps.length > 0) {
                    children.push(
                      new Paragraph({
                        children: [
                          new TextRun({ text: '攻击过程:', bold: true, size: 24 }),
                        ],
                        spacing: { after: 200 },
                      })
                    );
                    v.attack_steps.forEach((step, i) => {
                      children.push(
                        new Paragraph({
                          children: [
                            new TextRun({ text: `${i + 1}. ${step.action} （响应码: ${step.response_code}, 时间: ${step.response_time_ms}ms）`, size: 22 }),
                          ],
                          spacing: { after: 150 },
                        })
                      );
                    });
                  }

                  if (v.references && v.references.length > 0) {
                    children.push(
                      new Paragraph({
                        children: [
                          new TextRun({ text: '参考资料:', bold: true, size: 24 }),
                        ],
                        spacing: { after: 200 },
                      })
                    );
                    v.references.forEach((ref) => {
                      children.push(
                        new Paragraph({
                          children: [
                            new TextRun({ text: ref, size: 22, color: '0066CC' }),
                          ],
                          spacing: { after: 150 },
                        })
                      );
                    });
                  }
                }
              });
            } else {
              children.push(
                new Paragraph({
                  children: [
                    new TextRun({ text: '当前报告未发现漏洞。', size: 24 }),
                  ],
                  spacing: { after: 200 },
                })
              );
            }

            // 创建文档
            const doc = new Document({
              sections: [
                {
                  properties: {},
                  children: children,
                },
              ],
            });

            // 生成DOCX文件
            const buffer = await Packer.toBlob(doc);
            blob = buffer;
            filename = `scan_report_${taskId}.docx`;
            mimeType = 'Word文档';
          } catch (docxError) {
            console.error('DOCX生成失败:', docxError);
            // 如果DOCX生成失败，回退到HTML格式
            const htmlContent = generateHtmlReport(report, includeEvidence);
            blob = new Blob([htmlContent], { type: 'text/html;charset=utf-8' });
            filename = `scan_report_${taskId}.html`;
            mimeType = 'HTML (Word文档生成失败，回退到HTML)';
            message.warning('Word文档生成失败，已导出为HTML格式');
          }
          break;

        default:
          message.error('不支持的导出格式');
          return;
      }

      // 创建下载链接
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      message.success(`${mimeType} 报告导出成功`);
      setExportModalVisible(false);

    } catch (error: any) {
      console.error('导出报告失败:', error);
      message.error('导出报告失败，请稍后重试');
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'critical': return 'red';
      case 'high': return 'orange';
      case 'medium': return 'yellow';
      case 'low': return 'blue';
      case 'info': return 'gray';
      default: return 'default';
    }
  };

  const getRiskText = (level: string) => {
    switch (level) {
      case 'critical': return '危急';
      case 'high': return '高危';
      case 'medium': return '中危';
      case 'low': return '低危';
      case 'info': return '信息';
      default: return level;
    }
  };

  const vulnerabilityColumns = [
    {
      title: '漏洞名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string, record: Vulnerability) => (
        <div>
          <div className="font-medium text-gray-900 dark:text-gray-100">{text}</div>
          <div className="text-sm text-gray-500">{record.type}</div>
        </div>
      ),
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      key: 'risk_level',
      render: (level: string, record: Vulnerability) => (
        <Tag color={getRiskColor(level)}>
          {getRiskText(level)} ({record.cvss_score})
        </Tag>
      ),
    },
    {
      title: 'URL',
      dataIndex: 'url',
      key: 'url',
      render: (url: string, record: Vulnerability) => (
        <div>
          <div className="text-sm font-mono break-all">{url}</div>
          <div className="text-xs text-gray-500">
            {record.method} {record.parameter && `| 参数: ${record.parameter}`}
          </div>
        </div>
      ),
    },
    {
      title: '发现时间',
      dataIndex: 'detected_at',
      key: 'detected_at',
      render: (date: string) => new Date(date).toLocaleString('zh-CN'),
    },
    {
      title: '操作',
      key: 'action',
      render: (_: any, record: Vulnerability) => (
        <Space size="small">
          <Button
            type="link"
            size="small"
            icon={<EyeOutlined />}
            onClick={() => {
              setSelectedVulnerability(record);
              setVulnerabilityModalVisible(true);
            }}
            className="text-tape-brown hover:text-tape-dark"
          >
            详情
          </Button>
        </Space>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-96">
        <Spin size="large" />
      </div>
    );
  }

  // 如果有taskId但没有报告，显示错误信息
  if (taskId && !report) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              检测报告
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              查看和导出安全检测报告
            </p>
          </div>
          <Button
            icon={<FileTextOutlined />}
            onClick={() => navigate('/reports')}
            className="bg-tape-brown hover:bg-tape-dark border-tape-brown hover:border-tape-dark"
          >
            返回报告列表
          </Button>
        </div>

        <Card className="card-retro">
          <Empty
            description="报告未生成或任务尚未完成"
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          >
            <Button
              type="primary"
              onClick={() => navigate('/reports')}
              className="bg-tape-brown hover:bg-tape-dark border-tape-brown hover:border-tape-dark"
            >
              返回报告列表
            </Button>
          </Empty>
        </Card>
      </div>
    );
  }

  // 如果没有taskId，显示报告列表
  if (!taskId) {
    const reportsColumns = [
      {
        title: '任务名称',
        dataIndex: 'task_name',
        key: 'task_name',
        render: (name: string, record: Task) => name || `任务 ${record.task_id.slice(-6)}`,
      },
      {
        title: '目标URL',
        dataIndex: 'target_url',
        key: 'target_url',
        ellipsis: true,
        render: (url: string) => (
          <Tooltip title={url}>
            <span className="truncate max-w-xs inline-block">{url}</span>
          </Tooltip>
        ),
      },
      {
        title: '漏洞数量',
        dataIndex: 'vulnerabilities_found',
        key: 'vulnerabilities_found',
        render: (count: number) => (
          <Tag color={count > 0 ? 'red' : 'green'}>
            {count || 0}
          </Tag>
        ),
      },
      {
        title: '完成时间',
        dataIndex: 'completed_at',
        key: 'completed_at',
        render: (date: string) => date ? new Date(date).toLocaleString('zh-CN') : '-',
      },
      {
        title: '操作',
        key: 'action',
        render: (_: any, record: Task) => (
          <Space size="small">
            <Button
              type="link"
              icon={<EyeOutlined />}
              onClick={() => navigate(`/reports?taskId=${record.task_id}`)}
              className="text-tape-brown hover:text-tape-dark"
            >
              查看报告
            </Button>
            <Button
              type="link"
              icon={<ExportOutlined />}
              onClick={() => {
                setExportModalVisible(true);
                // 设置当前任务ID用于导出
                navigate(`/reports?taskId=${record.task_id}`, { replace: true });
              }}
              className="text-blue-600 hover:text-blue-800"
            >
              导出
            </Button>
          </Space>
        ),
      },
    ];

    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              检测报告
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              查看已完成的扫描任务报告
            </p>
          </div>
          <Space>
            <Button
              icon={<ReloadOutlined />}
              onClick={loadReportsList}
              loading={listLoading}
            >
              刷新
            </Button>
            <Button
              icon={<FileTextOutlined />}
              onClick={() => navigate('/tasks')}
              className="bg-tape-brown hover:bg-tape-dark border-tape-brown hover:border-tape-dark"
            >
              查看所有任务
            </Button>
          </Space>
        </div>

        <Card className="card-retro">
          <Table
            columns={reportsColumns}
            dataSource={reportsList}
            loading={listLoading}
            rowKey="task_id"
            pagination={{
              current: pagination.current,
              pageSize: pagination.pageSize,
              total: pagination.total,
              onChange: (page, pageSize) => {
                setPagination(prev => ({ ...prev, current: page, pageSize }));
              },
              showSizeChanger: true,
              showQuickJumper: true,
              showTotal: (total, range) =>
                `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
            }}
            locale={{
              emptyText: (
                <Empty
                  description="暂无已完成的扫描任务"
                  image={Empty.PRESENTED_IMAGE_SIMPLE}
                >
                  <Button
                    type="primary"
                    onClick={() => navigate('/tasks')}
                    className="bg-tape-brown hover:bg-tape-dark border-tape-brown hover:border-tape-dark"
                  >
                    创建新任务
                  </Button>
                </Empty>
              ),
            }}
          />
        </Card>
      </div>
    );
  }

  // 确保report存在（虽然前面已经检查，但为了类型安全）
  if (!report) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              检测报告
            </h1>
            <p className="text-gray-600 dark:text-gray-400 mt-1">
              报告数据加载失败
            </p>
          </div>
          <Button
            icon={<FileTextOutlined />}
            onClick={() => navigate('/reports')}
            className="bg-tape-brown hover:bg-tape-dark border-tape-brown hover:border-tape-dark"
          >
            返回报告列表
          </Button>
        </div>
        <Card className="card-retro">
          <Empty description="报告数据加载失败，请重试" />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 标题和操作 */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
            检测报告
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            任务ID: {report.task_id} | 扫描时间: {new Date(report.scan_time).toLocaleString('zh-CN')}
          </p>
        </div>
        <Space>
          <Button
            icon={<ExportOutlined />}
            onClick={() => setExportModalVisible(true)}
          >
            导出报告
          </Button>
          <Button
            icon={<PrinterOutlined />}
            onClick={() => window.print()}
          >
            打印
          </Button>
          <Button
            icon={<FileTextOutlined />}
            onClick={() => navigate('/tasks')}
          >
            返回任务列表
          </Button>
        </Space>
      </div>

      {/* 扫描概览 */}
      <Card className="card-modern" title="扫描概览">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Descriptions column={1} size="small">
            <Descriptions.Item label="目标URL">{report.target_url}</Descriptions.Item>
            <Descriptions.Item label="扫描持续时间">
              {Math.floor(report.scan_duration / 60)}分 {report.scan_duration % 60}秒
            </Descriptions.Item>
            <Descriptions.Item label="扫描页面数">{report.summary.pages_scanned}</Descriptions.Item>
            <Descriptions.Item label="执行模块数">{report.summary.modules_executed}</Descriptions.Item>
          </Descriptions>

          <Descriptions column={1} size="small">
            <Descriptions.Item label="服务器信息">
              {report.technology_stack.server || '未知'}
            </Descriptions.Item>
            <Descriptions.Item label="编程语言">
              {report.technology_stack.language || '未知'}
            </Descriptions.Item>
            <Descriptions.Item label="框架">
              {report.technology_stack.framework || '未知'}
            </Descriptions.Item>
            <Descriptions.Item label="数据库">
              {report.technology_stack.database || '未知'}
            </Descriptions.Item>
          </Descriptions>
        </div>
      </Card>

      {/* 漏洞统计 */}
      <Card className="card-modern" title="漏洞统计">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <Card size="small" className="text-center border-red-200 bg-red-50 dark:bg-red-900/20">
            <div className="text-3xl font-bold text-red-600">{report.summary.critical}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">危急</div>
          </Card>
          <Card size="small" className="text-center border-orange-200 bg-orange-50 dark:bg-orange-900/20">
            <div className="text-3xl font-bold text-orange-600">{report.summary.high}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">高危</div>
          </Card>
          <Card size="small" className="text-center border-yellow-200 bg-yellow-50 dark:bg-yellow-900/20">
            <div className="text-3xl font-bold text-yellow-600">{report.summary.medium}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">中危</div>
          </Card>
          <Card size="small" className="text-center border-blue-200 bg-blue-50 dark:bg-blue-900/20">
            <div className="text-3xl font-bold text-blue-600">{report.summary.low}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">低危</div>
          </Card>
          <Card size="small" className="text-center border-gray-200 bg-gray-50 dark:bg-gray-900/20">
            <div className="text-3xl font-bold text-gray-600">{report.summary.info}</div>
            <div className="text-sm text-gray-600 dark:text-gray-400">信息</div>
          </Card>
        </div>

        <div className="text-center">
          <div className="text-lg font-medium mb-2">
            总共发现 {report.summary.total_vulnerabilities} 个安全问题
          </div>
          <Progress
            percent={report.summary.total_vulnerabilities > 0 ? 100 : 0}
            status={report.summary.critical > 0 ? "exception" : "success"}
            strokeColor={report.summary.critical > 0 ? "#ff4d4f" : "#52c41a"}
            showInfo={false}
          />
        </div>
      </Card>

      {/* 漏洞详情列表 */}
      <Card className="card-modern" title="漏洞详情">
        <Table
          columns={vulnerabilityColumns}
          dataSource={report.vulnerabilities}
          rowKey="vulnerability_id"
          pagination={{
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
          }}
          size="middle"
        />
      </Card>

      {/* 导出报告模态框 */}
      <Modal
        title="导出报告"
        open={exportModalVisible}
        onOk={handleExport}
        onCancel={() => setExportModalVisible(false)}
        okText="导出"
        cancelText="取消"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">导出格式</label>
            <Select
              value={exportFormat}
              onChange={setExportFormat}
              className="w-full"
            >
              <Option value="docx">Word 文档（前端生成）</Option>
              <Option value="pdf">PDF 文档（后端生成）</Option>
              <Option value="json">JSON 格式（前端生成）</Option>
              <Option value="html">HTML 格式（前端生成）</Option>
              <Option value="markdown">Markdown 文本（前端生成）</Option>
            </Select>
          </div>
          <div>
            <label className="flex items-center">
              <input
                type="checkbox"
                checked={includeEvidence}
                onChange={(e) => setIncludeEvidence(e.target.checked)}
                className="mr-2"
              />
              <span className="text-sm">包含攻击证据和截图</span>
            </label>
          </div>
        </div>
      </Modal>

      {/* 漏洞详情模态框 */}
      <Modal
        title={
          <div className="flex items-center">
            <AlertOutlined className="text-brand-primary mr-2" />
            {selectedVulnerability?.name}
          </div>
        }
        open={vulnerabilityModalVisible}
        onCancel={() => setVulnerabilityModalVisible(false)}
        footer={null}
        width={800}
      >
        {selectedVulnerability && (
          <div className="space-y-4">
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="漏洞类型">{selectedVulnerability.type}</Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <Tag color={getRiskColor(selectedVulnerability.risk_level)}>
                  {getRiskText(selectedVulnerability.risk_level)}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="CVSS评分">{selectedVulnerability.cvss_score}</Descriptions.Item>
              <Descriptions.Item label="CVSS向量">{selectedVulnerability.cvss_vector}</Descriptions.Item>
              <Descriptions.Item label="URL">{selectedVulnerability.url}</Descriptions.Item>
              <Descriptions.Item label="请求方法">{selectedVulnerability.method}</Descriptions.Item>
              {selectedVulnerability.parameter && (
                <Descriptions.Item label="参数">{selectedVulnerability.parameter}</Descriptions.Item>
              )}
              {selectedVulnerability.payload && (
                <Descriptions.Item label="攻击载荷">
                  <code className="bg-gray-100 dark:bg-gray-800 px-2 py-1 rounded text-sm">
                    {selectedVulnerability.payload}
                  </code>
                </Descriptions.Item>
              )}
              <Descriptions.Item label="证据">{selectedVulnerability.evidence}</Descriptions.Item>
              <Descriptions.Item label="描述">{selectedVulnerability.description}</Descriptions.Item>
              <Descriptions.Item label="修复建议">{selectedVulnerability.remediation}</Descriptions.Item>
              <Descriptions.Item label="参考资料">
                <ul className="list-disc list-inside">
                  {selectedVulnerability.references.map((ref, index) => (
                    <li key={index}>
                      <a href={ref} target="_blank" rel="noopener noreferrer" className="text-tape-brown hover:text-tape-dark">
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </Descriptions.Item>
            </Descriptions>

            {/* 攻击步骤 */}
            {selectedVulnerability.attack_steps && selectedVulnerability.attack_steps.length > 0 && (
              <div>
                <h4 className="font-medium mb-2">攻击过程</h4>
                <List
                  size="small"
                  dataSource={selectedVulnerability.attack_steps}
                  renderItem={(step, index) => (
                    <List.Item key={index}>
                      <List.Item.Meta
                        avatar={<Avatar size="small">{index + 1}</Avatar>}
                        title={step.action}
                        description={`${step.response_code} | ${step.response_time_ms}ms`}
                      />
                    </List.Item>
                  )}
                />
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default Reports;
