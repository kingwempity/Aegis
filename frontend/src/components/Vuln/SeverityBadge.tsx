/**
 * 漏洞严重程度标签组件
 */
import React from 'react';
import { Tag } from 'antd';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'default' | 'small';
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'default' }) => {
  const severityMap: Record<string, { color: string; label: string }> = {
    critical: { color: '#ff4d4f', label: '严重' },
    high: { color: '#ff7875', label: '高危' },
    medium: { color: '#faad14', label: '中危' },
    low: { color: '#1677ff', label: '低危' },
    info: { color: '#8c8c8c', label: '信息' },
  };

  const config = severityMap[severity.toLowerCase()] || {
    color: '#8c8c8c',
    label: severity,
  };

  return (
    <Tag color={config.color} style={{ margin: 0 }}>
      {config.label}
    </Tag>
  );
};

export default SeverityBadge;
