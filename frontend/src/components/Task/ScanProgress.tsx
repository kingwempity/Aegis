/**
 * 扫描进度条组件
 * 显示扫描阶段和进度
 */
import React from 'react';
import { Progress, Steps } from 'antd';

interface ScanProgressProps {
  progress: number; // 0-100
  currentStage?: string;
  stages?: Array<{ title: string; description?: string }>;
}

const ScanProgress: React.FC<ScanProgressProps> = ({
  progress,
  currentStage,
  stages = [
    { title: '初始化', description: '准备扫描环境' },
    { title: '爬取链接', description: '发现目标URL' },
    { title: '漏洞检测', description: '执行检测插件' },
    { title: '生成报告', description: '整理扫描结果' },
  ],
}) => {
  // 根据进度计算当前步骤
  const currentStep = Math.floor((progress / 100) * stages.length);

  return (
    <div>
      <Progress
        percent={progress}
        status={progress === 100 ? 'success' : 'active'}
        strokeColor={{
          '0%': '#1677ff',
          '100%': '#52c41a',
        }}
        style={{ marginBottom: 16 }}
      />
      {currentStage && (
        <div style={{ marginBottom: 16, color: '#595959', fontSize: 14 }}>
          当前阶段: {currentStage}
        </div>
      )}
      <Steps
        size="small"
        current={currentStep}
        items={stages.map((stage) => ({
          title: stage.title,
          description: stage.description,
        }))}
      />
    </div>
  );
};

export default ScanProgress;
