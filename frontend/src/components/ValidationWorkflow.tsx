import React from 'react';

interface ValidationWorkflowProps {
  currentStep?: 'surface' | 'targets' | 'validation' | 'findings' | 'reports';
  compact?: boolean;
}

const workflowSteps = [
  {
    key: 'surface',
    title: 'Attack Surface',
    description: '发现主机、端口与暴露服务',
  },
  {
    key: 'targets',
    title: 'Web Targets',
    description: '筛选要进入 Web 验证的目标',
  },
  {
    key: 'validation',
    title: 'Attack Validation',
    description: '执行模拟攻击验证与载荷测试',
  },
  {
    key: 'findings',
    title: 'Validated Findings',
    description: '查看可利用性证明与证据链',
  },
  {
    key: 'reports',
    title: 'Attack Reports',
    description: '导出攻击验证结论与风险摘要',
  },
] as const;

const ValidationWorkflow: React.FC<ValidationWorkflowProps> = ({ currentStep, compact = false }) => {
  const currentIndex = currentStep ? workflowSteps.findIndex((item) => item.key === currentStep) : -1;

  return (
    <div className={`rounded-3xl border border-[#e7ebf0] bg-white shadow-[0_10px_30px_rgba(15,23,42,0.08)] ${compact ? 'p-4' : 'p-6'}`}>
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-[0.28em] text-[#94a3b8]">Validation Workflow</h3>
          <p className="mt-1 text-sm text-[#64748b]">将攻击面摸排、Web 模拟攻击验证与报告输出串成一条完整闭环。</p>
        </div>
        <div className="rounded-full bg-[#fff4ea] px-3 py-1 text-xs font-semibold text-[#d97706]">
          BAS Pipeline
        </div>
      </div>

      <div className={`mt-5 grid gap-3 ${compact ? 'grid-cols-1 md:grid-cols-5' : 'grid-cols-1 lg:grid-cols-5'}`}>
        {workflowSteps.map((step, index) => {
          const isActive = currentStep === step.key;
          const isPast = currentIndex > index;
          const cardClassName = isActive
            ? 'border-[#fed7aa] bg-[#fff7ed] shadow-[0_8px_18px_rgba(249,115,22,0.12)]'
            : isPast
              ? 'border-[#a7f3d0] bg-[#ecfdf5]'
              : 'border-[#edf1f5] bg-[#f8fafc]';

          const badgeClassName = isActive
            ? 'bg-[#f97316] text-white'
            : isPast
              ? 'bg-[#10b981] text-white'
              : 'bg-white text-[#94a3b8] border border-[#eef2f7]';

          const statusLabel = currentIndex < 0 ? '流程环节' : isActive ? '当前环节' : isPast ? '已完成' : '后续环节';
          const statusClassName = isActive
            ? 'text-[#f97316]'
            : isPast
              ? 'text-[#94a3b8]'
              : 'text-[#94a3b8]';

          return (
            <div
              key={step.key}
              className={`relative rounded-[22px] border p-4 transition-all ${cardClassName}`}
            >
              <div className="flex items-center justify-between gap-3">
                <span className={`flex h-9 w-9 items-center justify-center rounded-full text-sm font-bold ${badgeClassName}`}>
                  {index + 1}
                </span>
                <span className={`text-[11px] font-semibold tracking-wide ${statusClassName}`}>
                  {statusLabel}
                </span>
              </div>
              <div className="mt-4">
                <div className="text-[1.02rem] font-bold text-[#183b56]">{step.title}</div>
                <p className="mt-2 text-sm leading-6 text-[#64809a]">{step.description}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ValidationWorkflow;
