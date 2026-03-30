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
  return (
    <div className={`rounded-2xl border border-gray-100 bg-white shadow-sm ${compact ? 'p-4' : 'p-6'}`}>
      <div className="flex items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-[0.2em] text-gray-400">Validation Workflow</h3>
          <p className="mt-1 text-sm text-gray-500">将攻击面摸排、Web 模拟攻击验证与报告输出串成一条完整闭环。</p>
        </div>
        <div className="rounded-full bg-orange-50 px-3 py-1 text-xs font-semibold text-[#c25b00]">
          BAS Pipeline
        </div>
      </div>

      <div className={`mt-5 grid gap-3 ${compact ? 'grid-cols-1 md:grid-cols-5' : 'grid-cols-1 lg:grid-cols-5'}`}>
        {workflowSteps.map((step, index) => {
          const isActive = currentStep === step.key;
          const isPast = currentStep ? workflowSteps.findIndex((item) => item.key === currentStep) > index : false;

          return (
            <div
              key={step.key}
              className={`relative rounded-2xl border p-4 transition-all ${
                isActive
                  ? 'border-orange-200 bg-orange-50 shadow-sm'
                  : isPast
                    ? 'border-emerald-200 bg-emerald-50'
                    : 'border-gray-100 bg-gray-50'
              }`}
            >
              <div className="flex items-center justify-between gap-3">
                <span
                  className={`flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold ${
                    isActive
                      ? 'bg-[#ff6b00] text-white'
                      : isPast
                        ? 'bg-emerald-500 text-white'
                        : 'bg-white text-gray-400'
                  }`}
                >
                  {index + 1}
                </span>
                <span className={`text-[11px] font-semibold uppercase tracking-wide ${isActive ? 'text-[#c25b00]' : 'text-gray-400'}`}>
                  {isActive ? '当前环节' : isPast ? '已完成' : '后续环节'}
                </span>
              </div>
              <div className="mt-4">
                <div className="text-sm font-bold text-[#2d3343]">{step.title}</div>
                <p className="mt-1 text-xs leading-5 text-gray-500">{step.description}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default ValidationWorkflow;
