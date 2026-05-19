import React from 'react';

interface ScanProgressProps {
  progress: number;
  label?: string;
}

/** \u626b\u63cf\u8fdb\u5ea6\u6761\uff08\u4f9b\u6267\u884c\u63a7\u5236\u53f0\u9876\u680f\u590d\u7528\uff09 */
const ScanProgress: React.FC<ScanProgressProps> = ({ progress, label }) => (
  <div className="flex h-2 w-full items-center gap-2">
    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[#e2e8f0]">
      <div
        className="h-full bg-[#ff6b00] transition-all duration-500"
        style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
      />
    </div>
    <span className="text-xs font-semibold text-[#64748b]">{label ?? `${progress}%`}</span>
  </div>
);

export default ScanProgress;
