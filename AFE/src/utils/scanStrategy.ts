export interface ScanStrategyMeta {
  value: string;
  label: string;
  summary: string;
  scope: string;
  speed: string;
  intensity: string;
  useCase: string;
  disclaimer: string;
  riskLevel: 'low' | 'medium' | 'high';
  riskLabel: string;
  riskDescription: string;
  estimatedResults: {
    vulns: string;
    duration: string;
    payloads: string;
    attackPaths: string;
  };
  attributeScores: {
    coverage: number;
    speed: number;
    depth: number;
    resourceUsage: number;
  };
}

const STRATEGY_META: Record<string, ScanStrategyMeta> = {
  attack_validation: {
    value: 'attack_validation',
    label: '模拟攻击验证',
    summary: '平衡覆盖范围与验证深度，适合日常验证、复测和演示。',
    scope: '中等覆盖',
    speed: '中等耗时',
    intensity: '平衡型',
    useCase: '适合常规任务，需要可利用性证明但不追求全站极限覆盖。',
    disclaimer: '本模式会执行可控的无害化攻击验证，重点输出载荷、路径和证据链，不等同于全站最深度审计。',
    riskLevel: 'medium',
    riskLabel: '中等强度',
    riskDescription: '标准验证模式，对目标性能影响较小，适合大多数场景。',
    estimatedResults: {
      vulns: '8-15 个',
      duration: '2-4 分钟',
      payloads: '15-25 个',
      attackPaths: '5-10 条',
    },
    attributeScores: {
      coverage: 60,
      speed: 60,
      depth: 70,
      resourceUsage: 50,
    },
  },
  full_audit: {
    value: 'full_audit',
    label: '全量攻击验证',
    summary: '扩大路径、插件和载荷覆盖面，尽量发现更多可验证风险。',
    scope: '高覆盖',
    speed: '高耗时',
    intensity: '覆盖型',
    useCase: '适合上线前全面评估、重要系统巡检和阶段性集中审计。',
    disclaimer: '本模式强调覆盖广度和验证深度，通常请求更多、执行更久，对目标环境压力也更高。',
    riskLevel: 'high',
    riskLabel: '高强度',
    riskDescription: '深度审计模式，可能对目标系统产生较高负载，建议在低峰期执行。',
    estimatedResults: {
      vulns: '20-40 个',
      duration: '3-6 分钟',
      payloads: '40-70 个',
      attackPaths: '15-25 条',
    },
    attributeScores: {
      coverage: 95,
      speed: 20,
      depth: 95,
      resourceUsage: 90,
    },
  },
  focused_probe: {
    value: 'focused_probe',
    label: '定向漏洞验证',
    summary: '围绕特定入口、疑似参数或漏洞类型快速确认风险。',
    scope: '聚焦覆盖',
    speed: '较低耗时',
    intensity: '聚焦型',
    useCase: '适合复核单点问题、验证修复结果或对高价值入口做快速确认。',
    disclaimer: '本模式结果仅代表指定方向的验证结论，不代表对整站或整应用完成全面覆盖。',
    riskLevel: 'low',
    riskLabel: '低强度',
    riskDescription: '精准测试模式，资源消耗极低，适合快速验证和应急响应。',
    estimatedResults: {
      vulns: '3-8 个',
      duration: '1-2 分钟',
      payloads: '5-12 个',
      attackPaths: '2-5 条',
    },
    attributeScores: {
      coverage: 30,
      speed: 85,
      depth: 60,
      resourceUsage: 20,
    },
  },
  default: {
    value: 'default',
    label: '基础验证式扫描',
    summary: '兼容历史任务的基础模式。',
    scope: '基础覆盖',
    speed: '常规耗时',
    intensity: '基础型',
    useCase: '适合兼容旧数据或未声明明确验证模式的任务。',
    disclaimer: '该模式主要用于历史兼容，后续建议统一迁移到明确的三种验证模式。',
    riskLevel: 'medium',
    riskLabel: '中等强度',
    riskDescription: '标准验证模式，对目标性能影响较小。',
    estimatedResults: {
      vulns: '5-12 个',
      duration: '2-3 分钟',
      payloads: '10-20 个',
      attackPaths: '3-8 条',
    },
    attributeScores: {
      coverage: 45,
      speed: 65,
      depth: 50,
      resourceUsage: 40,
    },
  },
  full: {
    value: 'full',
    label: '基础验证式扫描',
    summary: '兼容历史任务的基础模式。',
    scope: '基础覆盖',
    speed: '常规耗时',
    intensity: '基础型',
    useCase: '适合兼容旧数据或未声明明确验证模式的任务。',
    disclaimer: '该模式主要用于历史兼容，后续建议统一迁移到明确的三种验证模式。',
    riskLevel: 'medium',
    riskLabel: '中等强度',
    riskDescription: '标准验证模式，对目标性能影响较小。',
    estimatedResults: {
      vulns: '5-12 个',
      duration: '2-3 分钟',
      payloads: '10-20 个',
      attackPaths: '3-8 条',
    },
    attributeScores: {
      coverage: 45,
      speed: 65,
      depth: 50,
      resourceUsage: 40,
    },
  },
  fast: {
    value: 'fast',
    label: '基础验证式扫描',
    summary: '兼容历史任务的基础模式。',
    scope: '基础覆盖',
    speed: '较低耗时',
    intensity: '基础型',
    useCase: '适合兼容旧数据或未声明明确验证模式的任务。',
    disclaimer: '该模式主要用于历史兼容，后续建议统一迁移到明确的三种验证模式。',
    riskLevel: 'low',
    riskLabel: '低强度',
    riskDescription: '快速测试模式，资源消耗较低。',
    estimatedResults: {
      vulns: '3-8 个',
      duration: '1-2 分钟',
      payloads: '5-15 个',
      attackPaths: '2-6 条',
    },
    attributeScores: {
      coverage: 35,
      speed: 75,
      depth: 45,
      resourceUsage: 30,
    },
  },
};

const FALLBACK_META = STRATEGY_META.default;

export const SCAN_STRATEGY_OPTIONS: ScanStrategyMeta[] = [
  STRATEGY_META.attack_validation,
  STRATEGY_META.full_audit,
  STRATEGY_META.focused_probe,
];

export const getScanStrategyMeta = (strategy?: string): ScanStrategyMeta => {
  if (!strategy) {
    return FALLBACK_META;
  }
  return STRATEGY_META[strategy] || {
    ...FALLBACK_META,
    value: strategy,
    label: strategy,
  };
};

