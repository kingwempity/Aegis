/**
 * Payload 验证逻辑
 * 
 * 根据漏洞类型验证用户输入的 Payload 是否包含关键特征。
 */

export interface ValidationResult {
  isValid: boolean;
  feedback: string;
  score: number; // 0-100
  detectedPatterns: string[];
}

/**
 * 通用验证（默认）
 */
function validateGeneric(input: string, expected?: string): ValidationResult {
  return {
    isValid: input.length > 0,
    feedback: '请输入有效的 Payload',
    score: input.length > 5 ? 50 : 20,
    detectedPatterns: ['已输入内容'],
  };
}

/**
 * 验证 Payload 是否包含目标漏洞类型的关键特征
 */
export function validatePayload(
  vulnType: string,
  userInput: string,
  expectedPayload?: string
): ValidationResult {
  const input = userInput.trim();
  
  if (!input) {
    return {
      isValid: false,
      feedback: '请输入 Payload',
      score: 0,
      detectedPatterns: [],
    };
  }

  const validators: Record<string, (input: string, expected?: string) => ValidationResult> = {
    SQLI: validateSQLInjection,
    XSS_REFLECTED: validateXSS,
    XSS_STORED: validateXSS,
    CMD_INJECTION: validateCommandInjection,
    LFI: validateLFI,
    RFI: validateRFI,
    SSRF: validateSSRF,
    XXE: validateXXE,
    PATH_TRAVERSAL: validatePathTraversal,
    INFO_DISCLOSURE: validateInfoDisclosure,
    OPEN_REDIRECT: validateOpenRedirect,
    CSRF: validateCSRF,
  };

  const validator = validators[vulnType] || validateGeneric;
  return validator(input, expectedPayload);
}

/**
 * SQL注入验证
 */
function validateSQLInjection(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /['"]/ , name: '引号注入', weight: 20 },
    { pattern: /\bOR\b/i, name: 'OR 逻辑运算', weight: 25 },
    { pattern: /\bAND\b/i, name: 'AND 逻辑运算', weight: 15 },
    { pattern: /['"]?\s*=\s*['"]?/, name: '等式比较', weight: 15 },
    { pattern: /--\s*$/, name: '注释符', weight: 15 },
    { pattern: /#\s*$/, name: 'MySQL 注释', weight: 10 },
    { pattern: /\bUNION\b/i, name: 'UNION 查询', weight: 30 },
    { pattern: /\bSELECT\b/i, name: 'SELECT 语句', weight: 25 },
    { pattern: /\bSLEEP\b/i, name: '时间盲注', weight: 20 },
    { pattern: /\bBENCHMARK\b/i, name: '基准测试注入', weight: 20 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '输入中包含单引号/双引号（注入点标识）',
    '使用 OR/AND 构造逻辑条件',
    '使用 -- 或 # 注释后续 SQL',
  ]);
}

/**
 * XSS 验证
 */
function validateXSS(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /<script>/i, name: 'Script 标签', weight: 40 },
    { pattern: /alert\s*\(/i, name: 'Alert 函数', weight: 30 },
    { pattern: /onerror\s*=/i, name: 'Error 事件', weight: 25 },
    { pattern: /onload\s*=/i, name: 'Load 事件', weight: 25 },
    { pattern: /onclick\s*=/i, name: 'Click 事件', weight: 20 },
    { pattern: /javascript:/i, name: 'JavaScript 协议', weight: 20 },
    { pattern: /document\.cookie/i, name: 'Cookie 访问', weight: 30 },
    { pattern: /<img\s/i, name: 'Image 标签注入', weight: 20 },
    { pattern: /<svg/i, name: 'SVG 标签注入', weight: 20 },
    { pattern: /<iframe/i, name: 'iFrame 标签注入', weight: 25 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 <script> 标签注入 JavaScript',
    '使用 alert() 验证 XSS 执行',
    '使用事件属性（onerror/onload）触发脚本',
  ]);
}

/**
 * 命令注入验证
 */
function validateCommandInjection(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /;/, name: '命令分隔符', weight: 25 },
    { pattern: /\|/, name: '管道符', weight: 25 },
    { pattern: /&&/, name: '逻辑与', weight: 20 },
    { pattern: /\|\|/, name: '逻辑或', weight: 20 },
    { pattern: /`[^`]+`/, name: '反引号命令替换', weight: 30 },
    { pattern: /\$\(.*\)/, name: '命令替换语法', weight: 30 },
    { pattern: /\/etc\/passwd/i, name: '敏感文件访问', weight: 25 },
    { pattern: /\bcat\b/i, name: 'cat 命令', weight: 15 },
    { pattern: /\bls\b/i, name: 'ls 命令', weight: 10 },
    { pattern: /\bwhoami\b/i, name: 'whoami 命令', weight: 15 },
    { pattern: /\bid\b/i, name: 'id 命令', weight: 15 },
    { pattern: /\buname\b/i, name: 'uname 命令', weight: 15 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 ; 或 | 连接系统命令',
    '尝试读取 /etc/passwd 等敏感文件',
    '使用反引号或 $() 进行命令替换',
  ]);
}

/**
 * 本地文件包含 (LFI) 验证
 */
function validateLFI(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /\.\.\//, name: '目录遍历', weight: 30 },
    { pattern: /\/etc\/passwd/i, name: '/etc/passwd', weight: 30 },
    { pattern: /\/etc\/shadow/i, name: '/etc/shadow', weight: 25 },
    { pattern: /php:\/\/filter/i, name: 'PHP 过滤器', weight: 35 },
    { pattern: /php:\/\/input/i, name: 'PHP 输入流', weight: 30 },
    { pattern: /data:\/\/text\/plain/i, name: 'Data 协议', weight: 30 },
    { pattern: /expect:\/\/cmd/i, name: 'Expect 协议', weight: 30 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 ../ 进行目录遍历',
    '尝试包含 /etc/passwd 等系统文件',
    '使用 php://filter 读取源码',
  ]);
}

/**
 * 远程文件包含 (RFI) 验证
 */
function validateRFI(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /https?:\/\//i, name: 'HTTP URL', weight: 30 },
    { pattern: /\.txt$/i, name: '文本文件', weight: 15 },
    { pattern: /\.php$/i, name: 'PHP 文件', weight: 20 },
    { pattern: /\?.*=/, name: 'URL 参数', weight: 15 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 HTTP URL 指向远程文件',
    '确保目标服务器允许远程包含',
  ]);
}

/**
 * SSRF 验证
 */
function validateSSRF(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /127\.0\.0\.1/i, name: '本地回环地址', weight: 25 },
    { pattern: /localhost/i, name: 'localhost', weight: 25 },
    { pattern: /0\.0\.0\.0/i, name: '全零地址', weight: 20 },
    { pattern: /169\.254\.169\.254/i, name: 'AWS 元数据', weight: 35 },
    { pattern: /http:\/\/10\./i, name: '内网地址 (10.x)', weight: 25 },
    { pattern: /http:\/\/192\.168\./i, name: '内网地址 (192.168.x)', weight: 25 },
    { pattern: /http:\/\/172\.(1[6-9]|2\d|3[01])\./i, name: '内网地址 (172.16-31.x)', weight: 25 },
    { pattern: /file:\/\//i, name: 'File 协议', weight: 30 },
    { pattern: /gopher:\/\//i, name: 'Gopher 协议', weight: 30 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '尝试访问 127.0.0.1 或 localhost',
    '访问云服务商元数据地址',
    '尝试访问内网地址 (10.x, 192.168.x)',
  ]);
}

/**
 * XXE 验证
 */
function validateXXE(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /<!DOCTYPE/i, name: 'DOCTYPE 声明', weight: 30 },
    { pattern: /<!ENTITY/i, name: 'ENTITY 声明', weight: 30 },
    { pattern: /SYSTEM\s+["']/i, name: 'SYSTEM 实体', weight: 30 },
    { pattern: /PUBLIC\s+["']/i, name: 'PUBLIC 实体', weight: 25 },
    { pattern: /%[a-zA-Z]+;/, name: '参数实体', weight: 25 },
    { pattern: /file:\/\/\/etc\/passwd/i, name: '文件读取', weight: 35 },
    { pattern: /&[a-zA-Z]+;/, name: '实体引用', weight: 20 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 <!DOCTYPE> 定义外部实体',
    '使用 SYSTEM 加载外部资源',
    '使用 &entity; 引用实体',
  ]);
}

/**
 * 路径穿越验证
 */
function validatePathTraversal(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /\.\.\//, name: '目录遍历序列', weight: 30 },
    { pattern: /\.\.\\/, name: 'Windows 目录遍历', weight: 30 },
    { pattern: /%2e%2e%2f/i, name: 'URL 编码遍历', weight: 25 },
    { pattern: /%2e%2e%5c/i, name: 'URL 编码遍历 (Windows)', weight: 25 },
    { pattern: /\/etc\/passwd/i, name: '/etc/passwd', weight: 25 },
    { pattern: /\\windows\\system32/i, name: 'Windows 系统目录', weight: 25 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用 ../ 或 ..\\ 跳出当前目录',
    '尝试访问系统敏感文件',
  ]);
}

/**
 * 信息泄露验证
 */
function validateInfoDisclosure(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /\.git\//i, name: 'Git 目录访问', weight: 30 },
    { pattern: /\.env$/i, name: '环境变量文件', weight: 30 },
    { pattern: /\.svn\//i, name: 'SVN 目录访问', weight: 25 },
    { pattern: /\/debug/i, name: '调试接口访问', weight: 20 },
    { pattern: /\/admin/i, name: '管理页面访问', weight: 20 },
    { pattern: /\/backup/i, name: '备份文件访问', weight: 25 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '尝试访问 .git 或 .env 等敏感目录',
    '查看是否有调试信息暴露',
  ]);
}

/**
 * 开放重定向验证
 */
function validateOpenRedirect(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /https?:\/\/evil\.com/i, name: '恶意域名', weight: 30 },
    { pattern: /https?:\/\/attacker/i, name: '攻击者域名', weight: 25 },
    { pattern: /\/\/evil/i, name: '协议相对 URL', weight: 25 },
    { pattern: /\\evil/i, name: '反斜杠重定向', weight: 20 },
    { pattern: /%0d/i, name: '回车注入', weight: 25 },
    { pattern: /%0a/i, name: '换行注入', weight: 25 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '使用完整的恶意 URL 进行重定向',
    '尝试协议相对 URL (//evil.com)',
  ]);
}

/**
 * CSRF 验证
 */
function validateCSRF(input: string, expected?: string): ValidationResult {
  const patterns: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /<form/i, name: '表单构造', weight: 25 },
    { pattern: /<img[^>]+src=/i, name: 'Image CSRF', weight: 25 },
    { pattern: /<iframe/i, name: 'iFrame CSRF', weight: 25 },
    { pattern: /csrf_token/i, name: 'CSRF Token', weight: 30 },
    { pattern: /action=["']http/i, name: '跨域提交', weight: 20 },
  ];

  return evaluatePatterns(input, patterns, expected, [
    '构造恶意表单自动提交请求',
    '使用 <img> 或 <iframe> 发起请求',
  ]);
}

/**
 * 评估模式匹配结果
 */
function evaluatePatterns(
  input: string,
  patterns: Array<{ pattern: RegExp; name: string; weight: number }>,
  expectedPayload?: string,
  hints?: string[]
): ValidationResult {
  const detectedPatterns: string[] = [];
  let totalScore = 0;
  let maxScore = 0;

  for (const { pattern, name, weight } of patterns) {
    maxScore += weight;
    if (pattern.test(input)) {
      detectedPatterns.push(name);
      totalScore += weight;
    }
  }

  // 归一化分数到 0-100
  const normalizedScore = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;

  // 判断是否有效（至少包含一个关键特征）
  const isValid = detectedPatterns.length > 0 && normalizedScore >= 40;

  // 生成反馈
  let feedback = '';
  if (isValid) {
    feedback = `✅ 成功！检测到：${detectedPatterns.join('、')}`;
  } else if (detectedPatterns.length > 0) {
    feedback = `⚠️ 部分匹配：${detectedPatterns.join('、')}，继续完善 Payload`;
  } else {
    feedback = '❌ 未检测到关键特征，请参考提示或查看答案';
  }

  return {
    isValid,
    feedback,
    score: normalizedScore,
    detectedPatterns,
  };
}
