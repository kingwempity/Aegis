// 用户相关类型
export interface User {
  user_id: string;
  username: string;
  email: string;
  full_name?: string;
  role: 'user' | 'admin';
  created_at: string;
  total_tasks: number;
  total_scans: number;
  is_active?: boolean;
  is_superuser?: boolean;
  last_login?: string;
}

// 系统用户类型（管理员视角）
export interface SystemUser extends User {
  is_active: boolean;
  is_superuser: boolean;
  last_login?: string;
}

// 任务相关类型
export interface Task {
  task_id: string;
  task_name: string;
  target_url: string;
  status: 'queued' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  current_phase?: string;
  vulnerabilities_found?: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  duration_seconds?: number;
  pages_scanned?: number;
  scan_profile: 'quick' | 'full' | 'custom';
  modules_enabled?: string[];
  created_by: {
    user_id: string;
    username: string;
  };
}

// 漏洞相关类型
export interface Vulnerability {
  id: string;
  task_id: string;
  name: string;
  type: string;
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  parameter?: string;
  payload?: string;
  evidence: string;
  cvss_score: number;
  cvss_vector: string;
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  remediation: string;
  references: string[];
  attack_steps?: AttackStep[];
  screenshots?: Screenshot[];
  detected_at: string;
}

export interface AttackStep {
  step: number;
  action: string;
  response_code: number;
  response_time_ms: number;
}

export interface Screenshot {
  url: string;
  description: string;
}

// 报告相关类型
export interface ScanReport {
  task_id: string;
  target_url: string;
  scan_time: string;
  scan_duration: number;
  summary: {
    total_vulnerabilities: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    pages_scanned: number;
    modules_executed: number;
  };
  vulnerabilities: Vulnerability[];
  technology_stack: {
    server?: string;
    language?: string;
    framework?: string;
    database?: string;
  };
}

// 统计相关类型
export interface Statistics {
  total_scans: number;
  vulnerabilities_found: number;
  critical_vulnerabilities: number;
  active_tasks: number;
  system_uptime_hours: number;
}

export interface ChartData {
  chart_type: string;
  data: {
    labels: string[];
    values: number[];
    colors: string[];
  };
  time_range: string;
}

// API响应类型
export interface ApiResponse<T = any> {
  code: number;
  message: string;
  data: T;
}

// 认证相关类型
export interface LoginRequest {
  username: string;
  password: string;
}

export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  full_name?: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

// 任务创建类型
export interface CreateTaskRequest {
  target_url: string;
  task_name?: string;
  scan_profile?: 'quick' | 'full' | 'custom';
  custom_modules?: string[];
  auth_token?: string;
  auth_cookies?: string;
  max_depth?: number;
  max_pages?: number;
  timeout?: number;
  user_agent?: string;
  headers?: Record<string, string>;
  exclude_patterns?: string[];
}

// WebSocket消息类型
export interface WSMessage {
  type: 'status_update' | 'progress_update' | 'vulnerability_found' | 'task_completed' | 'task_failed' | 'error';
  task_id?: string;
  data?: any;
  code?: number;
  message?: string;
  timestamp: string;
}

// 主题相关类型
export interface ThemeContextType {
  isDark: boolean;
  toggleTheme: () => void;
}

// 认证上下文类型
export interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  loading: boolean;
  login: (credentials: LoginRequest) => Promise<void>;
  register: (userData: RegisterRequest) => Promise<void>;
  logout: () => void;
  refreshToken: () => Promise<void>;
  error?: string | null;
  clearError?: () => void;
  isLoading?: boolean;
  isError?: boolean;
}
