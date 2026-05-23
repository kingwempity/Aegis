/**
 * Aegis 前端 API 客户端
 * 负责 with FastAPI 后端进行通信
 */

const getApiBaseUrl = (): string => {
  // 始终使用相对路径，让浏览器根据当前页面的协议（HTTP 或 HTTPS）和域名自动匹配
  // 这可以完美解决 Mixed Content 问题，并支持各种反向代理场景
  return '/api/v1';
};

const joinApiPath = (path: string): string => {
  const base = getApiBaseUrl().replace(/\/$/, '');
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${base}${normalizedPath}`;
};

export const getApiResourceUrl = (path: string) => joinApiPath(path);

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }

  get isTemporaryGatewayError(): boolean {
    return this.status === 502 || this.status === 503 || this.status === 504;
  }
}

const parseErrorResponse = async (response: Response, fallback: string): Promise<never> => {
  const errorText = await response.text();
  if (!errorText) {
    throw new ApiError(fallback, response.status);
  }

  try {
    const errorData = JSON.parse(errorText);
    throw new ApiError(errorData.detail || errorData.message || fallback, response.status);
  } catch {
    if (errorText.includes('<html') || errorText.includes('<!DOCTYPE')) {
      throw new ApiError(`服务暂时不可用（HTTP ${response.status}）`, response.status);
    }
    throw new ApiError(errorText || fallback, response.status);
  }
};

export interface ScanTask {
  id: number;
  display_id: number;
  target_url: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  scan_strategy: string;
  target_paths?: string[];
  target_vuln_types?: string[];
  target_parameters?: string[];
  progress?: number;
  current_stage?: string;
  vulnerabilities_found?: number;
  created_at: string;
  duration_seconds?: number;
}

export interface ScanExecutionEvent {
  id: number;
  task_id: number;
  seq: number;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface ScanExecutionEventList {
  task_id: number;
  events: ScanExecutionEvent[];
  next_after_seq: number;
  has_more: boolean;
}

export interface Vulnerability {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target_url: string;
  description?: string;
  vuln_type?: string;
  parameter?: string;
  payload_present: boolean;
  attack_path_present: boolean;
  evidence_present: boolean;
  created_at: string;
}

export interface Target {
  id: number;
  url: string;
  description?: string;
  status: string;
  created_at: string;
  is_active?: boolean;
  last_scanned?: string;
  critical_vulns?: number;
  high_vulns?: number;
  low_vulns?: number;
}

export interface Asset {
  id: number;
  ip_address: string;
  hostname: string;
  mac_address: string;
  open_ports: number[];
  os_info: string;
  services: string[];
  network_range: string;
  status: string;
  last_seen: string;
}

export interface Report {
  id: number;
  task_id: number;
  display_id: number;
  target_url: string;
  risk_score: number;
  vuln_count: number;
  validated_findings: number;
  payload_count: number;
  attack_path_count: number;
  created_at: string;
  scan_strategy?: string;
}

export interface ReportPreviewVulnerability {
  id: number;
  title: string;
  type?: string;
  severity?: string;
  cvss_score?: number;
  url?: string;
  parameter?: string;
  description?: string;
  remediation?: string;
  payload_present: boolean;
  attack_path_present: boolean;
  evidence_present: boolean;
  attack_status?: string;
  attack_stage_count?: number;
  attack_artifact_count?: number;
  attack_final_reason?: string;
  attack_steps?: AttackStep[];
  attack_artifacts?: AttackArtifact[];
  attack_chain_summary?: {
    total_stages: number;
    successful_stages: number;
    failed_stages: number;
    total_duration_ms?: number;
    attack_vector?: string;
    entry_point?: string;
  };
}

export interface ReportPreview {
  task_id: number;
  target_url: string;
  status: string;
  scan_strategy?: string;
  scan_time?: string | null;
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  attack_simulation_summary?: {
    validated_findings: number;
    payload_count: number;
    attack_path_count: number;
    validated_attack_paths?: number;
    artifact_count?: number;
  };
  vulnerabilities: ReportPreviewVulnerability[];
}

export interface User {
  id: number;
  username: string;
  email: string;
  role: string;
  status: string;
}

export interface ScanProfile {
  id: number;
  name: string;
  description: string;
  is_default: boolean;
  speed?: string;
  vulnerability_types?: string[];
}

export interface HelpContent {
  id: number;
  key: string;
  title: string;
  description: string | null;
  content: string | null;
  icon: string;
  icon_color: string;
  link: string | null;
  order: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface HelpContentCreate {
  key: string;
  title: string;
  description?: string;
  content?: string;
  icon?: string;
  icon_color?: string;
  link?: string;
  order?: number;
  is_active?: boolean;
}

export interface HelpContentUpdate {
  title?: string;
  description?: string;
  content?: string;
  icon?: string;
  icon_color?: string;
  link?: string;
  order?: number;
  is_active?: boolean;
}

// 通知相关类型
export interface Notification {
  id: string;
  type: 'success' | 'warning' | 'info' | 'error';
  category: 'user_management' | 'scan' | 'system' | 'security';
  title: string;
  message: string;
  time: string;
  read: boolean;
  extra_data?: Record<string, any>;
  priority?: 'low' | 'medium' | 'high' | 'critical';
  delivery_status?: 'pending' | 'delivered' | 'failed';
}

export interface NotificationListResponse {
  total: number;
  unread_count: number;
  notifications: Notification[];
}

export interface TopThreat {
  id: number;
  title: string;
  severity: string;
  target_url: string;
}

export interface DashboardStats {
  running_scans: number;
  pending_scans: number;
  total_scans: number;
  open_ports: number;
  total_targets: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  total_vulnerabilities: number;
  validated_findings: number;
  top_threats: TopThreat[];
}

export interface DiscoveryScanStatus {
  is_scanning: boolean;
  progress: number;
  message: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface VulnerabilityListResponse {
  total: number;
  items: Vulnerability[];
}

export interface TaskListResponse {
  total: number;
  items: ScanTask[];
}

export const api = {
  async getStats(): Promise<DashboardStats> {
    const response = await fetch(joinApiPath('/stats/dashboard'));
    if (!response.ok) throw new Error('Failed to fetch stats');
    return response.json();
  },

  async getTasks(skip: number = 0, limit: number = 100): Promise<TaskListResponse> {
    const response = await fetch(joinApiPath(`/tasks?skip=${skip}&limit=${limit}`));
    if (!response.ok) throw new Error('Failed to fetch tasks');
    return response.json();
  },

  async getTask(taskId: number): Promise<ScanTask> {
    const response = await fetch(joinApiPath(`/tasks/${taskId}`));
    if (!response.ok) throw new Error('Failed to fetch task');
    return response.json();
  },

  async getTaskExecutionEvents(
    taskId: number,
    afterSeq = 0,
    limit = 200,
    eventTypes?: string[],
  ): Promise<ScanExecutionEventList> {
    const params = new URLSearchParams({
      after_seq: String(afterSeq),
      limit: String(limit),
    });
    if (eventTypes?.length) {
      params.set('event_types', eventTypes.join(','));
    }
    const response = await fetch(joinApiPath(`/tasks/${taskId}/execution-events?${params}`));
    if (!response.ok) throw new Error('Failed to fetch execution events');
    return response.json();
  },

  async createTask(data: { target_url: string; scan_strategy: string; target_paths?: string[]; target_vuln_types?: string[]; target_parameters?: string[] }): Promise<ScanTask> {
    const response = await fetch(joinApiPath('/tasks'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error('Failed to create task');
    return response.json();
  },

  async stopTask(taskId: number): Promise<void> {
    const response = await fetch(joinApiPath(`/tasks/${taskId}/stop`), {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to stop task');
  },

  async deleteTask(taskId: number): Promise<void> {
    const response = await fetch(joinApiPath(`/tasks/${taskId}`), { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除任务失败');
  },

  async deleteReport(taskId: number): Promise<void> {
    const response = await fetch(joinApiPath(`/reports/${taskId}`), { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除报告失败');
  },

  async deleteTarget(targetId: number): Promise<void> {
    const response = await fetch(joinApiPath(`/discovery/targets/${targetId}`), { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除目标失败');
  },

  async getVulnerabilities(severity?: string, skip: number = 0, limit: number = 50): Promise<VulnerabilityListResponse> {
    const params = new URLSearchParams();
    if (severity) params.append('severity', severity);
    params.append('skip', String(skip));
    params.append('limit', String(limit));
    
    const url = joinApiPath(`/vulnerabilities?${params.toString()}`);
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
    return response.json();
  },

  async getTargets(): Promise<Target[]> {
    const response = await fetch(joinApiPath('/discovery/targets'));
    if (!response.ok) throw new Error('Failed to fetch targets');
    return response.json();
  },

  async addTarget(url: string, description?: string): Promise<Target> {
    const response = await fetch(joinApiPath('/discovery/targets'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, description }),
    });
    if (!response.ok) throw new Error('Failed to add target');
    return response.json();
  },

  async getDiscoverySuggestedRange(): Promise<{ network_range: string }> {
    const response = await fetch(joinApiPath('/discovery/suggested-range'));
    if (!response.ok) return { network_range: '192.168.1.0/24' };
    return response.json();
  },

  async getAssets(): Promise<Asset[]> {
    const response = await fetch(joinApiPath('/discovery/assets'));
    if (!response.ok) throw new Error('Failed to fetch assets');
    return response.json();
  },

  async startDiscoveryScan(networkRange: string = "192.168.1.0/24", force: boolean = false): Promise<{ status: string; message: string; task_id: string }> {
    const query = new URLSearchParams({
      network_range: networkRange,
      force: String(force),
    });
    const response = await fetch(joinApiPath(`/discovery/scan/start?${query.toString()}`), {
      method: 'POST',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '启动扫描失败');
    }
    return response.json();
  },

  async getDiscoveryScanStatus(): Promise<DiscoveryScanStatus> {
    const response = await fetch(joinApiPath('/discovery/scan/status'));
    if (!response.ok) {
      return parseErrorResponse(response, '获取扫描状态失败');
    }
    return response.json();
  },

  async stopDiscoveryScan(): Promise<{ status: string; message: string }> {
    const response = await fetch(joinApiPath('/discovery/scan/stop'), {
      method: 'POST',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '停止扫描失败');
    }
    return response.json();
  },

  async clearDiscoveryResults(): Promise<{ deleted: number; message: string }> {
    const response = await fetch(joinApiPath('/discovery/results'), {
      method: 'DELETE',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '清除结果失败');
    }
    return response.json();
  },

  async getReports(): Promise<Report[]> {
    const response = await fetch(joinApiPath('/reports'));
    if (!response.ok) throw new Error('Failed to fetch reports');
    return response.json();
  },

  async getReportPreview(taskId: number): Promise<ReportPreview> {
    const response = await fetch(joinApiPath(`/reports/${taskId}/preview`));
    if (!response.ok) throw new Error('Failed to fetch report preview');
    return response.json();
  },

  async getUsers(): Promise<User[]> {
    const response = await fetch(joinApiPath('/users'));
    if (!response.ok) throw new Error('Failed to fetch users');
    return response.json();
  },

  async addUser(username: string, email: string, role: string, status: string = 'Active'): Promise<User> {
    const response = await fetch(joinApiPath('/users'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, role, status }),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to add user');
    }
    return response.json();
  },

  async getProfiles(): Promise<ScanProfile[]> {
    const response = await fetch(joinApiPath('/profiles'));
    if (!response.ok) throw new Error('Failed to fetch profiles');
    return response.json();
  },

  async addProfile(name: string, description: string, speed: string, vulnerability_types: string[]): Promise<ScanProfile> {
    const response = await fetch(joinApiPath('/profiles'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, speed, vulnerability_types }),
    });
    if (!response.ok) throw new Error('Failed to add profile');
    return response.json();
  },

  async updateProfile(id: number, name: string, description: string, speed: string, vulnerability_types: string[]): Promise<ScanProfile> {
    const response = await fetch(joinApiPath(`/profiles/${id}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, speed, vulnerability_types }),
    });
    if (!response.ok) throw new Error('Failed to update profile');
    return response.json();
  },

  async deleteProfile(id: number): Promise<void> {
    const response = await fetch(joinApiPath(`/profiles/${id}`), { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete profile');
  },

  // ==================== 帮助内容管理 API ====================

  async getHelpContents(activeOnly: boolean = false): Promise<HelpContent[]> {
    const response = await fetch(joinApiPath(`/help?active_only=${activeOnly}`));
    if (!response.ok) throw new Error('Failed to fetch help contents');
    return response.json();
  },

  async getHelpContent(id: number): Promise<HelpContent> {
    const response = await fetch(joinApiPath(`/help/${id}`));
    if (!response.ok) throw new Error('Failed to fetch help content');
    return response.json();
  },

  async getHelpContentByKey(key: string): Promise<HelpContent> {
    const response = await fetch(joinApiPath(`/help/key/${key}`));
    if (!response.ok) throw new Error('Failed to fetch help content');
    return response.json();
  },

  async createHelpContent(data: HelpContentCreate): Promise<HelpContent> {
    const response = await fetch(joinApiPath('/help'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || 'Failed to create help content');
    }
    return response.json();
  },

  async updateHelpContent(id: number, data: HelpContentUpdate): Promise<HelpContent> {
    const response = await fetch(joinApiPath(`/help/${id}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error('Failed to update help content');
    return response.json();
  },

  async deleteHelpContent(id: number): Promise<void> {
    const response = await fetch(joinApiPath(`/help/${id}`), { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete help content');
  },

  async initDefaultHelpContents(): Promise<{ status: string; message: string }> {
    const response = await fetch(joinApiPath('/help/init-default'), { method: 'POST' });
    if (!response.ok) throw new Error('Failed to init default help contents');
    return response.json();
  },

  // ==================== 通知管理 API ====================

  async getNotifications(category?: string, unreadOnly: boolean = false, limit: number = 50): Promise<NotificationListResponse> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    params.append('unread_only', String(unreadOnly));
    params.append('limit', String(limit));
    
    const response = await fetch(joinApiPath(`/notifications?${params.toString()}`));
    if (!response.ok) throw new Error('Failed to fetch notifications');
    return response.json();
  },

  async getUnreadNotificationCount(): Promise<{ unread_count: number }> {
    const response = await fetch(joinApiPath('/notifications/unread-count'));
    if (!response.ok) throw new Error('Failed to fetch unread count');
    return response.json();
  },

  async markNotificationAsRead(notificationId: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(joinApiPath(`/notifications/${notificationId}/mark-read`), {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to mark notification as read');
    return response.json();
  },

  async markAllNotificationsAsRead(notificationIds?: string[]): Promise<{ success: boolean; marked_count: number }> {
    const response = await fetch(joinApiPath('/notifications/mark-read'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notification_ids: notificationIds || null }),
    });
    if (!response.ok) throw new Error('Failed to mark all notifications as read');
    return response.json();
  },

  async deleteNotification(notificationId: string): Promise<{ success: boolean; message: string }> {
    const response = await fetch(joinApiPath(`/notifications/${notificationId}`), {
      method: 'DELETE',
    });
    if (!response.ok) throw new Error('Failed to delete notification');
    return response.json();
  },

  async clearAllNotifications(): Promise<{ success: boolean; message: string; cleared_count: number }> {
    const response = await fetch(joinApiPath('/notifications/clear-all'), {
      method: 'DELETE',
    });
    if (!response.ok) throw new Error('Failed to clear all notifications');
    return response.json();
  },

  // ==================== 漏洞实验室 API ====================

  async getLabScenarios(params?: {
    vuln_type?: string;
    difficulty?: string;
    search?: string;
    page?: number;
    page_size?: number;
  }): Promise<{ items: LabScenario[]; total: number }> {
    const searchParams = new URLSearchParams();
    if (params?.vuln_type) searchParams.append('vuln_type', params.vuln_type);
    if (params?.difficulty) searchParams.append('difficulty', params.difficulty);
    if (params?.search) searchParams.append('search', params.search);
    if (params?.page) searchParams.append('page', String(params.page));
    if (params?.page_size) searchParams.append('page_size', String(params.page_size));
    
    const response = await fetch(joinApiPath(`/lab/scenarios?${searchParams.toString()}`));
    if (!response.ok) throw new Error('Failed to fetch lab scenarios');
    return response.json();
  },

  async getLabScenario(id: number): Promise<LabScenario> {
    const response = await fetch(joinApiPath(`/lab/scenarios/${id}`));
    if (!response.ok) throw new Error('Failed to fetch lab scenario');
    return response.json();
  },

  async getLabVulnTypes(): Promise<VulnTypeInfo[]> {
    const response = await fetch(joinApiPath('/lab/vuln-types'));
    if (!response.ok) throw new Error('Failed to fetch vuln types');
    return response.json();
  },

  async getLabDifficultyLevels(): Promise<Record<string, string>> {
    const response = await fetch(joinApiPath('/lab/difficulty-levels'));
    if (!response.ok) throw new Error('Failed to fetch difficulty levels');
    return response.json();
  },
};

// 漏洞实验室相关类型
export interface LabScenario {
  id: number;
  name: string;
  vuln_type: string;
  difficulty: string;
  description?: string;
  attack_steps: AttackStep[];
  remediation: Remediation[];
  learning: Learning;
  tags: string[];
  is_active: boolean;
  is_auto_generated?: boolean;
  source_scan_task_id?: number;
  created_at?: string;
  updated_at?: string;
}

export interface AttackStepArtifact {
  name: string;
  value: string;
  source_stage?: string;
  artifact_type?: string;
  confidence?: number;
}

export interface AttackStepEvidence {
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
    raw?: string;
  };
  response?: {
    status_code?: number;
    status_text?: string;
    headers?: Record<string, string>;
    body?: string;
    body_snippet?: string;
    raw?: string;
  };
  matched_conditions?: Array<string | Record<string, unknown>>;
  matched_patterns?: Array<{
    pattern: string;
    match_type: string;
    matched_text?: string;
  }>;
  timing_ms?: number;
}

export interface AttackStep {
  step?: number;
  stage_id?: string;
  stage_name?: string;
  stage_title?: string;
  stage_goal?: string;
  method?: string;
  url?: string;
  description?: string;
  matched_conditions?: Array<string | Record<string, unknown>>;
  artifacts?: AttackStepArtifact[];
  extracted?: Record<string, unknown>;
  success?: boolean;
  duration_ms?: number;
  evidence?: AttackStepEvidence;
  request?: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response?: {
    status_code?: number;
    headers?: Record<string, string>;
    body?: string;
  };
  payload?: string;
  result?: string;
  status?: string;
  timestamp?: string;
}

export interface AttackArtifact {
  name: string;
  value: string;
  source_stage?: string;
  artifact_type?: string;
  confidence?: number;
}

export interface Remediation {
  title: string;
  description?: string;
  code?: string;
  language?: string;
}

export interface Learning {
  principle?: string;
  cwe?: string;
  owasp?: string;
  impact?: string;
  references?: string[];
}

export interface VulnTypeInfo {
  code: string;
  name: string;
  count: number;
}
