/**
 * Aegis 前端 API 客户端
 * 负责 with FastAPI 后端进行通信
 */

const getApiBaseUrl = (): string => {
  if (typeof window === 'undefined') {
    return '/api/v1';
  }

  const { protocol, hostname } = window.location;
  const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

  if (isLocalhost) {
    return 'http://localhost:8000/api/v1';
  }

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
  target_url: string;
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  created_at: string;
}

export interface Vulnerability {
  id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  target_url: string;
  description?: string;
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
  target_url: string;
  risk_score: number;
  vuln_count: number;
  created_at: string;
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
}

export interface DiscoveryScanStatus {
  is_scanning: boolean;
  progress: number;
  message: string;
  started_at: string | null;
  completed_at: string | null;
}

export const api = {
  async getStats(): Promise<DashboardStats> {
    const response = await fetch(joinApiPath('/stats/dashboard'));
    if (!response.ok) throw new Error('Failed to fetch stats');
    return response.json();
  },

  async getTasks(): Promise<ScanTask[]> {
    const response = await fetch(joinApiPath('/tasks'));
    if (!response.ok) throw new Error('Failed to fetch tasks');
    return response.json();
  },

  async createTask(url: string): Promise<ScanTask> {
    const response = await fetch(joinApiPath('/tasks'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url }),
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

  async getVulnerabilities(severity?: string): Promise<Vulnerability[]> {
    const url =
      severity
        ? joinApiPath(`/vulnerabilities?severity=${encodeURIComponent(severity)}`)
        : joinApiPath('/vulnerabilities');
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
};
