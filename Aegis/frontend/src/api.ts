/**
 * Aegis 前端 API 客户端
 * 负责 with FastAPI 后端进行通信
 */

// 动态获取 API 基础地址
// 如果在浏览器中运行，自动将 localhost 替换为当前访问的服务器 IP
export const getApiBaseUrl = () => {
  if (import.meta.env.VITE_API_URL) return import.meta.env.VITE_API_URL;
  
  // 如果是浏览器环境
  if (typeof window !== 'undefined') {
    const { hostname } = window.location;

    // 本地开发默认直连 FastAPI 的 8000 端口
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
      return 'http://localhost:8000/api/v1';
    }

    // 生产环境优先走同源 /api 代理，避免 HTTPS 页面触发 Mixed Content
    return '/api/v1';
  }
  
  return 'http://localhost:8000/api/v1';
};

export const API_BASE_URL = getApiBaseUrl();

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
  // 兼容旧版 UI 字段
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
  // 获取仪表盘统计数据
  async getStats(): Promise<DashboardStats> {
    const response = await fetch(`${API_BASE_URL}/stats/dashboard`);
    if (!response.ok) throw new Error('Failed to fetch stats');
    return response.json();
  },

  // 获取任务列表
  async getTasks(): Promise<ScanTask[]> {
    const response = await fetch(`${API_BASE_URL}/tasks`);
    if (!response.ok) throw new Error('Failed to fetch tasks');
    return response.json();
  },

  // 创建新扫描任务
  async createTask(url: string): Promise<ScanTask> {
    const response = await fetch(`${API_BASE_URL}/tasks`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: url }),
    });
    if (!response.ok) throw new Error('Failed to create task');
    return response.json();
  },

  // 停止扫描任务
  async stopTask(taskId: number): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/tasks/${taskId}/stop`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to stop task');
  },

  // 删除扫描任务（同时会从报告列表中移除）
  async deleteTask(taskId: number): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/tasks/${taskId}`, { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除任务失败');
  },

  // 删除报告（删除对应任务及漏洞记录）
  async deleteReport(taskId: number): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/reports/${taskId}`, { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除报告失败');
  },

  // 删除目标
  async deleteTarget(targetId: number): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/discovery/targets/${targetId}`, { method: 'DELETE' });
    if (!response.ok) return parseErrorResponse(response, '删除目标失败');
  },

  // 获取漏洞列表
  async getVulnerabilities(severity?: string): Promise<Vulnerability[]> {
    const url =
      severity
        ? `${API_BASE_URL}/vulnerabilities?severity=${severity}`
        : `${API_BASE_URL}/vulnerabilities`;
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
    return response.json();
  },

  // 获取目标列表 (Discovery 模块)
  async getTargets(): Promise<Target[]> {
    const response = await fetch(`${API_BASE_URL}/discovery/targets`);
    if (!response.ok) throw new Error('Failed to fetch targets');
    return response.json();
  },

  // 添加新目标 (Discovery 模块)
  async addTarget(url: string, description?: string): Promise<Target> {
    const response = await fetch(`${API_BASE_URL}/discovery/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, description }),
    });
    if (!response.ok) throw new Error('Failed to add target');
    return response.json();
  },

  // 获取建议的扫描网段（云/Docker 部署时可从环境变量配置 VPC 网段）
  async getDiscoverySuggestedRange(): Promise<{ network_range: string }> {
    const response = await fetch(`${API_BASE_URL}/discovery/suggested-range`);
    if (!response.ok) return { network_range: '192.168.1.0/24' };
    return response.json();
  },

  // 获取资产发现列表 (Discovery 模块)
  async getAssets(): Promise<Asset[]> {
    const response = await fetch(`${API_BASE_URL}/discovery/assets`);
    if (!response.ok) throw new Error('Failed to fetch assets');
    return response.json();
  },

  // 触发网络发现扫描 (Discovery 模块)
  async startDiscoveryScan(networkRange: string = "192.168.1.0/24", force: boolean = false): Promise<{ status: string; message: string; task_id: string }> {
    const query = new URLSearchParams({
      network_range: networkRange,
      force: String(force),
    });
    const response = await fetch(`${API_BASE_URL}/discovery/scan/start?${query.toString()}`, {
      method: 'POST',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '启动扫描失败');
    }
    return response.json();
  },

  // 获取网络扫描状态 (Discovery 模块)
  async getDiscoveryScanStatus(): Promise<DiscoveryScanStatus> {
    const response = await fetch(`${API_BASE_URL}/discovery/scan/status`);
    if (!response.ok) {
      return parseErrorResponse(response, '获取扫描状态失败');
    }
    return response.json();
  },

  // 停止网络扫描 (Discovery 模块)
  async stopDiscoveryScan(): Promise<{ status: string; message: string }> {
    const response = await fetch(`${API_BASE_URL}/discovery/scan/stop`, {
      method: 'POST',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '停止扫描失败');
    }
    return response.json();
  },

  // 清除网络发现结果 (Discovery 模块)
  async clearDiscoveryResults(): Promise<{ deleted: number; message: string }> {
    const response = await fetch(`${API_BASE_URL}/discovery/results`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      return parseErrorResponse(response, '清除结果失败');
    }
    return response.json();
  },

  // 获取报告列表
  async getReports(): Promise<Report[]> {
    const response = await fetch(`${API_BASE_URL}/reports`);
    if (!response.ok) throw new Error('Failed to fetch reports');
    return response.json();
  },

  // 获取用户列表
  async getUsers(): Promise<User[]> {
    const response = await fetch(`${API_BASE_URL}/users`);
    if (!response.ok) throw new Error('Failed to fetch users');
    return response.json();
  },

  // 添加新用户
  async addUser(username: string, email: string, role: string, status: string = 'Active'): Promise<User> {
    const response = await fetch(`${API_BASE_URL}/users`, {
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

  // 获取扫描配置列表
  async getProfiles(): Promise<ScanProfile[]> {
    const response = await fetch(`${API_BASE_URL}/profiles`);
    if (!response.ok) throw new Error('Failed to fetch profiles');
    return response.json();
  },

  // 添加新扫描配置
  async addProfile(name: string, description: string, speed: string, vulnerability_types: string[]): Promise<ScanProfile> {
    const response = await fetch(`${API_BASE_URL}/profiles`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description, speed, vulnerability_types }),
    });
    if (!response.ok) throw new Error('Failed to add profile');
    return response.json();
  },
};
