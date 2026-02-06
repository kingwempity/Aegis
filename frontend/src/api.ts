/**
 * Aegis 前端 API 客户端
 * 负责 with FastAPI 后端进行通信
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

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
  ip: string;
  hostname: string;
  ports: number[];
  services: string[];
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

  // 获取漏洞列表
  async getVulnerabilities(severity?: string): Promise<Vulnerability[]> {
    const url = severity 
      ? `${API_BASE_URL}/vulnerabilities?severity=${severity}`
      : `${API_BASE_URL}/vulnerabilities`;
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch vulnerabilities');
    return response.json();
  },

  // 获取目标列表
  async getTargets(): Promise<Target[]> {
    const response = await fetch(`${API_BASE_URL}/discovery/targets`);
    if (!response.ok) throw new Error('Failed to fetch targets');
    return response.json();
  },

  // 添加新目标
  async addTarget(url: string, description?: string): Promise<Target> {
    const response = await fetch(`${API_BASE_URL}/discovery/targets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, description }),
    });
    if (!response.ok) throw new Error('Failed to add target');
    return response.json();
  },

  // 获取资产发现列表
  async getAssets(): Promise<Asset[]> {
    const response = await fetch(`${API_BASE_URL}/discovery/assets`);
    if (!response.ok) throw new Error('Failed to fetch assets');
    return response.json();
  },

  // 触发网络发现扫描
  async startNetworkScan(): Promise<void> {
    const response = await fetch(`${API_BASE_URL}/discovery/scan`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to start network scan');
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
  async addUser(username: string, email: string, role: string, status: string = "Active"): Promise<User> {
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
  }
};
