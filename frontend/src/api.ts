/**
 * Aegis 前端 API 客户端
 * 负责与 FastAPI 后端进行通信
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
  is_active: boolean;
  last_scanned: string;
  critical_vulns: number;
  high_vulns: number;
  low_vulns: number;
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
    const response = await fetch(`${API_BASE_URL}/targets`);
    if (!response.ok) {
      // 如果后端还没实现该接口，返回 Mock 数据以防前端崩溃
      console.warn('Targets API not implemented, returning mock data');
      return [
        { id: 1, url: '192.168.10.156', is_active: true, last_scanned: new Date().toISOString(), critical_vulns: 0, high_vulns: 8, low_vulns: 2 }
      ];
    }
    return response.json();
  }
};
