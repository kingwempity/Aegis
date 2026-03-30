import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { ApiResponse, LoginRequest, RegisterRequest, AuthResponse, CreateTaskRequest, Task, ScanReport, Vulnerability, Statistics, ChartData } from '../types';

// 创建axios实例
const api: AxiosInstance = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000/api/v1',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// 请求拦截器 - 添加认证token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('access_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    console.error('请求拦截器错误:', error);
    return Promise.reject(error);
  }
);

// 响应拦截器 - 处理各种错误情况
api.interceptors.response.use(
  (response: AxiosResponse) => {
    return response;
  },
  async (error) => {
    console.error('API响应错误:', error);

    // 网络错误
    if (!error.response) {
      error.code = 'NETWORK_ERROR';
      error.message = '网络连接失败，请检查网络连接';
      return Promise.reject(error);
    }

    const { status, data } = error.response;

    // 认证错误 - 尝试自动刷新token
    if (status === 401) {
      const refreshToken = localStorage.getItem('refresh_token');

      // 如果有refresh_token且不是refresh接口本身失败的，尝试刷新
      if (refreshToken && !error.config.url?.includes('/auth/refresh/')) {
        try {
          console.log('尝试刷新access token...');
          const refreshResponse = await apiService.refreshToken();

          // 刷新成功，更新localStorage
          localStorage.setItem('access_token', refreshResponse.access_token);
          if (refreshResponse.refresh_token) {
            localStorage.setItem('refresh_token', refreshResponse.refresh_token);
          }

          // 重试原始请求
          console.log('Token刷新成功，重试原始请求...');
          error.config.headers.Authorization = `Bearer ${refreshResponse.access_token}`;
          return api.request(error.config);

        } catch (refreshError) {
          console.error('Token刷新失败:', refreshError);
          // 刷新失败，清除token并跳转登录页
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');

          if (!window.location.pathname.includes('/login')) {
            window.location.href = '/login';
          }
        }
      } else {
        // 没有refresh_token或已经是refresh接口失败，直接跳转登录页
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');

        if (!window.location.pathname.includes('/login')) {
          window.location.href = '/login';
        }
      }
    }

    // 服务器错误
    if (status >= 500) {
      error.message = '服务器内部错误，请稍后重试';
    }

    // 客户端错误
    else if (status >= 400) {
      error.message = data?.message || `请求失败 (${status})`;
    }

    return Promise.reject(error);
  }
);

// API服务类
class ApiService {
  private retryCount = 0;
  private maxRetries = 2;

  // 通用请求方法，带重试机制
  private async request<T>(
    method: 'get' | 'post' | 'put' | 'delete',
    url: string,
    data?: any,
    config?: any
  ): Promise<T> {
    try {
      let response;
      switch (method) {
        case 'get':
          response = await api.get(url, config);
          break;
        case 'post':
          response = await api.post(url, data, config);
          break;
        case 'put':
          response = await api.put(url, data, config);
          break;
        case 'delete':
          response = await api.delete(url, config);
          break;
        default:
          throw new Error(`不支持的请求方法: ${method}`);
      }

      // 重置重试计数
      this.retryCount = 0;
      return response.data.data;

    } catch (error: any) {
      // 如果是网络错误或服务器错误，且未达到最大重试次数，则重试
      if (
        (error.code === 'NETWORK_ERROR' || error.response?.status >= 500) &&
        this.retryCount < this.maxRetries
      ) {
        this.retryCount++;
        console.log(`请求失败，正在重试 (${this.retryCount}/${this.maxRetries}):`, url);

        // 延迟重试
        await new Promise(resolve => setTimeout(resolve, 1000 * this.retryCount));
        return this.request(method, url, data, config);
      }

      // 重置重试计数并抛出错误
      this.retryCount = 0;
      throw error;
    }
  }

  // 认证相关API
  async login(credentials: LoginRequest): Promise<AuthResponse> {
    return this.request<AuthResponse>('post', '/auth/login/', credentials);
  }

  async register(userData: RegisterRequest): Promise<any> {
    return this.request('post', '/auth/register/', userData);
  }

  async refreshToken(): Promise<AuthResponse> {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      throw new Error('没有找到refresh token');
    }

    const response = await this.request<{ access_token: string; refresh_token?: string; token_type: string; expires_in: number }>('post', '/auth/refresh/', {
      refresh_token: refreshToken,
    });

    // 构建完整的AuthResponse格式，如果没有新的refresh_token就使用旧的
    return {
      access_token: response.access_token,
      refresh_token: response.refresh_token || refreshToken,
      token_type: response.token_type,
      expires_in: response.expires_in,
      user: {} as any // 刷新token时不需要用户信息
    };
  }

  async logout(): Promise<void> {
    try {
      await this.request('post', '/auth/logout/');
    } catch (error) {
      // 登出失败不影响用户体验，只记录日志
      console.warn('登出请求失败:', error);
    }
  }

  async getCurrentUser(): Promise<any> {
    return this.request('get', '/auth/me/');
  }

  // 任务管理API
  async createTask(taskData: CreateTaskRequest): Promise<{ task_id: string; status: string; created_at: string }> {
    return this.request('post', '/tasks/create/', taskData);
  }

  async getTaskStatus(taskId: string): Promise<any> {
    return this.request('get', `/tasks/${taskId}/status/`);
  }

  async getTasks(params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    sort_by?: string;
    order?: string;
  }): Promise<{ total: number; page: number; page_size: number; tasks: Task[] }> {
    return this.request('get', '/tasks/list/', undefined, { params });
  }

  async cancelTask(taskId: string): Promise<any> {
    // 后端路由为 /api/v1/tasks/<task_id>/cancel/，需保留末尾斜杠避免 404
    const response = await api.post<ApiResponse>(`/tasks/${taskId}/cancel/`);
    return response.data.data;
  }

  async getTaskDetail(taskId: string): Promise<Task> {
    return this.request<Task>('get', `/tasks/${taskId}/`);
  }

  // 检测结果API
  async getScanReport(taskId: string, format: 'json' | 'pdf' = 'json'): Promise<ScanReport | Blob> {
    if (format === 'pdf') {
      const response = await api.get(`/tasks/${taskId}/report/`, {
        params: { format },
        responseType: 'blob',
      });
      return response.data;
    }

    return this.request<ScanReport>('get', `/tasks/${taskId}/report/`, undefined, {
      params: { format },
    });
  }

  async getVulnerabilityDetail(vulnerabilityId: string): Promise<Vulnerability> {
    return this.request<Vulnerability>('get', `/vulnerabilities/${vulnerabilityId}/`);
  }

  async getVulnerabilityEvidence(vulnerabilityId: string): Promise<any> {
    return this.request('get', `/vulnerabilities/${vulnerabilityId}/evidence/`);
  }

  async exportReport(taskId: string, format: 'pdf' | 'excel' | 'html' | 'markdown', includeEvidence: boolean = false): Promise<Blob> {
    // 对于返回Blob的方法，直接使用axios实例，因为request方法期望JSON响应
    console.log('导出报告请求:', { taskId, format, includeEvidence });
    
    try {
      const response = await api.get(`/tasks/${taskId}/report/export`, {
        params: { format, include_evidence: includeEvidence },
        responseType: 'blob',
      });
      
      console.log('导出报告响应:', { 
        status: response.status, 
        contentType: response.headers['content-type'],
        size: response.data?.size 
      });
      
      // 检查Content-Type，如果是JSON说明是错误响应
      const contentType = response.headers['content-type'] || '';
      if (contentType.includes('application/json')) {
        // 尝试解析JSON错误
        const text = await response.data.text();
        const errorData = JSON.parse(text);
        throw new Error(errorData.message || '导出报告失败');
      }
      
      return response.data;
    } catch (error: any) {
      console.error('导出报告错误:', {
        status: error.response?.status,
        statusText: error.response?.statusText,
        url: error.config?.url,
        taskId,
      });
      
      // 处理错误响应（后端返回JSON但被axios解析为Blob）
      if (error.response && error.response.data instanceof Blob) {
        try {
          const text = await error.response.data.text();
          console.log('错误响应内容:', text.substring(0, 200));
          
          // 尝试解析JSON错误信息
          if (text.trim().startsWith('{')) {
            const errorData = JSON.parse(text);
            const errorMessage = errorData.message || errorData.data?.message || '导出报告失败';
            console.error('解析的错误信息:', errorMessage);
            throw new Error(errorMessage);
          }
        } catch (parseError) {
          // 解析失败，使用状态码判断错误类型
          console.error('解析错误响应失败:', parseError);
        }
      }
      
      // 根据状态码返回友好的错误信息
      const status = error.response?.status;
      if (status === 400) {
        throw new Error('任务未完成，无法导出报告');
      } else if (status === 403) {
        // 尝试从响应中获取详细错误信息
        if (error.response && error.response.data instanceof Blob) {
          try {
            const text = await error.response.data.text();
            if (text.trim().startsWith('{')) {
              const errorData = JSON.parse(text);
              throw new Error(errorData.message || '您没有权限访问该任务');
            }
          } catch {
            // 解析失败，使用默认消息
          }
        }
        throw new Error(`您没有权限访问该任务 (任务ID: ${taskId})`);
      } else if (status === 404) {
        // 检查是否是路由404还是任务不存在
        const url = error.config?.url || '';
        if (url.includes('/report/export/')) {
          // 尝试从响应中获取详细错误信息
          if (error.response && error.response.data instanceof Blob) {
            try {
              const text = await error.response.data.text();
              if (text.trim().startsWith('{')) {
                const errorData = JSON.parse(text);
                throw new Error(errorData.message || `任务不存在 (任务ID: ${taskId})`);
              }
            } catch {
              // 解析失败，使用默认消息
            }
          }
          throw new Error(`任务不存在 (任务ID: ${taskId})`);
        } else {
          throw new Error('导出接口不存在，请检查后端路由配置');
        }
      } else if (status === 401) {
        throw new Error('未授权，请重新登录');
      } else if (error.message) {
        throw new Error(error.message);
      } else {
        throw new Error('导出报告失败');
      }
    }
  }

  // 漏洞库管理API
  async getModules(): Promise<any> {
    return this.request('get', '/modules/list/');
  }

  async updateModules(): Promise<any> {
    return this.request('post', '/modules/update/');
  }

  async getModuleDetail(moduleId: string): Promise<any> {
    return this.request('get', `/modules/${moduleId}/`);
  }

  // 统计与监控API
  async getStatistics(): Promise<Statistics> {
    return this.request<Statistics>('get', '/stats/overview/');
  }

  async getChartData(chartType: string, timeRange: string = '30d', taskId?: string): Promise<ChartData> {
    return this.request<ChartData>('get', '/stats/charts/', undefined, {
      params: { chart_type: chartType, time_range: timeRange, task_id: taskId },
    });
  }

  // 管理员API
  async getAdminStatistics(): Promise<any> {
    return this.request('get', '/admin/statistics/');
  }

  async getAllUsers(params?: { page?: number; page_size?: number }): Promise<any[]> {
    return this.request('get', '/admin/users/', undefined, { params });
  }

  async createUser(userData: any): Promise<any> {
    return this.request('post', '/admin/users/', userData);
  }

  async updateUser(userId: string, userData: any): Promise<any> {
    return this.request('put', `/admin/users/${userId}/`, userData);
  }

  async deleteUser(userId: string): Promise<any> {
    return this.request('delete', `/admin/users/${userId}/`);
  }

  async getAllTasks(params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    user_filter?: string;
  }): Promise<{ total: number; page: number; page_size: number; tasks: Task[] }> {
    return this.request('get', '/admin/tasks/', undefined, { params });
  }

  async deleteTask(taskId: string): Promise<any> {
    return this.request('delete', `/admin/tasks/${taskId}/`);
  }
}

// 导出单例实例
export const apiService = new ApiService();
export default apiService;
