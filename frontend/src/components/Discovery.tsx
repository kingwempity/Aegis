import React, { useEffect, useState, useRef } from 'react';
import { api, ApiError, Asset, DiscoveryScanStatus } from '../api';
// 使用自定义的轻量级图标组件，彻底摆脱 lucide-react 库
import { Play, StopCircle, Wifi, Info, Trash2 } from './Icons';


const isValidIPv4 = (value: string): boolean => {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const num = Number(part);
    return num >= 0 && num <= 255;
  });
};

const normalizeCidr = (input: string): string | null => {
  const trimmed = input.trim();
  const [ip, mask] = trimmed.split('/');
  const prefix = Number(mask);

  if (!ip || !mask || !Number.isInteger(prefix) || prefix < 0 || prefix > 32 || !isValidIPv4(ip)) {
    return null;
  }

  const octets = ip.split('.').map(Number);
  const ipInt = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  const maskInt = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const networkInt = ipInt & maskInt;
  const normalizedIp = [
    (networkInt >>> 24) & 255,
    (networkInt >>> 16) & 255,
    (networkInt >>> 8) & 255,
    networkInt & 255,
  ].join('.');

  return `${normalizedIp}/${prefix}`;
};

const Discovery: React.FC = () => {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanStatus, setScanStatus] = useState<DiscoveryScanStatus | null>(null);
  const [message, setMessage] = useState<{ text: string; type: 'success' | 'error' } | null>(null);
  const [networkRange, setNetworkRange] = useState('192.168.1.0/24'); // 默认扫描范围
  const statusTimeoutRef = useRef<number | null>(null);
  const isFetchingStatusRef = useRef(false);
  const statusErrorCountRef = useRef(0);
  const gatewayErrorCountRef = useRef(0);
  const gatewayWarningShownRef = useRef(false);

  const clearStatusPolling = () => {
    if (statusTimeoutRef.current) {
      clearTimeout(statusTimeoutRef.current);
      statusTimeoutRef.current = null;
    }
  };

  const scheduleNextStatusPoll = (delay = 3000) => {
    clearStatusPolling();
    statusTimeoutRef.current = window.setTimeout(() => {
      fetchScanStatus();
    }, delay);
  };

  const startStatusPolling = (immediate = false) => {
    if (immediate) {
      fetchScanStatus();
      return;
    }
    scheduleNextStatusPoll();
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await api.getAssets();
      setAssets(data);
    } catch (error) {
      console.error('Error fetching assets:', error);
      setMessage({ text: '获取资产列表失败', type: 'error' });
    } finally {
      setLoading(false);
    }
  };

  const fetchScanStatus = async () => {
    if (isFetchingStatusRef.current) {
      return;
    }

    isFetchingStatusRef.current = true;
    try {
      const status = await api.getDiscoveryScanStatus();
      statusErrorCountRef.current = 0;
      gatewayErrorCountRef.current = 0;
      gatewayWarningShownRef.current = false;
      setScanStatus(status);
      if (!status.is_scanning) {
        clearStatusPolling();
        if (status.progress === 100) {
          setMessage({ text: status.message || '网络发现扫描完成', type: 'success' });
          fetchData(); // 扫描完成后刷新资产列表
        } else if (status.progress === 0 && status.message && status.message.includes('失败')) {
          setMessage({ text: status.message, type: 'error' });
        }
      } else {
        scheduleNextStatusPoll();
      }
    } catch (error) {
      if (error instanceof ApiError && error.isTemporaryGatewayError) {
        gatewayErrorCountRef.current += 1;
        const backoffDelay = Math.min(3000 * 2 ** (gatewayErrorCountRef.current - 1), 30000);
        if (!gatewayWarningShownRef.current) {
          setMessage({ text: '状态服务短暂超时，系统将自动重试...', type: 'error' });
          gatewayWarningShownRef.current = true;
        }
        scheduleNextStatusPoll(backoffDelay);
        return;
      }

      console.error('Error fetching scan status:', error);
      statusErrorCountRef.current += 1;
      if (statusErrorCountRef.current >= 3) {
        clearStatusPolling();
        setMessage({ text: '扫描状态接口不可用，已暂停轮询，请稍后重试', type: 'error' });
      } else {
        setMessage({ text: `获取扫描状态失败（${statusErrorCountRef.current}/3）`, type: 'error' });
        scheduleNextStatusPoll();
      }
    } finally {
      isFetchingStatusRef.current = false;
    }
  };

  useEffect(() => {
    fetchData();
    fetchScanStatus();
    api.getDiscoverySuggestedRange().then(({ network_range }) => {
      if (network_range && normalizeCidr(network_range)) setNetworkRange(network_range);
    }).catch(() => {});

    return () => {
      clearStatusPolling();
    };
  }, []);

  const handleStartScan = async () => {
    setMessage(null);

    const normalizedRange = normalizeCidr(networkRange);
    if (!normalizedRange) {
      setMessage({ text: '网段格式无效，请输入如 192.168.1.0/24', type: 'error' });
      return;
    }

    setNetworkRange(normalizedRange);

    try {
      const result = await api.startDiscoveryScan(normalizedRange);
      if (result.status === 'already_running') {
        setMessage({ text: result.message || '扫描任务正在进行中', type: 'success' });
      } else {
        setMessage({ text: '网络发现扫描已启动', type: 'success' });
      }
      statusErrorCountRef.current = 0;
      gatewayErrorCountRef.current = 0;
      startStatusPolling(true);
    } catch (error: any) {
      const detail = error?.message || '';
      // 后端返回“扫描任务正在进行中”时，尝试强制启动一次
      if (detail.includes('扫描任务正在进行中')) {
        try {
          await api.startDiscoveryScan(normalizedRange, true);
          setMessage({ text: '检测到已有扫描任务，已强制重启扫描', type: 'success' });
          statusErrorCountRef.current = 0;
          gatewayErrorCountRef.current = 0;
          startStatusPolling(true);
          return;
        } catch (forceError: any) {
          setMessage({ text: forceError.message || '强制启动扫描失败，请稍后再试', type: 'error' });
          return;
        }
      }
      setMessage({ text: detail || '启动扫描失败，请稍后再试', type: 'error' });
    }
  };

  const handleStopScan = async () => {
    setMessage(null);
    try {
      await api.stopDiscoveryScan();
      setMessage({ text: '网络发现扫描已停止', type: 'success' });
    } catch (error: any) {
      setMessage({ text: error.message || '停止扫描失败，请稍后再试', type: 'error' });
    }
  };

  const handleClearResults = async () => {
    if (!window.confirm('确定要清除所有发现结果吗？此操作不可逆。')) {
      return;
    }
    setMessage(null);
    try {
      await api.clearDiscoveryResults();
      setMessage({ text: '所有发现结果已清除', type: 'success' });
      fetchData(); // 清除后刷新列表
    } catch (error: any) {
      setMessage({ text: error.message || '清除结果失败，请稍后再试', type: 'error' });
    }
  };

  return (
    <div className="flex flex-col gap-8 max-w-7xl mx-auto p-4 md:p-8">
      <div className="rounded-3xl border border-[#d9e6ee] bg-gradient-to-r from-[#eef5f7] via-[#f5f8fa] to-[#edf4f7] px-8 py-7 text-[#334155] shadow-[0_16px_40px_rgba(148,163,184,0.16)]">
        <div className="max-w-3xl">
          <div className="inline-flex rounded-full border border-[#d7e6ec] bg-[#e7f0f4] px-3 py-1 text-xs font-semibold tracking-wide text-[#567487]">
            Attack Surface Discovery
          </div>
          <h2 className="mt-4 text-3xl font-black tracking-tight text-[#243b53]">资产发现与攻击面摸排</h2>
          <p className="mt-3 text-sm leading-6 text-[#5b7083]">
            这里负责发现主机、开放端口与服务，用于构建攻击面视图；真正的 Web 模拟攻击验证请在 Web Targets 和 Attack Validation 中发起。
          </p>
        </div>
      </div>

      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="text-3xl font-black text-[#2d3343] tracking-tight">攻击面发现</h2>
          <p className="text-gray-400 mt-1 font-medium">自动发现网络中的设备、开放端口和可暴露服务</p>
          <p className="text-amber-600/90 mt-1.5 text-xs font-medium">
            部署在 Docker 且无法使用 VPC 时，使用 172.17.0.0/24 可发现本机网关及同主机上的容器。
          </p>
        </div>
        <div className="flex items-center gap-3">
          <input
            type="text"
            value={networkRange}
            onChange={(e) => setNetworkRange(e.target.value)}
            placeholder="例如: 192.168.1.0/24"
            className="px-4 py-2.5 bg-gray-50 border-none rounded-xl focus:ring-2 focus:ring-orange-500/20 transition-all text-[#2d3343] font-medium placeholder:text-gray-400 text-sm w-48"
            disabled={scanStatus?.is_scanning}
          />
          {scanStatus?.is_scanning ? (
            <button
              onClick={handleStopScan}
              className="flex items-center gap-2 px-5 py-2.5 bg-red-500 text-white rounded-xl font-bold text-sm hover:bg-red-600 transition-all shadow-lg shadow-red-200 active:scale-95"
            >
              <StopCircle size={18} strokeWidth={3} />
              停止发现
            </button>
          ) : (
            <button
              onClick={handleStartScan}
              className="flex items-center gap-2 px-5 py-2.5 bg-[#ff6b00] text-white rounded-xl font-bold text-sm hover:bg-[#e66000] transition-all shadow-lg shadow-orange-200 active:scale-95"
            >
              <Play size={18} strokeWidth={3} />
              开始发现
            </button>
          )}
          <button
            onClick={handleClearResults}
            className="flex items-center gap-2 px-5 py-2.5 bg-gray-100 text-gray-600 rounded-xl font-bold text-sm hover:bg-gray-200 transition-all active:scale-95"
          >
            <Trash2 size={18} strokeWidth={2} />
            清除结果
          </button>
        </div>
      </div>

      {message && (
        <div className={`p-4 rounded-2xl text-sm font-medium flex items-center gap-3 animate-in fade-in slide-in-from-top-1 ${message.type === 'success' ? 'bg-green-50 text-green-600' : 'bg-red-50 text-red-600'}`}>
          <Info size={18} />
          {message.text}
        </div>
      )}

      {scanStatus?.is_scanning && (
        <div className="bg-white rounded-3xl shadow-sm border border-gray-100 p-6 flex flex-col gap-4">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-orange-50 rounded-xl flex items-center justify-center text-[#ff6b00]">
              <Wifi size={24} />
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-bold text-[#2d3343]">攻击面发现进行中...</h3>
              <p className="text-sm text-gray-500">{scanStatus.message || '正在识别网络设备与暴露服务...'}</p>
            </div>
            <span className="text-2xl font-bold text-[#ff6b00]">{scanStatus.progress}%</span>
          </div>
          <div className="w-full bg-gray-100 rounded-full h-2.5">
            <div
              className="bg-[#ff6b00] h-2.5 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${scanStatus.progress}%` }}
            ></div>
          </div>
        </div>
      )}

      <div className="bg-white rounded-3xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">IP 地址</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">主机名</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">MAC 地址</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">开放端口</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">操作系统</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">暴露服务</th>
              <th className="px-8 py-4 text-xs font-bold text-gray-400 uppercase tracking-wider">最后在线</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {loading ? (
              Array(5).fill(0).map((_, i) => (
                <tr key={i} className="animate-pulse">
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded w-3/4"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded w-1/2"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded w-1/3"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded w-2/3"></div></td>
                  <td className="px-8 py-5"><div className="h-4 bg-gray-100 rounded w-1/4"></div></td>
                </tr>
              ))
            ) : assets.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-8 py-12 text-center text-gray-400">
                  <div className="flex flex-col items-center justify-center">
                    <Wifi size={48} className="text-gray-200 mb-4" />
                    <p className="font-bold">暂未发现任何攻击面资产</p>
                    <p className="text-sm mt-1">点击“开始发现”来识别网络中的设备与开放服务</p>
                  </div>
                </td>
              </tr>
            ) : (
              assets.map((asset) => (
                <tr key={asset.ip_address} className="hover:bg-gray-50/50 transition-colors">
                  <td className="px-8 py-5 font-bold text-[#2d3343]">{asset.ip_address}</td>
                  <td className="px-8 py-5 text-gray-600">{asset.hostname || '-'}</td>
                  <td className="px-8 py-5 text-gray-600">{asset.mac_address || '-'}</td>
                  <td className="px-8 py-5">
                    <div className="flex flex-wrap gap-1">
                      {asset.open_ports.length > 0 ? (
                        asset.open_ports.map(port => (
                          <span key={port} className="px-2 py-0.5 bg-blue-50 text-blue-600 rounded text-[10px] font-bold">{port}</span>
                        ))
                      ) : (
                        <span className="text-gray-400 text-[10px]">-</span>
                      )}
                    </div>
                  </td>
                  <td className="px-8 py-5 text-gray-600">{asset.os_info || '-'}</td>
                  <td className="px-8 py-5 text-gray-500 text-sm">
                    {asset.services.length > 0 ? asset.services.join(', ') : '-'}
                  </td>
                  <td className="px-8 py-5 text-gray-400 text-xs">{new Date(asset.last_seen).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default Discovery;
